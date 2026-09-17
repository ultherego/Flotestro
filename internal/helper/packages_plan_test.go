package helper

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/plan"
)

// fakePlanner stands in for the package manager: it answers every plan
// with the content it was given, under the header of the request, and
// records what it was asked to execute.
type fakePlanner struct {
	content packages.Plan
	applied []string
	// planErr makes the plan fail, as it does when the metadata cache is
	// gone.
	planErr error
}

func (f *fakePlanner) Name() string             { return "apt" }
func (f *fakePlanner) Available() bool          { return true }
func (f *fakePlanner) LockHeld() (bool, string) { return false, "" }
func (f *fakePlanner) Refresh(context.Context) error {
	return nil
}
func (f *fakePlanner) DatabaseBroken(context.Context) bool { return false }
func (f *fakePlanner) Upgrade(context.Context, packages.Options) (packages.Apply, error) {
	return packages.Apply{}, errors.New("the fake planner does not upgrade by name")
}

func (f *fakePlanner) Plan(_ context.Context, options packages.Options) (packages.Plan, error) {
	if f.planErr != nil {
		return packages.Plan{}, f.planErr
	}
	p := f.content
	p.Changes = append([]packages.Change(nil), f.content.Changes...)
	p.SchemaVersion = plan.SchemaVersion
	p.PlannerVersion = packages.PlannerVersion
	p.Mode = options.Mode
	p.HostID = options.Header.HostID
	p.InventoryRevision = options.Header.InventoryRevision
	p.ExpiresAt = options.Header.ExpiresAt
	return p, nil
}

func (f *fakePlanner) ApplyExact(_ context.Context, approved packages.Plan, _ packages.Options) (packages.Apply, error) {
	f.applied = approved.ExactSpecs()
	achieved, missed := approved.Envelope().Effects.Settle(map[string]string{"openssl": "3.0.16-1"})
	return packages.Apply{Manager: "apt", EffectsAchieved: achieved, EffectsMissed: missed}, plan.Partial(missed)
}

func approvedContent() packages.Plan {
	return packages.Plan{
		Manager: "apt", Mode: packages.ModeUpgrade, ResourceRevision: "apt:0123",
		Changes: []packages.Change{{
			Name: "openssl", CurrentVersion: "3.0.15-1", CandidateVersion: "3.0.16-1",
			Origin: "Debian-Security:12/stable-security", Architecture: "amd64",
			Action: packages.ActionUpgrade, Reason: packages.ReasonRequested,
		}},
		Rollback: packages.Rollback{Mechanism: packages.RollbackNone, Reason: "apt keeps no transaction to undo"},
	}
}

// approvedRequest is the order as the agent hands it to the helper: the
// digest the agent computed at planning under the given header, and the
// header itself.
func approvedRequest(t *testing.T, content packages.Plan, header packages.PlanHeader) *helperv1.HelperRequest {
	t.Helper()
	planner := &fakePlanner{content: content}
	planned, err := planner.Plan(context.Background(), packages.Options{Mode: packages.ModeUpgrade, Header: header})
	if err != nil {
		t.Fatal(err)
	}
	specs := make([]*helperv1.PackageExactSpec, 0, len(planned.Changes))
	for _, change := range planned.Changes {
		specs = append(specs, &helperv1.PackageExactSpec{
			Name: change.Name, CurrentVersion: change.CurrentVersion, CandidateVersion: change.CandidateVersion,
			Architecture: change.Architecture, Origin: change.Origin, Action: change.Action,
		})
	}
	return &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "task-plan",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  30,
		Action: &helperv1.HelperRequest_PackageAction{
			PackageAction: &helperv1.PackageActionRequest{
				Operation:             helperv1.PackageActionRequest_OPERATION_UPGRADE,
				PlanHash:              planned.Hash(),
				PlanSchemaVersion:     plan.SchemaVersion,
				PlannerVersion:        packages.PlannerVersion,
				PlanHostId:            header.HostID,
				PlanInventoryRevision: header.InventoryRevision,
				PlanResourceRevision:  content.ResourceRevision,
				PlanExpiresAtUnix:     header.ExpiresAt.Unix(),
				ExactSpecs:            specs,
			},
		},
	}
}

func testHeader() packages.PlanHeader {
	return packages.PlanHeader{HostID: "host-1", InventoryRevision: "rev-1",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
}

// A repository that changed between the approval and the execution gives
// stale_plan, names the package that moved, and nothing runs.
func TestTheHelperRefusesAPlanWhoseRepositoryMoved(t *testing.T) {
	request := approvedRequest(t, approvedContent(), testHeader())
	moved := approvedContent()
	moved.Changes[0].Origin = "Debian:12/stable"
	planner := &fakePlanner{content: moved}
	server := testServer()
	server.packageManager = func() (packages.Manager, error) { return planner, nil }

	response := server.handle(context.Background(), request, nil)
	if response.GetAccepted() {
		t.Fatal("a plan whose repository moved was executed")
	}
	if response.GetErrorCode() != plan.ErrorStalePlan {
		t.Fatalf("code = %q, expected %q: %s", response.GetErrorCode(), plan.ErrorStalePlan, response.GetMessage())
	}
	if !strings.Contains(response.GetMessage(), "openssl: approved from Debian-Security:12/stable-security, now from Debian:12/stable") {
		t.Errorf("the refusal does not name the package that moved: %s", response.GetMessage())
	}
	if planner.applied != nil {
		t.Errorf("the transaction ran on a stale plan: %v", planner.applied)
	}
}

// Another architecture of the same version is another plan too.
func TestTheHelperRefusesAPlanWhoseArchitectureMoved(t *testing.T) {
	request := approvedRequest(t, approvedContent(), testHeader())
	moved := approvedContent()
	moved.Changes[0].Architecture = "i386"
	planner := &fakePlanner{content: moved}
	server := testServer()
	server.packageManager = func() (packages.Manager, error) { return planner, nil }
	response := server.handle(context.Background(), request, nil)
	if response.GetAccepted() || response.GetErrorCode() != plan.ErrorStalePlan {
		t.Fatalf("code = %q, accepted = %v", response.GetErrorCode(), response.GetAccepted())
	}
}

// The same plan runs, on the exact specs, and the result settles the
// effects.
func TestTheHelperExecutesTheApprovedPlanExactly(t *testing.T) {
	request := approvedRequest(t, approvedContent(), testHeader())
	planner := &fakePlanner{content: approvedContent()}
	server := testServer()
	server.packageManager = func() (packages.Manager, error) { return planner, nil }
	response := server.handle(context.Background(), request, nil)
	if !response.GetAccepted() {
		t.Fatalf("the approved plan was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	if len(planner.applied) != 1 || planner.applied[0] != "openssl:amd64=3.0.16-1" {
		t.Errorf("the transaction ran on %v, expected the exact spec", planner.applied)
	}
	result := response.GetPackageResult()
	if len(result.GetEffectsAchieved()) != 1 || result.GetEffectsAchieved()[0].GetSubject() != "openssl" ||
		result.GetEffectsAchieved()[0].GetObserved() != "3.0.16-1" || !result.GetEffectsAchieved()[0].GetAchieved() {
		t.Errorf("effects = %+v", result.GetEffectsAchieved())
	}
}

// An effect the host did not reach is a partial result with its own
// code, and the result names it.
func TestTheHelperReportsAPartialResult(t *testing.T) {
	content := approvedContent()
	content.Changes = append(content.Changes, packages.Change{
		Name: "libssl3", CurrentVersion: "3.0.15-1", CandidateVersion: "3.0.16-1",
		Origin: "Debian-Security:12/stable-security", Architecture: "amd64", Action: packages.ActionUpgrade,
	})
	request := approvedRequest(t, content, testHeader())
	planner := &fakePlanner{content: content}
	server := testServer()
	server.packageManager = func() (packages.Manager, error) { return planner, nil }
	response := server.handle(context.Background(), request, nil)
	if response.GetAccepted() || response.GetErrorCode() != plan.ErrorEffectsPartial {
		t.Fatalf("code = %q, accepted = %v", response.GetErrorCode(), response.GetAccepted())
	}
	missed := response.GetPackageResult().GetEffectsMissed()
	if len(missed) != 1 || missed[0].GetSubject() != "libssl3" || missed[0].GetObserved() != "absent" {
		t.Errorf("missed = %+v", missed)
	}
	if len(response.GetPackageResult().GetEffectsAchieved()) != 1 {
		t.Errorf("achieved = %+v", response.GetPackageResult().GetEffectsAchieved())
	}
}

// A plan made by another planner version is not a stale plan and not a
// JSON error: it has to be computed again.
func TestTheHelperAsksForAReplanOnAnotherPlannerVersion(t *testing.T) {
	request := approvedRequest(t, approvedContent(), testHeader())
	request.GetPackageAction().PlannerVersion = "packages/0"
	planner := &fakePlanner{content: approvedContent()}
	server := testServer()
	server.packageManager = func() (packages.Manager, error) { return planner, nil }
	response := server.handle(context.Background(), request, nil)
	if response.GetAccepted() || response.GetErrorCode() != plan.ErrorReplanRequired {
		t.Fatalf("code = %q, accepted = %v", response.GetErrorCode(), response.GetAccepted())
	}
	if planner.applied != nil {
		t.Error("the transaction ran under another planner version")
	}
}

// A plan past its expiry is refused whatever its digest looks like.
func TestTheHelperRefusesAnExpiredPlan(t *testing.T) {
	header := testHeader()
	header.ExpiresAt = time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	request := approvedRequest(t, approvedContent(), header)
	planner := &fakePlanner{content: approvedContent()}
	server := testServer()
	server.packageManager = func() (packages.Manager, error) { return planner, nil }
	response := server.handle(context.Background(), request, nil)
	if response.GetAccepted() || response.GetErrorCode() != plan.ErrorPlanExpired {
		t.Fatalf("code = %q, accepted = %v", response.GetErrorCode(), response.GetAccepted())
	}
}

// A digest the agent could have tampered with is not a match: the hash
// the helper expects comes from the panel's order, and a plan that does
// not hash to it does not run.
func TestTheHelperRefusesATamperedDigest(t *testing.T) {
	request := approvedRequest(t, approvedContent(), testHeader())
	request.GetPackageAction().PlanHash[0] ^= 0xff
	planner := &fakePlanner{content: approvedContent()}
	server := testServer()
	server.packageManager = func() (packages.Manager, error) { return planner, nil }
	response := server.handle(context.Background(), request, nil)
	if response.GetAccepted() || response.GetErrorCode() != plan.ErrorStalePlan {
		t.Fatalf("code = %q, accepted = %v", response.GetErrorCode(), response.GetAccepted())
	}
}

// The order without a digest is a legacy one and takes the old path: the
// fake planner has no upgrade by name, and that is the failure reported.
func TestAnOrderWithoutADigestIsNotBoundToAPlan(t *testing.T) {
	request := approvedRequest(t, approvedContent(), testHeader())
	request.GetPackageAction().PlanHash = nil
	planner := &fakePlanner{content: approvedContent()}
	server := testServer()
	server.packageManager = func() (packages.Manager, error) { return planner, nil }
	response := server.handle(context.Background(), request, nil)
	if response.GetAccepted() || response.GetErrorCode() != packages.ErrorTransaction {
		t.Fatalf("code = %q, accepted = %v", response.GetErrorCode(), response.GetAccepted())
	}
	if planner.applied != nil {
		t.Error("an order without a digest ran the exact path")
	}
}
