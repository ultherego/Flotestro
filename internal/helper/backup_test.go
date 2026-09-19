package helper

import (
	"context"
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/backup"
)

// planningAdapter answers with the repository state a case wants and counts
// nothing else: the binding of a plan is decided by the state the host reads
// again, not by the tool that reads it.
type planningAdapter struct {
	state backup.State
	err   error
}

func (a *planningAdapter) Name() string                   { return "test" }
func (a *planningAdapter) Available() bool                { return true }
func (a *planningAdapter) Version(context.Context) string { return "0" }

func (a *planningAdapter) Plan(context.Context, backup.Order) (backup.State, error) {
	return a.state, a.err
}

func (a *planningAdapter) Run(context.Context, backup.Order, backup.ProgressFunc) (backup.Result, error) {
	return backup.Result{}, nil
}

func (a *planningAdapter) Verify(context.Context, backup.Order) (backup.Result, error) {
	return backup.Result{}, nil
}

func (a *planningAdapter) RestoreData(context.Context, backup.Order) (backup.Result, error) {
	return backup.Result{}, nil
}

// backupOrder is a definition the plan of which can be computed without a
// repository: a runbook copy needs no tool on the host.
func backupOrder() backup.Order {
	return backup.Order{Definition: backup.Definition{
		ID: "nightly", Tool: backup.ToolRunbook, Repository: "/srv/backup",
		Runbook: "nightly.sh", Initialize: true,
	}}
}

// The digest of backup.
func TestABackupIsBoundToThePlanItWasApprovedWith(t *testing.T) {
	ctx := context.Background()
	order := backupOrder()
	adapter := &planningAdapter{state: backup.State{Tool: backup.ToolRunbook, Repository: "/srv/backup"}}
	current := backup.Compute(adapter.state, order.Definition, false, false, nil)
	if current.PlanHash == "" {
		t.Fatal("the plan of the copy has no digest")
	}

	held := &helperv1.BackupRequest{PlanHash: current.PlanHash}
	if refusal := checkBackupPlanDigest(ctx, adapter, order, held, false); refusal != nil {
		t.Fatalf("the plan that still holds was refused: %s %s", refusal.GetErrorCode(), refusal.GetMessage())
	}

	foreign := &helperv1.BackupRequest{PlanHash: "0000000000000000000000000000000000000000000000000000000000000000"}
	refusal := checkBackupPlanDigest(ctx, adapter, order, foreign, false)
	if refusal == nil {
		t.Fatal("a digest from another plan was accepted")
	}
	if refusal.GetAccepted() || refusal.GetErrorCode() != errorStalePlan {
		t.Errorf("code = %q, expected %s", refusal.GetErrorCode(), errorStalePlan)
	}

	// A check hashes another plan than a copy - it describes another
	// change - so the digest of a copy does not let a check through.
	if refusal := checkBackupPlanDigest(ctx, adapter, order, held, true); refusal == nil {
		t.Error("the digest of a copy let a check through")
	}

	// The single-host convenience that is left: an order without a digest is the
	// operator ordering a copy from the host's own screen, and it is not refused.
	if refusal := checkBackupPlanDigest(ctx, adapter, order, &helperv1.BackupRequest{}, false); refusal != nil {
		t.Errorf("an order without a plan was refused: %s", refusal.GetErrorCode())
	}
}

// A repository that answers differently than at the planning gives another
// digest: the operator approved unpacking out of the repository as it was, and
// a repository with another copy in it is not that repository.
func TestARepositoryThatMovedRefusesTheApprovedPlan(t *testing.T) {
	ctx := context.Background()
	order := backupOrder()
	planned := backup.State{Tool: backup.ToolRunbook, Repository: "/srv/backup"}
	approved := backup.Compute(planned, order.Definition, false, false, nil)

	moved := planned
	moved.Snapshots = []backup.Snapshot{{ID: "snapshot-taken-since"}}
	adapter := &planningAdapter{state: moved}

	refusal := checkBackupPlanDigest(ctx, adapter, order,
		&helperv1.BackupRequest{PlanHash: approved.PlanHash}, false)
	if refusal == nil || refusal.GetErrorCode() != errorStalePlan {
		t.Fatalf("refusal = %+v, expected %s", refusal, errorStalePlan)
	}
}
