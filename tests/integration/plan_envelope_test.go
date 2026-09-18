//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"regexp"
	"testing"
	"time"
)

// The plan envelope of chapter 7: a package plan names, for every element,
// the exact version, the architecture, the origin and the direction; the
// execution runs exactly that and settles every effect; a plan the host no
// longer computes - or one whose digest was tampered with - is refused
// with stale_plan and nothing is applied.

// envelopePlan is the package plan as the API serves it, with the header
// of the envelope. It is decoded apart from packageDetail so the test
// reads exactly the fields the envelope adds.
type envelopePlan struct {
	Kind              string          `json:"kind"`
	Manager           string          `json:"manager"`
	Mode              string          `json:"mode"`
	PlanHash          string          `json:"plan_hash"`
	SchemaVersion     uint32          `json:"schema_version"`
	PlannerVersion    string          `json:"planner_version"`
	HostID            string          `json:"host_id"`
	InventoryRevision string          `json:"inventory_revision"`
	ResourceRevision  string          `json:"resource_revision"`
	ExpiresAt         string          `json:"expires_at"`
	Description       string          `json:"description"`
	Envelope          json.RawMessage `json:"envelope"`
	Rollback          struct {
		Mechanism string `json:"mechanism"`
		Available bool   `json:"available"`
		Reason    string `json:"reason"`
	} `json:"rollback"`
	Changes []envelopeChange `json:"changes"`
}

type envelopeChange struct {
	Name             string `json:"name"`
	CurrentVersion   string `json:"current_version"`
	CandidateVersion string `json:"candidate_version"`
	Origin           string `json:"origin"`
	Architecture     string `json:"architecture"`
	Action           string `json:"action"`
	Reason           string `json:"reason"`
}

// envelopeApply is the result of a transaction with the settled effects.
type envelopeApply struct {
	Kind    string `json:"kind"`
	Applied []struct {
		Name             string `json:"name"`
		CandidateVersion string `json:"candidate_version"`
		Effect           string `json:"effect"`
		ObservedVersion  string `json:"observed_version"`
	} `json:"applied"`
	Effects []struct {
		Name            string `json:"name"`
		Effect          string `json:"effect"`
		ObservedVersion string `json:"observed_version"`
	} `json:"effects"`
}

// rawAttempts reads the attempts of a job with their detail untouched.
func rawAttempts(h *harness, jobID string) []json.RawMessage {
	h.t.Helper()
	var result struct {
		Items []struct {
			Detail json.RawMessage `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &result)
	details := make([]json.RawMessage, 0, len(result.Items))
	for _, item := range result.Items {
		details = append(details, item.Detail)
	}
	return details
}

// planInstall computes the installation plan of one package and returns
// it with the envelope header.
func planInstall(t *testing.T, h *harness, hostID, pkg string) envelopePlan {
	t.Helper()
	job, _ := h.runOperation(hostID, map[string]any{
		"action": "packages.plan", "reason": lifecycleReason,
		"payload": map[string]any{"package_plan": map[string]any{
			"mode": "install", "only_packages": []string{pkg}, "refresh_metadata": true,
		}},
	}, 5*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the installation plan ended in state %s: %s %s", job.State, job.ResultErrorCode, job.ResultMessage)
	}
	details := rawAttempts(h, job.ID)
	if len(details) == 0 || len(details[len(details)-1]) == 0 {
		t.Fatal("the plan job has no result")
	}
	var plan envelopePlan
	if err := json.Unmarshal(details[len(details)-1], &plan); err != nil {
		t.Fatalf("decoding the plan: %v", err)
	}
	if plan.Kind != "package_plan" {
		t.Fatalf("no typed plan result: %s", truncate(details[len(details)-1], 300))
	}
	return plan
}

// planReference is the reference of a plan as an order carries it.
func planReference(plan envelopePlan) map[string]any {
	changes := make([]map[string]any, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		changes = append(changes, map[string]any{
			"name": change.Name, "current_version": change.CurrentVersion,
			"candidate_version": change.CandidateVersion, "architecture": change.Architecture,
			"origin": change.Origin, "action": change.Action,
		})
	}
	return map[string]any{
		"schema_version": plan.SchemaVersion, "planner_version": plan.PlannerVersion,
		"inventory_revision": plan.InventoryRevision, "resource_revision": plan.ResourceRevision,
		"expires_at": plan.ExpiresAt, "changes": changes,
	}
}

// ensureAbsent removes the package when it is installed, so the
// installation plan below has something to install. The removal goes
// through the same door as the rest: a plan of the removal set, an
// approval, a second person in production.
func ensureAbsent(t *testing.T, h *harness, host hostView, pkg string) {
	t.Helper()
	plan := dnfRemovalPlan(t, h, host.ID, pkg)
	if len(plan.Removals) == 0 {
		return
	}
	removal := h.createOperation(host.ID, map[string]any{
		"action": "packages.remove", "reason": lifecycleReason,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{pkg}, "expected_removals": plan.Removals,
		}},
	})
	state := h.approve(removal.ID, removal.PayloadHash)
	if state.State == "awaiting_approval" {
		second := h.withToken(h.createPrincipal(uniqueSubject("second-person-envelope"),
			[]map[string]string{{"role": "approver", "site": host.Site, "environment": host.Environment}}))
		state = second.approve(removal.ID, removal.PayloadHash)
	}
	if final := h.awaitTerminal(removal.ID, 10*time.Minute); final.State != "succeeded" {
		t.Fatalf("the removal of %s before the test ended in state %s: %s", pkg, final.State, final.ResultMessage)
	}
}

var planDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TestPackagePlanCarriesTheEnvelope checks that a plan on Debian and on
// the RHEL family names, per element, the origin, the architecture and
// the direction, and carries the header of the envelope: the planner, the
// expiry and the canonical body the digest was computed over.
func TestPackagePlanCarriesTheEnvelope(t *testing.T) {
	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			h := newHarness(t)
			host := h.hostByFamily(family)
			ensureAbsent(t, h, host, testPackage)
			plan := planInstall(t, h, host.ID, testPackage)

			if !planDigestPattern.MatchString(plan.PlanHash) {
				t.Errorf("the plan digest is not a SHA-256: %q", plan.PlanHash)
			}
			if plan.PlannerVersion == "" || plan.SchemaVersion == 0 {
				t.Errorf("the plan names no planner: version %q, schema %d", plan.PlannerVersion, plan.SchemaVersion)
			}
			if plan.HostID != host.ID {
				t.Errorf("the plan is for host %q, computed on %q", plan.HostID, host.ID)
			}
			expiry, err := time.Parse(time.RFC3339, plan.ExpiresAt)
			if err != nil || !expiry.After(time.Now()) {
				t.Errorf("the plan has no expiry ahead: %q (%v)", plan.ExpiresAt, err)
			}
			if plan.ResourceRevision == "" {
				t.Error("the plan names no revision of the repository metadata")
			}
			if len(plan.Envelope) == 0 {
				t.Error("the plan carries no canonical envelope")
			}
			if plan.Rollback.Mechanism == "" {
				t.Error("the plan does not say whether the change can be rolled back")
			}
			if len(plan.Changes) == 0 {
				t.Fatalf("the installation plan of %s is empty: %s", testPackage, plan.Description)
			}
			for _, change := range plan.Changes {
				if change.Origin == "" || change.Architecture == "" {
					t.Errorf("%s: origin %q, architecture %q", change.Name, change.Origin, change.Architecture)
				}
				switch change.Action {
				case "install", "upgrade", "downgrade", "remove":
				default:
					t.Errorf("%s: the direction is %q", change.Name, change.Action)
				}
				if change.Action != "remove" && change.CandidateVersion == "" {
					t.Errorf("%s: no candidate version", change.Name)
				}
			}
		})
	}
}

// TestLifecycleInstallExecutesTheApprovedPlanExactly installs a small
// package through a plan bound to its envelope: the transaction runs on
// the exact versions of the plan and the result lists every effect
// reached.
func TestLifecycleInstallExecutesTheApprovedPlanExactly(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	ensureAbsent(t, h, host, testPackage)
	plan := planInstall(t, h, host.ID, testPackage)
	if len(plan.Changes) == 0 {
		t.Fatalf("nothing to install: %s", plan.Description)
	}
	t.Cleanup(func() {
		h.createOperation(host.ID, map[string]any{
			"action": "packages.remove", "reason": lifecycleReason,
			"target_confirmation": host.Hostname,
			"payload": map[string]any{"package_change": map[string]any{
				"packages": []string{testPackage}, "expected_removals": []string{testPackage},
			}},
		})
	})

	job, _ := h.runOperation(host.ID, map[string]any{
		"action": "packages.install", "reason": lifecycleReason,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{testPackage}, "plan_hash": plan.PlanHash, "plan": planReference(plan),
		}},
	}, 10*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the bound installation ended in state %s: %s %s", job.State, job.ResultErrorCode, job.ResultMessage)
	}
	details := rawAttempts(h, job.ID)
	var apply envelopeApply
	if len(details) == 0 || json.Unmarshal(details[len(details)-1], &apply) != nil {
		t.Fatalf("the installation has no readable result: %+v", details)
	}
	// The effect of the package asked for is settled as achieved with the
	// version the plan named, whichever list the panel puts it in.
	achieved := false
	for _, entry := range apply.Applied {
		if entry.Name == testPackage && entry.Effect == "achieved" {
			achieved = true
		}
	}
	for _, entry := range apply.Effects {
		if entry.Name == testPackage && entry.Effect == "achieved" {
			achieved = true
		}
	}
	if !achieved {
		t.Errorf("the result does not settle the effect on %s as achieved: %s", testPackage, truncate(details[len(details)-1], 600))
	}
	// The version installed is the version the plan named.
	var expected string
	for _, change := range plan.Changes {
		if change.Name == testPackage {
			expected = change.CandidateVersion
		}
	}
	found := false
	for _, entry := range apply.Applied {
		if entry.Name == testPackage && entry.Effect == "" && entry.CandidateVersion == expected {
			found = true
		}
	}
	if !found {
		t.Errorf("%s was not recorded as installed at %s: %s", testPackage, expected, truncate(details[len(details)-1], 600))
	}
}

// TestATamperedPlanHashIsRefusedByTheHost binds an installation to a
// digest that is not the digest of the plan the host computes: the host
// refuses with stale_plan and changes nothing.
func TestATamperedPlanHashIsRefusedByTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	ensureAbsent(t, h, host, testPackage)
	plan := planInstall(t, h, host.ID, testPackage)
	if len(plan.Changes) == 0 {
		t.Fatalf("nothing to install: %s", plan.Description)
	}
	tampered := []byte(plan.PlanHash)
	if tampered[0] == '0' {
		tampered[0] = 'f'
	} else {
		tampered[0] = '0'
	}

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.install", "reason": lifecycleReason,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{testPackage}, "plan_hash": string(tampered), "plan": planReference(plan),
		}},
	}, 10*time.Minute)
	if job.State == "succeeded" {
		t.Fatal("an installation bound to a tampered digest was carried out")
	}
	last := attempts[len(attempts)-1]
	if last.ErrorCode != "stale_plan" {
		t.Fatalf("error code = %q, expected stale_plan: %s", last.ErrorCode, last.Message)
	}
	if last.Detail != nil && len(last.Detail.Applied) > 0 {
		t.Errorf("the refused transaction changed %d packages", len(last.Detail.Applied))
	}
	// The package is still absent: the removal plan finds nothing.
	if after := dnfRemovalPlan(t, h, host.ID, testPackage); len(after.Removals) != 0 {
		t.Errorf("%s is installed after a refused transaction: %v", testPackage, after.Removals)
	}
}

// TestAnExpiredPlanReferenceIsRefusedByTheAPI checks the panel's own
// answer: an order bound to a plan past its expiry is refused with 409
// plan_expired before a job is queued for it.
func TestAnExpiredPlanReferenceIsRefusedByTheAPI(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	reference := map[string]any{
		"schema_version": 1, "planner_version": "packages/1",
		"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}
	var problem struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "packages.upgrade", "reason": lifecycleReason,
		"payload": map[string]any{"package_upgrade": map[string]any{
			"packages":  []string{"bash"},
			"plan_hash": "0000000000000000000000000000000000000000000000000000000000000000",
			"plan":      reference,
		}},
	}, &problem, http.StatusConflict)
	if problem.Code != "plan_expired" {
		t.Fatalf("code = %q, expected plan_expired", problem.Code)
	}
}
