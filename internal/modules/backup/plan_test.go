package backup

import (
	"strings"
	"testing"
	"time"
)

func testDefinition() Definition {
	return Definition{
		ID: "data", Tool: ToolRestic, Repository: "/srv/copies",
		Paths: []string{"/etc/flotestro", "/srv/data"}, KeepLast: 7, Prune: true,
	}
}

func testSize(existing map[string]uint64) func(string) (uint64, bool) {
	return func(path string) (uint64, bool) {
		bytes, present := existing[path]
		return bytes, present
	}
}

func TestCopyPlanDescribesScopeFromThisHost(t *testing.T) {
	now := time.Now()
	state := State{Tool: ToolRestic, Repository: "/srv/copies",
		Snapshots: []Snapshot{{ID: "a"}, {ID: "b"}}, LastSuccessAt: &now}
	plan := Compute(state, testDefinition(), false, false,
		testSize(map[string]uint64{"/etc/flotestro": 3 << 20}))

	if plan.Action != PlanRun || plan.Refusal != "" || !plan.RepositoryReady {
		t.Fatalf("copy plan: %+v", plan)
	}
	if len(plan.Paths) != 1 || len(plan.MissingPaths) != 1 || plan.MissingPaths[0] != "/srv/data" {
		t.Errorf("scope: %+v / %+v", plan.Paths, plan.MissingPaths)
	}
	if plan.BytesOnHost == nil || *plan.BytesOnHost != 3<<20 {
		t.Errorf("scope size: %v", plan.BytesOnHost)
	}
	if !plan.Verified || !strings.Contains(strings.Join(plan.Changes, ";"), "check the repository") {
		t.Errorf("copy without a check: %+v", plan.Changes)
	}
	if !strings.Contains(plan.Retention, "7 last") || !strings.Contains(plan.Retention, "pruned") {
		t.Errorf("retention: %q", plan.Retention)
	}

	// A host without any of the directories would write an empty copy -
	// that is a refusal.
	empty := Compute(state, testDefinition(), false, false,
		testSize(map[string]uint64{}))
	if !strings.Contains(empty.Refusal, "none of the named directories") {
		t.Errorf("host without data: %+v", empty)
	}
	if plan.PlanHash == empty.PlanHash || plan.PlanHash == "" {
		t.Error("plan fingerprints do not differ")
	}
}

func TestCopyPlanDistinguishesUnreadRepository(t *testing.T) {
	unread := State{UnavailableReason: "repository does not exist"}
	noConsent := Compute(unread, testDefinition(), false, false,
		testSize(map[string]uint64{"/etc/flotestro": 1}))
	if !strings.Contains(noConsent.Refusal, "requires explicit consent") || noConsent.WillInitialize {
		t.Errorf("repository without consent: %+v", noConsent)
	}

	consent := testDefinition()
	consent.Initialize = true
	withConsent := Compute(unread, consent, false, false,
		testSize(map[string]uint64{"/etc/flotestro": 1}))
	if withConsent.Refusal != "" || !withConsent.WillInitialize {
		t.Errorf("repository with consent: %+v", withConsent)
	}

	// A verification cannot be done on a repository that does not answer.
	verification := Compute(unread, consent, true, false, nil)
	if !strings.Contains(verification.Refusal, "did not answer") {
		t.Errorf("verification without a repository: %+v", verification)
	}
	ok := Compute(State{Snapshots: []Snapshot{{ID: "a"}}}, testDefinition(), true, true, nil)
	if ok.Action != PlanVerify || len(ok.Changes) != 2 || !ok.ReadData {
		t.Errorf("verification with data read: %+v", ok)
	}
}
