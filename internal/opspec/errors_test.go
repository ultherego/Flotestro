package opspec

import "testing"

// Every guide names a stage, a retry policy and both answers - what
// happened and what to do - and no code appears twice. A code that raises
// the failure rate has to be a failure of the change, never an exclusion.
func TestErrorGuidesAreComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, guide := range ErrorGuides() {
		if seen[guide.Code] {
			t.Errorf("%s is listed twice", guide.Code)
		}
		seen[guide.Code] = true
		if guide.Stage == "" || guide.Retry == "" || guide.Meaning == "" || guide.Action == "" {
			t.Errorf("%s is missing a stage, a retry policy, a meaning or an action: %+v", guide.Code, guide)
		}
	}
	for _, excluded := range []string{"capability_missing", "maintenance", "offline", "conflict", "quarantined",
		"skipped_offline", "offline_deadline", "plan_changed_offline"} {
		guide, ok := ErrorGuideFor(excluded)
		if !ok || guide.CountsAsFailure {
			t.Errorf("%s counts as a failure of the change: %+v (%v)", excluded, guide, ok)
		}
	}
	if _, ok := ErrorGuideFor("something_nobody_wrote"); ok {
		t.Error("an unknown code got a guide")
	}
}
