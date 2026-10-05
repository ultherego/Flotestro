package helper

import (
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// HP-03. The grant that exists for running something as root was asked for
// against the account the *order* names - and a run_now may carry the
// identifier alone. Whoever held schedule.run could then execute root's entry
// on demand, because the order said nothing and nothing read the entry.
func TestRunningAnEntryAsksAboutTheAccountTheHostHolds(t *testing.T) {
	withoutGrant := []string{"schedule.run"}
	withGrant := []string{"schedule.run", PermissionScheduleRootExec}

	if refusal := checkScheduleRunAs("root", withoutGrant); refusal == nil {
		t.Error("root's entry ran without the grant, on an order that named no account")
	} else if refusal.GetErrorCode() != ErrorRootGrantRequired {
		t.Errorf("the refusal is %q, expected %q", refusal.GetErrorCode(), ErrorRootGrantRequired)
	}
	if refusal := checkScheduleRunAs("root", withGrant); refusal != nil {
		t.Errorf("root's entry was refused although the grant is there: %v", refusal.GetMessage())
	}
	if refusal := checkScheduleRunAs("backup", withoutGrant); refusal != nil {
		t.Errorf("an ordinary account's entry was refused: %v", refusal.GetMessage())
	}
	// A request without a capability at all is judged by the panel alone, as
	// everywhere else in this helper.
	if refusal := checkScheduleRunAs("root", nil); refusal != nil {
		t.Errorf("a request with no capability was judged here: %v", refusal.GetMessage())
	}
}

// And the refusal names a code the operator can look up.
func TestTheRootGrantRefusalCarriesItsCode(t *testing.T) {
	refusal := checkScheduleRunAs("root", []string{"schedule.run"})
	if refusal == nil {
		t.Fatal("no refusal")
	}
	var _ *helperv1.HelperResponse = refusal
	if refusal.GetMessage() == "" {
		t.Error("the refusal says nothing")
	}
}
