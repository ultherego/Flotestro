package helpercap

import (
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// A read is exempt from the capability because it changes nothing - which
// holds only while a read really runs nothing. A backup plan runs the backup
// tool as root with the repository, the arguments and the environment the
// order carries, so it is carried out under a capability like a change is
// (audit of 6c38561, HP-01).
func TestABackupPlanIsCarriedOutUnderACapability(t *testing.T) {
	plan := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Backup{
		Backup: &helperv1.BackupRequest{Operation: helperv1.BackupRequest_OPERATION_PLAN},
	}}
	expectation := Expect(plan)
	if expectation.Mutating {
		t.Error("a plan was called a change of the host")
	}
	if !expectation.Authorized {
		t.Fatal("a plan that runs the backup tool as root passes without a capability")
	}
	if !expectation.Allows(string(opspec.ActionBackupPlan)) {
		t.Error("the capability of a backup plan does not authorize the plan")
	}

	// The policy refuses it without one, in enforce mode.
	decision := NewPolicy(ModeEnforce, nil).Decide(plan)
	if decision.Allowed || decision.Code != ErrorCapabilityRequired {
		t.Fatalf("allowed=%v code=%q", decision.Allowed, decision.Code)
	}
	// And the panel mints one, because the action says it is carried out under
	// a capability - the two ends read the same table.
	if !opspec.ActionBackupPlan.UnderCapability() {
		t.Error("the panel would not mint a capability for a plan the helper refuses without one")
	}

	// A read that is only a read keeps its exemption: nothing of the caller's
	// reaches a process.
	facts := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_TrustUpdate{
		TrustUpdate: &helperv1.HelperTrustUpdateRequest{},
	}}
	if Expect(facts).Authorized {
		t.Error("a read that runs nothing was put under a capability")
	}
}
