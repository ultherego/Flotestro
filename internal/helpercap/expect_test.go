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

// A consent to trust an authority named the anchor and the plan digest, and
// not the bytes - and the helper checks the plan digest only when it gets one.
// So a capability for authority A installed the bytes of authority B under the
// file name of A, and the host began to believe everything B signs (audit of
// 6c38561, HP-04).
func TestATrustChangeIsBoundToTheMaterialItInstalls(t *testing.T) {
	const approved = "-----BEGIN CERTIFICATE-----\nAPPROVED\n-----END CERTIFICATE-----\n"
	const other = "-----BEGIN CERTIFICATE-----\nSOMEBODY ELSE\n-----END CERTIFICATE-----\n"
	bound := &BoundPayload{
		Action: opspec.ActionCertificateTrustEnsure,
		Payload: opspec.Payload{Certificate: &opspec.CertificatePayload{
			AnchorID: "lab-ca", Certificate: approved, PlanHash: "d4e5f6"}},
	}
	request := func(material string) *helperv1.HelperRequest {
		return &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Certificate{
			Certificate: &helperv1.CertificateRequest{
				Operation: helperv1.CertificateRequest_OPERATION_TRUST_ENSURE,
				AnchorId:  "lab-ca", PlanHash: "d4e5f6", Certificate: []byte(material)}}}
	}
	if err := CheckBinding(request(approved), bound, nil); err != nil {
		t.Fatalf("the approved authority was refused: %v", err)
	}
	if err := CheckBinding(request(other), bound, nil); err == nil {
		t.Fatal("another authority was installed under the approved capability")
	}

	// A renewal and a trust removal name what is already on the host and send
	// no material, so there is nothing to compare and they are not refused for
	// an empty digest.
	for _, operation := range []helperv1.CertificateRequest_Operation{
		helperv1.CertificateRequest_OPERATION_RENEW,
		helperv1.CertificateRequest_OPERATION_TRUST_REMOVE,
	} {
		naming := &helperv1.HelperRequest{Action: &helperv1.HelperRequest_Certificate{
			Certificate: &helperv1.CertificateRequest{
				Operation: operation, AnchorId: "lab-ca", PlanHash: "d4e5f6"}}}
		if err := CheckBinding(naming, bound, nil); err != nil {
			t.Errorf("%s was refused although it carries no material: %v", operation, err)
		}
	}

	// And of the operations marked critical, this one no longer is the only
	// one that needs no plan.
	if !opspec.ActionCertificateTrustEnsure.RequiresPlan() {
		t.Error("a trust change still takes no plan")
	}
}
