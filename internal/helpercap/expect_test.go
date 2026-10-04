package helpercap

import (
	"encoding/hex"
	"testing"
	"time"

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
	// And so does the capability of a copy: the verification of a copy reads
	// the repository with a plan, before the run and after it, under the
	// capability of that run. Admitting only the capability of a plan ended
	// every verified backup as "applied_unverified" - the change made and the
	// verifier refused at the door.
	for _, action := range []opspec.ActionType{
		opspec.ActionBackupRun, opspec.ActionBackupVerify, opspec.ActionBackupRestore,
	} {
		if !expectation.Allows(string(action)) {
			t.Errorf("the capability of %s does not authorize the plan its verification reads", action)
		}
	}
	// Not anything else, though: a capability for another module does not buy
	// a run of the backup tool.
	if expectation.Allows(string(opspec.ActionUnitStart)) {
		t.Error("a capability for another operation authorizes a backup plan")
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

	// What this capability does not bind, said out loud: a trust change carries
	// no plan, so nothing here says what the authority is installed over. The
	// panel orders this operation directly - its own button does - and
	// requiring a plan would be a change to that flow, which is the owner's.
	// The material is bound, which is what closes the hole the audit found.
	if opspec.ActionCertificateTrustEnsure.RequiresPlan() {
		t.Error("a trust change now takes a plan; the panel's direct order has to carry one")
	}
}

// The binding of a package action compared the list of packages and, for a
// hold, the direction. The plan the change is bound to - which the agent puts
// on the request - the header of its envelope, its expiry, security_only and
// allow_downgrade went unchecked: a consent to install two packages authorized
// installing them out of any plan, including one from last week with
// allow_downgrade on, which is a way back to a version with a known hole
// (audit of 6c38561, PKG-01).
func TestAPackageOrderIsBoundBeyondTheListOfPackages(t *testing.T) {
	approved := &opspec.PackageChangePayload{
		Packages: []string{"nginx", "openssl"},
		PlanHash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		Plan: &opspec.PlanReference{
			SchemaVersion: 1, PlannerVersion: "apt-1", InventoryRevision: "inv-9",
			ResourceRevision: "res-4", ExpiresAt: "2026-10-04T18:00:00Z",
			Changes: []opspec.PlanChangeEntry{{
				Name: "nginx", CurrentVersion: "1.0", CandidateVersion: "1.1",
				Architecture: "amd64", Origin: "debian", Action: "upgrade"}},
		},
	}
	bound := &BoundPayload{Action: opspec.ActionPackageInstall,
		Payload: opspec.Payload{PackageChange: approved}}

	order := func(change func(*helperv1.PackageActionRequest)) *helperv1.HelperRequest {
		hash, err := hex.DecodeString(approved.PlanHash)
		if err != nil {
			t.Fatal(err)
		}
		expiry, err := time.Parse(time.RFC3339, approved.Plan.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		request := &helperv1.PackageActionRequest{
			Operation: helperv1.PackageActionRequest_OPERATION_INSTALL,
			Packages:  []string{"nginx", "openssl"},
			PlanHash:  hash, PlanSchemaVersion: 1, PlannerVersion: "apt-1",
			PlanInventoryRevision: "inv-9", PlanResourceRevision: "res-4",
			PlanExpiresAtUnix: expiry.Unix(),
			ExactSpecs: []*helperv1.PackageExactSpec{{
				Name: "nginx", CurrentVersion: "1.0", CandidateVersion: "1.1",
				Architecture: "amd64", Origin: "debian", Action: "upgrade"}},
		}
		change(request)
		return &helperv1.HelperRequest{
			Action: &helperv1.HelperRequest_PackageAction{PackageAction: request}}
	}

	if err := CheckBinding(order(func(*helperv1.PackageActionRequest) {}), bound, nil); err != nil {
		t.Fatalf("the order the panel signed was refused: %v", err)
	}
	for name, change := range map[string]func(*helperv1.PackageActionRequest){
		"a plan of its own":    func(r *helperv1.PackageActionRequest) { r.PlanHash = make([]byte, 32) },
		"another planner":      func(r *helperv1.PackageActionRequest) { r.PlannerVersion = "apt-0" },
		"another inventory":    func(r *helperv1.PackageActionRequest) { r.PlanInventoryRevision = "inv-1" },
		"a later expiry":       func(r *helperv1.PackageActionRequest) { r.PlanExpiresAtUnix += 86400 },
		"a downgrade":          func(r *helperv1.PackageActionRequest) { r.AllowDowngrade = true },
		"only security":        func(r *helperv1.PackageActionRequest) { r.SecurityOnly = true },
		"another candidate":    func(r *helperv1.PackageActionRequest) { r.ExactSpecs[0].CandidateVersion = "0.9" },
		"a removal nobody saw": func(r *helperv1.PackageActionRequest) { r.ExpectedRemovals = []string{"openssh-server"} },
	} {
		if err := CheckBinding(order(change), bound, nil); err == nil {
			t.Errorf("%s was accepted under the approved capability", name)
		}
	}
}
