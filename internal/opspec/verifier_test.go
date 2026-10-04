package opspec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/modules/docker"
)

// Every mutating operation names the read that confirms it, every read names
// none, and the names are the registry's.
func TestEveryMutatingOperationDeclaresAVerifier(t *testing.T) {
	if err := ValidateVerifiers(); err != nil {
		t.Fatalf("the verifiers do not validate: %v", err)
	}
	for _, action := range AllActions() {
		verifier := action.Verifier()
		if !KnownVerifier(verifier) {
			t.Errorf("%s: verifier %q is not in the registry", action, verifier)
		}
		if !action.Mutating() && verifier != VerifierNone {
			t.Errorf("%s: a read has the verifier %q", action, verifier)
		}
		spec := action.Describe()
		if spec.Verifier != verifier || spec.OnUnverified != action.OnUnverified() {
			t.Errorf("%s: the catalogue says %s/%s, the registry %s/%s",
				action, spec.Verifier, spec.OnUnverified, verifier, action.OnUnverified())
		}
	}
	for action, want := range map[ActionType]Verifier{
		ActionUnitRestart:    VerifierUnitState,
		ActionPackageInstall: VerifierPackageVersions,
		ActionFileEnsure:     VerifierFileContent,
		ActionMountEnsure:    VerifierMountState,
		ActionSystemReboot:   VerifierReboot,
		ActionAgentUpgrade:   VerifierAgentVersion,
		ActionBackupRun:      VerifierBackupRun,
		ActionReadJournal:    VerifierNone,
		ActionPackagePlan:    VerifierNone,
		ActionProcessSignal:  VerifierNone,
	} {
		if got := action.Verifier(); got != want {
			t.Errorf("%s: verifier %s, want %s", action, got, want)
		}
	}
	if !ActionSystemReboot.Verifier().PanelSettled() || ActionUnitRestart.Verifier().PanelSettled() {
		t.Error("the panel settles a reboot and not a unit restart")
	}
}

// A rollback on an unverified change is declared only where the host
// keeps what puts the previous state back; everything else reports.
func TestOnUnverifiedRollbackSitsOnlyOnReversibleChanges(t *testing.T) {
	for _, action := range []ActionType{ActionFileEnsure, ActionFileRollback, ActionSysctlEnsure} {
		if action.OnUnverified() != UnverifiedRollback {
			t.Errorf("%s: on_unverified %s, want rollback", action, action.OnUnverified())
		}
		if action.Contract().Rollback == RollbackNone {
			t.Errorf("%s: a rollback on unverified with no rollback class", action)
		}
	}
	for _, action := range []ActionType{ActionUnitRestart, ActionDiskWipe, ActionSystemReboot, ActionReadJournal, ActionType("nobody.wrote.this")} {
		if action.OnUnverified() != UnverifiedReport {
			t.Errorf("%s: on_unverified %s, want report", action, action.OnUnverified())
		}
	}
}

// A mutating operation that slipped into the table without a verifier
// fails the start with its name in the error, like an undeclared contract.
func TestAMutationWithoutAVerifierFailsTheStart(t *testing.T) {
	const stray ActionType = "test.stray.mutation"
	actionSpecs[stray] = actionSpec{mutating: true, permission: "test", timeoutSeconds: 1, risk: RiskLow}
	defer delete(actionSpecs, stray)
	err := ValidateVerifiers()
	if err == nil || !strings.Contains(err.Error(), string(stray)) {
		t.Fatalf("the stray mutation passed: %v", err)
	}
	actionSpecs[stray] = actionSpec{mutating: true, permission: "test", timeoutSeconds: 1, risk: RiskLow,
		verifier: Verifier("nobody.wrote.this")}
	if err := ValidateVerifiers(); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("an unknown verifier passed: %v", err)
	}
}

// The codes of the verification are in the guide with the verify stage, so
// a job and a campaign host carrying them land on the operator's advice.
func TestTheGuideCoversTheVerificationCodes(t *testing.T) {
	for _, code := range []string{ErrorAppliedUnverified, ErrorRebootNotObserved} {
		guide, ok := ErrorGuideFor(code)
		if !ok {
			t.Errorf("%s has no guide", code)
			continue
		}
		if guide.Stage != "verify" || !guide.CountsAsFailure {
			t.Errorf("%s: stage %s, counts as failure %v", code, guide.Stage, guide.CountsAsFailure)
		}
	}
}

// planBindings gives every operation that declares it needs a plan the same
// order twice: once carrying what binds it to one and once with that binding
// taken out. Two different mechanisms enforce the rule - CheckPlanBinding for
// most operations, the validation branch of the module for Docker and Compose -
// and the test below holds both to it from the registry, so an operation that
// starts declaring requiresPlan and is not listed here fails rather than
// slipping through unguarded.
var planBindings = map[ActionType]struct{ bound, unbound Payload }{
	ActionMountEnsure: {
		bound: Payload{Storage: &StoragePayload{Source: "/dev/sdb1", Target: "/srv/data",
			FSType: "ext4", Persist: true, PlanHash: "a1b2c3"}},
		unbound: Payload{Storage: &StoragePayload{Source: "/dev/sdb1", Target: "/srv/data",
			FSType: "ext4", Persist: true}},
	},
	ActionMountRemove: {
		bound:   Payload{Storage: &StoragePayload{Target: "/srv/data", PlanHash: "a1b2c3"}},
		unbound: Payload{Storage: &StoragePayload{Target: "/srv/data"}},
	},
	ActionPackageInstall: {
		bound:   Payload{PackageChange: &PackageChangePayload{Packages: []string{"nginx"}, PlanHash: "a1b2c3"}},
		unbound: Payload{PackageChange: &PackageChangePayload{Packages: []string{"nginx"}}},
	},
	ActionPackageUpgrade: {
		bound:   Payload{PackageUpgrade: &PackageUpgradePayload{Packages: []string{"nginx"}, PlanHash: "a1b2c3"}},
		unbound: Payload{PackageUpgrade: &PackageUpgradePayload{Packages: []string{"nginx"}}},
	},
	// A removal binds to the set of packages the operator saw go rather than
	// to a digest: that set is its plan.
	ActionPackageRemove: {
		bound: Payload{PackageChange: &PackageChangePayload{Packages: []string{"nginx"},
			ExpectedRemovals: []string{"nginx", "nginx-common"}}},
		unbound: Payload{PackageChange: &PackageChangePayload{Packages: []string{"nginx"}}},
	},
	ActionBackupRestore: {
		bound: Payload{Backup: &BackupPayload{ID: "nightly", Tool: "restic",
			Repository: "sftp:backup@vault:/srv/restic", SnapshotID: "9f2c1a",
			Target: "/srv/restore", Overwrite: "empty-target", PlanHash: "a1b2c3"}},
		unbound: Payload{Backup: &BackupPayload{ID: "nightly", Tool: "restic",
			Repository: "sftp:backup@vault:/srv/restic", SnapshotID: "9f2c1a",
			Target: "/srv/restore", Overwrite: "empty-target"}},
	},
	ActionComposeDeploy: {
		bound: Payload{Compose: &ComposePayload{Project: "storefront",
			Manifest: composeManifestForPlanBinding, PlanDigest: "sha256:" + strings.Repeat("a", 64)}},
		unbound: Payload{Compose: &ComposePayload{Project: "storefront",
			Manifest: composeManifestForPlanBinding}},
	},
	ActionDockerContainerEnsure: {
		bound: Payload{DockerEnsure: &DockerEnsurePayload{
			Container:  &docker.ContainerRequest{Name: "storefront", Image: "nginx:1.27"},
			PlanDigest: "sha256:" + strings.Repeat("a", 64)}},
		unbound: Payload{DockerEnsure: &DockerEnsurePayload{
			Container: &docker.ContainerRequest{Name: "storefront", Image: "nginx:1.27"}}},
	},
	ActionDockerNetworkEnsure: {
		bound: Payload{DockerEnsure: &DockerEnsurePayload{
			Network:    &docker.NetworkSpec{Name: "storefront"},
			PlanDigest: "sha256:" + strings.Repeat("a", 64)}},
		unbound: Payload{DockerEnsure: &DockerEnsurePayload{
			Network: &docker.NetworkSpec{Name: "storefront"}}},
	},
	ActionDockerNetworkRemove: {
		bound: Payload{DockerEnsure: &DockerEnsurePayload{Kind: DockerKindNetwork, Name: "storefront",
			PlanDigest: "sha256:" + strings.Repeat("a", 64)}},
		unbound: Payload{DockerEnsure: &DockerEnsurePayload{Kind: DockerKindNetwork, Name: "storefront"}},
	},
	ActionDockerVolumeEnsure: {
		bound: Payload{DockerEnsure: &DockerEnsurePayload{
			Volume:     &docker.VolumeSpec{Name: "storefront-data"},
			PlanDigest: "sha256:" + strings.Repeat("a", 64)}},
		unbound: Payload{DockerEnsure: &DockerEnsurePayload{
			Volume: &docker.VolumeSpec{Name: "storefront-data"}}},
	},
	ActionDockerVolumeRemove: {
		bound: Payload{DockerEnsure: &DockerEnsurePayload{Kind: DockerKindVolume, Name: "storefront-data",
			PlanDigest: "sha256:" + strings.Repeat("a", 64)}},
		unbound: Payload{DockerEnsure: &DockerEnsurePayload{Kind: DockerKindVolume, Name: "storefront-data"}},
	},
	ActionCertificateDeploy: {}, // filled in by the test: the material is generated.
}

const composeManifestForPlanBinding = "services:\n  web:\n    image: nginx:1.27\n"

// Two mechanisms hold an order to the plan it was approved from, and nothing
// says both stay closed. This does: whichever of them answers, an operation
// that declares it needs a plan must refuse an order carrying none, and must
// accept the same order once it carries one.
func TestEveryOperationThatNeedsAPlanRefusesAnOrderWithoutOne(t *testing.T) {
	bindings := map[ActionType]struct{ bound, unbound Payload }{}
	for action, pair := range planBindings {
		bindings[action] = pair
	}
	bindings[ActionCertificateDeploy] = certificatePlanBinding(t)

	for _, action := range AllActions() {
		if !action.RequiresPlan() {
			continue
		}
		pair, listed := bindings[action]
		if !listed {
			t.Errorf("%s declares it needs a plan and this test has no order for it", action)
			continue
		}
		// The order carrying a plan has to pass both gates; otherwise the
		// refusal below could be about anything else in the payload.
		if err := Validate(action, pair.bound); err != nil {
			t.Errorf("%s: the order with a plan was refused by the validation: %v", action, err)
			continue
		}
		if err := CheckPlanBinding(action, pair.bound); err != nil {
			t.Errorf("%s: the order with a plan was refused by the binding check: %v", action, err)
			continue
		}
		// The same order without the plan, through whichever gate answers.
		err := Validate(action, pair.unbound)
		if err == nil {
			err = CheckPlanBinding(action, pair.unbound)
		}
		if err == nil {
			t.Errorf("%s: an order carrying no plan was accepted by both mechanisms", action)
			continue
		}
		// And the refusal is about the missing binding rather than about
		// something else the payload lacks. A removal binds to the set of
		// packages the operator approved, so its refusal names that set.
		if code := RefusalCode(err); code != RefusalPlanBindingMissing &&
			!strings.Contains(err.Error(), "plan") &&
			!strings.Contains(err.Error(), "approved set") {
			t.Errorf("%s: refused with %q (%v), which does not name the plan", action, code, err)
		}
	}
}

// certificatePlanBinding builds the deployment order twice over a certificate
// this test generates: the validation parses the material, so a placeholder
// would be refused for the wrong reason.
func certificatePlanBinding(t *testing.T) struct{ bound, unbound Payload } {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "storefront.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bound := Payload{Certificate: &CertificatePayload{
		Path: "/etc/ssl/local/storefront.crt", Certificate: string(pemBytes), PlanHash: "a1b2c3"}}
	unbound := Payload{Certificate: &CertificatePayload{
		Path: "/etc/ssl/local/storefront.crt", Certificate: string(pemBytes)}}
	return struct{ bound, unbound Payload }{bound: bound, unbound: unbound}
}

// trustPlanBinding is the order that adds an authority to the host's trust
// store, with and without the plan it is bound to. It is kept for the day the
// owner decides a trust change goes through a planning step: the operation is
// critical and carries no plan today, because the panel orders it directly.
func trustPlanBinding(t *testing.T) struct{ bound, unbound Payload } {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Flotestro Lab CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bound := Payload{Certificate: &CertificatePayload{
		AnchorID: "lab-ca", Certificate: string(pemBytes), PlanHash: "d4e5f6"}}
	unbound := Payload{Certificate: &CertificatePayload{
		AnchorID: "lab-ca", Certificate: string(pemBytes)}}
	return struct{ bound, unbound Payload }{bound: bound, unbound: unbound}
}

// The operation that rewrites the whole key list of an account is the one that
// can hand somebody else the account: it ranks critical and the operator
// confirms who they are right before ordering it. The integration test always
// supplies a reason, so dropping the step-up would go unnoticed there.
func TestRewritingTheKeyListIsCriticalAndNeedsFreshAuthentication(t *testing.T) {
	for _, action := range []ActionType{ActionLocalSSHKeysReplaceAll, ActionLocalSSHKeysSet} {
		if risk := action.Risk(); risk != RiskCritical {
			t.Errorf("%s: risk %s, want %s", action, risk, RiskCritical)
		}
		if !action.RequiresFreshAuth() {
			t.Errorf("%s: no fresh confirmation of the operator's identity is required", action)
		}
		// The catalogue the panel serves says the same, or the dialog and the
		// registry disagree about what the operator has to do.
		if spec := action.Describe(); spec.Risk != RiskCritical {
			t.Errorf("%s: the catalogue says risk %s", action, spec.Risk)
		}
	}
	// Adding a key is a smaller decision than rewriting the list, and the two
	// are not to drift into the same rank by accident.
	if ActionLocalSSHKeysAdd.Risk() != RiskHigh {
		t.Errorf("localuser.sshkeys.add: risk %s, want %s", ActionLocalSSHKeysAdd.Risk(), RiskHigh)
	}
}
