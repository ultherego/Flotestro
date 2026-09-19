package pki

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func countCertificates(t *testing.T, bundle []byte) int {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		t.Fatal("the bundle contains no certificates")
	}
	return strings.Count(string(bundle), "BEGIN CERTIFICATE")
}

// TestTheRotationHasTwoPhases guards the condition that protects the fleet
// from being cut off.
func TestTheRotationHasTwoPhases(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	original := trust.Active().Certificate.SerialNumber.String()

	if countCertificates(t, trust.Bundle()) != 1 {
		t.Fatal("a fresh set should have exactly one CA")
	}

	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != "pending" {
		t.Errorf("the state of the prepared CA = %q", prepared.State)
	}
	// The prepared CA is already distributed and recognised, but it does not
	// sign.
	if trust.Active().Certificate.SerialNumber.String() != original {
		t.Error("preparing must not change the signing CA")
	}
	if countCertificates(t, trust.Bundle()) != 2 {
		t.Error("the prepared CA has to reach the bundle")
	}
	if _, err := trust.Prepare(); err == nil {
		t.Error("a second preparation while a CA is pending should be refused")
	}

	active, err := trust.Activate()
	if err != nil {
		t.Fatal(err)
	}
	if active.Serial != prepared.Serial {
		t.Errorf("signing was taken over by the CA %s, expected %s", active.Serial, prepared.Serial)
	}
	// The previous CA stays recognised: the agent certificates issued with it
	// are valid.
	if countCertificates(t, trust.Bundle()) != 2 {
		t.Error("after the handover the set has to contain the old and the new CA")
	}
	if _, err := trust.Activate(); err == nil {
		t.Error("a handover without a prepared CA should be refused")
	}
}

func TestTheSetSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}

	// The panel restarts during the rotation; the state has to survive.
	again, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	pending, preparedAt := again.Pending()
	if pending == nil {
		t.Fatal("the prepared CA did not survive the restart")
	}
	if pending.Certificate.SerialNumber.String() != prepared.Serial {
		t.Error("after the restart a different CA is pending than the prepared one")
	}
	if preparedAt.IsZero() {
		t.Error("the moment of preparation did not survive the restart")
	}
	if preparedAt.After(time.Now()) {
		t.Error("the moment of preparation must not be in the future")
	}

	if _, err := again.Activate(); err != nil {
		t.Fatal(err)
	}
	afterActivation, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if afterActivation.Active().Certificate.SerialNumber.String() != prepared.Serial {
		t.Error("after the restart a different CA signs than the approved one")
	}
	if pending, _ := afterActivation.Pending(); pending != nil {
		t.Error("after the handover no CA may stay pending")
	}
	if countCertificates(t, afterActivation.Bundle()) != 2 {
		t.Error("the withdrawn CA has to stay in the trust set")
	}
}

// TestThePreparationMarkerIsResilient checks the behaviour when the marker
// file is missing.
func TestThePreparationMarkerIsResilient(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, pendingAtFile)); err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	restored, err := EnsureTrust(dir)
	if err != nil {
		t.Fatalf("a missing marker stopped the panel: %v", err)
	}
	_, preparedAt := restored.Pending()
	if preparedAt.Before(before.Add(-time.Minute)) {
		t.Errorf("too early a moment of preparation was taken: %s", preparedAt)
	}
	// The marker is to be written so that the next restart does not move it.
	if _, err := os.Stat(filepath.Join(dir, pendingAtFile)); err != nil {
		t.Error("the marker was not restored on disk")
	}
}

func TestWithdrawalProtectsTheHosts(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	activeFingerprint := trust.Authorities()[0].Fingerprint
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Activate(); err != nil {
		t.Fatal(err)
	}

	var withdrawn string
	for _, ca := range trust.Authorities() {
		if ca.State == "retired" {
			withdrawn = ca.Fingerprint
		}
	}
	if withdrawn == "" {
		t.Fatal("no withdrawn CA after the handover")
	}

	// As long as hosts hold certificates from this CA, removing it would cut
	// them off.
	if err := trust.Retire(withdrawn, 3); err == nil {
		t.Error("withdrawing a CA that is in use should be refused")
	}
	if err := trust.Retire(activeFingerprint, 0); err != nil {
		// activeFingerprint is withdrawn by now, so removing it is allowed.
		t.Errorf("an unused CA should be removable: %v", err)
	}
	if countCertificates(t, trust.Bundle()) != 1 {
		t.Error("after the removal only the signing CA is to stay in the set")
	}
	if err := trust.Retire(trust.Authorities()[0].Fingerprint, 0); err == nil {
		t.Error("the CA that signs must not be removed")
	}
}

// An activation interrupted between the key and the certificate is finished at
// the next open rather than reported as a broken CA: the key goes first, the
// pending certificate stays until both are in place, and that combination is
func TestAnInterruptedActivationIsFinishedAtTheNextOpen(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	// Replay the crash: the new key landed, the certificate did not.
	pendingKey, err := os.ReadFile(filepath.Join(dir, pendingKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), pendingKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("the half-done handover reads as %v, want %v", err, ErrStateMismatch)
	}
	recovered, err := OpenTrust(dir)
	if err != nil {
		t.Fatalf("the half-done handover was not finished: %v", err)
	}
	if recovered.Active().Certificate.SerialNumber.String() != prepared.Serial {
		t.Errorf("after the recovery %s signs, want %s",
			recovered.Active().Certificate.SerialNumber, prepared.Serial)
	}
	if pending, _ := recovered.Pending(); pending != nil {
		t.Error("the finished handover left a CA pending")
	}
	if err := recovered.Active().VerifyPair(); err != nil {
		t.Error(err)
	}

	// A key that matches neither the active nor the pending certificate
	// is not an interrupted handover: it stops the panel.
	broken := t.TempDir()
	if _, err := EnsureTrust(broken); err != nil {
		t.Fatal(err)
	}
	foreign := t.TempDir()
	if _, err := Init(foreign); err != nil {
		t.Fatal(err)
	}
	foreignKey, err := os.ReadFile(filepath.Join(foreign, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "ca.key"), foreignKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTrust(broken); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("a foreign key opened as %v, want %v", err, ErrStateMismatch)
	}
}

// The handover tells the installation record about the new issuer once
// the files are in place, and never before.
func TestTheActivationHookRunsAfterTheFiles(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	var seen string
	trust.SetActivationHook(func(active *CA) {
		onDisk, err := Open(dir)
		if err != nil {
			t.Errorf("the hook ran before the pair landed: %v", err)
			return
		}
		if !onDisk.Certificate.Equal(active.Certificate) {
			t.Error("the hook ran with a CA other than the one on disk")
		}
		seen = active.IssuerID()
	})
	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if seen != "" {
		t.Fatal("preparing a CA ran the activation hook")
	}
	active, err := trust.Activate()
	if err != nil {
		t.Fatal(err)
	}
	if active.Serial != prepared.Serial || seen != trust.Active().IssuerID() {
		t.Fatalf("hook saw %q, active issuer %q", seen, trust.Active().IssuerID())
	}
}
