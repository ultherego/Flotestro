package pki

import (
	"crypto/x509"
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
// from being cut off. A new CA has to be recognised and distributed before it
// starts signing: a server certificate issued by a CA the agent does not know
// ends in the loss of the connection to the whole fleet at the panel's next
// restart.
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
// file is missing. The panel is then to take the safe value rather than
// refuse to start or assume the fleet already knows the new CA.
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
