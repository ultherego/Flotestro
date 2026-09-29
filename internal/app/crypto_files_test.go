package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/cryptostate"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/secrets"
)

// installation builds a state directory with everything a panel keeps in one:
// two keys of the secret store, a fleet CA, a CA prepared to take over, and
// the signer of the root helper's capabilities.
func installation(t *testing.T) (installationFiles, *cryptostate.Record) {
	t.Helper()
	dir := t.TempDir()
	files := installationFiles{
		StateDir:      dir,
		LegacyKeyPath: filepath.Join(dir, "secrets.key"),
		HelperKeyPath: filepath.Join(dir, "helper-signing.key"),
	}
	if err := secrets.WriteKeyFile(filepath.Join(dir, cryptostate.KeysDir, "k-one.key"),
		bytes.Repeat([]byte{1}, secrets.KeyLength)); err != nil {
		t.Fatal(err)
	}
	if err := secrets.WriteKeyFile(files.LegacyKeyPath,
		bytes.Repeat([]byte{2}, secrets.KeyLength)); err != nil {
		t.Fatal(err)
	}
	trust, err := pki.InitTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := helpercap.LoadOrGenerateSigner(files.HelperKeyPath); err != nil {
		t.Fatal(err)
	}
	// An authority withdrawn from signing: no key left, and the fleet still has
	// to recognise the hosts it issued for.
	withdrawn, err := pki.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	retiredPath := filepath.Join(dir, pki.RetiredCertDir,
		withdrawn.Certificate.SerialNumber.String()+".pem")
	if err := os.MkdirAll(filepath.Dir(retiredPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retiredPath, withdrawn.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return files, &cryptostate.Record{
		InstallationID: "6283c373-ab8a-4527-ad96-9a59b46a9234",
		IssuerID:       ca.IssuerID(),
		Revision:       3,
	}
}

// Everything the replicas need equally has to be found, and found as the thing
// it is. A migration that quietly left one key behind would produce an
// installation that starts, serves, and then cannot renew a certificate or
// open one secret - the failure arriving weeks later.
func TestEveryPrivateKeyOfAnInstallationIsFound(t *testing.T) {
	files, record := installation(t)
	materials, err := files.collect()
	if err != nil {
		t.Fatal(err)
	}
	byPurpose := map[string][]cryptostate.Material{}
	for _, material := range materials {
		byPurpose[material.Purpose] = append(byPurpose[material.Purpose], material)
		if len(material.Bytes) == 0 {
			t.Errorf("the key %s was collected empty", material.KeyID)
		}
		if err := cryptostate.ValidateKeyID(material.KeyID); err != nil {
			t.Errorf("the key %s cannot be a row: %v", material.KeyID, err)
		}
	}
	if got := len(byPurpose[cryptostate.PurposeSecrets]); got != 2 {
		t.Errorf("the secret store has %d keys, want the named one and the legacy one", got)
	}
	if got := len(byPurpose[cryptostate.PurposeAgentCA]); got != 2 {
		t.Errorf("the fleet has %d authorities, want the active one and the prepared one", got)
	}
	if got := len(byPurpose[cryptostate.PurposeHelperSigning]); got != 1 {
		t.Errorf("the helper has %d signing keys, want one", got)
	}

	// The authority that the record names is the active one; the other is the
	// one prepared to take over, and it carries the moment it was prepared.
	active, prepared := 0, 0
	for _, material := range byPurpose[cryptostate.PurposeAgentCA] {
		keyPEM, certPEM, preparedAt, err := cryptostate.AuthorityParts(material.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(keyPEM), "PRIVATE KEY") || !strings.Contains(string(certPEM), "CERTIFICATE") {
			t.Errorf("the authority %s did not come with both halves", material.KeyID)
		}
		if material.KeyID == record.IssuerID {
			active++
			if len(preparedAt) != 0 {
				t.Error("the active authority says it is prepared")
			}
			continue
		}
		prepared++
		if len(preparedAt) == 0 {
			t.Error("the prepared authority lost the moment it was prepared")
		}
	}
	if active != 1 || prepared != 1 {
		t.Errorf("%d active and %d prepared authorities", active, prepared)
	}

	// A fleet whose hosts trust a helper signing key that is not there is a
	// fleet this command must not pretend to have moved.
	if err := os.Remove(files.HelperKeyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := files.collect(); err == nil {
		t.Error("an installation with no helper signing key was collected anyway")
	}
}

// What went in comes back out into the same files, byte for byte: that is what
// makes the migration reversible, and the reversibility is what lets an
// operator run it at all.
func TestTheKeysComeBackIntoTheFilesTheyCameFrom(t *testing.T) {
	files, record := installation(t)
	materials, err := files.collect()
	if err != nil {
		t.Fatal(err)
	}
	// The legacy key came from secrets.key and goes back as a key of the
	// directory, which is where the panel that adopted it reads it from.
	restored := t.TempDir()
	into := installationFiles{
		StateDir:      restored,
		LegacyKeyPath: filepath.Join(restored, "secrets.key"),
		HelperKeyPath: filepath.Join(restored, "helper-signing.key"),
	}
	plan, err := into.restorePlan(materials, record)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan {
		if err := step.write(); err != nil {
			t.Fatal(err)
		}
	}

	again, err := into.collect()
	if err != nil {
		t.Fatalf("the restored installation could not be read: %v", err)
	}
	if len(again) != len(materials) {
		t.Fatalf("the installation came back with %d keys of %d", len(again), len(materials))
	}
	digests := map[string]string{}
	for _, material := range materials {
		digests[material.KeyID] = material.Digest()
	}
	for _, material := range again {
		if digests[material.KeyID] != material.Digest() {
			t.Errorf("the key %s came back changed", material.KeyID)
		}
	}

	// The certificate of an authority is public and has to stay readable to
	// whoever serves it; its key must not.
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{pki.CAKeyFile, 0o600},
		{pki.CACertFile, 0o644},
		{filepath.Join(cryptostate.KeysDir, "k-one.key"), 0o600},
		{"helper-signing.key", 0o600},
	} {
		info, err := os.Stat(filepath.Join(restored, test.name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != test.mode {
			t.Errorf("%s came back as %04o, want %04o", test.name, info.Mode().Perm(), test.mode)
		}
	}
}

// The database holding one thing and the files another is exactly the state in
// which nobody may remove the files.
func TestFilesAreNotForgottenWhileTheDatabaseDisagreesWithThem(t *testing.T) {
	files, _ := installation(t)
	materials, err := files.collect()
	if err != nil {
		t.Fatal(err)
	}
	if err := sameKeys(materials, materials); err != nil {
		t.Fatalf("an installation disagreed with itself: %v", err)
	}
	if err := sameKeys(materials, materials[1:]); err == nil {
		t.Error("a key that is only in the files was called safe to remove")
	}
	changed := append([]cryptostate.Material(nil), materials...)
	changed[0].Bytes = append([]byte("x"), changed[0].Bytes...)
	if err := sameKeys(materials, changed); err == nil {
		t.Error("a key that holds one thing on disk and another in the database was called safe to remove")
	}
}

// The certificates of the withdrawn authorities are public and carry no key,
// which is exactly why they are easy to forget. An installation that moves
// into the database without them stops recognising every host that has not
// renewed since the rotation.
func TestTheWithdrawnAuthoritiesAreFoundAndPutBack(t *testing.T) {
	files, _ := installation(t)
	retired, err := files.collectRetired()
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 {
		t.Fatalf("the installation has %d withdrawn authorities, want one", len(retired))
	}
	// The serial names the certificate, not the file: a file somebody renamed
	// still describes the authority it holds.
	serial, err := cryptostate.RetiredSerial(retired[0].Certificate)
	if err != nil || serial != retired[0].Serial {
		t.Errorf("the withdrawn authority is named %q and holds %q (%v)", retired[0].Serial, serial, err)
	}

	restored := t.TempDir()
	into := installationFiles{StateDir: restored, HelperKeyPath: filepath.Join(restored, "helper-signing.key")}
	for _, step := range into.retiredPlan(retired) {
		if err := step.write(); err != nil {
			t.Fatal(err)
		}
	}
	again, err := into.collectRetired()
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 1 || again[0].Serial != retired[0].Serial ||
		string(again[0].Certificate) != string(retired[0].Certificate) {
		t.Error("the withdrawn authority did not come back as it went in")
	}

	// And a certificate the database never received is not one this command
	// may throw away.
	if err := sameAuthorities(retired, retired); err != nil {
		t.Fatalf("an installation disagreed with itself: %v", err)
	}
	if err := sameAuthorities(retired, nil); err == nil {
		t.Error("a withdrawn authority only on disk was called safe to remove")
	}
}
