package app

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/secrets"
)

// The backup of a key migration must not live in the directory the migration
// is about to empty. forget-files copies the key files there and then removes
// the originals; a copy in the same directory is not a copy of anything.
func TestABackupInsideTheStateDirectoryIsRefused(t *testing.T) {
	state := t.TempDir()
	elsewhere := t.TempDir()
	for _, test := range []struct {
		name     string
		backupTo string
		refused  bool
	}{
		{"a directory of its own", elsewhere, false},
		{"the state directory itself", state, true},
		{"a directory under it", filepath.Join(state, "backups"), true},
		{"a path that only looks like it", state + "-backups", false},
		{"the way back out of it", filepath.Join(state, "..", filepath.Base(elsewhere)), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			inside, err := within(state, test.backupTo)
			if err != nil {
				t.Fatal(err)
			}
			if inside != test.refused {
				t.Errorf("%s inside %s = %v", test.backupTo, state, inside)
			}
		})
	}
}

// TestWhatAPendingMigrationCounts is the reader of the number H-01 is measured
// by, with the writer beside it: the first form is owed even when the key it
// names is the active one, and a version already on the active key is not.
func TestWhatAPendingMigrationCounts(t *testing.T) {
	counts := map[string]int{
		secrets.LegacyFormLabel: 3,
		secrets.LegacyKeyID:     2,
		"k-0000000000000001":    1,
	}
	// The one case the label exists for: the legacy key is active, so its own
	// envelopes are done, and the three versions of the first form are not.
	if pending := pendingMigration(counts, secrets.LegacyKeyID); pending != 4 {
		t.Fatalf("with %s active the migration owes %d versions rather than 4", secrets.LegacyKeyID, pending)
	}
	// One step outside, from the legitimate side: the same rows with the other
	// key active owe everything but that key's own.
	if pending := pendingMigration(counts, "k-0000000000000001"); pending != 5 {
		t.Fatalf("with k-0000000000000001 active the migration owes %d versions rather than 5", pending)
	}
	// A database with no installation record has no active key, so every live
	// version is owed - which is the state a restored historical copy is in.
	if pending := pendingMigration(counts, ""); pending != 6 {
		t.Fatalf("with no record the migration owes %d versions rather than 6", pending)
	}
	if pending := pendingMigration(map[string]int{"k-0000000000000001": 7}, "k-0000000000000001"); pending != 0 {
		t.Fatalf("an installation entirely on its active key owes %d versions rather than none", pending)
	}
}

// TestTheStatusOfACopyWithNoRecordNamesTheFirstForm pins the lines a script
// reads, including the label of the first form: counting the backlog by key_id
// alone counts it wrong.
func TestTheStatusOfACopyWithNoRecordNamesTheFirstForm(t *testing.T) {
	var out strings.Builder
	report := cryptoStatusReport{
		VersionsByKey: map[string]int{secrets.LegacyFormLabel: 3},
		Pending:       3,
	}
	printCryptoStatus(&out, report)
	printed := out.String()
	for _, line := range []string{
		"installation_id: none",
		"versions_by_key legacy/v1: 3",
		"live_versions: 3",
		"pending_migration: 3",
	} {
		if !strings.Contains(printed, line+"\n") {
			t.Fatalf("the report does not carry the line %q:\n%s", line, printed)
		}
	}

	out.Reset()
	printCryptoStatus(&out, cryptoStatusReport{
		Installation:  "427d6c9b-d089-4674-9912-bceabae00723",
		Provider:      "local-sealed",
		ActiveKeyID:   "k-0000000000000001",
		VersionsByKey: map[string]int{"k-0000000000000001": 3},
	})
	printed = out.String()
	if !strings.Contains(printed, "pending_migration: 0\n") {
		t.Fatalf("a migrated installation does not report an empty backlog:\n%s", printed)
	}
	if strings.Contains(printed, "note:") {
		t.Fatalf("a migrated installation is told there is work to do:\n%s", printed)
	}
}

// TestWhatTheVerificationOfTheStorePrints pins the fields a trial reads off
// each line, and that a version which did not open is told apart from one
// destroyed on purpose. The two used to be one "not available".
func TestWhatTheVerificationOfTheStorePrints(t *testing.T) {
	var out strings.Builder
	printVerification(&out, []secrets.VersionCheck{
		{SecretName: "db-root", Version: 1, EnvelopeVersion: 1, SHA256: "aa"},
		{SecretName: "db-root", Version: 2, EnvelopeVersion: 2, KeyID: "legacy", SHA256: "bb"},
		{SecretName: "gone", Version: 1, EnvelopeVersion: 2, KeyID: "legacy", Destroyed: true},
		{SecretName: "wrong", Version: 1, EnvelopeVersion: 1, Err: errors.New("cipher: message authentication failed")},
	})
	printed := out.String()
	for _, line := range []string{
		// A version of the first form names no key, and "-" says so rather
		// than an empty column a reader would misalign.
		"db-root version 1 envelope 1 key - sha256 aa",
		"db-root version 2 envelope 2 key legacy sha256 bb",
		"gone version 1 envelope 2 key legacy destroyed",
		"wrong version 1 envelope 1 key - FAILED cipher: message authentication failed",
		"opened: 2",
		"destroyed: 1",
		"failed: 1",
	} {
		if !strings.Contains(printed, line+"\n") {
			t.Fatalf("the report does not carry the line %q:\n%s", line, printed)
		}
	}
}
