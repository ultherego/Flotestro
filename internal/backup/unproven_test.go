package backup

import (
	"os"
	"strings"
	"testing"
)

// A run that cannot say which configuration it used proves nothing about the
// one in force. Treating a missing fingerprint as a match reported a definition
// as covered by a copy nobody can tie to it - a false readiness - and migration
// 0145 said so in its own comment ("a null reads as unknown rather than as a
// match") while the SQL beside it said the opposite for three weeks.
func TestARunWithNoFingerprintIsNotEvidenceForTheConfigurationInForce(t *testing.T) {
	if strings.Contains(runOfCurrentConfig, "is null") {
		t.Fatalf("a null fingerprint still passes as a match: %s", runOfCurrentConfig)
	}
	for _, needed := range []string{
		"r.config_sha256 is not null",
		"d.config_sha256 is not null",
		"r.config_sha256 = d.config_sha256",
	} {
		if !strings.Contains(runOfCurrentConfig, needed) {
			t.Errorf("the condition does not require %q: %s", needed, runOfCurrentConfig)
		}
	}

	// Every reader of the runs asks it, so one of them cannot drift into
	// counting a run the others refuse.
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := os.ReadFile("aggregate.go")
	if err != nil {
		t.Fatal(err)
	}
	asked := strings.Count(string(store), "runOfCurrentConfig") +
		strings.Count(string(aggregate), "runOfCurrentConfig")
	// The constant's own declaration, plus the readers.
	if asked < 4 {
		t.Errorf("the condition is named %d times; the summary, the list, the repository load "+
			"and the fleet aggregate each ask it", asked)
	}
}

// And the migration's comment and the code it describes say the same thing now.
func TestTheMigrationAndTheQueryAgreeAboutAnAbsentFingerprint(t *testing.T) {
	migration, err := os.ReadFile("../../db/migrations/0145_backup_run_config.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migration), `a null reads as "unknown" rather than as a match`) {
		t.Skip("the migration no longer makes that claim; nothing to hold the query to")
	}
	if strings.Contains(runOfCurrentConfig, "is null or") {
		t.Error("the migration says unknown and the query says match")
	}
}
