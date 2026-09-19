package vuln

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
)

// A verdict that does not name the data behind it cannot be read.
func TestTheVerdictOfAHostNamesTheGenerationThatProducedIt(t *testing.T) {
	snapshot := debianSnapshot("trixie")
	snapshot.GenerationID = "11111111-1111-1111-1111-111111111111"
	snapshot.GenerationAt = now.Add(-2 * time.Hour)

	evaluation := Evaluate(debianInput(debPackage("openssl", "3.0.11-1", "openssl")),
		snapshot, nil, 6*time.Hour, now)

	if evaluation.State.GenerationID != snapshot.GenerationID {
		t.Fatalf("generation_id = %q, expected %q",
			evaluation.State.GenerationID, snapshot.GenerationID)
	}
	if evaluation.State.GenerationAt == nil || !evaluation.State.GenerationAt.Equal(snapshot.GenerationAt) {
		t.Fatalf("generation_at = %v, expected %v",
			evaluation.State.GenerationAt, snapshot.GenerationAt)
	}
}

// Two hosts judged in one pass against the same snapshot name the same
// generation.
func TestTwoHostsJudgedInOnePassNameTheSameGeneration(t *testing.T) {
	snapshot := debianSnapshot("trixie")
	snapshot.GenerationID = "22222222-2222-2222-2222-222222222222"
	snapshot.GenerationAt = now.Add(-time.Hour)

	first := debianInput(debPackage("openssl", "3.0.11-1", "openssl"))
	second := debianInput(debPackage("curl", "8.5.0-1", "curl"))
	second.HostID = "host-2"
	second.Hostname = "web-02"

	one := Evaluate(first, snapshot, nil, 6*time.Hour, now)
	two := Evaluate(second, snapshot, nil, 6*time.Hour, now.Add(time.Minute))

	if one.State.GenerationID != two.State.GenerationID {
		t.Fatalf("two hosts of one pass name different generations: %q and %q",
			one.State.GenerationID, two.State.GenerationID)
	}
	if one.State.EvaluatedAt.Equal(*two.State.EvaluatedAt) {
		t.Fatal("the two verdicts were expected to be written at different moments")
	}

	// A later fetch is a different generation, and a host judged against
	// it is visibly ahead of one that was not.
	next := snapshot
	next.Digest = "def456"
	next.GenerationID = "33333333-3333-3333-3333-333333333333"
	next.GenerationAt = now
	reassessed := Evaluate(first, next, nil, 6*time.Hour, now.Add(time.Hour))
	if reassessed.State.GenerationID == one.State.GenerationID {
		t.Fatal("a verdict against a new snapshot kept the previous generation")
	}
}

// A snapshot without a generation leaves the verdict without one.
func TestAVerdictWithoutAGenerationSaysSoRatherThanInventingOne(t *testing.T) {
	// The shape the scheduler builds for a host whose findings come from
	// its own repositories: a digest and a moment, and no generation.
	collected := now.Add(-30 * time.Minute)
	snapshot := Snapshot{
		Provider: "fedora", Digest: "host-metadata-1", Releases: []string{"42"},
		FetchedAt: collected, GenerationAt: collected, Active: true,
	}
	input := Input{
		HostID: "host-3", Hostname: "lab-01", Distribution: "fedora", Release: "42",
		InventoryDigest: "list-9", AdvisoryDigest: "host-metadata-1",
		Packages: []packages.InstalledPackage{{
			Name: "openssl", Version: "3.2.1-1.fc42", Architecture: "x86_64",
			SourceName: "openssl", SourceVersion: "3.2.1-1.fc42",
			Origin: "fedora", OriginClass: packages.OriginDistribution,
		}},
	}

	state := Evaluate(input, snapshot, nil, 6*time.Hour, now).State
	if state.GenerationID != "" {
		t.Fatalf("a verdict from host metadata invented a generation: %q", state.GenerationID)
	}
	// The moment the data were read still stands in its place, so the age
	// of the answer is not lost with the identifier.
	if state.GenerationAt == nil || !state.GenerationAt.Equal(collected) {
		t.Fatalf("generation_at = %v, expected the moment the metadata were read (%v)",
			state.GenerationAt, collected)
	}
}
