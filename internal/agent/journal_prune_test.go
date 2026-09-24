package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A marker of a task nobody resolved says the outcome is unknown: the agent
// started a change and cannot tell whether the host carried it out. Pruning it
// with the rest of the journal turned that into "it never ran", and the task
// was then carried out a second time - in the one place the agent otherwise
// answers outcome_unknown correctly.
func TestPruningKeepsTheMarkerOfATaskNobodyResolved(t *testing.T) {
	dir := t.TempDir()
	journal, err := NewIdempotencyJournal(dir, time.Hour)
	if err != nil {
		t.Fatalf("the journal: %v", err)
	}
	marker := InFlight{
		IdempotencyKey: "key-unresolved", TaskID: "task-1",
		Action: "packages.upgrade", StartedAt: time.Now().Add(-48 * time.Hour),
	}
	if err := journal.MarkInFlight(marker); err != nil {
		t.Fatalf("writing the marker: %v", err)
	}
	// Age everything in the journal well past the TTL.
	old := time.Now().Add(-48 * time.Hour)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.Chtimes(filepath.Join(dir, entry.Name()), old, old); err != nil {
			t.Fatal(err)
		}
	}

	journal.Prune()

	if _, ok := journal.InFlight("key-unresolved"); !ok {
		t.Fatal("the marker of an unresolved task was pruned; the agent would run the task again")
	}
	if markers := journal.InFlightMarkers(); len(markers) != 1 {
		t.Errorf("the journal lists %d unresolved tasks, want one", len(markers))
	}
}
