package spool

import (
	"os"
	"testing"
)

// A compaction that stopped between writing a record into the active segment
// and removing the old one leaves the same record in two segments. The rebuild
// kept one of them in the index and both in byHost, so an acknowledgement
// deleted the indexed copy and left the other pointing at a dead offset: the
// record went out again for as long as the spool lived, and live never came
// back to zero, so the compaction counted bytes that were not there.
//
// No gate can catch this: the failure has to land between two statements. The
// directory is therefore fabricated - the bytes of one segment copied into
// another - which is the shape an interrupted compaction leaves behind.
func TestARecordLeftInTwoSegmentsByAnInterruptedCompactionIsOneRecord(t *testing.T) {
	dir := t.TempDir()
	spool := open(t, dir, Options{})
	appendMessage(t, spool, "host-1", signed(result("job-1"), "session-a", 7))
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}

	// The segment the record sits in, copied under the name of the next one:
	// two files, the same record in both, which is where a compaction that
	// stopped half way leaves it.
	first, err := os.ReadFile(segmentPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segmentPath(dir, 2), first, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened := open(t, dir, Options{})

	records, err := reopened.Next("host-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("the spool offers %d records, and one record was written", len(records))
	}

	// And the acknowledgement has to take the whole of it: the copy left
	// behind is what used to be delivered for ever.
	taken, err := reopened.AckID("host-1", records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !taken {
		t.Fatal("the acknowledgement found nothing to take")
	}
	left, err := reopened.Next("host-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("after the acknowledgement the spool still offers %d records", len(left))
	}
}
