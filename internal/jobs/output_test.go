package jobs

import (
	"bytes"
	"testing"
)

// The bound of the output is the task's, not the agent's word. An agent
// that sends more than the task allows gets its result cut here, and the
// cut is visible as a truncation.
func TestOutputIsClampedToTheTaskBound(t *testing.T) {
	stdout := bytes.Repeat([]byte("o"), 60)
	stderr := bytes.Repeat([]byte("e"), 60)

	out, errOut, truncated := clampOutput(stdout, stderr, false, 100)
	if len(out) != 60 || len(errOut) != 40 || !truncated {
		t.Fatalf("clamped to %d+%d bytes, truncated=%v", len(out), len(errOut), truncated)
	}

	// The standard output alone above the bound leaves no room for the
	// error stream.
	out, errOut, truncated = clampOutput(bytes.Repeat([]byte("o"), 150), stderr, false, 100)
	if len(out) != 100 || len(errOut) != 0 || !truncated {
		t.Fatalf("clamped to %d+%d bytes, truncated=%v", len(out), len(errOut), truncated)
	}

	// Output within the bound passes untouched, and a truncation the agent
	// reported itself is kept.
	out, errOut, truncated = clampOutput(stdout, stderr, true, 200)
	if len(out) != 60 || len(errOut) != 60 || !truncated {
		t.Fatalf("output within the bound changed: %d+%d bytes, truncated=%v",
			len(out), len(errOut), truncated)
	}
	if _, _, truncated := clampOutput(stdout, stderr, false, 0); truncated {
		t.Fatal("a task without a bound truncated the output")
	}
}
