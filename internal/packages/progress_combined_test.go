package packages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Two pipes read by two goroutines cannot say which line came first, so the
// adapter that needs that order gets one pipe. The test is of the order, because
// the order is the whole reason the merged runner exists.
func TestTheMergedRunnerKeepsTheOrderTheToolWroteIn(t *testing.T) {
	script := filepath.Join(t.TempDir(), "two-streams")
	body := "#!/bin/sh\n" +
		"echo first-on-stdout\n" +
		"echo first-on-stderr >&2\n" +
		"echo second-on-stdout\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	result := runMergedWithProgress(t.Context(), 30*time.Second, nil, script)
	if !result.Ran || result.ExitCode != 0 {
		t.Fatalf("the script did not run: %+v", result)
	}
	want := []string{"first-on-stdout", "first-on-stderr", "second-on-stdout"}
	got := strings.Fields(strings.TrimSpace(result.Combined))
	if len(got) != len(want) {
		t.Fatalf("the combined output is %q, want the three lines in order", result.Combined)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the combined output is %q, want %v in that order", result.Combined, want)
		}
	}
	// Everything is in one text, and the other field is empty rather than half
	// the answer: a reader that took Stderr alone would see nothing at all, which
	// is better than seeing a part and believing it whole.
	if result.Stderr != "" {
		t.Errorf("the merged run left Stderr = %q", result.Stderr)
	}
	if result.Stdout != result.Combined {
		t.Errorf("Stdout and Combined differ after a merged run")
	}
}

// The ordinary runner keeps the streams apart, and says nothing about the order.
func TestTheOrdinaryRunnerKeepsTheStreamsApart(t *testing.T) {
	script := filepath.Join(t.TempDir(), "two-streams")
	body := "#!/bin/sh\necho on-stdout\necho on-stderr >&2\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	result := runWithProgress(t.Context(), 30*time.Second, nil, false, script)
	if !strings.Contains(result.Stdout, "on-stdout") || strings.Contains(result.Stdout, "on-stderr") {
		t.Errorf("stdout = %q", result.Stdout)
	}
	if !strings.Contains(result.Stderr, "on-stderr") || strings.Contains(result.Stderr, "on-stdout") {
		t.Errorf("stderr = %q", result.Stderr)
	}
	if result.Combined != "" {
		t.Errorf("the ordinary runner filled Combined = %q; nothing may rely on an order it cannot keep",
			result.Combined)
	}
}
