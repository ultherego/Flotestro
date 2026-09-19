package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A tool of the host can write more than the agent has room for. Counting rows
// out of a cut output would answer with a smaller number than the host holds.

// boundsScript writes an executable script and returns its path.
func boundsScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheAgentBoundedWriterStopsAtItsLimitAndSaysSo(t *testing.T) {
	writer := &boundedWriter{limit: 4}
	n, err := writer.Write([]byte("abcdefgh"))
	if n != 8 || err != nil {
		t.Fatalf("Write returned (%d, %v), expected (8, nil)", n, err)
	}
	if writer.String() != "abcd" || !writer.over {
		t.Errorf("kept %q (over=%v), expected the first four bytes and a mark", writer.String(), writer.over)
	}
}

func TestTheAgentRefusesToCountRowsOfACutOutput(t *testing.T) {
	tool := boundsScript(t, "yes "+strings.Repeat("0123456789", 6)+" | head -n 150000\n")
	result := runCommand(context.Background(), time.Minute, tool)
	if !result.Truncated || result.Complete() {
		t.Fatalf("a %d byte output was accepted whole: %+v", len(result.Stdout), result)
	}
	if len(result.Stdout) > maxCommandOutput {
		t.Errorf("kept %d bytes, more than the bound of %d", len(result.Stdout), maxCommandOutput)
	}
	if !strings.Contains(result.Reason(), "more than the agent reads") {
		t.Errorf("the reason does not say what happened: %q", result.Reason())
	}
}

func TestTheAgentReadsAListingLineByLine(t *testing.T) {
	tool := boundsScript(t, "printf 'a.service\\nb.service\\n'\n")
	var lines []string
	result := runCommandLines(context.Background(), time.Minute, func(line string) {
		lines = append(lines, line)
	}, tool)
	if !result.Complete() {
		t.Fatalf("the tool did not run: %+v", result)
	}
	if strings.Join(lines, ",") != "a.service,b.service" {
		t.Errorf("read %v, expected the two lines", lines)
	}
	if result.Stdout != "" {
		t.Error("a streamed read kept the output as well")
	}
}

func TestTheAgentRefusesAListingWithALineItCannotHold(t *testing.T) {
	tool := boundsScript(t, "yes "+strings.Repeat("0123456789", 6)+" | head -n 40000 | tr -d '\\n'\n")
	result := runCommandLines(context.Background(), time.Minute, func(string) {}, tool)
	if result.Ran || result.Complete() {
		t.Fatalf("a listing with a hole in it was accepted: %+v", result)
	}
	if !errors.Is(result.Err, ErrOutputTooLong) {
		t.Errorf("the refusal is untyped: %v", result.Err)
	}
}

func TestACutResultIsNeverComplete(t *testing.T) {
	cases := map[string]struct {
		result commandResult
		want   bool
	}{
		"ran and whole":  {commandResult{Ran: true, ExitCode: 0}, true},
		"ran and cut":    {commandResult{Ran: true, ExitCode: 0, Truncated: true}, false},
		"ran and failed": {commandResult{Ran: true, ExitCode: 1}, false},
		"never ran":      {commandResult{}, false},
	}
	for name, test := range cases {
		if got := test.result.Complete(); got != test.want {
			t.Errorf("%s: Complete() = %v, expected %v", name, got, test.want)
		}
	}
}

// A journal read answers with the end of what it read. The limit of the task
// is applied while journalctl writes, so a read of ten thousand lines never
// exists whole - and the answer has to be the same bytes as before.
func TestTheTailBufferKeepsTheEndAndSaysItCut(t *testing.T) {
	cases := []struct {
		name   string
		limit  int
		writes []string
		want   string
		cut    bool
	}{
		{"everything fits", 16, []string{"one ", "two"}, "one two", false},
		{"cut across writes", 4, []string{"abcd", "efg"}, "defg", true},
		{"one write longer than the limit", 3, []string{"abcdefg"}, "efg", true},
		{"exactly the limit", 4, []string{"ab", "cd"}, "abcd", false},
	}
	for _, test := range cases {
		buffer := newTailBuffer(test.limit)
		for _, part := range test.writes {
			n, err := buffer.Write([]byte(part))
			if n != len(part) || err != nil {
				t.Fatalf("%s: Write returned (%d, %v)", test.name, n, err)
			}
		}
		if string(buffer.data) != test.want || buffer.cut != test.cut {
			t.Errorf("%s: kept %q (cut=%v), expected %q (cut=%v)",
				test.name, buffer.data, buffer.cut, test.want, test.cut)
		}
	}
}

func TestTheTailBufferNeverGrowsPastItsLimit(t *testing.T) {
	buffer := newTailBuffer(1024)
	for i := 0; i < 1000; i++ {
		if _, err := buffer.Write([]byte(strings.Repeat("x", 512))); err != nil {
			t.Fatal(err)
		}
	}
	if len(buffer.data) != 1024 || cap(buffer.data) != 1024 {
		t.Errorf("the buffer holds %d bytes in %d, expected 1024 in 1024",
			len(buffer.data), cap(buffer.data))
	}
	if !buffer.cut {
		t.Error("half a megabyte was written and nothing was reported as cut")
	}
}
