package packages

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A tool of the host can write more than the agent has room for. What the
// agent must never do is read part of a listing and answer with it.

// shellScript writes an executable script and returns its path.
func shellScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheBoundedWriterStopsAtItsLimitAndSaysSo(t *testing.T) {
	writer := &boundedWriter{limit: 10}
	n, err := writer.Write([]byte("0123456789abcdef"))
	if n != 16 || err != nil {
		// The tool is told its bytes were taken; a short write would break a
		// transaction over a counter.
		t.Fatalf("Write returned (%d, %v), expected (16, nil)", n, err)
	}
	if writer.String() != "0123456789" {
		t.Errorf("kept %q, expected the first ten bytes", writer.String())
	}
	if !writer.over {
		t.Error("the writer did not remember that it stopped")
	}
}

func TestTheBoundedWriterKeepsEverythingBelowItsLimit(t *testing.T) {
	writer := &boundedWriter{limit: 16}
	for _, part := range []string{"one ", "two ", "three"} {
		if _, err := writer.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if writer.String() != "one two three" || writer.over {
		t.Errorf("kept %q (over=%v), expected the whole text", writer.String(), writer.over)
	}
}

func TestACutOutputIsARefusalAndNotAShorterAnswer(t *testing.T) {
	// Nine megabytes of sixty-five byte lines: past the bound of one call.
	tool := shellScript(t, "yes "+strings.Repeat("0123456789", 6)+" | head -n 150000\n")
	result := run(context.Background(), time.Minute, tool)
	if !result.Truncated {
		t.Fatalf("a %d byte output was not reported as cut", len(result.Stdout))
	}
	if result.Complete() {
		t.Error("a cut output was called complete")
	}
	if len(result.Stdout) > maxCommandOutput {
		t.Errorf("kept %d bytes, more than the bound of %d", len(result.Stdout), maxCommandOutput)
	}
	if !strings.Contains(result.Reason(), "more than the agent reads") {
		t.Errorf("the reason does not say what happened: %q", result.Reason())
	}
}

func TestAStreamedOutputArrivesLineByLineAndIsNeverHeldWhole(t *testing.T) {
	tool := shellScript(t, "printf 'one\\ntwo\\nthree\\n'\n")
	var lines []string
	result := runLines(context.Background(), time.Minute, func(line string) {
		lines = append(lines, line)
	}, tool)
	if !result.Complete() {
		t.Fatalf("the tool did not run: %+v", result)
	}
	if strings.Join(lines, ",") != "one,two,three" {
		t.Errorf("read %v, expected the three lines", lines)
	}
	if result.Stdout != "" {
		t.Error("a streamed read kept the output as well")
	}
}

func TestAStreamedReadRefusesALineItCannotHold(t *testing.T) {
	// One line of some megabytes: longer than a line may be.
	tool := shellScript(t, "yes "+strings.Repeat("0123456789", 6)+" | head -n 40000 | tr -d '\\n'\n")
	seen := 0
	result := runLines(context.Background(), time.Minute, func(string) { seen++ }, tool)
	if result.Ran || result.Complete() {
		t.Fatalf("a listing with a hole in it was accepted: %+v", result)
	}
	if !result.Truncated {
		t.Error("the result does not say the output was cut")
	}
	if !errors.Is(result.Err, ErrOutputTooLong) {
		t.Errorf("the refusal is untyped: %v", result.Err)
	}
}

func TestAnUnreadableListingCarriesItsOwnCode(t *testing.T) {
	cut := commandResult{Ran: true, ExitCode: 0, Truncated: true}
	if reason := cut.unreadable("dpkg-query"); !strings.HasPrefix(reason, ErrorOutputTooLarge+":") {
		t.Errorf("the reason does not carry the code: %q", reason)
	}
	failed := commandResult{Ran: true, ExitCode: 2, Stderr: "no such database\n"}
	if reason := failed.unreadable("dpkg-query"); strings.Contains(reason, ErrorOutputTooLarge) {
		t.Errorf("a failing tool was reported as a cut output: %q", reason)
	}
}

// The status file of dpkg carries the description of every package on the
// host. It is read stanza by stanza, and a stanza nobody could read is not a
// host with fewer blocked packages.

func TestTheStatusFileIsReadStanzaByStanzaToItsLastOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	content := "Package: one\nStatus: install ok installed\nDescription: fine\n\n" +
		"Package: two\nStatus: install ok half-configured\nDescription: waiting\n\n" +
		"Package: three\nStatus: install ok unpacked\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := blockedFromStatusFile(path)
	if len(blocked) != 2 {
		t.Fatalf("found %d blocked packages, expected two: %+v", len(blocked), blocked)
	}
	// The last stanza has no blank line after it and still counts.
	if blocked[0].Name != "two" || blocked[1].Name != "three" {
		t.Errorf("found %+v, expected two and three", blocked)
	}
}

func TestAStatusFileWithALineTooLongIsNotAHostWithoutBlockedPackages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	content := "Package: one\nStatus: install ok half-configured\n" +
		"Description: " + strings.Repeat("x", maxLineBytes+1) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if blocked := blockedFromStatusFile(path); blocked != nil {
		t.Errorf("a file that could not be read gave an answer: %+v", blocked)
	}
}
