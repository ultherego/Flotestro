package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func sampleRecords(n int) []Record {
	records := make([]Record, 0, n)
	base := time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		records = append(records, Record{
			ID: int64(i + 1), OccurredAt: base.Add(time.Duration(i) * time.Second),
			ActorType: "user", ActorID: "alice", Action: "unit.restart",
			TargetType: "host", TargetID: "h1", Outcome: "success",
			Detail: json.RawMessage(`{"unit":"sshd"}`),
		})
	}
	return records
}

func export(t *testing.T, records []Record) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := NewChainWriter(&buffer)
	for _, record := range records {
		if err := writer.Write(record); err != nil {
			t.Fatalf("writing: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	return buffer.Bytes()
}

func TestChainVerifiesWhatTheWriterWrote(t *testing.T) {
	file := export(t, sampleRecords(5))
	report, err := VerifyChain(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("a fresh export does not verify: %v", err)
	}
	if report.Count != 5 || report.First != 1 || report.Last != 5 {
		t.Errorf("report = %+v", report)
	}

	// The first line follows the empty string, as the document says.
	first := strings.SplitN(string(file), "\n", 2)[0]
	if !strings.Contains(first, `"prev_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`) {
		t.Errorf("the first line does not chain from the empty string: %s", first)
	}
	lines := strings.Split(strings.TrimSpace(string(file)), "\n")
	if !strings.HasPrefix(lines[len(lines)-1], `{"count":5,"sha256_chain":"`) {
		t.Errorf("the closing line = %s", lines[len(lines)-1])
	}
}

func TestChainWithoutEventsStillCloses(t *testing.T) {
	file := export(t, nil)
	report, err := VerifyChain(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("an empty export does not verify: %v", err)
	}
	if report.Count != 0 {
		t.Errorf("count = %d", report.Count)
	}
}

func TestChainNoticesTampering(t *testing.T) {
	file := export(t, sampleRecords(4))
	lines := strings.Split(strings.TrimSuffix(string(file), "\n"), "\n")
	// splice returns the lines with those from i to j replaced by the given ones.
	splice := func(i, j int, replacement ...string) []string {
		result := append([]string{}, lines[:i]...)
		result = append(result, replacement...)
		return append(result, lines[j:]...)
	}

	cases := []struct {
		name  string
		lines []string
	}{
		{"a changed event", splice(1, 2, strings.Replace(lines[1], "alice", "mallory", 1))},
		{"a removed event", splice(1, 2)},
		{"a repeated event", splice(1, 1, lines[1])},
		{"a missing closing", lines[:len(lines)-1]},
		{"a line after the closing", append(append([]string{}, lines...), lines[0])},
		{"a foreign line", splice(2, 2, `{"note":"hello"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyChain(strings.NewReader(strings.Join(tc.lines, "\n") + "\n"))
			if !errors.Is(err, ErrChainBroken) {
				t.Fatalf("err = %v, expected a broken chain", err)
			}
		})
	}
}

func TestChainToleratesLineEndingsAndATrailingBlank(t *testing.T) {
	file := export(t, sampleRecords(3))
	windows := strings.ReplaceAll(string(file), "\n", "\r\n") + "\r\n"
	if _, err := VerifyChain(strings.NewReader(windows)); err != nil {
		t.Fatalf("a file with CRLF and a blank tail does not verify: %v", err)
	}
}

func TestChainWriterRefusesWritesAfterClose(t *testing.T) {
	writer := NewChainWriter(&bytes.Buffer{})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(sampleRecords(1)[0]); err == nil {
		t.Error("a write after the closing line was accepted")
	}
}
