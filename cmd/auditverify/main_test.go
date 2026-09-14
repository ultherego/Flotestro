package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
)

func exportFile(t *testing.T, events int) string {
	t.Helper()
	var buffer bytes.Buffer
	writer := audit.NewChainWriter(&buffer)
	for i := 0; i < events; i++ {
		if err := writer.Write(audit.Record{
			ID: int64(i + 1), OccurredAt: time.Now(), ActorType: "user", ActorID: "alice",
			Action: "audit.read", Outcome: "success", Detail: json.RawMessage(`{}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "export.jsonl")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAnIntactExportVerifies(t *testing.T) {
	path := exportFile(t, 3)
	var out, errOut bytes.Buffer
	if status := run([]string{path}, nil, &out, &errOut); status != 0 {
		t.Fatalf("status %d; stderr: %s", status, errOut.String())
	}
	if !strings.Contains(out.String(), "OK, 3 events (1 to 3)") {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestATamperedExportIsReported(t *testing.T) {
	path := exportFile(t, 3)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(content, []byte("alice"), []byte("mallory"), 1)
	var out, errOut bytes.Buffer
	if status := run([]string{"-"}, bytes.NewReader(tampered), &out, &errOut); status != 1 {
		t.Fatalf("status %d, expected 1; stdout: %s", status, out.String())
	}
	if !strings.Contains(errOut.String(), "BROKEN") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestAMissingFileIsAWrongInvocation(t *testing.T) {
	var out, errOut bytes.Buffer
	if status := run([]string{filepath.Join(t.TempDir(), "absent.jsonl")}, nil, &out, &errOut); status != 2 {
		t.Errorf("status %d, expected 2", status)
	}
	if status := run([]string{"a", "b"}, nil, &out, &errOut); status != 2 {
		t.Errorf("two arguments: status %d, expected 2", status)
	}
}
