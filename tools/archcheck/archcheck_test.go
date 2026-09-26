package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The boundaries are checked by the ordinary test run and not only by a step of
// the workflow: a rule that holds in one place and not the other is a rule
// somebody will cross locally and find out about an hour later.
func TestTheBoundariesOfTheTreeHold(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	problems, err := violations(root)
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if len(problems) > 0 {
		t.Errorf("%d import(s) cross a boundary:\n%s", len(problems), strings.Join(problems, "\n"))
	}
}

// And the checker itself has to be able to see a crossing, or a green run says
// nothing. The helper owning plumbing that a module imports is the crossing this
// tool was written for.
func TestTheCheckerSeesACrossing(t *testing.T) {
	dir := t.TempDir()
	module := filepath.Join(dir, "internal", "modules", "example")
	if err := writeAll(module, "example.go", `package example

import _ "github.com/ultherego/flotestro/internal/helper"
`); err != nil {
		t.Fatal(err)
	}
	problems, err := violations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "internal/helper") {
		t.Fatalf("the checker did not see a module importing the helper: %v", problems)
	}
}

// writeAll puts one file in place, making the directories on the way.
func writeAll(dir, name, body string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
}
