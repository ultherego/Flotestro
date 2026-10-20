package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A runbook index linked to a file deleted nine days earlier and nobody saw: an
// operator in an incident follows the link and finds nothing. Every relative
// link of the runbooks has to resolve to a file that is there.
func TestEveryRelativeLinkOfTheRunbooksResolves(t *testing.T) {
	files, err := filepath.Glob("../../docs/runbooks/*.md")
	if err != nil || len(files) == 0 {
		t.Fatalf("no runbooks found: %v", err)
	}
	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range link.FindAllStringSubmatch(string(raw), -1) {
			target := match[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			target, _, _ = strings.Cut(target, "#")
			if target == "" {
				continue
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(file), target)); err != nil {
				t.Errorf("%s links to %s, which is not there", filepath.Base(file), match[1])
			}
		}
	}
}
