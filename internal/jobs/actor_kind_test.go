package jobs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every place that creates a task says what ordered it. The alternative was
// reading it off the author's name, and that was wrong in both directions
// within one day: absence read as "the panel's own" let a blocked operator's
// work leave with a signed capability, absence read as "blocked" would have
// stopped every campaign, and the prefix list written afterwards carried three
// prefixes nobody writes and missed two that are.
func TestEveryTaskSaysWhatOrderedIt(t *testing.T) {
	root := filepath.Join("..", "..")
	var without []string
	checked := 0
	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(content)
		at := 0
		for {
			start := strings.Index(text[at:], "jobs.Spec{")
			if start < 0 {
				start = strings.Index(text[at:], "Spec{")
				if start < 0 || !strings.HasSuffix(path, "store.go") {
					break
				}
				break
			}
			start += at
			end := start + 1200
			if end > len(text) {
				end = len(text)
			}
			checked++
			if !strings.Contains(text[start:end], "CreatedByKind") {
				without = append(without, filepath.ToSlash(path))
			}
			at = start + len("jobs.Spec{")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no task creation was found; this check read nothing")
	}
	for _, path := range without {
		t.Errorf("%s creates a task without saying what ordered it", path)
	}
}

// The zero value is not a licence: a row from before the column is read as a
// person, which is the side that asks questions rather than the side that
// skips them.
func TestAnUnrecordedKindIsNotMachinery(t *testing.T) {
	if ActorUnknown == ActorMachinery {
		t.Fatal("an unrecorded kind is the panel's own machinery")
	}
	if ActorUnknown.Valid() {
		t.Error("an unrecorded kind passes as one this panel writes")
	}
	if !ActorPerson.Valid() || !ActorMachinery.Valid() {
		t.Error("a kind this panel writes does not pass as one")
	}
}
