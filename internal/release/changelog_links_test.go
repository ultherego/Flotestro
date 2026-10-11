package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	changelogHeading = regexp.MustCompile(`(?m)^## \[([^\]]+)\]`)
	changelogLink    = regexp.MustCompile(`(?m)^\[([^\]]+)\]:\s+\S+`)
)

// Every version the changelog announces has to carry the link that shows what
// went into it. The two drift apart quietly: the heading is written when the
// entry is, the link at the bottom is written from memory at tagging time,
// and nothing reads the pair.
//
// Counted on 11.10: 0.62.0 and 0.62.1 had entries and no links at all, and
// [Unreleased] still compared from v0.61.0 - two releases behind. A reader
// following those links was shown the wrong range for a month.
func TestEveryChangelogEntryCarriesItsLink(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("reading the changelog: %v", err)
	}
	text := string(raw)

	linked := map[string]bool{}
	for _, match := range changelogLink.FindAllStringSubmatch(text, -1) {
		linked[match[1]] = true
	}
	if len(linked) == 0 {
		t.Fatal("the changelog carries no links at all, so this guard is reading the wrong file")
	}

	var headings []string
	for _, match := range changelogHeading.FindAllStringSubmatch(text, -1) {
		headings = append(headings, match[1])
	}
	if len(headings) == 0 {
		t.Fatal("the changelog announces no versions, so this guard is reading the wrong file")
	}

	for _, version := range headings {
		if !linked[version] {
			t.Errorf("the changelog announces %q and links nothing for it; "+
				"a reader following the links is shown another version's range", version)
		}
	}

	// And the other way: a link to a version nobody announced is a line left
	// over from a release that was renamed or abandoned.
	announced := map[string]bool{}
	for _, version := range headings {
		announced[version] = true
	}
	for version := range linked {
		// [Unreleased] is a standing link of the Keep a Changelog shape: it
		// points at everything since the newest tag and has no entry of its
		// own between releases.
		if strings.EqualFold(version, "Unreleased") {
			continue
		}
		if !announced[version] {
			t.Errorf("the changelog links %q and announces no entry for it", version)
		}
	}

	// [Unreleased] compares from the newest release. Pointing it at an older
	// one is the drift this test exists for, and it is invisible by reading.
	newest := ""
	for _, version := range headings {
		if !strings.EqualFold(version, "Unreleased") {
			newest = version
			break
		}
	}
	if newest != "" {
		want := "compare/v" + newest + "...HEAD"
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "[Unreleased]:") && !strings.Contains(line, want) {
				t.Errorf("[Unreleased] does not compare from v%s, the newest release: %s", newest, line)
			}
		}
	}
}
