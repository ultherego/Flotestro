package opspec

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The published reference was written out of this catalogue once, and nothing
// has kept the two together since. A code added here and not there is a
// refusal an operator meets in the panel and cannot look up.
func TestEveryRefusalIsInThePublishedReference(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "site", "docs", "errors.html")
	page, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("the published reference is not in this tree: %v", err)
	}
	documented := map[string]bool{}
	entry := regexp.MustCompile(`<code class="refusal">([a-z0-9_]+)</code>`)
	for _, match := range entry.FindAllStringSubmatch(string(page), -1) {
		documented[match[1]] = true
	}
	if len(documented) == 0 {
		t.Fatal("the reference lists no refusal at all; the pattern no longer matches it")
	}
	var missing []string
	for _, guide := range ErrorGuides() {
		if !documented[guide.Code] {
			missing = append(missing, guide.Code)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d refusals are not in %s:\n  %s",
			len(missing), filepath.Base(path), strings.Join(missing, "\n  "))
	}
}
