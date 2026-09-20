package opspec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The operations chapter names every typed operation the panel can order.
// One added here and not there is a thing the product does that its manual
// does not admit to.
func TestEveryOperationIsInThePublishedReference(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "site", "docs", "operations.html")
	page, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("the published reference is not in this tree: %v", err)
	}
	text := string(page)
	if !strings.Contains(text, `id="op-`) {
		t.Fatal("the reference names no operation at all; the anchors have changed shape")
	}
	var missing []string
	for _, action := range AllActions() {
		// The anchor is the action with every separator turned into a hyphen.
		slug := strings.NewReplacer(".", "-", "_", "-").Replace(string(action))
		anchor := `id="op-` + slug + `"`
		if !strings.Contains(text, anchor) {
			missing = append(missing, string(action))
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d operations are not in %s:\n  %s",
			len(missing), filepath.Base(path), strings.Join(missing, "\n  "))
	}
}
