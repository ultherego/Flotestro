package opspec

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The site says how many typed operations there are, in five places, and the
// number went on being printed one short after the registry grew. Each page is
// read and held to the registry, so adding an operation fails here until the
// pages say so.
func TestThePagesCountTheOperationsTheRegistryHolds(t *testing.T) {
	want := len(AllActions())
	for _, one := range []struct{ file, pattern string }{
		{"../../docs/site/docs/introduction.html", `holds (\d+) typed operations`},
		{"../../docs/site/docs/introduction.html", `Each of the (\d+) operations`},
		{"../../docs/site/docs/operations.html", `one of (\d+) t`},
		{"../../docs/site/pl/docs/introduction.html", `Każda ze (\d+) operacji`},
	} {
		raw, err := os.ReadFile(one.file)
		if err != nil {
			t.Fatal(err)
		}
		found := regexp.MustCompile(one.pattern).FindSubmatch(raw)
		if found == nil {
			t.Errorf("%s no longer says %q; change the page and this test together", one.file, one.pattern)
			continue
		}
		if got, _ := strconv.Atoi(string(found[1])); got != want {
			t.Errorf("%s says %d typed operations, the registry holds %d", one.file, got, want)
		}
	}
}

// The group table of the operations page counts what the page lists under each
// group; the Directory row said 4 above five entries.
func TestTheGroupTableOfTheOperationsPageCountsWhatItLists(t *testing.T) {
	raw, err := os.ReadFile("../../docs/site/docs/operations.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	rows := regexp.MustCompile(`<tr><td><a href="#group-([a-z-]+)">[^<]*</a></td><td>(\d+)</td></tr>`).FindAllStringSubmatch(page, -1)
	if len(rows) == 0 {
		t.Fatal("the page has no group table any more; change the page and this test together")
	}
	sections := regexp.MustCompile(`<h2 id="group-([a-z-]+)">`).FindAllStringSubmatchIndex(page, -1)
	for _, row := range rows {
		listed := -1
		for i, loc := range sections {
			if page[loc[2]:loc[3]] != row[1] {
				continue
			}
			end := len(page)
			if i+1 < len(sections) {
				end = sections[i+1][0]
			}
			listed = len(regexp.MustCompile(`<tr><td><a href="#op-`).FindAllString(page[loc[0]:end], -1))
		}
		if listed < 0 {
			continue
		}
		if got, _ := strconv.Atoi(row[2]); got != listed {
			t.Errorf("group %s: the table says %d, the page lists %d", row[1], got, listed)
		}
	}
}
