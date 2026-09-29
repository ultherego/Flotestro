package opspec

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

// publishedReferences are the pages that transcribe this catalogue: the
// English manual and the Polish one. Both carry the same counts and the same
// entries, so both are checked against the same source.
func publishedReferences() []string {
	return []string{
		filepath.Join("..", "..", "docs", "site", "docs", "errors.html"),
		filepath.Join("..", "..", "docs", "site", "pl", "docs", "errors.html"),
	}
}

// readPublishedReference reads one page, or skips the way the test above
// does when the site is not in this tree.
func readPublishedReference(t *testing.T, path string) string {
	t.Helper()
	page, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("the published reference is not in this tree: %v", err)
	}
	return string(page)
}

// refusalsPerStage is the count of codes the catalogue holds under each
// stage: the number a page that transcribes it has to state.
func refusalsPerStage() map[string]int {
	perStage := map[string]int{}
	for _, guide := range ErrorGuides() {
		perStage[guide.Stage]++
	}
	return perStage
}

var (
	// A row of the summary table: the stage, then how many codes it holds.
	stageTableRow = regexp.MustCompile(
		`<tr><td><a href="#stage-([a-z]+)"><code>[a-z]+</code></a></td><td>(\d+)</td></tr>`)
	// The heading of a stage section and the count right underneath it. The
	// word after the number is English on one page and Polish on the other,
	// so only the number is read.
	stageSectionCount = regexp.MustCompile(
		`<h2 id="stage-([a-z]+)">[^<]*</h2>\n<p>(\d+) [^<]*</p>`)
	// An entry under a stage section.
	stageSectionEntry = regexp.MustCompile(
		`<dt id="[^"]*"><code class="refusal">([a-z0-9_]+)</code></dt>`)
	// The opening paragraph, which states the size of the whole guide.
	ledeParagraph = regexp.MustCompile(`(?s)<p class="lede">(.*?)</p>`)
	// A number the lede states as a number, not one buried in a path such as
	// the /api/v1/ of the endpoint it names.
	ledeNumber = regexp.MustCompile(`(?:^|[\s>(])(\d+)(?:[\s<),.])`)
)

// A section headed "22 codes" that holds twenty-four of them is the page
// telling the operator it is complete when it is not. The summary table and
// the section headings both state a count, and both are checked per stage:
// a check of the total alone lets two stages drift in opposite directions.
func TestThePublishedReferenceStatesTheCountTheCatalogueHoldsForEveryStage(t *testing.T) {
	catalogue := refusalsPerStage()
	for _, path := range publishedReferences() {
		page := readPublishedReference(t, path)
		for _, stated := range []struct {
			where   string
			pattern *regexp.Regexp
		}{
			{"the stage table", stageTableRow},
			{"the heading of the section", stageSectionCount},
		} {
			counts := countsIn(t, path, stated.where, page, stated.pattern)
			for _, stage := range sortedKeys(catalogue) {
				count, ok := counts[stage]
				if !ok {
					t.Errorf("%s: %s states no count for the %s stage, which holds %d codes",
						pageName(path), stated.where, stage, catalogue[stage])
					continue
				}
				if count != catalogue[stage] {
					t.Errorf("%s: %s states %d codes under the %s stage, the catalogue has %d",
						pageName(path), stated.where, count, stage, catalogue[stage])
				}
			}
			for _, stage := range sortedKeys(counts) {
				if _, ok := catalogue[stage]; !ok {
					t.Errorf("%s: %s states a count for the %s stage, which the catalogue does not have",
						pageName(path), stated.where, stage)
				}
			}
		}
		total := len(ErrorGuides())
		if stated := ledeTotalOf(t, path, page); stated != total {
			t.Errorf("%s: the lede says the guide holds %d entries, the catalogue holds %d",
				pageName(path), stated, total)
		}
	}
}

// pageName names a page by its place in the site, so a failure says which
// of the two languages drifted.
func pageName(path string) string {
	return strings.TrimPrefix(filepath.ToSlash(path), "../../")
}

// countsIn reads the per-stage counts one part of the page states.
func countsIn(t *testing.T, path, where, page string, pattern *regexp.Regexp) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, match := range pattern.FindAllStringSubmatch(page, -1) {
		stated, err := strconv.Atoi(match[2])
		if err != nil {
			t.Fatalf("%s: %s states %q for the %s stage, which is not a number",
				filepath.Base(path), where, match[2], match[1])
		}
		counts[match[1]] = stated
	}
	if len(counts) == 0 {
		t.Fatalf("%s: %s states no count at all; the pattern no longer matches it",
			filepath.Base(path), where)
	}
	return counts
}

// ledeTotalOf reads the one number the opening paragraph states.
func ledeTotalOf(t *testing.T, path, page string) int {
	t.Helper()
	lede := ledeParagraph.FindStringSubmatch(page)
	if lede == nil {
		t.Fatalf("%s: the page has no lede; the pattern no longer matches it", filepath.Base(path))
	}
	var numbers []int
	for _, match := range ledeNumber.FindAllStringSubmatch(lede[1], -1) {
		stated, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatalf("%s: the lede states %q, which is not a number", filepath.Base(path), match[1])
		}
		numbers = append(numbers, stated)
	}
	if len(numbers) != 1 {
		t.Fatalf("%s: the lede states %d numbers, %v; it is meant to state one, the size of the guide",
			filepath.Base(path), len(numbers), numbers)
	}
	return numbers[0]
}

// The count under a heading is only worth as much as what the section holds,
// so the entries themselves are read: every code the catalogue puts under a
// stage is filed under that stage's heading, and nothing else is.
func TestThePublishedReferenceFilesEveryRefusalUnderTheStageTheCatalogueGivesIt(t *testing.T) {
	stageOf := map[string]string{}
	for _, guide := range ErrorGuides() {
		stageOf[guide.Code] = guide.Stage
	}
	for _, path := range publishedReferences() {
		page := readPublishedReference(t, path)
		filed := entriesPerStage(t, path, page)
		for _, stage := range sortedStages(filed) {
			for _, code := range filed[stage] {
				if stageOf[code] != stage {
					t.Errorf("%s: %s is filed under the %s stage, the catalogue puts it under %s",
						pageName(path), code, stage, stageOf[code])
				}
			}
		}
	}
}

// A code the catalogue dropped is worse than a missing one: the operator
// looks it up, reads what to do, and waits for a refusal the panel will
// never report.
func TestThePublishedReferenceListsNoRefusalTheCatalogueDoesNotHave(t *testing.T) {
	known := map[string]bool{}
	for _, guide := range ErrorGuides() {
		known[guide.Code] = true
	}
	for _, path := range publishedReferences() {
		page := readPublishedReference(t, path)
		listed := map[string]bool{}
		entry := regexp.MustCompile(`<code class="refusal">([a-z0-9_]+)</code>`)
		for _, match := range entry.FindAllStringSubmatch(page, -1) {
			listed[match[1]] = true
		}
		if len(listed) == 0 {
			t.Fatalf("%s: the page lists no refusal at all; the pattern no longer matches it",
				filepath.Base(path))
		}
		var stale []string
		for code := range listed {
			if !known[code] {
				stale = append(stale, code)
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s lists %d refusals the catalogue no longer has:\n  %s",
				pageName(path), len(stale), strings.Join(stale, "\n  "))
		}
	}
}

// entriesPerStage reads which codes the page files under each stage heading.
func entriesPerStage(t *testing.T, path, page string) map[string][]string {
	t.Helper()
	heading := regexp.MustCompile(`<h2 id="stage-([a-z]+)">`)
	bounds := heading.FindAllStringSubmatchIndex(page, -1)
	if len(bounds) == 0 {
		t.Fatalf("%s: the page has no stage section; the pattern no longer matches it",
			filepath.Base(path))
	}
	sections := map[string][]string{}
	for i, bound := range bounds {
		end := len(page)
		if i+1 < len(bounds) {
			end = bounds[i+1][0]
		}
		stage := page[bound[2]:bound[3]]
		for _, match := range stageSectionEntry.FindAllStringSubmatch(page[bound[1]:end], -1) {
			sections[stage] = append(sections[stage], match[1])
		}
	}
	return sections
}

// sortedStages keeps a failure report in an order that does not move between
// runs.
func sortedStages(sections map[string][]string) []string {
	stages := make([]string, 0, len(sections))
	for stage := range sections {
		stages = append(stages, stage)
	}
	sort.Strings(stages)
	return stages
}

// sortedKeys keeps a failure report in an order that does not move between
// runs.
func sortedKeys(counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
