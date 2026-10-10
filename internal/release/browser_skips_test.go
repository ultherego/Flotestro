package release

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The skip contract holds for both suites: the gate reads a Playwright
// annotation the same way it reads a Go skip, and one without a class is a
// fatal run either way. The Go side has had a ratchet since the contract
// landed, and it names the directories it walks - web was not one of them,
// so every test.skip in the browser suite was accounted for by nothing. This
// is the same ratchet for the other suite: a classified skip carries the
// sentinel, an unclassified one has to be on the list, and the list may only
// shrink.
const browserSkipAllowlist = "testdata/browser-skips.txt"

// Where the browser suite lives. web/src holds the component tests, which
// never skip at runtime; the acceptance specs are what the gate attests.
var browserDirectories = []string{"web/e2e"}

func TestNoUnclassifiedSkipInTheBrowserSuite(t *testing.T) {
	root := filepath.Join("..", "..")
	found, err := findBrowserSkips(root, browserDirectories...)
	if err != nil {
		t.Fatalf("reading the browser suite: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("the walk found no test.skip at all in the browser suite, " +
			"which means it is looking in the wrong place")
	}
	allowed, err := readSkipAllowlist(browserSkipAllowlist)
	if err != nil {
		t.Fatalf("reading %s: %v", browserSkipAllowlist, err)
	}

	for _, problem := range browserSkipProblems(found, allowed) {
		t.Error(problem)
	}
	for _, skip := range found {
		t.Logf("%s:%d\t%s", skip.file, skip.line, skip.call)
	}
	t.Logf("%d unclassified skips in the browser suite, %d allowed", len(found), total(allowed))
}

// browserSkipProblems is the Go ratchet's comparison, worded for the other
// suite: a skip nobody allowed, and an entry with nothing left to allow.
func browserSkipProblems(found []directSkip, allowed map[skipKey]int) []string {
	byKey := map[skipKey][]directSkip{}
	for _, skip := range found {
		byKey[skipKey{file: skip.file, call: skip.call}] = append(
			byKey[skipKey{file: skip.file, call: skip.call}], skip)
	}

	var problems []string
	for _, key := range sortedKeys(byKey) {
		places := byKey[key]
		if len(places) <= allowed[key] {
			continue
		}
		where := make([]string, 0, len(places))
		for _, place := range places {
			where = append(where, place.file+":"+strconv.Itoa(place.line))
		}
		problems = append(problems, fmt.Sprintf(
			"%s\nis a skip the gate cannot classify; %d of it are on %s and %d are in the tree: %s\n"+
				"put the sentinel in the reason instead: "+
				`FLOTESTRO-SKIP class=absent reason="..."`,
			key.call, allowed[key], browserSkipAllowlist, len(places), strings.Join(where, " ")))
	}

	for _, key := range sortedKeys(allowed) {
		if surplus := allowed[key] - len(byKey[key]); surplus > 0 {
			problems = append(problems, fmt.Sprintf(
				"%s allows %d of\n%s\nin %s, and %d are left: delete the stale line, "+
					"because an allowlist that outlives what it allows stops being a ratchet",
				browserSkipAllowlist, allowed[key], key.call, key.file, len(byKey[key])))
		}
	}
	return problems
}

// And the ratchet has to be able to see one arrive, in both directions: a
// classified skip is invisible to it, an unclassified one is not, and a
// surplus entry is a failure of its own.
func TestTheBrowserRatchetSeesASkipNobodyAllowed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "web", "e2e")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `import { test } from "@playwright/test";

test("one", async () => {
  test.skip(true, "the condition nobody classified");
});

test("two", async () => {
  test.skip(
    true,
    'FLOTESTRO-SKIP class=absent reason="said out loud"',
  );
});

// A reason that merely mentions a paren ")" does not end the call early.
test("three", async () => {
  test.skip(await thing(), "a reason with a ) in it");
});
`
	if err := os.WriteFile(filepath.Join(dir, "example.spec.ts"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	found, err := findBrowserSkips(root, browserDirectories...)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("the walk did not find the two unclassified skips and leave the classified one: %+v", found)
	}
	if found[0].line != 4 || found[1].line != 16 {
		t.Fatalf("the skips were not found where they are: %+v", found)
	}
	if !strings.Contains(found[1].call, "a reason with a ) in it") {
		t.Fatalf("a paren inside the reason cut the call short: %q", found[1].call)
	}

	problems := browserSkipProblems(found, map[skipKey]int{})
	if len(problems) != 2 {
		t.Fatalf("the unallowed skips were not both reported: %v", problems)
	}

	allowed := map[skipKey]int{}
	for _, skip := range found {
		allowed[skipKey{file: skip.file, call: skip.call}]++
	}
	if problems := browserSkipProblems(found, allowed); len(problems) != 0 {
		t.Fatalf("allowed skips were still reported: %v", problems)
	}
	for key := range allowed {
		allowed[key]++
	}
	if problems := browserSkipProblems(found, allowed); len(problems) != 2 {
		t.Fatalf("entries allowing more than the tree holds were not reported: %v", problems)
	}
}

// The directory list is something the suite can grow out of, exactly as the Go
// one did: a spec file outside web/e2e would be read by nothing.
func TestTheBrowserRatchetLooksWhereverTheSuiteLives(t *testing.T) {
	root := filepath.Join("..", "..")
	scanned := map[string]bool{}
	for _, directory := range browserDirectories {
		scanned[filepath.ToSlash(directory)] = true
	}

	var missed []string
	err := filepath.WalkDir(filepath.Join(root, "web"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "node_modules", "dist", "test-results", "playwright-report":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".spec.ts") && !strings.HasSuffix(path, ".spec.tsx") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		directory := filepath.ToSlash(filepath.Dir(relative))
		for walked := range scanned {
			if directory == walked || strings.HasPrefix(directory, walked+"/") {
				return nil
			}
		}
		missed = append(missed, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(missed)
	for _, file := range missed {
		t.Errorf("%s is a browser spec outside %v, so a skip added there is checked by nothing",
			file, browserDirectories)
	}
}

// findBrowserSkips returns every test.skip call in the given directories whose
// reason does not carry the gate's sentinel. The call text is collapsed onto
// one line, so the allowlist matches on what the skip says rather than on
// where it sits.
func findBrowserSkips(root string, directories ...string) ([]directSkip, error) {
	var found []directSkip
	for _, directory := range directories {
		base := filepath.Join(root, filepath.FromSlash(directory))
		if _, err := os.Stat(base); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".ts") && !strings.HasSuffix(path, ".tsx") {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			found = append(found, browserSkipsIn(string(content), filepath.ToSlash(relative))...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].file != found[j].file {
			return found[i].file < found[j].file
		}
		return found[i].line < found[j].line
	})
	return found, nil
}

const browserSkipCall = "test.skip("

func browserSkipsIn(content, name string) []directSkip {
	var found []directSkip
	for at := 0; ; {
		next := strings.Index(content[at:], browserSkipCall)
		if next < 0 {
			break
		}
		start := at + next
		open := start + len(browserSkipCall) - 1
		end := closingParen(content, open)
		at = open + 1
		if end < 0 {
			continue
		}
		at = end + 1
		call := strings.Join(strings.Fields(content[start:end+1]), " ")
		if strings.Contains(call, skipSentinel) {
			continue
		}
		found = append(found, directSkip{
			file: name,
			line: strings.Count(content[:start], "\n") + 1,
			call: call,
		})
	}
	return found
}

// closingParen finds the paren that closes the one at open, reading quotes and
// template literals as text: a reason is allowed to contain a paren, and a
// scanner that counted it would cut the call in half and match nothing.
func closingParen(content string, open int) int {
	depth := 0
	for i := open; i < len(content); i++ {
		switch c := content[i]; c {
		case '\\':
			i++
		case '\'', '"', '`':
			i = endOfString(content, i, c)
			if i < 0 {
				return -1
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// endOfString returns the index of the quote that closes the one at start. A
// template literal may hold ${...} with quotes of its own, so the expression
// is skipped as a nested run rather than scanned as text.
func endOfString(content string, start int, quote byte) int {
	for i := start + 1; i < len(content); i++ {
		switch c := content[i]; {
		case c == '\\':
			i++
		case quote == '`' && c == '$' && i+1 < len(content) && content[i+1] == '{':
			end := closingBrace(content, i+1)
			if end < 0 {
				return -1
			}
			i = end
		case c == quote:
			return i
		}
	}
	return -1
}

func closingBrace(content string, open int) int {
	depth := 0
	for i := open; i < len(content); i++ {
		switch c := content[i]; c {
		case '\\':
			i++
		case '\'', '"', '`':
			i = endOfString(content, i, c)
			if i < 0 {
				return -1
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
