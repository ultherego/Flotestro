package release

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The gate refuses every skip that does not say which kind of skip it is, so an
// unclassified t.Skip is a release that cannot be attested. Classifying the
// ones already in the tree is work; stopping new ones from arriving is a test.
// The allowlist is the set that existed when the contract landed, and it may
// only shrink: a skip that is not on it fails here, and an entry that no longer
// matches anything fails too, so the list cannot rot into a rubber stamp.
const skipAllowlist = "testdata/direct-skips.txt"

// The classification helpers are the one place a direct skip belongs. They are
// named the same in every package that has one.
var classificationHelpers = map[string]bool{
	"absent": true, "notApplicable": true, "waived": true,
}

// Where the Go code of this repository lives. The ratchet used to read two of
// these, which left cmd, db and tools free to grow skips nobody accounted for.
// TestTheRatchetLooksWhereverGoCodeLives keeps the list from falling behind the
// tree, because a guard narrowed until it passes is worth less than none.
var goDirectories = []string{"cmd", "db", "internal", "tests", "tools"}

// directSkip is one t.Skip/t.Skipf/t.SkipNow call as found in the tree.
type directSkip struct {
	file string // slash-separated, relative to the repository root
	line int
	call string // the call as written, collapsed onto one line
}

// key identifies a skip by what it says rather than by where it sits, so an
// unrelated edit above it does not invalidate the allowlist.
type skipKey struct {
	file string
	call string
}

func TestNoDirectSkipOutsideTheClassificationHelpers(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		absent(t, "the repository root is not at %s: %v", root, err)
	}

	found, err := findDirectSkips(root, goDirectories...)
	if err != nil {
		t.Fatalf("reading the tree: %v", err)
	}
	allowed, err := readSkipAllowlist(skipAllowlist)
	if err != nil {
		t.Fatalf("reading %s: %v", skipAllowlist, err)
	}

	for _, problem := range skipProblems(found, allowed) {
		t.Error(problem)
	}
	t.Logf("%d direct skips in the tree, %d allowed", len(found), total(allowed))
}

// skipProblems compares what the tree holds against what the allowlist permits,
// in both directions: a skip nobody allowed, and an entry with nothing left to
// allow. It is a function rather than the body of the test so that the test
// below can hand it a tree it built on purpose.
func skipProblems(found []directSkip, allowed map[skipKey]int) []string {
	byKey := map[skipKey][]directSkip{}
	for _, skip := range found {
		key := skipKey{file: skip.file, call: skip.call}
		byKey[key] = append(byKey[key], skip)
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
			"%s\nis a direct skip the gate cannot classify; %d of it are on %s and %d are in the tree: %s\n"+
				"say which kind of skip it is with absent(), notApplicable() or waived() instead",
			key.call, allowed[key], skipAllowlist, len(places), strings.Join(where, " ")))
	}

	for _, key := range sortedKeys(allowed) {
		if surplus := allowed[key] - len(byKey[key]); surplus > 0 {
			problems = append(problems, fmt.Sprintf(
				"%s allows %d of\n%s\nin %s, and %d are left: delete the stale line, "+
					"because an allowlist that outlives what it allows stops being a ratchet",
				skipAllowlist, allowed[key], key.call, key.file, len(byKey[key])))
		}
	}
	return problems
}

// And the ratchet has to be able to see a new skip arrive, or a green run over
// 233 allowed ones says nothing at all. Both directions are checked, because
// each on its own can be made to pass by narrowing the other.
func TestTheRatchetSeesASkipNobodyAllowed(t *testing.T) {
	root := t.TempDir()
	body := `package example

import "testing"

func TestSomething(t *testing.T) {
	t.Skip("the condition nobody classified")
}
`
	dir := filepath.Join(root, "internal", "example")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example_test.go"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	found, err := findDirectSkips(root, goDirectories...)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].file != "internal/example/example_test.go" || found[0].line != 6 {
		t.Fatalf("the walk did not find the one skip where it is: %+v", found)
	}

	problems := skipProblems(found, map[skipKey]int{})
	if len(problems) != 1 || !strings.Contains(problems[0], "internal/example/example_test.go:6") {
		t.Fatalf("an unallowed skip was not reported with its place: %v", problems)
	}

	// Allowed, it is silent; allowed twice over, the surplus entry is the
	// failure instead.
	key := skipKey{file: found[0].file, call: found[0].call}
	if problems := skipProblems(found, map[skipKey]int{key: 1}); len(problems) != 0 {
		t.Fatalf("an allowed skip was still reported: %v", problems)
	}
	if problems := skipProblems(found, map[skipKey]int{key: 2}); len(problems) != 1 {
		t.Fatalf("an entry allowing more than the tree holds was not reported: %v", problems)
	}
}

// The ratchet reads a list of directories, and a list is something the tree can
// grow out of: cmd, db and tools were outside it for a while, so a skip added
// there was allowed by nobody and seen by nothing.
func TestTheRatchetLooksWhereverGoCodeLives(t *testing.T) {
	root := filepath.Join("..", "..")
	scanned := map[string]bool{}
	for _, directory := range goDirectories {
		scanned[directory] = true
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		// Dot directories hold no product code, and .claude holds the
		// worktrees of other agents: walking those would read another
		// checkout's tree as if it were this one.
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || entry.Name() == "web" {
			continue
		}
		holdsGo := false
		err := filepath.WalkDir(filepath.Join(root, entry.Name()), func(path string, found os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !found.IsDir() && strings.HasSuffix(path, ".go") {
				holdsGo = true
				return filepath.SkipAll
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if holdsGo && !scanned[entry.Name()] {
			t.Errorf("%s/ holds Go files and goDirectories does not name it, "+
				"so a direct skip added there is checked by nothing", entry.Name())
		}
	}
}

func sortedKeys[V any](m map[skipKey]V) []skipKey {
	keys := make([]skipKey, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].file != keys[j].file {
			return keys[i].file < keys[j].file
		}
		return keys[i].call < keys[j].call
	})
	return keys
}

func total(counts map[skipKey]int) int {
	sum := 0
	for _, count := range counts {
		sum += count
	}
	return sum
}

// findDirectSkips parses every Go file under the given directories of root and
// returns the Skip calls made on a testing receiver.
func findDirectSkips(root string, directories ...string) ([]directSkip, error) {
	var found []directSkip
	for _, directory := range directories {
		// A directory that is not there holds no skips. Naming one that never
		// existed is caught from the other side instead: the allowlist then has
		// entries with nothing left to match, and that is a failure.
		if _, err := os.Stat(filepath.Join(root, directory)); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				switch entry.Name() {
				case "testdata", "node_modules", ".git":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			skips, err := directSkipsIn(path, filepath.ToSlash(relative))
			if err != nil {
				return err
			}
			found = append(found, skips...)
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

func directSkipsIn(path, name string) ([]directSkip, error) {
	fset := token.NewFileSet()
	// The build tags are not consulted on purpose: a skip behind //go:build
	// integration is exactly the kind the gate has to account for.
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}

	// Which names hold a testing receiver in this file: parameters, results,
	// struct fields and declared variables all arrive as ast.Field or
	// ast.ValueSpec, so one pass finds them all.
	receivers := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch declared := node.(type) {
		case *ast.Field:
			if isTestingType(declared.Type) {
				for _, name := range declared.Names {
					receivers[name.Name] = true
				}
			}
		case *ast.ValueSpec:
			if isTestingType(declared.Type) {
				for _, name := range declared.Names {
					receivers[name.Name] = true
				}
			}
		}
		return true
	})

	// The helpers themselves emit the one classified skip each, which is the
	// whole point of them.
	type span struct{ from, to token.Pos }
	var exempt []span
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Body != nil && classificationHelpers[function.Name.Name] {
			exempt = append(exempt, span{function.Pos(), function.End()})
		}
	}
	exempted := func(at token.Pos) bool {
		for _, one := range exempt {
			if at >= one.from && at < one.to {
				return true
			}
		}
		return false
	}

	var found []directSkip
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "Skip", "Skipf", "SkipNow":
		default:
			return true
		}
		if !isTestingReceiver(selector.X, receivers) || exempted(call.Pos()) {
			return true
		}
		var text bytes.Buffer
		if err := printer.Fprint(&text, fset, call); err != nil {
			return true
		}
		found = append(found, directSkip{
			file: name,
			line: fset.Position(call.Pos()).Line,
			call: strings.Join(strings.Fields(text.String()), " "),
		})
		return true
	})
	return found, nil
}

// isTestingReceiver decides whether the thing Skip was called on is a test
// handle. Without type information the answer comes from the declarations of
// the file plus the conventional names, which together cover t.Skip, h.t.Skip
// and a receiver named anything as long as it was declared with its type.
func isTestingReceiver(expr ast.Expr, receivers map[string]bool) bool {
	name := ""
	switch base := expr.(type) {
	case *ast.Ident:
		name = base.Name
	case *ast.SelectorExpr:
		name = base.Sel.Name
	default:
		return false
	}
	return receivers[name] || name == "t" || name == "b" || name == "tb"
}

func isTestingType(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || pkg.Name != "testing" {
		return false
	}
	switch selector.Sel.Name {
	case "T", "B", "TB":
		return true
	}
	return false
}

// readSkipAllowlist reads the checked-in list. Each line is
// "<file>:<line><tab><call>"; the line number is what it was when the entry was
// written and is informational, because the call text is what gets matched.
func readSkipAllowlist(path string) (map[skipKey]int, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	allowed := map[skipKey]int{}
	for number, line := range strings.Split(string(content), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		place, call, ok := strings.Cut(line, "\t")
		if !ok {
			return nil, &parseError{path: path, line: number + 1, text: line}
		}
		file := place
		if at := strings.LastIndex(place, ":"); at >= 0 {
			file = place[:at]
		}
		allowed[skipKey{file: file, call: call}]++
	}
	return allowed, nil
}

type parseError struct {
	path string
	line int
	text string
}

func (e *parseError) Error() string {
	return e.path + ":" + strconv.Itoa(e.line) + ": no tab between the place and the call: " + e.text
}
