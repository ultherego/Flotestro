package release

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A green gate says how many tests ran and that none failed. It cannot say
// which tests there were meant to be, so a test deleted from the tree reads
// exactly like a test that passed - and that is the hole the capability
// manifest was asked to close and does not: the manifest names the adapters a
// host offered, not the scenarios anybody wrote against them.
//
// This is the cheap half of that, and it is the half that was actually costing
// us. The inventory is every test function in the tree, by file and name. A
// test that disappears from the tree while its line stays here fails, so a
// deletion has to be made deliberately, in the same commit, where a reviewer
// sees it in the diff. A test that arrives and is not here fails too, so the
// inventory cannot go stale and quietly stop protecting the tests added since.
//
//	go test ./internal/release/ -run TestTheTestInventoryIsTheTree
//	UPDATE_TEST_INVENTORY=1 go test ./internal/release/ -run TestTheTestInventoryIsTheTree
//
// The second form rewrites the file. It is the only way to change it, which is
// the point: the diff is the record.
const testInventory = "testdata/test-inventory.txt"

// TestTheTestInventoryIsTheTree compares the inventory with the tree in both
// directions. One direction alone can be made to pass by narrowing the other.
func TestTheTestInventoryIsTheTree(t *testing.T) {
	found, err := testFunctions(repositoryRoot(t), goDirectories)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("no test function was found in the tree, so this guard checked nothing")
	}

	if os.Getenv("UPDATE_TEST_INVENTORY") != "" {
		if err := os.WriteFile(testInventory,
			[]byte(strings.Join(found, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s rewritten with %d tests; the diff is the record", testInventory, len(found))
		return
	}

	recorded, err := readInventory(testInventory)
	if err != nil {
		t.Fatalf("reading %s: %v", testInventory, err)
	}
	for _, problem := range inventoryProblems(found, recorded) {
		t.Error(problem)
	}
	t.Logf("%d test functions in the tree, %d recorded", len(found), len(recorded))
}

// inventoryProblems is a function of its two inputs so that the test below can
// hand it a tree it built on purpose.
func inventoryProblems(found, recorded []string) []string {
	have := map[string]bool{}
	for _, entry := range found {
		have[entry] = true
	}
	known := map[string]bool{}
	for _, entry := range recorded {
		known[entry] = true
	}
	var problems []string
	for _, entry := range recorded {
		if !have[entry] {
			problems = append(problems, fmt.Sprintf(
				"%s is in %s and not in the tree: a test was removed or renamed. If that was "+
					"meant, rewrite the inventory in the same commit (UPDATE_TEST_INVENTORY=1), "+
					"so the deletion is in the diff and not in the silence",
				entry, testInventory))
		}
	}
	for _, entry := range found {
		if !known[entry] {
			problems = append(problems, fmt.Sprintf(
				"%s is in the tree and not in %s: rewrite the inventory, or the tests added "+
					"since stop being protected by it",
				entry, testInventory))
		}
	}
	return problems
}

// testFunctions names every test function in the tree, as "<file>:<name>",
// sorted. The file is part of the name because a test that moves between
// packages is a change worth seeing.
func testFunctions(root string, directories []string) ([]string, error) {
	var found []string
	set := token.NewFileSet()
	for _, directory := range directories {
		base := filepath.Join(root, directory)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				// Vendored or scratch trees are not this repository's tests.
				if name := entry.Name(); name == "vendor" || name == "node_modules" ||
					name == "testdata" || strings.HasPrefix(name, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(set, path, nil, 0)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Recv != nil {
					continue
				}
				name := function.Name.Name
				if !strings.HasPrefix(name, "Test") && !strings.HasPrefix(name, "Fuzz") &&
					!strings.HasPrefix(name, "Benchmark") {
					continue
				}
				found = append(found, filepath.ToSlash(relative)+":"+name)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(found)
	return found, nil
}

func readInventory(path string) ([]string, error) {
	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var entries []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	sort.Strings(entries)
	return entries, nil
}

// And the ratchet has to be able to see a test disappear, or a green run over
// a thousand recorded ones says nothing at all. Both directions, because each
// on its own can be made to pass by narrowing the other.
func TestTheInventoryRatchetSeesATestComeAndGo(t *testing.T) {
	gone := inventoryProblems(
		[]string{"internal/x/a_test.go:TestOne"},
		[]string{"internal/x/a_test.go:TestOne", "internal/x/a_test.go:TestTwo"})
	if len(gone) != 1 || !strings.Contains(gone[0], "TestTwo") {
		t.Errorf("a test removed from the tree was not named: %v", gone)
	}
	arrived := inventoryProblems(
		[]string{"internal/x/a_test.go:TestOne", "internal/x/a_test.go:TestTwo"},
		[]string{"internal/x/a_test.go:TestOne"})
	if len(arrived) != 1 || !strings.Contains(arrived[0], "TestTwo") {
		t.Errorf("a test the inventory does not know was not named: %v", arrived)
	}
	if problems := inventoryProblems(
		[]string{"internal/x/a_test.go:TestOne"},
		[]string{"internal/x/a_test.go:TestOne"}); len(problems) != 0 {
		t.Errorf("a tree that matches its inventory was reported: %v", problems)
	}
}
