package helpercap

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoOrderDigestCanBeReadAsItsOwnStructure asks every order bound by a
// digest the question HP-02 asked of the backup order: can content be written
// so that it reads as the structure around it? A list joined by a separator
// answers yes - Packages=["nginx\x1fbackdoor"] hashed to the same bytes as
// Packages=["nginx","backdoor"], so a consent to install one package was a
// consent to install two. The backup order was given a length-prefixed form on
// 05.10 and its neighbour, which shares the defect, was not asked.
func TestNoOrderDigestCanBeReadAsItsOwnStructure(t *testing.T) {
	cases := []struct {
		name  string
		one   func() string
		other func() string
	}{
		{
			name:  "packages, a separator inside one name",
			one:   packageOrder{Operation: "install", Packages: []string{"nginx\x1fbackdoor"}}.digest,
			other: packageOrder{Operation: "install", Packages: []string{"nginx", "backdoor"}}.digest,
		},
		{
			name:  "packages, the removals borrowed from the names",
			one:   packageOrder{Operation: "install", Packages: []string{"nginx", "sudo"}}.digest,
			other: packageOrder{Operation: "install", Packages: []string{"nginx"}, ExpectedRemovals: []string{"sudo"}}.digest,
		},
		{
			name: "a plan change, a separator inside the name",
			one: packageOrder{Operation: "upgrade",
				Changes: [][]string{{"nginx\x1f1.0", "", "", "", "", ""}}}.digest,
			other: packageOrder{Operation: "upgrade",
				Changes: [][]string{{"nginx", "1.0", "", "", "", ""}}}.digest,
		},
		{
			name: "a plan, two changes against one that carries both",
			one: packageOrder{Operation: "upgrade",
				Changes: [][]string{{"a", "", "", "", "", ""}, {"b", "", "", "", "", ""}}}.digest,
			other: packageOrder{Operation: "upgrade",
				Changes: [][]string{{"a", "", "", "", "", "", "b", "", "", "", "", ""}}}.digest,
		},
		{
			name:  "a repository, a separator inside one suite",
			one:   repositoryOrder{ID: "r", Suites: []string{"stable\x1funstable"}}.digest,
			other: repositoryOrder{ID: "r", Suites: []string{"stable", "unstable"}}.digest,
		},
		{
			name:  "a repository, the components borrowed from the suites",
			one:   repositoryOrder{ID: "r", Suites: []string{"stable", "main"}}.digest,
			other: repositoryOrder{ID: "r", Suites: []string{"stable"}, Components: []string{"main"}}.digest,
		},
		{
			name:  "a backup, a separator inside one path of a restore",
			one:   backupOrder{ID: "b", Include: []string{"/safe\x1f/extra"}}.digest,
			other: backupOrder{ID: "b", Include: []string{"/safe", "/extra"}}.digest,
		},
	}
	for _, each := range cases {
		if each.one() == each.other() {
			t.Errorf("%s: two different orders share one digest", each.name)
		}
	}

	// And one order's digest is not another's, so a consent cannot be moved
	// between families.
	empty := map[string]string{
		"package":    packageOrder{}.digest(),
		"repository": repositoryOrder{}.digest(),
		"backup":     backupOrder{}.digest(),
	}
	seen := map[string]string{}
	for family, digest := range empty {
		if other, clash := seen[digest]; clash {
			t.Errorf("an empty %s order and an empty %s order share one digest", family, other)
		}
		seen[digest] = family
	}
}

// TestNoOrderDigestJoinsAListWithASeparator is the guard for the next order
// that gets a digest: the shape that caused HP-02 does not come back. It reads
// the bodies that compute an order digest and the bodies that fill one, which
// is where the joining actually was - the plan changes were six fields glued
// together on their way into the order, not in digest() itself. A scan that
// found no such body is a failure rather than a pass.
func TestNoOrderDigestJoinsAListWithASeparator(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	bodies := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(set, filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			named := function.Name.Name
			if named != "digest" && !strings.HasSuffix(named, "OrderDigest") &&
				!strings.HasSuffix(named, "RequestDigest") {
				continue
			}
			bodies++
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "Join" {
					return true
				}
				if packageName, ok := selector.X.(*ast.Ident); ok && packageName.Name == "strings" {
					t.Errorf("%s: %s joins a list on its way into a digest", name, named)
				}
				return true
			})
		}
	}
	if bodies == 0 {
		t.Fatal("no body computing or filling an order digest was found, so nothing was checked")
	}
	t.Logf("%d bodies computing or filling an order digest were read", bodies)
}
