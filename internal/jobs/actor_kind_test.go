package jobs

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
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

// A call site that names the panel's own work as its author and calls it a
// person is a programming error: no account can ever answer for it, so the
// task waits or refuses forever. It is caught here, by reading the sources,
// and not at runtime - the runtime check that did this matched by prefix and
// refused every person whose account began with "system".
//
// Read from the syntax rather than by grep: a field of a jobs.Spec is a field
// of a jobs.Spec wherever it is written, and a name mentioned in a comment or
// a log line is not one.
func TestNoCallSitePairsTheOwnWorkOfThePanelWithAPerson(t *testing.T) {
	// The namespaces the panel writes for itself, as the code that builds them
	// does: "campaign:"+id, "directory-change:"+id, "flotestro/vuln",
	// "system". A name missing here only means this test asks about less; it
	// cannot refuse anything at runtime, because nothing reads it there.
	own := []string{"campaign:", "directory-change:", "flotestro/", "system"}

	sites := 0
	err := filepath.WalkDir("..", func(path string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case entry.IsDir() && (entry.Name() == "genproto" || entry.Name() == "testdata"):
			return fs.SkipDir
		case entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go"):
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok || !isJobSpec(literal.Type) {
				return true
			}
			author, kind := specAuthor(literal)
			if kind == "" {
				return true
			}
			// Counted here, where a spec declares a kind at all: that is what
			// says the walk reached the call sites. Most of them pass the
			// author in a variable, which this test cannot judge and does not
			// pretend to.
			sites++
			if kind != "ActorPerson" || author == "" {
				return true
			}
			for _, prefix := range own {
				if strings.HasPrefix(author, prefix) {
					t.Errorf("%s writes a task whose author is %q and whose kind is a person; "+
						"no account answers for that name, so the task can only wait or refuse",
						path, author)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A walk that inspected nothing would pass in silence.
	if sites == 0 {
		t.Fatal("no spec declaring an actor kind was found, so this test read nothing")
	}
	t.Logf("%d call site(s) declare an actor kind", sites)
}

// isJobSpec says whether a composite literal is a jobs.Spec, written from
// inside this package or from another.
func isJobSpec(node ast.Expr) bool {
	switch typed := node.(type) {
	case *ast.Ident:
		return typed.Name == "Spec"
	case *ast.SelectorExpr:
		return typed.Sel.Name == "Spec"
	}
	return false
}

// specAuthor reads the author and the kind out of a spec literal. The author
// is read only when it begins with a string: "campaign:" + campaign.Name is
// the shape that mattered, and a value computed elsewhere is not a name this
// test can judge.
func specAuthor(literal *ast.CompositeLit) (author, kind string) {
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := pair.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "CreatedBy":
			author = leadingString(pair.Value)
		case "CreatedByKind":
			if selector, ok := pair.Value.(*ast.SelectorExpr); ok {
				kind = selector.Sel.Name
			} else if ident, ok := pair.Value.(*ast.Ident); ok {
				kind = ident.Name
			}
		}
	}
	return author, kind
}

// leadingString returns the literal text an expression starts with, following
// the left side of a concatenation.
func leadingString(node ast.Expr) string {
	switch typed := node.(type) {
	case *ast.BasicLit:
		if typed.Kind == token.STRING {
			text, err := strconv.Unquote(typed.Value)
			if err == nil {
				return text
			}
		}
	case *ast.BinaryExpr:
		if typed.Op == token.ADD {
			return leadingString(typed.X)
		}
	}
	return ""
}
