package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The store is asked for a secret in one place, and that place keeps the
// receipt.
//
// The helper refuses bytes of a secret that no receipt vouches for, and the
// receipt arrives beside the value: e.secrets returns (value, receipt, err).
// A consumer that wrote `value, _, err := e.secrets(...)` threw the receipt
// away, nothing was remembered for the task, callHelper had nothing to attach,
// and the helper refused with "the private key comes from the secret ... and
// the request carries no receipt for its bytes". Two consumers did that - the
// certificate's private key and a package repository's password - and the gate
// of 06.10 reported four failures for it.
//
// It was invisible for days because callHelper called itself: the agent died on
// the stack before any binding was reached, so the refusal had nothing to
// refuse. Fixing the recursion made these four appear, which is the whole
// reason a suite runs against a real fleet.
func TestOnlyTheReceiptKeepingFetchAsksTheSecretStore(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	// The one function that may ask the store, because it is the one that
	// remembers what came back.
	const keeper = "fetchSecretWithReceipt"
	asked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			receiver := ""
			if function.Recv != nil && len(function.Recv.List) == 1 && len(function.Recv.List[0].Names) == 1 {
				receiver = function.Recv.List[0].Names[0].Name
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "secrets" {
					return true
				}
				ident, ok := selector.X.(*ast.Ident)
				if !ok || receiver == "" || ident.Name != receiver {
					return true
				}
				asked++
				if function.Name.Name != keeper {
					t.Errorf("%s:%d: %s asks the secret store directly; only %s may, because only "+
						"it keeps the receipt the helper needs",
						name, fset.Position(selector.Sel.Pos()).Line, function.Name.Name, keeper)
				}
				return true
			})
		}
	}
	// A guard that found no call site would pass over a package that had
	// stopped asking the store at all, which is not the same as asking it
	// correctly.
	if asked == 0 {
		t.Fatalf("nothing in this package asks the secret store, so this test read nothing; "+
			"%s is the only place that may", keeper)
	}
	t.Logf("%d call site(s) ask the store, all inside %s", asked, keeper)
}

// And the nil check belongs to that one place too: a consumer that tested
// e.secrets for nil itself was a consumer that had the store in its hands.
func TestTheStoreIsCheckedWhereItIsAsked(t *testing.T) {
	keeper, err := os.ReadFile("backup.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keeper), "if e.secrets == nil {") {
		t.Error("fetchSecretWithReceipt no longer refuses a missing store; a consumer would " +
			"then call a nil function instead of being told why")
	}
	for _, name := range []string{"certificates.go", "repositories.go", "files.go"} {
		source, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), "e.secrets == nil") {
			t.Errorf("%s checks the secret store itself, which means it holds it", name)
		}
	}
}
