package release

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// A method whose body has no branch at all and ends by calling itself is an
// infinite loop, always, with no input that avoids it.
//
// internal/agent/backup.go carried one. callHelper was written as a wrapper -
// attach the receipts, then make the call - and the call it made was itself.
// Every task that reaches the helper through that wrapper took the agent down
// with a stack overflow: 9,586,610 frames in the journal of agent-ubuntu, no
// session reaching the panel, and the laboratory's relay step failing on a
// symptom four layers away from the cause. The compiler says nothing, go vet
// says nothing, and no unit test could substitute the helper because the field
// is a concrete type.
//
// The rule is deliberately narrow so that it cannot be wrong: real recursion
// has a base case, and a base case is a branch. A body with no if, for, switch,
// select or range in it has no base case to have.
func TestNoMethodCallsItselfWithNothingToStopIt(t *testing.T) {
	root := filepath.Join("..", "..")
	inspected := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case entry.IsDir():
			switch entry.Name() {
			case ".git", "node_modules", "genproto", "testdata", ".claude", "Vagrant", "web":
				return fs.SkipDir
			}
			return nil
		case !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go"):
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			// A file this walk cannot read is not a pass: say so.
			t.Errorf("%s: %v", path, err)
			return nil
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			inspected++
			if branches(function.Body) {
				continue
			}
			if at := selfCall(function); at != nil {
				t.Errorf("%s:%d: %s has no branch and calls itself; nothing stops it",
					path, fset.Position(*at).Line, function.Name.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if inspected == 0 {
		t.Fatal("no function was inspected, so this check read nothing")
	}
	t.Logf("%d function bodies inspected", inspected)
}

// branches says whether a body carries anything that could stop a recursion.
func branches(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		switch node.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt,
			*ast.TypeSwitchStmt, *ast.SelectStmt, *ast.FuncLit:
			found = true
			return false
		}
		return true
	})
	return found
}

// selfCall returns the position of a call to the function's own name on its own
// receiver, anywhere in the body.
func selfCall(function *ast.FuncDecl) *token.Pos {
	receiver := ""
	if function.Recv != nil && len(function.Recv.List) == 1 && len(function.Recv.List[0].Names) == 1 {
		receiver = function.Recv.List[0].Names[0].Name
	}
	var at *token.Pos
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch target := call.Fun.(type) {
		case *ast.Ident:
			// A plain function calling itself by name.
			if receiver == "" && target.Name == function.Name.Name {
				position := target.Pos()
				at = &position
			}
		case *ast.SelectorExpr:
			ident, isIdent := target.X.(*ast.Ident)
			if isIdent && receiver != "" && ident.Name == receiver &&
				target.Sel.Name == function.Name.Name {
				position := target.Sel.Pos()
				at = &position
			}
		}
		return true
	})
	return at
}
