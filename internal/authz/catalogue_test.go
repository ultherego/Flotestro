package authz

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// The catalogue of permissions is written out by hand, so it can go stale -
// and a permission missing from it is not a cosmetic gap: a role of the
// installation's own may hold only what the catalogue knows, so a permission
// that fell out of it cannot be granted by any role anybody defines here, and
// nothing anywhere would say why.
//
// The constants are the truth, this file is the comparison, and it runs in
// both directions: a constant missing from the list fails, and a list entry
// with no constant behind it fails too.
func TestEveryPermissionConstantIsInTheCatalogue(t *testing.T) {
	declared := permissionConstants(t)
	if len(declared) < 100 {
		t.Fatalf("only %d permission constants were parsed out of model.go; this check read the wrong thing", len(declared))
	}

	listed := map[Permission]bool{}
	for _, permission := range allPermissions {
		if listed[permission] {
			t.Errorf("%q is in the catalogue twice", permission)
		}
		listed[permission] = true
	}
	for _, permission := range declared {
		if !listed[permission] {
			t.Errorf("the constant for %q is declared and not in allPermissions, so no role of an installation's own can carry it", permission)
		}
	}
	known := map[Permission]bool{}
	for _, permission := range declared {
		known[permission] = true
	}
	for _, permission := range allPermissions {
		if !known[permission] {
			t.Errorf("the catalogue carries %q, which no constant declares", permission)
		}
	}

	// And the two helpers that read it answer for the same set.
	if got := len(AllPermissions()); got != len(declared) {
		t.Errorf("AllPermissions() returned %d of %d permissions", got, len(declared))
	}
	if KnownPermission("host.read.not.a.permission") {
		t.Error("KnownPermission accepted a name no constant declares")
	}
	if !KnownPermission(PermHostRead) {
		t.Error("KnownPermission refused a permission the product defines")
	}
	sorted := AllPermissions()
	if !sort.SliceIsSorted(sorted, func(i, j int) bool { return sorted[i] < sorted[j] }) {
		t.Error("AllPermissions() is not sorted, and a screen that lists it would order permissions by nothing")
	}
}

// permissionConstants reads every `Perm… Permission = "…"` out of the model.
func permissionConstants(t *testing.T) []Permission {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "model.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found []Permission
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		var currentType string
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if name, ok := value.Type.(*ast.Ident); ok {
				currentType = name.Name
			}
			if currentType != "Permission" {
				continue
			}
			for _, expression := range value.Values {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				found = append(found, Permission(literal.Value[1:len(literal.Value)-1]))
			}
		}
	}
	return found
}

// A built-in role's permissions are compiled in, and the database must never
// be a second answer about one. The distinction the whole feature rests on is
// this one, so it is pinned here rather than left to the store.
func TestABindingToARoleTheInstallationDefinedGrantsOnlyWhatWasReadWithIt(t *testing.T) {
	// A built-in role answers from the code, whatever the binding carries.
	builtIn := Binding{Role: RoleViewer, Scope: GlobalScope}
	if !builtIn.Grants(PermHostRead) {
		t.Error("a viewer binding does not grant host.read")
	}
	if builtIn.Grants(PermSystemReboot) {
		t.Error("a viewer binding grants system.reboot")
	}
	// A row in the database cannot widen a built-in role: the binding's own
	// list is not even consulted for one.
	widened := Binding{Role: RoleViewer, Scope: GlobalScope, Granted: []Permission{PermSystemReboot}}
	if widened.Grants(PermSystemReboot) {
		t.Error("a list read from the database widened a built-in role")
	}

	// A role of the installation's own answers from what was read with it.
	own := Binding{Role: Role("shift_lead"), Scope: GlobalScope,
		Granted: []Permission{PermHostRead, PermUnitRestart}}
	if !own.Grants(PermUnitRestart) {
		t.Error("a role of the installation's own does not grant what it was defined with")
	}
	if own.Grants(PermSystemReboot) {
		t.Error("a role of the installation's own grants what it was not defined with")
	}

	// The case that has to fail closed: a binding to a role of the
	// installation's own whose permissions were never read. It grants
	// nothing. The opposite - treating "not read" as "not restricted" - is
	// the shape of defect this whole split exists to make impossible.
	unread := Binding{Role: Role("shift_lead"), Scope: GlobalScope}
	for _, permission := range []Permission{PermHostRead, PermUnitRestart, PermSystemReboot} {
		if unread.Grants(permission) {
			t.Errorf("a binding whose role was never read granted %s", permission)
		}
	}
	if len(unread.Permissions()) != 0 {
		t.Errorf("a binding whose role was never read lists %v", unread.Permissions())
	}

	// And the principal built on it can do nothing at all, which is the form
	// the rest of the product asks the question in.
	nobody := Principal{Bindings: []Binding{unread}}
	if nobody.CanAnywhere(PermHostRead) || len(nobody.Permissions()) != 0 {
		t.Errorf("an identity holding only an unread role could act: %v", nobody.Permissions())
	}
}
