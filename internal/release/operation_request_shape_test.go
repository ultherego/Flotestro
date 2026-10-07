package release

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A scenario orders an operation by posting a map, and the panel decodes that
// map into createOperationRequest. Nothing connected the two: a key the struct
// does not carry is dropped by the decoder in silence, and the request goes out
// meaning something else.
//
// On 07.10 two scenarios wrote "action_type" - the name the *response* carries -
// where the request wants "action". The panel read an empty action and refused
// with unknown_action and the list of the ones it knows, which is exactly the
// right refusal; it just arrived the first time anybody ran those scenarios,
// a day after they were written.
//
// So the keys are checked against the product's own struct, read from its
// source. Nothing to keep in step by hand: a field renamed in the panel fails
// here until the scenarios follow it.
func TestAnOrderedOperationUsesTheFieldsThePanelDecodes(t *testing.T) {
	root := repositoryRoot(t)
	known, err := jsonFieldsOf(filepath.Join(root, "internal", "adminapi", "operations.go"),
		"createOperationRequest")
	if err != nil {
		t.Fatal(err)
	}
	if len(known) < 5 {
		t.Fatalf("createOperationRequest came back with %d fields, which cannot be right: %v",
			len(known), sorted(known))
	}

	entries, err := os.ReadDir(filepath.Join(root, "tests", "integration"))
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		path := filepath.Join(root, "tests", "integration", name)
		file, err := parser.ParseFile(set, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
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
			case "runOperation", "createOperation":
			default:
				return true
			}
			for _, argument := range call.Args {
				literal, ok := argument.(*ast.CompositeLit)
				if !ok || !isStringAnyMap(literal.Type) {
					continue
				}
				inspected++
				for _, element := range literal.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := pair.Key.(*ast.BasicLit)
					if !ok || key.Kind != token.STRING {
						continue
					}
					field, err := strconv.Unquote(key.Value)
					if err != nil || known[field] {
						continue
					}
					t.Errorf("%s:%d orders an operation with the field %q, which "+
						"createOperationRequest does not carry; the decoder drops it in silence. "+
						"The fields it carries: %s",
						name, set.Position(key.Pos()).Line, field, strings.Join(sorted(known), ", "))
				}
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no ordered operation was found in the suite, so this guard checked nothing")
	}
	t.Logf("%d ordered operations were read against %d fields of createOperationRequest",
		inspected, len(known))
}

func isStringAnyMap(expression ast.Expr) bool {
	mapType, ok := expression.(*ast.MapType)
	if !ok {
		return false
	}
	key, ok := mapType.Key.(*ast.Ident)
	if !ok || key.Name != "string" {
		return false
	}
	switch value := mapType.Value.(type) {
	case *ast.Ident:
		return value.Name == "any"
	case *ast.InterfaceType:
		return len(value.Methods.List) == 0
	}
	return false
}

// jsonFieldsOf reads the json names a struct carries, out of the source rather
// than out of a copy somebody keeps up to date.
func jsonFieldsOf(path, name string) (map[string]bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(path), nil, 0)
	if err != nil {
		return nil, err
	}
	fields := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok || spec.Name.Name != name {
			return true
		}
		structure, ok := spec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, field := range structure.Fields.List {
			if field.Tag == nil {
				continue
			}
			tag, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				continue
			}
			value := reflect.StructTag(tag).Get("json")
			if value == "" || value == "-" {
				continue
			}
			fields[strings.Split(value, ",")[0]] = true
		}
		return false
	})
	return fields, nil
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
