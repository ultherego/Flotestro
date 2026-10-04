package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"testing"
)

// AllCapabilities is read by the release gate to decide whether a run accounted
// for every adapter. A constant added to the file and forgotten in the list
// would make that accounting silently narrower, which is the one thing the list
// exists to prevent.
func TestAllCapabilitiesNamesEveryCapabilityConstant(t *testing.T) {
	declared := capabilityConstantsOf(t, "capabilities.go")
	if len(declared) == 0 {
		t.Fatal("no Cap* constant was found in capabilities.go; the parser, not the file, is wrong")
	}
	for name, value := range declared {
		if !slices.Contains(AllCapabilities, value) {
			t.Errorf("%s = %q is declared and missing from AllCapabilities", name, value)
		}
	}
	for _, value := range AllCapabilities {
		if !slices.Contains(valuesOf(declared), value) {
			t.Errorf("AllCapabilities names %q, which no Cap* constant declares", value)
		}
	}
	for index := 1; index < len(AllCapabilities); index++ {
		if AllCapabilities[index] == AllCapabilities[index-1] {
			t.Errorf("AllCapabilities names %q twice", AllCapabilities[index])
		}
	}
}

// capabilityConstantsOf returns the Cap* constants of a file by name and value.
func capabilityConstantsOf(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	found := map[string]string{}
	for _, decl := range file.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range value.Names {
				if len(name.Name) < 4 || name.Name[:3] != "Cap" || index >= len(value.Values) {
					continue
				}
				literal, ok := value.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				text, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("the value of %s is not a string literal: %v", name.Name, err)
				}
				found[name.Name] = text
			}
		}
	}
	return found
}

func valuesOf(constants map[string]string) []string {
	values := make([]string, 0, len(constants))
	for _, value := range constants {
		values = append(values, value)
	}
	return values
}
