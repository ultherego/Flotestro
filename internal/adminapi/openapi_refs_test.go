package adminapi

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// A $ref to a schema nobody defined is a document that reads as complete and
// is not: the generator writes "#/components/schemas/Thing", the component
// map has no Thing, and every tool that follows the reference gets nothing.
//
// Found on 11.10 by writing exactly that. Two new routes named their answers
// with ref("UnresolvedOperations") and ref("UnresolvedRuling") before either
// was registered, the whole suite stayed green, and the only thing that would
// have noticed was somebody reading the served document by hand.
func TestEveryReferenceInTheDocumentNamesASchemaThatExists(t *testing.T) {
	// Routes() first: the document's paths are built from the server's
	// contract, and a server that registered none has no paths to walk. The
	// first version of this guard read a document of components alone and
	// passed over two references nothing defined.
	server := &Server{}
	server.Routes()
	document := server.openAPI()

	components, _ := document["components"].(map[string]any)
	defined, _ := components["schemas"].(map[string]any)
	if len(defined) == 0 {
		t.Fatal("the document defines no schemas at all, so this guard is reading the wrong place")
	}

	// By reflection rather than by type switch. The first version of this
	// guard matched map[string]any and []any, and the document's paths are a
	// map[string]map[string]any - so it walked the components, found every
	// reference there satisfied, and passed. It was watched failing to see a
	// registration removed before this line was written: a guard that cannot
	// be shown failing is not a guard.
	dangling := map[string][]string{}
	var walk func(node reflect.Value, where string)
	walk = func(node reflect.Value, where string) {
		for node.Kind() == reflect.Interface || node.Kind() == reflect.Ptr {
			if node.IsNil() {
				return
			}
			node = node.Elem()
		}
		switch node.Kind() {
		case reflect.Map:
			for _, key := range node.MapKeys() {
				name := ""
				if key.Kind() == reflect.String {
					name = key.String()
				}
				value := node.MapIndex(key)
				if name == "$ref" {
					for value.Kind() == reflect.Interface {
						value = value.Elem()
					}
					if value.Kind() != reflect.String {
						continue
					}
					target := value.String()
					schema := strings.TrimPrefix(target, "#/components/schemas/")
					if schema == target {
						continue
					}
					if _, ok := defined[schema]; !ok {
						dangling[schema] = append(dangling[schema], where)
					}
					continue
				}
				walk(value, where+"."+name)
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < node.Len(); i++ {
				walk(node.Index(i), where+"[]")
			}
		}
	}
	walk(reflect.ValueOf(document), "")

	names := make([]string, 0, len(dangling))
	for name := range dangling {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Errorf("the document points at the schema %q, which nothing defines; "+
			"register it beside the others, or the served document is broken where it looks complete. Seen at: %s",
			name, strings.Join(dangling[name], ", "))
	}
}
