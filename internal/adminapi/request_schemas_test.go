package adminapi

import (
	"net/http"
	"strings"
	"testing"
)

// TestEverySchemaNamesARoute guards the one way a described body goes unnoticed:
// the table is looked up by the registered pattern, and a key spelled any other
// way - {key} for a route registered as {key...} - matches nothing, applies
// nothing and says nothing.
func TestEverySchemaNamesARoute(t *testing.T) {
	server := &Server{}
	server.Routes()
	registered := map[string]string{}
	for _, route := range server.contract {
		registered[route.Method+" "+route.Path] = route.Handler
	}
	for key := range requestSchemas {
		if _, ok := registered[key]; ok {
			continue
		}
		hint := ""
		for candidate := range registered {
			if openAPIPath(candidate) == openAPIPath(key) {
				hint = "; the route is registered as " + candidate
				break
			}
		}
		t.Errorf("requestSchemas describes %q, which no route answers%s", key, hint)
	}
	// A body is described for a route that takes one. A GET with a described
	// body is a schema nothing will ever read.
	for key := range requestSchemas {
		method, _, _ := strings.Cut(key, " ")
		if method != http.MethodPost && method != http.MethodPut {
			t.Errorf("requestSchemas describes the body of %q, and only POST and PUT carry one", key)
		}
	}
}
