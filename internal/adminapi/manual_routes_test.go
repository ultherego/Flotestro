package adminapi

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// manualRoute finds a route as the published manual writes one: a method and a
// path under /api/v1, inside a <code> element or in a block of shell.
var manualRoute = regexp.MustCompile(`\b(GET|POST|PUT|PATCH|DELETE)\s+(/api/v1/[A-Za-z0-9_{}./-]*)`)

// A manual that names a route the panel does not serve sends a reader to write
// code against nothing. This is not hypothetical: the laboratory's own webhook
// check ordered an operation with POST /api/v1/jobs for weeks, a route that has
// never existed - the panel answered 404 no_such_route, the check piped the
// answer into head and never looked, and the measurement passed on a backlog it
// had not caused. The manual was right where the script was wrong, and nothing
// compared either of them with the routes the server registers.
func TestEveryRouteTheManualNamesIsServed(t *testing.T) {
	server := &Server{}
	server.Routes()
	served := map[string]bool{}
	paths := map[string]bool{}
	for _, route := range server.contract {
		served[route.Method+" "+route.Path] = true
		paths[openAPIPath(route.Method+" "+route.Path)] = true
	}

	pages, err := filepath.Glob(filepath.Join("..", "..", "docs", "site", "docs", "*.html"))
	if err != nil {
		t.Fatal(err)
	}
	polish, err := filepath.Glob(filepath.Join("..", "..", "docs", "site", "pl", "docs", "*.html"))
	if err != nil {
		t.Fatal(err)
	}
	pages = append(pages, polish...)
	// Not a skip: a guard that finds nothing to check has to say so, or a
	// manual deleted from the tree would make this test green.
	if len(pages) == 0 {
		t.Fatal("no page of the published manual was found; this guard would pass over nothing")
	}

	// Asked of nothing, a check of this kind reports that all is well: the
	// count is part of the result.
	checked := 0
	unknown := map[string][]string{}
	for _, page := range pages {
		text, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		for _, found := range manualRoute.FindAllStringSubmatch(string(text), -1) {
			method, path := found[1], found[2]
			// A path written with a trailing dot or closing punctuation of the
			// prose around it.
			path = strings.TrimRight(path, "./")
			key := method + " " + path
			checked++
			if served[key] || paths[openAPIPath(key)] {
				continue
			}
			unknown[key] = append(unknown[key], filepath.Base(page))
		}
	}
	if checked == 0 {
		t.Fatal("no route was found in the manual at all; the shape the pages write them in has changed")
	}
	if len(unknown) == 0 {
		return
	}
	keys := make([]string, 0, len(unknown))
	for key := range unknown {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		t.Errorf("the manual names %q, which this panel does not serve (in %s)",
			key, strings.Join(unknown[key], ", "))
	}
	t.Logf("%d route mentions checked across %d pages", checked, len(pages))
}
