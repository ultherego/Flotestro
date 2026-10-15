package release

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The published API chapter is a hand-written table of every route, in two
// languages, with a count per section and a total in its first paragraph.
// Nothing compared it with the code.
//
// By 15.10 eight routes had been added without a row - the fleet readiness,
// the local access arrears, the arrangement of a screen in both directions,
// the three of the unresolved operations and the directory link of an
// identity - and the stated total was five behind. That is the documentation
// failing in the way that costs most: not missing, but present and wrong, so
// a reader concludes the panel cannot do something it does.
//
// The routes are read out of the registrations rather than from a list kept
// here, so a route added tomorrow fails this test until it is written down.
func TestEveryRouteIsInThePublishedTable(t *testing.T) {
	root := repositoryRoot(t)
	registered := registeredRoutes(t, root)
	if len(registered) < 200 {
		t.Fatalf("only %d routes were read out of internal/adminapi; this check read the wrong thing", len(registered))
	}

	for _, page := range []string{
		filepath.Join("docs", "site", "docs", "api.html"),
		filepath.Join("docs", "site", "pl", "docs", "api.html"),
	} {
		t.Run(page, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, page))
			if err != nil {
				t.Fatal(err)
			}
			documented := documentedRoutes(string(body))
			for route := range registered {
				if !documented[route] {
					t.Errorf("%s is registered and has no row: a reader of this page concludes the panel cannot do it", route)
				}
			}
			for route := range documented {
				if !registered[route] {
					t.Errorf("%s has a row and is not registered: the page promises a route that answers 404", route)
				}
			}

			// The numbers the page states about itself. A count beside a
			// section heading is read instead of counting the rows, so a
			// stale one is worse than none.
			for section, stated := range statedCounts(string(body)) {
				if rows := rowsInSection(string(body), section); rows != stated {
					t.Errorf("the table says %s has %d routes and the section has %d rows", section, stated, rows)
				}
			}
			if total, stated, ok := statedTotal(string(body)); ok && total != stated {
				t.Errorf("the page says %d routes under /api/v1 and the rows name %d", stated, total)
			}
		})
	}
}

var routeRegistration = regexp.MustCompile(`s\.route\(mux, "([A-Z]+) (/api/v1[^"]*)"`)

func registeredRoutes(t *testing.T, root string) map[string]bool {
	t.Helper()
	routes := map[string]bool{}
	directory := filepath.Join(root, "internal", "adminapi")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, found := range routeRegistration.FindAllStringSubmatch(string(body), -1) {
			routes[found[1]+" "+found[2]] = true
		}
	}
	return routes
}

var (
	documentedRow  = regexp.MustCompile(`method-[a-z]+">([A-Z]+)</span></td><td><code>(/api/v1[^<]*)</code>`)
	anyRow         = regexp.MustCompile(`method-[a-z]+">[A-Z]+</span>`)
	sectionHeading = regexp.MustCompile(`<h3 id="(routes-[a-z]+)">`)
	statedCount    = regexp.MustCompile(`<a href="#(routes-[a-z]+)">[^<]*</a></td><td>(\d+)</td>`)
	statedRoutes   = regexp.MustCompile(`(\d+) (?:routes|tras) (?:under|pod)`)
)

func documentedRoutes(page string) map[string]bool {
	routes := map[string]bool{}
	for _, found := range documentedRow.FindAllStringSubmatch(page, -1) {
		routes[found[1]+" "+html.UnescapeString(found[2])] = true
	}
	return routes
}

func statedCounts(page string) map[string]int {
	counts := map[string]int{}
	for _, found := range statedCount.FindAllStringSubmatch(page, -1) {
		counts[found[1]] = atoi(found[2])
	}
	return counts
}

// rowsInSection counts every row of one section, the few that are not under
// /api/v1 included: the number beside the heading counts rows, not paths.
func rowsInSection(page, section string) int {
	parts := sectionHeading.Split(page, -1)
	names := sectionHeading.FindAllStringSubmatch(page, -1)
	for i, name := range names {
		if name[1] == section {
			return len(anyRow.FindAllString(parts[i+1], -1))
		}
	}
	return -1
}

func statedTotal(page string) (actual, stated int, ok bool) {
	found := statedRoutes.FindStringSubmatch(page)
	if found == nil {
		return 0, 0, false
	}
	return len(documentedRoutes(page)), atoi(found[1]), true
}

func atoi(value string) int {
	number := 0
	if _, err := fmt.Sscanf(value, "%d", &number); err != nil {
		return -1
	}
	return number
}
