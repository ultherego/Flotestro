package adminapi

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryDeleteReasonTheePanelSendsIsKept guards a whole class of quiet
// loss: the panel stops an operator to ask why a thing is being removed,
// sends the answer as ?reason=, and the handler never reads it. Nothing
// fails, nothing is logged, and the trail records the removal with no
// reason beside it - which is the first question asked of it afterwards.
// Three handlers were doing this when the test was written. What is
// guarded is that the handler reads it at all; where it goes afterwards -
// the audit detail, or the evidence of a step-up - the handler decides.
func TestEveryDeleteReasonThePanelSendsIsKept(t *testing.T) {
	sends := panelDeletesWithAReason(t)
	if len(sends) == 0 {
		t.Fatal("no removal in the panel sends a reason; the test can no longer see the panel's source")
	}
	routes := deleteRoutes(t)
	source := packageSource(t)

	for _, path := range sends {
		handler, ok := routes[matchRoute(path, routes)]
		if !ok {
			t.Errorf("the panel sends a reason to DELETE %s, which this package does not serve", path)
			continue
		}
		body, ok := functionBody(source, handler)
		if !ok {
			t.Errorf("%s serves DELETE %s and is not in this package's source", handler, path)
			continue
		}
		// Either way of reading it counts: most handlers take it through
		// requestReason, which reads the query and the body alike.
		if !strings.Contains(body, `Get("reason")`) && !strings.Contains(body, "requestReason(") {
			t.Errorf("the panel asks for a reason before DELETE %s and sends it, but %s never reads it:"+
				" the trail keeps the removal without the why", path, handler)
		}
	}
}

// panelDeletesWithAReason returns the address of every removal the panel
// makes that carries a reason, as a route pattern with its interpolations
// replaced by a placeholder.
func panelDeletesWithAReason(t *testing.T) []string {
	t.Helper()
	call := regexp.MustCompile(`(?s)api\.del\(\s*(.{0,400}?)\)[,;\s]`)
	var found []string
	seen := map[string]bool{}
	root := filepath.Join("..", "..", "web", "src")
	err := filepath.Walk(root, func(name string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if ext := filepath.Ext(name); ext != ".ts" && ext != ".tsx" {
			return nil
		}
		if strings.HasSuffix(name, ".test.ts") || strings.HasSuffix(name, ".test.tsx") {
			return nil
		}
		text, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		for _, one := range call.FindAllStringSubmatch(string(text), -1) {
			argument := one[1]
			if !strings.Contains(argument, "reason=") {
				continue
			}
			address := regexp.MustCompile(`/api/v1/[^"'` + "`" + `?\s]*`).FindString(argument)
			if address == "" {
				continue
			}
			address = regexp.MustCompile(`\$\{[^}]*\}`).ReplaceAllString(address, "{x}")
			address = strings.TrimSuffix(address, "/")
			if !seen[address] {
				seen[address] = true
				found = append(found, address)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the panel's source: %v", err)
	}
	return found
}

// deleteRoutes maps every DELETE route this package registers to the name of
// the handler that serves it.
func deleteRoutes(t *testing.T) map[string]string {
	t.Helper()
	line := regexp.MustCompile(`s\.route\(mux, "DELETE ([^"]+)", s\.(\w+)\)`)
	routes := map[string]string{}
	for _, one := range line.FindAllStringSubmatch(packageSource(t), -1) {
		routes[one[1]] = one[2]
	}
	if len(routes) == 0 {
		t.Fatal("this package registers no DELETE route; the test can no longer read the route table")
	}
	return routes
}

// matchRoute finds the registered route an address belongs to, comparing the
// parts that are written down and letting each side's placeholders stand for
// anything.
func matchRoute(address string, routes map[string]string) string {
	given := strings.Split(strings.Trim(address, "/"), "/")
	for route := range routes {
		have := strings.Split(strings.Trim(route, "/"), "/")
		want := given
		if len(have) != len(want) {
			// A trailing {key...} swallows the rest of the address. The
			// shortened address is this route's own reading of it, not a
			// change to the address every later route is compared against.
			if n := len(have); n == 0 || !strings.HasSuffix(have[n-1], "...}") || len(want) < n {
				continue
			}
			want = append(append([]string{}, want[:len(have)-1]...), strings.Join(want[len(have)-1:], "/"))
		}
		same := true
		for i := range have {
			if strings.HasPrefix(have[i], "{") || want[i] == "{x}" {
				continue
			}
			if have[i] != want[i] {
				same = false
				break
			}
		}
		if same {
			return route
		}
	}
	return ""
}

// packageSource is every .go file of this package, joined.
func packageSource(t *testing.T) string {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("reading this package: %v", err)
	}
	var all strings.Builder
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		text, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		all.Write(text)
		all.WriteString("\n")
	}
	return all.String()
}

// functionBody returns the source of one method of the server.
func functionBody(source, name string) (string, bool) {
	at := strings.Index(source, "func (s *Server) "+name+"(")
	if at < 0 {
		return "", false
	}
	rest := source[at:]
	if end := strings.Index(rest[1:], "\nfunc "); end >= 0 {
		return rest[:end+1], true
	}
	return rest, true
}

// TestNoDeleteReadsItsReasonFromOneChannelOnly guards the other half of the
// same class: a client sends the reason the way the neighbouring route takes
// it - in the body, as the roles do - and a handler that reads only the query
// answers "a reason is required" to a request that carried one. The group
// mapping and the retirement of an authority did exactly that, and it cost an
// integration run. A handler reads it through requestReason, which takes the
// body and the query alike, or it does not read a reason at all.
func TestNoDeleteReadsItsReasonFromOneChannelOnly(t *testing.T) {
	routes := deleteRoutes(t)
	source := packageSource(t)
	for pattern, handler := range routes {
		body, ok := functionBody(source, handler)
		if !ok {
			continue
		}
		if strings.Contains(body, `Get("reason")`) && !strings.Contains(body, "requestReason(") {
			t.Errorf("%s (DELETE %s) reads the reason from the query only; take it through requestReason", handler, pattern)
		}
	}
}
