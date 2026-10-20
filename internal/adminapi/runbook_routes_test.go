package adminapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A runbook that names a route the product does not serve sends an operator to
// an answer that is 404. The certificate removal runbook is manual because the
// product has no operation for it, and the routes it does name are held to the
// router.
func TestTheCertificateRemovalRunbookNamesOnlyRoutesTheRouterServes(t *testing.T) {
	runbook, err := os.ReadFile("../../docs/runbooks/certificate-removal.md")
	if err != nil {
		t.Fatal(err)
	}
	router, err := os.ReadFile("adminapi.go")
	if err != nil {
		t.Fatal(err)
	}
	named := regexp.MustCompile("(?m)^(GET|DELETE|POST|PUT) (/api/v1/[^?\\s]+)").FindAllStringSubmatch(string(runbook), -1)
	if len(named) == 0 {
		t.Fatal("the runbook names no route any more; change the runbook and this test together")
	}
	for _, route := range named {
		pattern := regexp.MustCompile(`<[a-z-]+>`).ReplaceAllString(route[2], "{x}")
		want := route[1] + " " + pattern
		// The router writes the parameters as {id}; compare the shape.
		found := false
		for _, line := range strings.Split(string(router), "\n") {
			start := strings.Index(line, `"`+route[1]+" /api/v1/")
			if start < 0 {
				continue
			}
			served := line[start+1 : start+1+strings.Index(line[start+1:], `"`)]
			if regexp.MustCompile(`\{[a-z]+\}`).ReplaceAllString(served, "{x}") == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the runbook names %s %s, which the router does not serve", route[1], route[2])
		}
	}
}
