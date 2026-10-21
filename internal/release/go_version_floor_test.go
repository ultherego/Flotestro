package release

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The Go version of the module is a security decision: the standard library is part of
// what ships. A version below one that fixed an advisory the product reaches is held
// here, so a revert or a stale branch cannot put it back unnoticed; the CI scan finds
// the next advisory, and the next row is added when it does.
var goVersionFloors = []struct{ advisory, reaches, version string }{
	{"GO-2026-6809", "identitystore.Check calls x509.Certificate.Verify", "1.26.10"},
}

func versionParts(t *testing.T, version string) [3]int {
	t.Helper()
	var parts [3]int
	for i, field := range strings.SplitN(version, ".", 3) {
		n, err := strconv.Atoi(field)
		if err != nil {
			t.Fatalf("%q is not a Go version", version)
		}
		parts[i] = n
	}
	return parts
}

func TestTheModuleIsBuiltWithAGoThatCarriesTheFixesItNeeds(t *testing.T) {
	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	found := regexp.MustCompile(`(?m)^go (\d+\.\d+\.\d+)$`).FindSubmatch(raw)
	if found == nil {
		t.Fatal("go.mod names no Go version of the form 1.N.P")
	}
	have := versionParts(t, string(found[1]))
	for _, floor := range goVersionFloors {
		want := versionParts(t, floor.version)
		for i := range have {
			if have[i] > want[i] {
				break
			}
			if have[i] < want[i] {
				t.Errorf("go.mod says Go %s; %s (%s) is fixed in %s",
					found[1], floor.advisory, floor.reaches, floor.version)
				break
			}
		}
	}
}
