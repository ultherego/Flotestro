//go:build integration

package integration

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The version comparison corpus lives next to the implementation: the same
// file is read by the unit test and by this test, which asks the real tool
// about every pair.
const corpusPath = "../../internal/vuln/version/testdata/corpus.tsv"

type versionPair struct {
	Kind     string
	A, B     string
	Expected int
	Line     int
}

func versionCorpus(t *testing.T) []versionPair {
	t.Helper()
	file, err := os.Open(filepath.Clean(corpusPath))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	defer file.Close()

	var pairs []versionPair
	scanner := bufio.NewScanner(file)
	number := 0
	for scanner.Scan() {
		number++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("corpus, line %d: %d columns", number, len(fields))
		}
		expected, err := strconv.Atoi(fields[3])
		if err != nil {
			t.Fatalf("corpus, line %d: %v", number, err)
		}
		pairs = append(pairs, versionPair{
			Kind: fields[0], A: fields[1], B: fields[2], Expected: expected, Line: number,
		})
	}
	return pairs
}

// TestCorpusAgreesWithDpkg asks dpkg about every Debian version pair.
//
// A home-grown version comparison sooner or later drifts away from the
// package manager. A drift one way gives a false alarm, the other way - a
// vulnerability considered fixed. That is why the corpus is checked with the
// tool, not only with the unit test.
func TestCorpusAgreesWithDpkg(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("this machine has no dpkg")
	}
	checked := 0
	for _, pair := range versionCorpus(t) {
		if pair.Kind != "deb" {
			continue
		}
		checked++
		result := 0
		if exec.Command("dpkg", "--compare-versions", pair.A, "lt", pair.B).Run() == nil {
			result = -1
		} else if exec.Command("dpkg", "--compare-versions", pair.A, "gt", pair.B).Run() == nil {
			result = 1
		}
		if result != pair.Expected {
			t.Errorf("line %d: dpkg says %d for %q ? %q, corpus %d",
				pair.Line, result, pair.A, pair.B, pair.Expected)
		}
	}
	if checked == 0 {
		t.Fatal("the corpus has no Debian pair at all")
	}
	t.Logf("dpkg confirmed %d pairs", checked)
}

// rpmScript asks librpm to compare a version pair.
//
// The release is compared only when both sides have one - just like the
// correlator, because an advisory often gives the bare version without a
// release.
const rpmScript = `
import rpm, sys
def split(evr):
    epoch = "0"
    if ":" in evr:
        epoch, evr = evr.split(":", 1)
    if "-" in evr:
        version, release = evr.split("-", 1)
    else:
        version, release = evr, None
    return (epoch, version, release)
a, b = split(sys.argv[1]), split(sys.argv[2])
if a[2] is None or b[2] is None:
    a, b = (a[0], a[1], None), (b[0], b[1], None)
print(rpm.labelCompare(a, b))
`

// TestCorpusAgreesWithLibrpm asks librpm about every RPM version pair.
func TestCorpusAgreesWithLibrpm(t *testing.T) {
	if exec.Command("python3", "-c", "import rpm").Run() != nil {
		t.Skip("this machine has no Python bindings for librpm (python3-rpm)")
	}
	checked := 0
	for _, pair := range versionCorpus(t) {
		if pair.Kind != "rpm" {
			continue
		}
		checked++
		output, err := exec.Command("python3", "-c", rpmScript, pair.A, pair.B).Output()
		if err != nil {
			t.Fatalf("line %d: librpm: %v", pair.Line, err)
		}
		result, err := strconv.Atoi(strings.TrimSpace(string(output)))
		if err != nil {
			t.Fatalf("line %d: librpm answer %q", pair.Line, output)
		}
		if result != pair.Expected {
			t.Errorf("line %d: librpm says %d for %q ? %q, corpus %d",
				pair.Line, result, pair.A, pair.B, pair.Expected)
		}
	}
	if checked == 0 {
		t.Fatal("the corpus has no RPM pair at all")
	}
	t.Logf("librpm confirmed %d pairs", checked)
}
