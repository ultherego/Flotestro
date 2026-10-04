package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workflow(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", ".github", "workflows", name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(content)
}

// The verdict used to be an input of type choice with the options pass and
// fail: a human typed it and the status was worth the typing. It is recomputed
// from the report now, and this test is here so that the input cannot come
// back without somebody deleting a test that says why it went.
func TestTheLabGateTakesNoTypedVerdict(t *testing.T) {
	content := workflow(t, "lab-gate.yml")
	for _, forbidden := range []string{"inputs.result", "\n      result:"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("lab-gate.yml still carries %q: the verdict would be typed, not computed", forbidden)
		}
	}
	if !strings.Contains(content, "./internal/release/gatecheck") {
		t.Error("lab-gate.yml does not run gatecheck, so nothing recomputes the verdict")
	}
}

// A pasted report cannot be checked against the bytes it claims digests of, and
// a parser over it is not a trusted producer of evidence. The workflow takes
// the bundle the gate produced instead; these are the four things that has to
// mean, each of which a convenience could quietly undo.
func TestTheLabGateJudgesEvidenceAndNotAPastedReport(t *testing.T) {
	content := workflow(t, "lab-gate.yml")
	if strings.Contains(content, "\n      report:") || strings.Contains(content, "inputs.report") {
		t.Error("lab-gate.yml takes the report as an input again: nothing checks the bytes behind it")
	}
	// The bundle has to be fetched, not described.
	if !strings.Contains(content, "gh release download") {
		t.Error("lab-gate.yml fetches no evidence bundle")
	}
	// The tree has to come from git, in a checkout deep enough to hold it.
	if !strings.Contains(content, "git rev-parse \"$SHA^{tree}\"") {
		t.Error("lab-gate.yml does not read the tree of the commit out of git")
	}
	if !strings.Contains(content, "fetch-depth: 0") {
		t.Error("lab-gate.yml checks out shallowly, so git cannot hold the tree it compares")
	}
	// And gatecheck has to be given both, or it judges less than it could.
	if !strings.Contains(content, "-sha \"$SHA\" -tree \"$TREE\"") {
		t.Error("lab-gate.yml does not hand gatecheck the commit and the tree git holds")
	}
}

// A stable release takes a pass. A run that was green over approved
// limitations is a merge, not a shipment.
func TestTheReleaseRefusesALimitedVerdict(t *testing.T) {
	content := workflow(t, "release.yml")
	for _, wanted := range []string{"verdict=pass)", "verdict=limited)"} {
		if !strings.Contains(content, wanted) {
			t.Errorf("release.yml does not decide on %s", wanted)
		}
	}
}

// A script the release runs out of a sparse checkout has to be in it.
//
// The publication job checks out the product with sparse-checkout, naming one
// file, and ran two: sign-repo.sh, which was named, and repo-pages.sh, which
// was not. In a sparse checkout a file nobody asked for is simply not there, so
// the job reached for a script that had never been fetched - and a release job
// that fails at its last step leaves the repository half published.
//
// The two sides of this are twenty lines apart in one file, so the check is
// cheap: every "bash source/packaging/X.sh" has to appear in a sparse-checkout
// list of the same workflow.
func TestEveryScriptTheReleaseRunsIsCheckedOut(t *testing.T) {
	content := workflow(t, "release.yml")

	var sparse []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		// Both spellings: the one-line form and an item of the block form.
		if after, found := strings.CutPrefix(trimmed, "sparse-checkout:"); found {
			sparse = append(sparse, strings.TrimSpace(after))
			continue
		}
		if strings.HasPrefix(trimmed, "- packaging/") || strings.HasPrefix(trimmed, "packaging/") {
			sparse = append(sparse, strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(trimmed, "-")), " "))
		}
	}
	checkedOut := strings.Join(sparse, "\n")

	var missing []string
	for _, line := range strings.Split(content, "\n") {
		index := strings.Index(line, "source/packaging/")
		if index < 0 {
			continue
		}
		rest := line[index+len("source/"):]
		end := strings.IndexAny(rest, " \t\"'\\")
		if end >= 0 {
			rest = rest[:end]
		}
		if !strings.Contains(checkedOut, rest) {
			missing = append(missing, rest)
		}
	}
	for _, script := range missing {
		t.Errorf("the release runs %s and no sparse-checkout fetches it", script)
	}
	if len(sparse) == 0 {
		t.Fatal("no sparse-checkout was found in release.yml; this check read nothing")
	}
}
