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
	// The report is the only evidence there is; a run without one records
	// nothing at all.
	if !strings.Contains(content, "      report:\n        description: The contents of Vagrant/.gate/<sha>/result.json.\n        required: true\n") {
		t.Error("lab-gate.yml does not require the report")
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
