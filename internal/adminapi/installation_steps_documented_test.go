package adminapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/enrollment"
)

// The panel writes the commands an operator runs on a new host, and the
// installation chapter prints the same sequence "so that an operator knows
// what is being run". Nothing compared the two: the panel emitted a pin step -
// without which a helper on the default policy takes no trust bundle and the
// host enrols with nobody - and the chapter's table of steps did not have it,
// nor the step that writes the configuration. An operator who followed the
// chapter instead of the panel ended with a host that enrolled and then did
// nothing a capability is needed for.
func TestTheChapterNamesEveryStepThePanelGeneratesForAHost(t *testing.T) {
	chapter, err := os.ReadFile(filepath.Join("..", "..", "docs", "site", "docs", "installation.html"))
	if err != nil {
		t.Fatalf("the installation chapter is not readable, so this guard checks nothing: %v", err)
	}
	// The table writes "CA" where the panel's key is "ca"; the case of a
	// heading is not what this guard is about.
	text := strings.ToLower(string(chapter))

	families := installationFamilies(enrollment.KindAgent,
		installationRepository{URL: "https://example.invalid/packages", Package: "flotestro-agent"},
		"stable",
		installationFile{Path: "/etc/flotestro/agent.yaml", Content: "agent:\n"},
		installationCA{Path: "/var/lib/flotestro-agent/ca.pem", PEM: "-----BEGIN CERTIFICATE-----\n"},
		installationImage{},
		[]string{strings.Repeat("ab", 32)})
	if len(families) == 0 {
		t.Fatal("the panel generated no family of commands; this guard would pass over nothing")
	}

	steps := map[string]bool{}
	for _, family := range families {
		for _, step := range family.Steps {
			steps[step.Key] = true
		}
	}
	for step := range steps {
		// The table lists one step per row, by the key the panel uses.
		if !strings.Contains(text, "<td>"+strings.ToLower(step)+"</td>") {
			t.Errorf("the panel generates a %q step for every host and the installation chapter "+
				"does not list it among the steps; a reader following the chapter skips it", step)
		}
	}
	t.Logf("%d generated steps compared with the chapter's table", len(steps))
}
