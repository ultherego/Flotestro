package release

import (
	"strings"
	"testing"
)

// Half of this product is an interface, and the job that asks about known
// vulnerabilities asked about the Go half alone. On 08.10 npm reported nine
// advisories against the panel's dependencies; every one of them was in a
// build dependency and nothing shipped with them - which is an answer somebody
// has to read, not assume, and nothing in the repository read it.
//
// What a browser receives is what --omit=dev leaves, so that set is what the
// job is held to. The build's own dependencies are reported beside it and fail
// nothing: a vulnerability in a bundler is not a vulnerability in the panel.
func TestTheVulnerabilityJobAsksAboutBothHalvesOfTheProduct(t *testing.T) {
	job, found := parsedWorkflow(t, "ci.yml").Jobs["govulncheck"]
	if !found {
		t.Fatal("ci.yml declares no job asking about known vulnerabilities")
	}
	var go_, npm bool
	var shipped string
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "govulncheck") {
			go_ = true
		}
		if strings.Contains(step.Run, "npm audit") {
			npm = true
			shipped = step.Run
		}
	}
	if !go_ {
		t.Error("the job no longer asks govulncheck about the Go half")
	}
	if !npm {
		t.Fatal("the job asks nothing about the dependencies the panel ships; the Go half " +
			"is checked on every branch and the interface on none")
	}
	// The one that must fail is the shipped set, and it must not be excused by
	// a severity floor: an advisory in what a browser runs is an answer, not a
	// score.
	if !strings.Contains(shipped, "--omit=dev") {
		t.Error("the audit does not single out the dependencies that ship, so a build " +
			"dependency would fail the branch and the shipped ones would hide among them")
	}
	if !strings.Contains(shipped, "--audit-level=low") {
		t.Error("the audit of the shipped dependencies allows a severity floor")
	}
	// And the reporting half must not be able to fail the branch, or the
	// distinction collapses the first time a bundler has an advisory.
	if !strings.Contains(shipped, "|| true") {
		t.Error("the build's own dependencies are not reported with a failure of their own " +
			"ignored, so the job would refuse a branch over a vulnerability nothing ships")
	}
}
