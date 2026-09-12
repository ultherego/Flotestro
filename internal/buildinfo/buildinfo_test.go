package buildinfo

import (
	"strings"
	"testing"
)

func TestDescribeCarriesTheVersionAndTheEnvironment(t *testing.T) {
	description := Describe("flotestro-agentctl")
	if !strings.HasPrefix(description, "flotestro-agentctl "+Version) {
		t.Fatalf("description = %q", description)
	}
	if !strings.Contains(description, "go1") {
		t.Fatalf("the description carries no toolchain version: %q", description)
	}
}

// TestShortCommitMakesNothingUp guards the rule that unknown is neither zero
// nor a made-up value: without a commit written in and without metadata what
// is left is a visible emptiness rather than a digest that looks credible.
func TestShortCommitMakesNothingUp(t *testing.T) {
	previous := Commit
	t.Cleanup(func() { Commit = previous })

	Commit = "0123456789abcdef0123456789abcdef01234567"
	if got := ShortCommit(); got != "0123456789ab" {
		t.Fatalf("ShortCommit = %q", got)
	}
	Commit = "short"
	if got := ShortCommit(); got != "short" {
		t.Fatalf("ShortCommit = %q", got)
	}
}
