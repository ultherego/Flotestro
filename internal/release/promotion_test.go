package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A release workflow is validated when something fires it, and nothing fires
// this one except a tag. So its shape is read here instead.
//
// Until 11.10 the promotion was a matrix of three jobs, each gated on the
// release-signing environment. That asked for one decision four times - three
// promotions and the signing of the packages - which teaches an approver to
// click without reading. Worse, each job verified its own image and then moved
// its own names: the first image's names moved while the third had not been
// looked at, so a signature that failed on the third left a release two thirds
// published.
func TestThePromotionVerifiesEveryImageBeforeMovingAnyName(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "images.yml"))
	if err != nil {
		t.Fatalf("reading images.yml: %v", err)
	}
	text := string(raw)

	promote := jobBody(text, "promote")
	if promote == "" {
		t.Fatal("images.yml has no promote job, so this guard is reading the wrong thing")
	}

	// One job, not a matrix: the approval is per deployment, and a matrix is
	// one deployment per leg.
	if strings.Contains(promote, "matrix:") {
		t.Error("the promotion is a matrix again; every leg is its own approval, " +
			"which is the four-questions-for-one-decision this replaced")
	}

	// Every image verified before any name moves. Read as positions rather
	// than trusted: the ordering is the whole property.
	verify := strings.Index(promote, "cosign verify")
	move := strings.Index(promote, "imagetools create")
	switch {
	case verify < 0:
		t.Error("the promotion verifies no signature")
	case move < 0:
		t.Error("the promotion moves no name")
	case move < verify:
		t.Error("a name is moved before any signature is verified")
	}

	// The verification and the moving are separate steps, so that no image's
	// name can move inside the loop that is still verifying the others.
	if betweenSameStep(promote, verify, move) {
		t.Error("the verification and the moving are in one step; an image's names " +
			"would move while later images are still unverified")
	}

	// It takes every image's digest, not one.
	for _, want := range []string{"pattern: digest-*", "merge-multiple: true"} {
		if !strings.Contains(promote, want) {
			t.Errorf("the promotion does not carry %q, so it sees one image's digest", want)
		}
	}

	// And it says which images a release is made of, so a missing artefact is
	// a refusal rather than a release of whatever was downloaded.
	if !strings.Contains(promote, "EXPECTED: control-plane relay admin-tools") {
		t.Error("the promotion names no expected set of images; a release missing one " +
			"would promote the rest and look complete")
	}
}

// jobBody returns the lines of one job of a workflow, by its two-space key.
func jobBody(workflow, name string) string {
	start := strings.Index(workflow, "\n  "+name+":\n")
	if start < 0 {
		return ""
	}
	rest := workflow[start+1:]
	// The next line at the same indentation that is not a comment ends it.
	lines := strings.Split(rest, "\n")
	var body []string
	for i, line := range lines {
		if i > 0 && len(line) > 2 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ' && line[2] != '#' {
			break
		}
		body = append(body, line)
	}
	return strings.Join(body, "\n")
}

// betweenSameStep says whether two offsets fall inside one step, which is
// true when no "- name:" of a step begins between them.
func betweenSameStep(body string, first, second int) bool {
	if first < 0 || second < 0 || second < first {
		return false
	}
	return !strings.Contains(body[first:second], "\n      - name:")
}
