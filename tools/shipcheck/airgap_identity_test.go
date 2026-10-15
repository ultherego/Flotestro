package main

import (
	"strings"
	"testing"
)

// The procedure's certificate identity has to name the workflow that signs the
// images of that loop.
//
// The image of the package repository is signed by release.yml and the other
// three by images.yml. A loop copied together with its identity pattern
// therefore asks cosign to refuse an image that is correctly signed - and this
// part of the procedure has been wrong once already, for three releases, when
// there was no signature at all. The documentation warns about it in a
// sentence; until 15.10 nothing enforced the sentence.
func TestAVerifyLoopMustNameTheWorkflowThatSignsItsImages(t *testing.T) {
	const releaseSigns = `name: Release
on:
  push:
    tags: ['v*']
jobs:
  repository-image:
    runs-on: ubuntu-latest
    steps:
      - name: Sign it
        run: |
          cosign sign --yes "ghcr.io/owner/flotestro-package-repository@$DIGEST"
`
	// One loop over the repository image, with the workflow of its identity
	// left to the caller.
	procedure := func(workflow string) string {
		return strings.Join([]string{
			"```",
			"for name in package-repository; do",
			"  cosign verify \\",
			"    --certificate-identity-regexp " +
				`'^https://github\.com/o/R/\.github/workflows/` + workflow + `@refs/tags/v' \\`,
			`    "ghcr.io/owner/flotestro-$name:1.0"`,
			"done",
			"```",
			"",
		}, "\n")
	}

	root := t.TempDir()
	write(t, root, ".github/workflows/images.yml", signingWorkflow)
	write(t, root, ".github/workflows/release.yml", releaseSigns)

	// Asking for the publishing workflow's identity over an image the release
	// workflow signs: the operator's command would refuse it.
	write(t, root, "docker/README.md", procedure(`images\.yml`))
	only(t, run(t, root, "airgap-images-are-signed"), "release.yml")

	// Named correctly, the same tree is clean - this is a narrowing, not a
	// check that fails on everything.
	write(t, root, "docker/README.md", procedure(`release\.yml`))
	if findings := run(t, root, "airgap-images-are-signed"); len(findings) != 0 {
		t.Fatalf("a loop naming the workflow that signs its image was refused: %v", findings)
	}
}
