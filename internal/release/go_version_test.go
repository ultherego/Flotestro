package release

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var (
	goDirective = regexp.MustCompile(`(?m)^go (\d+)\.(\d+)(?:\.(\d+))?$`)
	goBaseImage = regexp.MustCompile(`(?m)^ARG GO_IMAGE=golang:(\d+)\.(\d+)(\.\d+)?[-\w]*$`)
)

// The toolchain is named once, in go.mod, and every workflow reads it from
// there. The image that builds the binaries names it a second time, as its base
// image, and nothing compared the two. A bump that fixed the advisories in
// go.mod and left the Containerfile behind would build the published images
// with the compiler that still has them - and the images are the only form the
// control plane ships in, so the vulnerability check in CI would pass over the
// artefact that carries the bug.
func TestTheImageBuildsWithTheToolchainTheModuleAsksFor(t *testing.T) {
	module, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("go.mod is not readable, so this guard checks nothing: %v", err)
	}
	wanted := goDirective.FindStringSubmatch(string(module))
	if wanted == nil {
		t.Fatal("go.mod names no go directive in the shape this guard reads")
	}
	containerfile, err := os.ReadFile(filepath.Join("..", "..", "docker", "Containerfile"))
	if err != nil {
		t.Fatalf("the Containerfile is not readable: %v", err)
	}
	image := goBaseImage.FindStringSubmatch(string(containerfile))
	if image == nil {
		t.Fatal("the Containerfile names no golang base image in the shape this guard reads")
	}
	if image[1] != wanted[1] || image[2] != wanted[2] {
		t.Errorf("go.mod asks for Go %s.%s and the image builds on golang:%s.%s; "+
			"the published binaries would be compiled by another release of the standard library "+
			"than the one the advisories were checked against",
			wanted[1], wanted[2], image[1], image[2])
	}
	t.Logf("go.mod asks for %s.%s and the image builds on golang:%s.%s",
		wanted[1], wanted[2], image[1], image[2])
}
