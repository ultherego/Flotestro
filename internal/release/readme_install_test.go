package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repositoryURL finds a package-repository address as the instructions write
// one, whatever quotes or shell punctuation sit around it.
var repositoryURL = regexp.MustCompile(`https://ultherego\.github\.io/Flotestro/packages/[A-Za-z0-9._/-]*`)

// The README is the page somebody installs from. Its commands are written by
// hand, in two places - the README and the installation chapter - and nothing
// compared them: the pacman instructions in the README were a Server line with
// no key import, so on a host that followed them pacman refused the database
// as untrusted, while the chapter had the three commands that work.
//
// This asks the narrower question a test can answer without a host: every
// address the README gives for the repository is one the installation chapter
// gives too, and every step the chapter considers necessary for a package
// manager the README names is a step the README names as well.
func TestTheReadmeInstallsFromTheSamePlaceAsTheChapter(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("the README is not readable, so this guard checks nothing: %v", err)
	}
	chapter, err := os.ReadFile(filepath.Join("..", "..", "docs", "site", "docs", "installation.html"))
	if err != nil {
		t.Fatalf("the installation chapter is not readable: %v", err)
	}
	text, manual := string(readme), string(chapter)

	addresses := map[string]bool{}
	for _, found := range repositoryURL.FindAllString(text, -1) {
		addresses[strings.TrimRight(found, "./")] = true
	}
	if len(addresses) == 0 {
		t.Fatal("the README names no repository address at all; this guard would pass over nothing")
	}
	for address := range addresses {
		if !strings.Contains(manual, address) {
			t.Errorf("the README installs from %q and the installation chapter never names it", address)
		}
	}

	// A package manager the README names has to be set up the way the chapter
	// says it has to be. The directory for the key is one of them: the README
	// wrote the key into /etc/apt/keyrings without creating it, which works
	// only on a release that ships it. These are the steps that are not optional: without
	// them the manager refuses the repository, and the reader is left with an
	// error that does not say which line was missing.
	required := map[string][]string{
		"apt":    {"install -d -m 0755 /etc/apt/keyrings", "signed-by="},
		"dnf":    {"rpm --import", "gpgcheck=1", "repo_gpgcheck=1"},
		"pacman": {"pacman-key --add", "--lsign-key", "SigLevel"},
	}
	checked := 0
	for manager, steps := range required {
		if !strings.Contains(text, manager) {
			continue
		}
		for _, step := range steps {
			checked++
			if !strings.Contains(text, step) {
				t.Errorf("the README tells a reader to use %s and never says %q, "+
					"which that manager needs before it will take the repository", manager, step)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the README names no package manager; either it changed shape or this guard stopped reading it")
	}
	t.Logf("%d repository addresses and %d set-up steps compared with the installation chapter",
		len(addresses), checked)
}
