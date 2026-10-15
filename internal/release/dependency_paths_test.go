package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A dependency tree must not be able to enter the product's history, and an
// ignore rule written with a trailing slash does not stop it.
//
// This was not hypothetical. A worktree built for one day's work had
// web/node_modules as a symbolic link to the main checkout's copy, and the
// first commit of that branch carried the link: .gitignore said
// "web/node_modules/", and a pattern ending in a slash matches a directory
// only. A symbolic link is not a directory, so the rule looked right, read
// right, and ignored nothing.
//
// What it would have shipped is worse than a stray file: a link whose target
// is a path on one machine. Anybody else's checkout gets a web/node_modules
// pointing at a directory that is not there, which is a build that fails for a
// reason nothing in the tree explains.
func TestADependencyTreeCannotEnterTheHistory(t *testing.T) {
	root := repositoryRoot(t)

	// The rules themselves, which is the half that holds in any checkout -
	// with or without a .git directory beside it.
	ignore, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	var covers bool
	for _, line := range strings.Split(string(ignore), "\n") {
		rule := strings.TrimSpace(line)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}
		// A rule covering the name whatever it is made of: no trailing slash,
		// so a file and a symbolic link are caught along with a directory.
		if rule == "node_modules" || strings.HasSuffix(rule, "/node_modules") {
			covers = true
		}
	}
	if !covers {
		t.Error(".gitignore has no node_modules rule without a trailing slash, " +
			"so a symbolic link of that name is not ignored")
	}

	// And the tree, when git is here to be asked. Not a skip when it is not:
	// the rule check above has already run, so this test never passes without
	// having checked anything.
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Log("no .git beside the sources, so the tracked paths were not read; the rules were")
		return
	}
	listed, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	for _, path := range strings.Split(strings.TrimRight(string(listed), "\x00"), "\x00") {
		if path == "" {
			continue
		}
		for _, part := range strings.Split(path, "/") {
			if part == "node_modules" {
				t.Errorf("%s is tracked, and nothing of a dependency tree belongs in this repository", path)
			}
		}
	}
}
