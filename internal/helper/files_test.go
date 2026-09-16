package helper

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/ultherego/flotestro/internal/modules/files"
)

// openDirectory opens a test directory the way the helper does before
// staging: without following symlinks on the way.
func openDirectory(t *testing.T, dir string) *os.File {
	t.Helper()
	handle, err := files.OpenWithoutSymlinks(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", dir, err)
	}
	t.Cleanup(func() { handle.Close() })
	return handle
}

// The staging file used to sit under a name derived from the target and
// was written with a call that follows symlinks: a link planted under that
// name had the helper overwrite any file, as root. The staging now never
// touches such a name, whichever way the file is created.
func TestStagingDoesNotFollowALinkPlantedUnderThePredictableName(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.conf")
	if err := os.WriteFile(victim, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The name the old code used for a target called "app.conf".
	planted := filepath.Join(dir, ".flotestro-validation-app.conf")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatal(err)
	}
	directory := openDirectory(t, dir)

	for _, anonymous := range []bool{true, false} {
		staged, err := stageForValidation(int(directory.Fd()), []byte("payload\n"), 0o600, ".conf", anonymous)
		if err != nil {
			t.Fatalf("staging (anonymous=%v): %v", anonymous, err)
		}
		if strings.Contains(staged.Name, "validation-app") {
			t.Errorf("the staging file took the predictable name %q", staged.Name)
		}
		staged.Discard(int(directory.Fd()))
	}

	content, err := os.ReadFile(victim)
	if err != nil || string(content) != "untouched\n" {
		t.Fatalf("the file behind the planted link changed: %q, %v", content, err)
	}
	target, err := os.Readlink(planted)
	if err != nil || target != victim {
		t.Fatalf("the planted link was replaced: %q, %v", target, err)
	}
}

// The named fallback is the path a file system without O_TMPFILE takes, so
// it is exercised on its own: the file is created with O_EXCL and
// O_NOFOLLOW in the opened directory, carries the content, keeps the
// suffix of the target for the tools that read the kind of file from it,
// and vanishes with Discard.
func TestNamedStagingCreatesAFreshFileAndRemovesIt(t *testing.T) {
	dir := t.TempDir()
	directory := openDirectory(t, dir)

	staged, err := stageForValidation(int(directory.Fd()), []byte("[Unit]\n"), 0o600, ".service", false)
	if err != nil {
		t.Fatalf("staging: %v", err)
	}
	if staged.Anonymous || staged.Name == "" {
		t.Fatalf("the fallback produced an anonymous file: %+v", staged)
	}
	if !strings.HasPrefix(staged.Name, ".flotestro-validate-") || !strings.HasSuffix(staged.Name, ".service") {
		t.Errorf("staging name = %q", staged.Name)
	}
	// The random part is 128 bits, written as 32 hex characters.
	random := strings.TrimSuffix(strings.TrimPrefix(staged.Name, ".flotestro-validate-"), ".service")
	if len(random) != 32 {
		t.Errorf("the random part of %q has %d characters, want 32", staged.Name, len(random))
	}
	info, err := os.Lstat(filepath.Join(dir, staged.Name))
	if err != nil {
		t.Fatalf("the staging file is not in the directory: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		t.Errorf("staging file mode = %v", info.Mode())
	}
	content, err := os.ReadFile(filepath.Join(dir, staged.Name))
	if err != nil || string(content) != "[Unit]\n" {
		t.Errorf("staged content = %q, %v", content, err)
	}
	// The descriptor handed to a tool reads from the start.
	head := make([]byte, 6)
	if n, err := staged.File.Read(head); err != nil || string(head[:n]) != "[Unit]" {
		t.Errorf("reading the staged descriptor: %q, %v", head[:n], err)
	}

	staged.Discard(int(directory.Fd()))
	if _, err := os.Lstat(filepath.Join(dir, staged.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staging file survived Discard: %v", err)
	}
}

// A link that is already there under the chosen name is refused, not
// opened: O_EXCL refuses the existing entry and O_NOFOLLOW refuses the
// link. The file behind it stays as it was.
func TestNamedStagingRefusesAnExistingLink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.conf")
	if err := os.WriteFile(victim, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const name = ".flotestro-validate-guessed.conf"
	if err := os.Symlink(victim, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	directory := openDirectory(t, dir)

	staged, err := stageNamed(int(directory.Fd()), name, []byte("payload\n"), 0o600)
	if err == nil {
		staged.Discard(int(directory.Fd()))
		t.Fatal("staging opened an existing link")
	}
	content, _ := os.ReadFile(victim)
	if string(content) != "untouched\n" {
		t.Fatalf("the file behind the link changed: %q", content)
	}
}

// An anonymous file has no entry in the directory at all, so there is
// nothing for anyone to plant a link over; it disappears with the
// descriptor. A file system without O_TMPFILE is allowed to answer with
// the named fallback instead.
func TestAnonymousStagingLeavesNoEntry(t *testing.T) {
	dir := t.TempDir()
	directory := openDirectory(t, dir)

	staged, err := stageForValidation(int(directory.Fd()), []byte("x = 1\n"), 0o600, ".conf", true)
	if err != nil {
		t.Fatalf("staging: %v", err)
	}
	defer staged.Discard(int(directory.Fd()))
	if !staged.Anonymous {
		t.Skipf("this file system has no O_TMPFILE; the named fallback was used (%s)", staged.Name)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("an anonymous file left entries in the directory: %v", entries)
	}
	head := make([]byte, 5)
	if n, err := staged.File.Read(head); err != nil || string(head[:n]) != "x = 1" {
		t.Errorf("reading the staged descriptor: %q, %v", head[:n], err)
	}
}

// A validator whose tool is not on the host is not a passed check: the
// caller gets the unavailable marker and refuses the write with its own
// code, instead of writing content nobody looked at.
func TestAMissingValidatorToolIsReportedAsUnavailable(t *testing.T) {
	validator := files.Validator{
		Name:    "probe",
		Command: []string{filepath.Join(t.TempDir(), "no-such-tool")},
	}
	_, err := testServer().checkContent(t.Context(), validator, filepath.Join(t.TempDir(), "app.conf"), []byte("x\n"))
	if !errors.Is(err, errValidatorUnavailable) {
		t.Fatalf("a missing tool gave %v, want the unavailable marker", err)
	}
	if allowsMissingValidator(nil, nil) {
		t.Fatal("an unchecked write is allowed before the contract carries the flag and the grant")
	}
}

// The tool gets the staged content and its verdict comes back with its
// output. The check runs against a script standing in for the tool, so the
// test sees which path the tool received and what it read there.
func TestTheValidatorReadsTheStagedContent(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "check.sh")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\ncat \"$1\"\ncase \"$1\" in /proc/self/fd/*) echo anonymous;; *) echo named;; esac\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, needsName := range []bool{false, true} {
		validator := files.Validator{Name: "probe", Command: []string{tool}, NeedsName: needsName}
		output, err := testServer().checkContent(t.Context(), validator, filepath.Join(dir, "app.conf"), []byte("content\n"))
		if err == nil {
			t.Fatalf("the tool's failure was not reported (needsName=%v)", needsName)
		}
		if !strings.HasPrefix(output, "content") {
			t.Errorf("the tool did not read the staged content (needsName=%v): %q", needsName, output)
		}
		if needsName && !strings.HasSuffix(output, "named") {
			t.Errorf("a tool that needs a name got an anonymous file: %q", output)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Errorf("staging left entries behind (needsName=%v): %v", needsName, entries)
		}
	}
}
