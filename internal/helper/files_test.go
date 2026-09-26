package helper

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
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

// The staging file used to sit under a name derived from the target and was
// written with a call that follows symlinks: a link planted under that name
// had the helper overwrite any file, as root.
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

// The named fallback is the path a file system without O_TMPFILE takes, so it
// is exercised on its own: created with O_EXCL and O_NOFOLLOW, and removed.
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

// A link that is already there under the chosen name is refused, not opened:
// O_EXCL refuses the existing entry and O_NOFOLLOW refuses the link.
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

// An anonymous file has no entry in the directory at all, so there is nothing
// for anyone to plant a link over; it disappears with the descriptor.
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

// A validator whose tool is not on the host is not a passed check: the caller
// gets the unavailable marker and refuses the write with its own code, instead
// of writing content nobody looked at.
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

// The tool gets the staged content and its verdict comes back with its output.
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

// versionStoreInTest points the store of previous contents and the registry of
// managed paths at directories of their own, so a test never touches the
// helper's state on the machine it runs on - and does not need that state to
// exist, which on a build runner it does not.
func versionStoreInTest(t *testing.T) files.VersionStore {
	t.Helper()
	previousRoot, previousRegistry := fileVersionRoot, fileRegistryPath
	state := t.TempDir()
	fileVersionRoot = filepath.Join(state, "versions")
	fileRegistryPath = filepath.Join(state, "files.json")
	t.Cleanup(func() { fileVersionRoot, fileRegistryPath = previousRoot, previousRegistry })
	return fileVersions()
}

// writeRequest builds an order for one file, the way the agent sends it.
func writeRequest(path string, mutate func(*helperv1.FileRequest)) *helperv1.FileRequest {
	action := &helperv1.FileRequest{
		Operation: helperv1.FileRequest_OPERATION_ENSURE,
		Path:      path,
	}
	mutate(action)
	return action
}

// scopeOf allows the directory of the test and nothing else: the scope is
// the host administrator's decision, and a test is not exempt from it.
func scopeOf(dir string) files.Allowlist {
	return files.Allowlist{Patterns: []string{dir + "/*"}, Source: "the test"}
}

// A write keeps the content it replaces, with the inode it had. Without that
// the contract of file.
func TestAWriteKeepsTheContentItReplaces(t *testing.T) {
	store := versionStoreInTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "app.conf")
	previous := []byte("key = first\n")
	if err := os.WriteFile(path, previous, 0o640); err != nil {
		t.Fatal(err)
	}

	response := testServer().writeFile(t.Context(), &helperv1.HelperRequest{TaskId: "task-1"},
		scopeOf(dir), writeRequest(path, func(action *helperv1.FileRequest) {
			action.Content = []byte("key = second\n")
			action.Mode = "0600"
			action.ExpectedSha256 = files.Fingerprint(previous)
		}))
	if !response.GetAccepted() {
		t.Fatalf("the write was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}

	versions := store.List(path)
	if len(versions) != 1 {
		t.Fatalf("the host kept %d versions of the file it overwrote", len(versions))
	}
	if versions[0].SHA256 != files.Fingerprint(previous) {
		t.Errorf("the kept version is not the content that was replaced: %+v", versions[0])
	}
	if versions[0].Mode != "0640" {
		t.Errorf("the version was kept without the permissions it had: %+v", versions[0])
	}
	if versions[0].OrderedBy != "task-1" {
		t.Errorf("the version does not say which order displaced it: %+v", versions[0])
	}
	// The result describes the whole change and not only a digest: it is
	// the answer to an approval that covered the whole intended state.
	var change files.Change
	if err := json.Unmarshal(response.GetFileResult().GetChange(), &change); err != nil {
		t.Fatalf("the result carries no description of the change: %v", err)
	}
	if change.BeforeSHA256 != files.Fingerprint(previous) ||
		change.AfterSHA256 != files.Fingerprint([]byte("key = second\n")) {
		t.Errorf("the change does not carry both digests: %+v", change)
	}
	if change.BeforeMode != "0640" || change.AfterMode != "0600" {
		t.Errorf("the change does not carry the inode before and after: %+v", change)
	}
	if change.SymlinkPolicy != files.SymlinkPolicyNoFollow || change.KeptVersion == nil {
		t.Errorf("the change does not say how the path was resolved or what was kept: %+v", change)
	}
}

// A return to a version puts back exactly what was kept - the bytes and the
// permissions - and refuses a digest this host never had instead of writing
// the newest copy.
func TestARollbackRestoresTheVersionThatWasNamed(t *testing.T) {
	store := versionStoreInTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "app.conf")
	first := []byte("key = first\nvalue = \xc3\xa9\n")
	if err := os.WriteFile(path, first, 0o640); err != nil {
		t.Fatal(err)
	}
	server := testServer()
	request := &helperv1.HelperRequest{TaskId: "task-1"}

	second := []byte("key = second\n")
	response := server.writeFile(t.Context(), request, scopeOf(dir),
		writeRequest(path, func(action *helperv1.FileRequest) {
			action.Content = second
			action.Mode = "0600"
			action.ExpectedSha256 = files.Fingerprint(first)
		}))
	if !response.GetAccepted() {
		t.Fatalf("the write was refused: %s", response.GetMessage())
	}

	// A digest nobody kept is refused with its own code, and the file stays
	// as it was.
	refused := server.writeFile(t.Context(), request, scopeOf(dir),
		writeRequest(path, func(action *helperv1.FileRequest) {
			action.VersionSha256 = files.Fingerprint([]byte("a content of another host\n"))
			action.ExpectedSha256 = files.Fingerprint(second)
		}))
	if refused.GetAccepted() || refused.GetErrorCode() != ErrorFileVersionUnknown {
		t.Fatalf("a rollback to an unknown version gave %q %s",
			refused.GetErrorCode(), refused.GetMessage())
	}
	if content, _ := os.ReadFile(path); string(content) != string(second) {
		t.Fatalf("the refused rollback changed the file: %q", content)
	}

	restored := server.writeFile(t.Context(), request, scopeOf(dir),
		writeRequest(path, func(action *helperv1.FileRequest) {
			action.VersionSha256 = files.Fingerprint(first)
			action.ExpectedSha256 = files.Fingerprint(second)
		}))
	if !restored.GetAccepted() {
		t.Fatalf("the rollback was refused: %s %s", restored.GetErrorCode(), restored.GetMessage())
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != string(first) {
		t.Fatalf("the file did not come back byte for byte: %q, %v", content, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("the permissions did not come back: %v, %v", info.Mode().Perm(), err)
	}
	// The content that was put back travels with the result: the panel has
	// no copy of a version only the host kept.
	if string(restored.GetFileResult().GetContent()) != string(first) {
		t.Error("the result does not carry the content that was restored")
	}
	// The write that the rollback itself is also keeps what it replaced:
	// going back to the newer content must stay possible.
	if _, _, err := store.Lookup(path, files.Fingerprint(second)); err != nil {
		t.Errorf("the rollback did not keep the content it replaced: %v", err)
	}
}

// A version the validator no longer accepts is not written back.
func TestARollbackRefusesAVersionTheValidatorRejects(t *testing.T) {
	versionStoreInTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "app.json")
	// The broken content got onto the host outside the panel - that is the
	// only way it can be there, because a write goes through the check.
	broken := []byte("{ not json at all\n")
	if err := os.WriteFile(path, broken, 0o644); err != nil {
		t.Fatal(err)
	}
	server := testServer()
	request := &helperv1.HelperRequest{TaskId: "task-1"}

	valid := []byte("{\"a\": 1}\n")
	response := server.writeFile(t.Context(), request, scopeOf(dir),
		writeRequest(path, func(action *helperv1.FileRequest) {
			action.Content = valid
			action.ExpectedSha256 = files.Fingerprint(broken)
		}))
	if !response.GetAccepted() {
		t.Fatalf("the write of valid content was refused: %s", response.GetMessage())
	}

	refused := server.writeFile(t.Context(), request, scopeOf(dir),
		writeRequest(path, func(action *helperv1.FileRequest) {
			action.VersionSha256 = files.Fingerprint(broken)
			action.ExpectedSha256 = files.Fingerprint(valid)
		}))
	if refused.GetAccepted() {
		t.Fatal("a version the validator rejects was written back")
	}
	if !strings.Contains(refused.GetMessage(), "json") {
		t.Errorf("the refusal does not name the check that gave it: %s", refused.GetMessage())
	}
	if content, _ := os.ReadFile(path); string(content) != string(valid) {
		t.Errorf("the refused rollback changed the file: %q", content)
	}
}

// The plan says who would check the content and in which version.
func TestThePlanCarriesTheIdentityOfTheValidator(t *testing.T) {
	versionStoreInTest(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "app.json")
	if err := os.WriteFile(path, []byte("{\"a\": 1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	response := testServer().planFile(t.Context(), &helperv1.HelperRequest{TaskId: "task-1"},
		scopeOf(dir), writeRequest(path, func(action *helperv1.FileRequest) {
			action.Operation = helperv1.FileRequest_OPERATION_PLAN
			action.Content = []byte("{\"a\": 2}\n")
			action.Mode = "0640"
		}))
	if !response.GetAccepted() {
		t.Fatalf("the plan was refused: %s", response.GetMessage())
	}
	var plan files.Plan
	if err := json.Unmarshal(response.GetFileResult().GetPlan(), &plan); err != nil {
		t.Fatalf("the plan did not come back: %v", err)
	}
	if !plan.Validator.Known || plan.Validator.Name != "json" ||
		plan.Validator.Version != files.BuiltInVersion {
		t.Errorf("the plan does not identify the check: %+v", plan.Validator)
	}
	if !plan.ContentChanges || !plan.ModeChanges {
		t.Errorf("the plan does not say what changes: %+v", plan)
	}
	if plan.SymlinkPolicy != files.SymlinkPolicyNoFollow {
		t.Errorf("the plan does not name the rule the path was resolved under: %q", plan.SymlinkPolicy)
	}
}
