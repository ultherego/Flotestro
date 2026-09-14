package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// TestShadowSemantics guards the separation of a lock from a missing password.
// An account created by the panel has no password and logs in with an SSH key;
// showing it as locked would be false information about access being cut off.
func TestShadowSemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	content := "" +
		"ordinary:$y$j9T$salt$hash:20000:0:99999:7:::\n" +
		"locked:!$y$j9T$salt$hash:20000:0:99999:7:::\n" +
		"keyonly:*:20000:0:99999:7:::\n" +
		"locked_without_password:!:20000:0:99999:7:::\n" +
		"empty::20000:0:99999:7:::\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	states, err := parseShadow(path)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]shadowState{
		"ordinary":                {locked: false, passwordSet: true},
		"locked":                  {locked: true, passwordSet: true},
		"keyonly":                 {locked: false, passwordSet: false},
		"locked_without_password": {locked: true, passwordSet: false},
		"empty":                   {locked: false, passwordSet: false},
	}
	for name, expected := range cases {
		got, known := states[name]
		if !known {
			t.Errorf("%s: no entry", name)
			continue
		}
		if got != expected {
			t.Errorf("%s: read %+v, expected %+v", name, got, expected)
		}
	}

	if _, err := parseShadow(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("a missing file has to be an error, not an empty map of accounts without passwords")
	}
}

func TestPublicKeyValidation(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 john@workstation"
	if err := validatePublicKey(key); err != nil {
		t.Fatalf("a valid key was rejected: %v", err)
	}

	// A newline character would allow a second key to be appended to
	// authorized_keys.
	for name, value := range map[string]string{
		"a private key":     "-----BEGIN OPENSSH PRIVATE KEY-----",
		"a newline":         key + "\nssh-rsa AAAAB3Nz stranger@workstation",
		"a carriage return": key + "\rssh-rsa AAAAB3Nz stranger@workstation",
		"a retired type":    "ssh-dss AAAAB3NzaC1kc3M john@workstation",
		"without material":  "ssh-ed25519",
		"empty":             "   ",
	} {
		if err := validatePublicKey(value); err == nil {
			t.Errorf("%s: the key should have been rejected", name)
		}
	}
}

func TestLocalAccountName(t *testing.T) {
	for _, name := range []string{"smith", "_service", "john-doe", "machine$"} {
		if !localUserNamePattern.MatchString(name) {
			t.Errorf("the name %q should be allowed", name)
		}
	}
	// The name is inserted into system commands and into the path of the home
	// directory, so the restriction is a security boundary, not cosmetics.
	for _, name := range []string{"Smith", "../root", "john doe", "root;rm", "", "john/doe"} {
		if localUserNamePattern.MatchString(name) {
			t.Errorf("the name %q should not be allowed", name)
		}
	}
}

// fakeAccountTool records the shadow tool calls instead of running them.
type fakeAccountTool struct {
	calls [][]string
	fail  string
}

func (f *fakeAccountTool) run(_ context.Context, _ time.Duration, tool string, args ...string) (string, string, error) {
	f.calls = append(f.calls, append([]string{tool}, args...))
	if f.fail != "" && tool == f.fail {
		return "", tool + ": refused by the fake", errors.New("exit status 1")
	}
	return "", "", nil
}

// accountServer is a helper whose account lookups and shadow tools are
// fakes: the handlers can be checked without an account on the machine
// running the tests.
func accountServer(tool *fakeAccountTool, records map[string]accountRecord) *Server {
	server := testServer()
	// The agent's identifier is put out of everybody's way: the tests
	// below use the identifier of whoever runs them for the owned files.
	server.allowedUID = ^uint32(0)
	server.accountTool = tool.run
	server.lookupAccount = func(name string) (accountRecord, error) {
		record, ok := records[name]
		if !ok {
			return accountRecord{}, errors.New("unknown account")
		}
		return record, nil
	}
	return server
}

func accountRequest(operation helperv1.LocalUserActionRequest_Operation,
	mutate func(*helperv1.LocalUserActionRequest)) *helperv1.HelperRequest {
	action := &helperv1.LocalUserActionRequest{Operation: operation, Name: "smith"}
	if mutate != nil {
		mutate(action)
	}
	return &helperv1.HelperRequest{
		ProtocolVersion: ProtocolVersion,
		TaskId:          "task-accounts",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		TimeoutSeconds:  30,
		Action:          &helperv1.HelperRequest_LocalUserAction{LocalUserAction: action},
	}
}

func joinedCall(call []string) string { return strings.Join(call, " ") }

// userRangeUID gives the identifier of whoever runs the tests, or skips the
// test when that identifier is a system one: the handlers refuse system
// accounts before they look at any file.
func userRangeUID(t *testing.T) int {
	t.Helper()
	if os.Getuid() < systemUIDCeiling {
		t.Skipf("the test needs a user-range identifier, running as %d", os.Getuid())
	}
	return os.Getuid()
}

// The group list is exact: usermod -G replaces the membership, so nothing
// the account collected earlier survives unseen. An empty list takes every
// supplementary group away.
func TestSetGroupsReplacesTheMembership(t *testing.T) {
	tool := &fakeAccountTool{}
	server := accountServer(tool, map[string]accountRecord{
		"smith": {Name: "smith", UID: 1500, GID: 1500, Home: "/home/smith", InPasswd: true},
	})
	response := server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_SET_GROUPS,
		func(a *helperv1.LocalUserActionRequest) { a.Groups = []string{"developers", "docker"} }), nil)
	if !response.GetAccepted() {
		t.Fatalf("the change was refused: %s %s", response.GetErrorCode(), response.GetMessage())
	}
	if len(tool.calls) != 1 || joinedCall(tool.calls[0]) != "usermod --groups developers,docker smith" {
		t.Fatalf("calls = %v", tool.calls)
	}

	tool.calls = nil
	response = server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_SET_GROUPS, nil), nil)
	if !response.GetAccepted() || len(tool.calls) != 1 || joinedCall(tool.calls[0]) != "usermod --groups  smith" {
		t.Fatalf("taking the groups away: accepted=%v calls=%v", response.GetAccepted(), tool.calls)
	}

	// A group name lands on the command line of a root tool.
	tool.calls = nil
	response = server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_SET_GROUPS,
		func(a *helperv1.LocalUserActionRequest) { a.Groups = []string{"sudo,root"} }), nil)
	if response.GetAccepted() || len(tool.calls) != 0 {
		t.Fatalf("a bad group name reached the tool: %v", tool.calls)
	}
}

func TestSetExpiryUsesChage(t *testing.T) {
	tool := &fakeAccountTool{}
	server := accountServer(tool, map[string]accountRecord{
		"smith": {Name: "smith", UID: 1500, GID: 1500, Home: "/home/smith", InPasswd: true},
	})
	response := server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_SET_EXPIRY,
		func(a *helperv1.LocalUserActionRequest) { a.ExpiresAt = "2030-06-30" }), nil)
	if !response.GetAccepted() || joinedCall(tool.calls[0]) != "chage --expiredate 2030-06-30 smith" {
		t.Fatalf("setting the expiry: accepted=%v calls=%v", response.GetAccepted(), tool.calls)
	}
	// An empty date clears the expiry: chage takes -1 for that.
	tool.calls = nil
	response = server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_SET_EXPIRY, nil), nil)
	if !response.GetAccepted() || joinedCall(tool.calls[0]) != "chage --expiredate -1 smith" {
		t.Fatalf("clearing the expiry: accepted=%v calls=%v", response.GetAccepted(), tool.calls)
	}
	tool.calls = nil
	response = server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_SET_EXPIRY,
		func(a *helperv1.LocalUserActionRequest) { a.ExpiresAt = "next week" }), nil)
	if response.GetAccepted() || len(tool.calls) != 0 {
		t.Fatalf("a bad date reached the tool: %v", tool.calls)
	}

	// A tool that fails ends in exec_failed with its first line of stderr.
	tool.fail = "chage"
	response = server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_SET_EXPIRY, nil), nil)
	if response.GetAccepted() || response.GetErrorCode() != ErrorExecFailed ||
		!strings.Contains(response.GetMessage(), "refused by the fake") {
		t.Fatalf("a failed tool: accepted=%v code=%q message=%q",
			response.GetAccepted(), response.GetErrorCode(), response.GetMessage())
	}
}

// Deleting removes the home only when the order says so, and never through
// a symbolic link: userdel -r would follow it as root and empty whatever it
// points at.
func TestDeleteRefusesASymlinkedHome(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "smith")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	tool := &fakeAccountTool{}
	server := accountServer(tool, map[string]accountRecord{
		"smith": {Name: "smith", UID: userRangeUID(t), GID: os.Getgid(), Home: link, InPasswd: true},
	})
	response := server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_DELETE,
		func(a *helperv1.LocalUserActionRequest) { a.RemoveHome = true }), nil)
	if response.GetAccepted() {
		t.Fatal("a deletion through a symbolic link was accepted")
	}
	if response.GetErrorCode() != ErrorSymlink {
		t.Fatalf("code = %q, expected %q", response.GetErrorCode(), ErrorSymlink)
	}
	if len(tool.calls) != 0 {
		t.Fatalf("userdel ran: %v", tool.calls)
	}

	// Without removing the home the link does not matter: the account goes,
	// the directory stays.
	response = server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_DELETE, nil), nil)
	if !response.GetAccepted() || joinedCall(tool.calls[0]) != "userdel smith" {
		t.Fatalf("deleting without the home: accepted=%v calls=%v", response.GetAccepted(), tool.calls)
	}
}

func TestDeleteRemovesAnOwnedHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "smith")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := &fakeAccountTool{}
	server := accountServer(tool, map[string]accountRecord{
		"smith": {Name: "smith", UID: userRangeUID(t), GID: os.Getgid(), Home: home, InPasswd: true},
	})
	response := server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_DELETE,
		func(a *helperv1.LocalUserActionRequest) { a.RemoveHome = true }), nil)
	if !response.GetAccepted() || joinedCall(tool.calls[0]) != "userdel --remove smith" {
		t.Fatalf("accepted=%v (%s) calls=%v", response.GetAccepted(), response.GetMessage(), tool.calls)
	}
}

// The system accounts, the directory accounts and the agent's own account
// are refused before any tool runs.
func TestAccountChangesRefuseProtectedAccounts(t *testing.T) {
	// The agent's own identifier: high enough to be nobody else's on the
	// machine running the tests.
	const agentUID = 3_000_000_000
	tool := &fakeAccountTool{}
	server := accountServer(tool, map[string]accountRecord{
		"daemon": {Name: "daemon", UID: 1, GID: 1, Home: "/usr/sbin", InPasswd: true},
		"jane":   {Name: "jane", UID: 20001, GID: 20001, Home: "/home/jane", InPasswd: false},
		"agent":  {Name: "agent", UID: agentUID, GID: 1000, Home: "/var/lib/flotestro-agent", InPasswd: true},
	})
	server.allowedUID = agentUID
	for name, code := range map[string]string{
		"daemon": ErrorSystemAccount, "jane": ErrorShadowsDirectory, "agent": ErrorProtectedAccount,
		"nobody-here": ErrorAccountMissing,
	} {
		for _, operation := range []helperv1.LocalUserActionRequest_Operation{
			helperv1.LocalUserActionRequest_OPERATION_DELETE,
			helperv1.LocalUserActionRequest_OPERATION_SET_GROUPS,
			helperv1.LocalUserActionRequest_OPERATION_SET_EXPIRY,
			helperv1.LocalUserActionRequest_OPERATION_LOCK,
		} {
			response := server.handle(context.Background(), accountRequest(operation,
				func(a *helperv1.LocalUserActionRequest) { a.Name = name }), nil)
			if response.GetAccepted() {
				t.Errorf("%s: %v was accepted", name, operation)
			}
			if response.GetErrorCode() != code {
				t.Errorf("%s: %v gave the code %q, expected %q", name, operation, response.GetErrorCode(), code)
			}
		}
	}
	if len(tool.calls) != 0 {
		t.Fatalf("a tool ran for a protected account: %v", tool.calls)
	}
}

// The helper runs as root in a directory the user controls. A link planted
// as ~/.ssh must not turn a key write into a write of root's own key file:
// the write is refused, and nothing is created behind the link.
func TestWritingKeysRefusesASymlinkedKeyDirectory(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "smith")
	target := filepath.Join(root, "victim")
	for _, dir := range []string{home, target} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}

	err := writeAuthorizedKeys(home, os.Getuid(), os.Getgid(), "ssh-ed25519 AAAA attacker\n")
	var symlink *symlinkError
	if !errors.As(err, &symlink) {
		t.Fatalf("err = %v, expected a symlink refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(target, "authorized_keys")); statErr == nil {
		t.Fatal("the key file was written behind the link")
	}

	if os.Getuid() < systemUIDCeiling {
		// The refusal of a system account comes first; the link check is
		// covered above.
		return
	}
	tool := &fakeAccountTool{}
	server := accountServer(tool, map[string]accountRecord{
		"smith": {Name: "smith", UID: os.Getuid(), GID: os.Getgid(), Home: home, InPasswd: true},
	})
	response := server.handle(context.Background(), accountRequest(
		helperv1.LocalUserActionRequest_OPERATION_SET_SSH_KEYS,
		func(a *helperv1.LocalUserActionRequest) {
			a.SshKeys = []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 x"}
		}), nil)
	if response.GetAccepted() || response.GetErrorCode() != ErrorSymlink {
		t.Fatalf("accepted=%v code=%q", response.GetAccepted(), response.GetErrorCode())
	}
}

// A home that is itself a link is refused for the same reason, on the write
// and on the read.
func TestASymlinkedHomeIsRefused(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "smith")
	if err := os.Symlink(real, home); err != nil {
		t.Fatal(err)
	}
	var symlink *symlinkError
	if err := writeAuthorizedKeys(home, os.Getuid(), os.Getgid(), ""); !errors.As(err, &symlink) {
		t.Fatalf("write: err = %v", err)
	}
	if _, err := readAuthorizedKeysFile(home); !errors.As(err, &symlink) {
		t.Fatalf("read: err = %v", err)
	}
}

// The ordinary path: the directory is created with 0700, the file with
// 0600, and a second write replaces the first atomically.
func TestWritingKeysCreatesTheDirectoryAndTheFile(t *testing.T) {
	home := filepath.Join(t.TempDir(), "smith")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAuthorizedKeys(home, os.Getuid(), os.Getgid(), "ssh-ed25519 AAAA one\n"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(home, ".ssh"))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf(".ssh: %v %v", info, err)
	}
	path := filepath.Join(home, ".ssh", "authorized_keys")
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("authorized_keys: %v %v", info, err)
	}
	if err := writeAuthorizedKeys(home, os.Getuid(), os.Getgid(), "ssh-ed25519 BBBB two\n"); err != nil {
		t.Fatal(err)
	}
	content, err := readAuthorizedKeysFile(home)
	if err != nil || string(content) != "ssh-ed25519 BBBB two\n" {
		t.Fatalf("content = %q (%v)", content, err)
	}
	if _, err := os.Lstat(filepath.Join(home, ".ssh", "authorized_keys.flotestro-tmp")); err == nil {
		t.Fatal("the temporary file was left behind")
	}

	// A link planted as the file itself is refused on the read.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", path); err != nil {
		t.Fatal(err)
	}
	var symlink *symlinkError
	if _, err := readAuthorizedKeysFile(home); !errors.As(err, &symlink) {
		t.Fatalf("a linked key file was read: %v", err)
	}
}

func TestParseAuthorizedKeysReportsFingerprints(t *testing.T) {
	content := "# a comment\n\n" +
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 jane@laptop\n" +
		"command=\"/bin/true\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 restricted\n" +
		"not a key at all\n"
	keys := parseAuthorizedKeys([]byte(content))
	if len(keys) != 2 {
		t.Fatalf("keys = %d, expected 2", len(keys))
	}
	for _, key := range keys {
		if key.GetType() != "ED25519" {
			t.Errorf("type = %q, expected ED25519", key.GetType())
		}
		if !strings.HasPrefix(key.GetFingerprint(), "SHA256:") {
			t.Errorf("fingerprint = %q", key.GetFingerprint())
		}
	}
	if keys[0].GetComment() != "jane@laptop" || keys[1].GetComment() != "restricted" {
		t.Errorf("comments = %q, %q", keys[0].GetComment(), keys[1].GetComment())
	}
}

// The expiry field of shadow is a day count; the panel shows a date.
func TestShadowExpiryBecomesADate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	content := "" +
		"expiring:$y$j9T$salt$hash:20000:0:99999:7::22000:\n" +
		"open:$y$j9T$salt$hash:20000:0:99999:7:::\n" +
		"odd:$y$j9T$salt$hash:20000:0:99999:7::-1:\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	states, err := parseShadow(path)
	if err != nil {
		t.Fatal(err)
	}
	if states["expiring"].expiresAt != "2030-03-27" {
		t.Errorf("expiring = %q", states["expiring"].expiresAt)
	}
	if states["open"].expiresAt != "" || states["odd"].expiresAt != "" {
		t.Errorf("open = %q, odd = %q", states["open"].expiresAt, states["odd"].expiresAt)
	}
}
