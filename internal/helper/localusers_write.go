package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// localUserNamePattern rejects names that cannot be a POSIX account. The name
// never reaches a shell, but the validation is the second line of defence.
var localUserNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)

// expiryDatePattern is the calendar date chage takes. The value lands on the
// command line of a root tool, so the shape is checked here again.
var expiryDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// Stable error codes of the operations on local accounts.
const (
	ErrorInvalidAccount   = "invalid_account"
	ErrorShadowsDirectory = "shadows_directory_account"
	ErrorSystemAccount    = "system_account"
	ErrorAccountExists    = "account_exists"
	ErrorAccountMissing   = "account_missing"
	// ErrorProtectedAccount marks the account the agent itself runs under:
	// changing it from the panel would cut the host off from the panel.
	ErrorProtectedAccount = "protected_account"
	// ErrorSymlink marks a home directory or a key directory that is a
	// symbolic link. The helper runs as root and a link placed by the user
	// would point its writes at somebody else's files.
	ErrorSymlink = "symlink_refused"
)

// systemUIDCeiling separates service accounts from the accounts of people.
// Accounts below this boundary belong to the system and the panel does not
// change them.
const systemUIDCeiling = 1000

// maxAuthorizedKeysBytes bounds the key file the helper reads back. A file
// larger than this is not a list of keys.
const maxAuthorizedKeysBytes = 1 << 20

// accountRecord is what the helper knows about an account before it changes
// it. The lookup is a function of the server, so the handlers can be checked
// without an account on the machine running the tests.
type accountRecord struct {
	Name     string
	UID      int
	GID      int
	Home     string
	InPasswd bool
}

// accountTool runs one of the shadow tools: useradd, usermod, userdel,
// chage. The name never comes from the request.
type accountTool func(ctx context.Context, timeout time.Duration, tool string, args ...string) (string, string, error)

// lookupAccount resolves an account through NSS and says whether it comes
// from /etc/passwd or from the directory.
func lookupAccount(name string) (accountRecord, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return accountRecord{}, err
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	return accountRecord{
		Name: name, UID: uid, GID: gid, Home: account.HomeDir, InPasswd: inPasswdFile(name),
	}, nil
}

// accounts returns the lookup the server uses: the injected one in tests,
// NSS otherwise.
func (s *Server) accounts() func(string) (accountRecord, error) {
	if s.lookupAccount != nil {
		return s.lookupAccount
	}
	return lookupAccount
}

// tool returns the runner of the shadow tools: the injected one in tests,
// the real one otherwise.
func (s *Server) tool() accountTool {
	if s.accountTool != nil {
		return s.accountTool
	}
	return runIdentityTool
}

// applyLocalUserAction changes a local account on the host.
//
// The panel does not manage passwords: accounts are created locked and access
// is granted with an SSH key. A password in the envelope of a task would be a
// secret in the database and in the logs.
func (s *Server) applyLocalUserAction(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.LocalUserActionRequest) *helperv1.HelperResponse {
	name := action.GetName()
	if !localUserNamePattern.MatchString(name) {
		return reject(ErrorInvalidAccount, fmt.Sprintf("invalid account name %q", name))
	}

	// Account changes are serialized: useradd and usermod write to the same
	// files.
	release, busy := s.hold(GuardAccounts, request)
	if busy != nil {
		return busy
	}
	defer release()

	operationCtx, cancel := deadline(ctx, request, 60*time.Second, 5*time.Minute)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.LocalUserActionRequest_OPERATION_CREATE:
		return s.createLocalUser(operationCtx, request, action)
	case helperv1.LocalUserActionRequest_OPERATION_LOCK:
		return s.setLocalUserLock(operationCtx, name, true)
	case helperv1.LocalUserActionRequest_OPERATION_UNLOCK:
		return s.setLocalUserLock(operationCtx, name, false)
	case helperv1.LocalUserActionRequest_OPERATION_SET_SSH_KEYS:
		return s.setLocalUserKeys(operationCtx, name, action.GetSshKeys())
	case helperv1.LocalUserActionRequest_OPERATION_SET_GROUPS:
		return s.setLocalUserGroups(operationCtx, name, action.GetGroups())
	case helperv1.LocalUserActionRequest_OPERATION_SET_EXPIRY:
		return s.setLocalUserExpiry(operationCtx, name, action.GetExpiresAt())
	case helperv1.LocalUserActionRequest_OPERATION_DELETE:
		return s.deleteLocalUser(operationCtx, request, name, action.GetRemoveHome())
	default:
		return reject(ErrorUnknownAction, "unknown local account operation")
	}
}

func (s *Server) createLocalUser(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.LocalUserActionRequest) *helperv1.HelperResponse {
	name := action.GetName()

	if existing, err := s.accounts()(name); err == nil {
		// An account resolved through NSS but absent from /etc/passwd comes from
		// the directory. Creating a local copy would shadow the identity from the
		// directory and make the UIDs diverge between hosts.
		if !existing.InPasswd {
			return reject(ErrorShadowsDirectory, fmt.Sprintf(
				"the account %s comes from the directory (UID %d); a local copy would shadow it",
				name, existing.UID))
		}
		return reject(ErrorAccountExists, fmt.Sprintf("the account %s already exists locally", name))
	}

	args := []string{"--shell", shellOrDefault(action.GetShell())}
	if gecos := action.GetGecos(); gecos != "" {
		args = append(args, "--comment", gecos)
	}
	if err := validateGroupNames(action.GetGroups()); err != nil {
		return reject(ErrorInvalidAccount, err.Error())
	}
	if groups := action.GetGroups(); len(groups) > 0 {
		args = append(args, "--groups", strings.Join(groups, ","))
	}
	if action.GetCreateHome() {
		args = append(args, "--create-home")
	}
	// The account is created with password login disabled, not locked. useradd
	// leaves an exclamation mark in shadow, which means "locked by the
	// administrator"; for an account served by an SSH key that is a false state,
	// and on top of that it makes a later unlock impossible.
	args = append(args, "--password", "*")
	args = append(args, name)

	if _, stderr, err := s.tool()(ctx, 60*time.Second, "useradd", args...); err != nil {
		return reject(ErrorExecFailed, "useradd: "+firstLineOf(stderr))
	}

	if keys := action.GetSshKeys(); len(keys) > 0 {
		if response := s.setLocalUserKeys(ctx, name, keys); !response.GetAccepted() {
			return response
		}
	}

	s.log.Info("a local account was created",
		"task_id", request.GetTaskId(), "account", name, "groups", len(action.GetGroups()))
	return &helperv1.HelperResponse{Accepted: true}
}

func (s *Server) setLocalUserLock(ctx context.Context, name string, lock bool) *helperv1.HelperResponse {
	if _, response := s.requireLocalAccount(name); response != nil {
		return response
	}
	flag := "--unlock"
	if lock {
		flag = "--lock"
	}
	if _, stderr, err := s.tool()(ctx, 30*time.Second, "usermod", flag, name); err != nil {
		return reject(ErrorExecFailed, "usermod: "+firstLineOf(stderr))
	}
	s.log.Info("the state of a local account was changed", "account", name, "locked", lock)
	return &helperv1.HelperResponse{Accepted: true}
}

// setLocalUserGroups sets the complete list of supplementary groups.
//
// The list is exact, not additive: usermod -G replaces the membership, so
// the state after the operation is the one in the order and nothing the
// account collected earlier survives unseen. The primary group is not
// touched.
func (s *Server) setLocalUserGroups(ctx context.Context, name string, groups []string) *helperv1.HelperResponse {
	if _, response := s.requireLocalAccount(name); response != nil {
		return response
	}
	if err := validateGroupNames(groups); err != nil {
		return reject(ErrorInvalidAccount, err.Error())
	}
	// An empty list is "--groups" with an empty argument: usermod takes it
	// as "no supplementary groups", which is exactly the order.
	if _, stderr, err := s.tool()(ctx, 30*time.Second, "usermod", "--groups", strings.Join(groups, ","), name); err != nil {
		return reject(ErrorExecFailed, "usermod: "+firstLineOf(stderr))
	}
	s.log.Info("the groups of a local account were set", "account", name, "groups", len(groups))
	return &helperv1.HelperResponse{Accepted: true}
}

// setLocalUserExpiry sets or clears the expiry date of the account.
func (s *Server) setLocalUserExpiry(ctx context.Context, name, expiresAt string) *helperv1.HelperResponse {
	if _, response := s.requireLocalAccount(name); response != nil {
		return response
	}
	// chage takes -1 as "no expiry"; the panel sends an empty date for it.
	date := "-1"
	if expiresAt != "" {
		if !expiryDatePattern.MatchString(expiresAt) {
			return reject(ErrorInvalidAccount, fmt.Sprintf("invalid expiry date %q", expiresAt))
		}
		if _, err := time.Parse("2006-01-02", expiresAt); err != nil {
			return reject(ErrorInvalidAccount, fmt.Sprintf("invalid expiry date %q", expiresAt))
		}
		date = expiresAt
	}
	if _, stderr, err := s.tool()(ctx, 30*time.Second, "chage", "--expiredate", date, name); err != nil {
		return reject(ErrorExecFailed, "chage: "+firstLineOf(stderr))
	}
	s.log.Info("the expiry of a local account was set", "account", name, "expires_at", expiresAt)
	return &helperv1.HelperResponse{Accepted: true}
}

// deleteLocalUser removes the account, and its home directory when the
// order says so.
//
// A home directory that is a symbolic link is refused: userdel -r would
// follow it as root and empty whatever it points at. A home that belongs to
// somebody else is refused for the same reason.
func (s *Server) deleteLocalUser(ctx context.Context, request *helperv1.HelperRequest,
	name string, removeHome bool) *helperv1.HelperResponse {
	account, response := s.requireLocalAccount(name)
	if response != nil {
		return response
	}
	args := []string{}
	if removeHome {
		if err := checkRemovableHome(account); err != nil {
			return reject(ErrorSymlink, err.Error())
		}
		args = append(args, "--remove")
	}
	args = append(args, name)
	if _, stderr, err := s.tool()(ctx, 120*time.Second, "userdel", args...); err != nil {
		return reject(ErrorExecFailed, "userdel: "+firstLineOf(stderr))
	}
	s.log.Info("a local account was deleted",
		"task_id", request.GetTaskId(), "account", name, "home_removed", removeHome)
	return &helperv1.HelperResponse{Accepted: true}
}

// checkRemovableHome says whether the home directory may go with the
// account: a real directory, owned by the account, and not one of the
// places every host has.
func checkRemovableHome(account accountRecord) error {
	home := filepath.Clean(account.Home)
	switch home {
	case "/", "/root", "/home", "/var", "/tmp", "/srv", "/opt", "/etc", "/usr":
		return fmt.Errorf("the home directory %s is not removed with an account", home)
	}
	info, err := os.Lstat(home)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// A missing home is nothing to remove and nothing to refuse.
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("the home directory %s is a symbolic link and is not followed", home)
	}
	if !info.IsDir() {
		return fmt.Errorf("the home %s is not a directory", home)
	}
	if owner, ok := ownerOf(info); ok && owner != account.UID {
		return fmt.Errorf("the home directory %s belongs to UID %d, not to the account", home, owner)
	}
	return nil
}

// setLocalUserKeys sets the complete set of public keys of an account.
func (s *Server) setLocalUserKeys(_ context.Context, name string, keys []string) *helperv1.HelperResponse {
	account, response := s.requireLocalAccount(name)
	if response != nil {
		return response
	}
	for _, key := range keys {
		if err := validatePublicKey(key); err != nil {
			return reject(ErrorInvalidAccount, err.Error())
		}
	}
	content := ""
	for _, key := range keys {
		content += strings.TrimSpace(key) + "\n"
	}
	if err := writeAuthorizedKeys(account.Home, account.UID, account.GID, content); err != nil {
		var symlink *symlinkError
		if errors.As(err, &symlink) {
			return reject(ErrorSymlink, err.Error())
		}
		return reject(ErrorExecFailed, err.Error())
	}
	s.log.Info("the SSH keys of a local account were set", "account", name, "keys", len(keys))
	return &helperv1.HelperResponse{Accepted: true}
}

// symlinkError marks a write refused because a link stood in its way.
type symlinkError struct{ path string }

func (e *symlinkError) Error() string {
	return "the path " + e.path + " is or leads through a symbolic link and is not followed"
}

// writeAuthorizedKeys replaces the key file of an account.
//
// The helper runs as root in a directory the user controls, so nothing here
// follows a link. The home is opened without resolving symlinks, the key
// directory is created and opened relative to it and checked to be a plain
// directory owned by the user or by root, and the file is created with
// O_EXCL and O_NOFOLLOW under that directory and renamed within it. A link
// planted as ~/.ssh or ~/.ssh/authorized_keys ends in a refusal, not in
// root's own key file being rewritten.
func writeAuthorizedKeys(home string, uid, gid int, content string) error {
	home = filepath.Clean(home)
	if !filepath.IsAbs(home) {
		return fmt.Errorf("the home directory %q is not absolute", home)
	}
	info, err := os.Lstat(home)
	if err != nil {
		return fmt.Errorf("the home directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return &symlinkError{path: home}
	}
	if !info.IsDir() {
		return fmt.Errorf("the home %s is not a directory", home)
	}

	homeFD, err := unix.Openat2(unix.AT_FDCWD, home, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
			return &symlinkError{path: home}
		}
		return fmt.Errorf("opening the home directory: %w", err)
	}
	defer unix.Close(homeFD)

	if err := unix.Mkdirat(homeFD, ".ssh", 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("creating .ssh: %w", err)
	}
	sshFD, err := unix.Openat2(homeFD, ".ssh", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOTDIR) {
			return &symlinkError{path: filepath.Join(home, ".ssh")}
		}
		return fmt.Errorf("opening .ssh: %w", err)
	}
	defer unix.Close(sshFD)

	var sshInfo unix.Stat_t
	if err := unix.Fstat(sshFD, &sshInfo); err != nil {
		return fmt.Errorf("reading .ssh: %w", err)
	}
	if sshInfo.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a directory", filepath.Join(home, ".ssh"))
	}
	// A key directory owned by a third account is not the user's: writing
	// keys into it would grant access on somebody else's behalf.
	if int(sshInfo.Uid) != uid && sshInfo.Uid != 0 {
		return fmt.Errorf("%s belongs to UID %d, not to the account", filepath.Join(home, ".ssh"), sshInfo.Uid)
	}
	if err := unix.Fchown(sshFD, uid, gid); err != nil {
		return fmt.Errorf("owning .ssh: %w", err)
	}
	if err := unix.Fchmod(sshFD, 0o700); err != nil {
		return fmt.Errorf("protecting .ssh: %w", err)
	}

	// An atomic write: an interrupted write must not leave a file that cuts
	// off access or grants it only in part. The temporary file is created
	// exclusively, so a link left there by the user is an error, not a
	// target.
	const temporary = "authorized_keys.flotestro-tmp"
	_ = unix.Unlinkat(sshFD, temporary, 0)
	fileFD, err := unix.Openat(sshFD, temporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("creating the key file: %w", err)
	}
	file := os.NewFile(uintptr(fileFD), filepath.Join(home, ".ssh", temporary))
	written := func() error {
		defer file.Close()
		if _, err := file.WriteString(content); err != nil {
			return err
		}
		if err := file.Chown(uid, gid); err != nil {
			return err
		}
		if err := file.Chmod(0o600); err != nil {
			return err
		}
		return file.Sync()
	}()
	if written != nil {
		_ = unix.Unlinkat(sshFD, temporary, 0)
		return fmt.Errorf("writing the key file: %w", written)
	}
	if err := unix.Renameat(sshFD, temporary, sshFD, "authorized_keys"); err != nil {
		_ = unix.Unlinkat(sshFD, temporary, 0)
		return fmt.Errorf("replacing the key file: %w", err)
	}
	return nil
}

// readAuthorizedKeysFile returns the content of an account's key file
// without following a link anywhere on the way, or nothing when there is
// no file. The helper runs as root: a link planted by the user must not
// make it read somebody else's file.
func readAuthorizedKeysFile(home string) ([]byte, error) {
	home = filepath.Clean(home)
	info, err := os.Lstat(home)
	if err != nil {
		return nil, fmt.Errorf("the home directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, &symlinkError{path: home}
	}
	path := filepath.Join(home, ".ssh", "authorized_keys")
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
			return nil, &symlinkError{path: path}
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if stat.Size() > maxAuthorizedKeysBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxAuthorizedKeysBytes)
	}
	content := make([]byte, stat.Size())
	n, err := file.Read(content)
	if err != nil && n == 0 {
		return nil, err
	}
	return content[:n], nil
}

// ownerOf reads the owner of a file from its stat record.
func ownerOf(info os.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}

// requireLocalAccount rejects operations on system accounts, on accounts
// that come from the directory and on the account of the agent itself.
func (s *Server) requireLocalAccount(name string) (accountRecord, *helperv1.HelperResponse) {
	account, err := s.accounts()(name)
	if err != nil {
		return accountRecord{}, reject(ErrorAccountMissing, fmt.Sprintf("the account %s does not exist", name))
	}
	if !account.InPasswd {
		return accountRecord{}, reject(ErrorShadowsDirectory, fmt.Sprintf(
			"the account %s comes from the directory; changes belong to the directory, not to the host", name))
	}
	if account.UID < systemUIDCeiling {
		// Service accounts belong to the packages that created them.
		return accountRecord{}, reject(ErrorSystemAccount, fmt.Sprintf(
			"the account %s is a system account (UID %d)", name, account.UID))
	}
	// The agent's own account is what the panel talks to the host through:
	// locking, deleting or regrouping it would cut the host off from the
	// panel with no way back.
	if uint32(account.UID) == s.allowedUID {
		return accountRecord{}, reject(ErrorProtectedAccount, fmt.Sprintf(
			"the account %s is the agent's own account and is not changed through the panel", name))
	}
	return account, nil
}

// inPasswdFile says whether the account comes from the file and not from the
// directory through NSS.
func inPasswdFile(name string) bool {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if before, _, found := strings.Cut(line, ":"); found && before == name {
			return true
		}
	}
	return false
}

func shellOrDefault(shell string) string {
	switch shell {
	case "/bin/bash", "/bin/sh", "/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/zsh":
		return shell
	default:
		return "/bin/bash"
	}
}

// validateGroupNames rejects a group that cannot be a POSIX group. The names
// land on the command line of usermod, joined by commas.
func validateGroupNames(groups []string) error {
	if len(groups) > 64 {
		return fmt.Errorf("too many groups: %d", len(groups))
	}
	for _, group := range groups {
		if !localUserNamePattern.MatchString(group) {
			return fmt.Errorf("invalid group name %q", group)
		}
	}
	return nil
}

// validatePublicKey rejects material that is not a public key.
func validatePublicKey(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("an empty SSH key")
	}
	if strings.Contains(trimmed, "PRIVATE KEY") {
		return fmt.Errorf("a private key was given; only a public key goes to the host")
	}
	if strings.ContainsAny(trimmed, "\n\r") {
		// Several lines in one key would allow an extra entry to be appended.
		return fmt.Errorf("the key contains a newline character")
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return fmt.Errorf("the SSH key does not have the form <type> <material>")
	}
	switch fields[0] {
	case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return nil
	default:
		return fmt.Errorf("unsupported SSH key type %q", fields[0])
	}
}
