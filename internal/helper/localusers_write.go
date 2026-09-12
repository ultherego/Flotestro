package helper

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// localUserNamePattern rejects names that cannot be a POSIX account. The name
// never reaches a shell, but the validation is the second line of defence.
var localUserNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)

// Stable error codes of the operations on local accounts.
const (
	ErrorInvalidAccount   = "invalid_account"
	ErrorShadowsDirectory = "shadows_directory_account"
	ErrorSystemAccount    = "system_account"
	ErrorAccountExists    = "account_exists"
	ErrorAccountMissing   = "account_missing"
)

// systemUIDCeiling separates service accounts from the accounts of people.
// Accounts below this boundary belong to the system and the panel does not
// change them.
const systemUIDCeiling = 1000

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

	s.accountMutex.Lock()
	defer s.accountMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = 60 * time.Second
	}
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
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
	default:
		return reject(ErrorUnknownAction, "unknown local account operation")
	}
}

func (s *Server) createLocalUser(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.LocalUserActionRequest) *helperv1.HelperResponse {
	name := action.GetName()

	if existing, err := user.Lookup(name); err == nil {
		// An account resolved through NSS but absent from /etc/passwd comes from
		// the directory. Creating a local copy would shadow the identity from the
		// directory and make the UIDs diverge between hosts.
		if !inPasswdFile(name) {
			return reject(ErrorShadowsDirectory, fmt.Sprintf(
				"the account %s comes from the directory (UID %s); a local copy would shadow it",
				name, existing.Uid))
		}
		return reject(ErrorAccountExists, fmt.Sprintf("the account %s already exists locally", name))
	}

	args := []string{"--shell", shellOrDefault(action.GetShell())}
	if gecos := action.GetGecos(); gecos != "" {
		args = append(args, "--comment", gecos)
	}
	for _, group := range action.GetGroups() {
		if !localUserNamePattern.MatchString(group) {
			return reject(ErrorInvalidAccount, fmt.Sprintf("invalid group name %q", group))
		}
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

	if _, stderr, err := runIdentityTool(ctx, 60*time.Second, "useradd", args...); err != nil {
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
	if response := s.requireLocalAccount(name); response != nil {
		return response
	}
	flag := "--unlock"
	if lock {
		flag = "--lock"
	}
	if _, stderr, err := runIdentityTool(ctx, 30*time.Second, "usermod", flag, name); err != nil {
		return reject(ErrorExecFailed, "usermod: "+firstLineOf(stderr))
	}
	s.log.Info("the state of a local account was changed", "account", name, "locked", lock)
	return &helperv1.HelperResponse{Accepted: true}
}

// setLocalUserKeys sets the complete set of public keys of an account.
func (s *Server) setLocalUserKeys(ctx context.Context, name string, keys []string) *helperv1.HelperResponse {
	if response := s.requireLocalAccount(name); response != nil {
		return response
	}
	for _, key := range keys {
		if err := validatePublicKey(key); err != nil {
			return reject(ErrorInvalidAccount, err.Error())
		}
	}

	account, err := user.Lookup(name)
	if err != nil {
		return reject(ErrorAccountMissing, err.Error())
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)

	sshDir := filepath.Join(account.HomeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if err := os.Chown(sshDir, uid, gid); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}

	path := filepath.Join(sshDir, "authorized_keys")
	content := ""
	for _, key := range keys {
		content += strings.TrimSpace(key) + "\n"
	}

	// An atomic write: an interrupted write must not leave a file that cuts off
	// access or grants it only in part.
	temporary := path + ".flotestro-tmp"
	if err := os.WriteFile(temporary, []byte(content), 0o600); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if err := os.Chown(temporary, uid, gid); err != nil {
		_ = os.Remove(temporary)
		return reject(ErrorExecFailed, err.Error())
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return reject(ErrorExecFailed, err.Error())
	}

	s.log.Info("the SSH keys of a local account were set", "account", name, "keys", len(keys))
	return &helperv1.HelperResponse{Accepted: true}
}

// requireLocalAccount rejects operations on system accounts and on accounts
// that come from the directory.
func (s *Server) requireLocalAccount(name string) *helperv1.HelperResponse {
	account, err := user.Lookup(name)
	if err != nil {
		return reject(ErrorAccountMissing, fmt.Sprintf("the account %s does not exist", name))
	}
	if !inPasswdFile(name) {
		return reject(ErrorShadowsDirectory, fmt.Sprintf(
			"the account %s comes from the directory; changes belong to the directory, not to the host", name))
	}
	if uid, convErr := strconv.Atoi(account.Uid); convErr == nil && uid < systemUIDCeiling {
		// Service accounts belong to the packages that created them.
		return reject(ErrorSystemAccount, fmt.Sprintf(
			"the account %s is a system account (UID %s)", name, account.Uid))
	}
	return nil
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
