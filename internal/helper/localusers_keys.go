package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/accounts"
)

// effectiveSSHDConfig reads what sshd applies, as sshd -T prints it.
var effectiveSSHDConfig = func(ctx context.Context) (string, error) {
	if !exists(sshdPath) {
		return "", errors.New("this host has no sshd server")
	}
	return toolOutput(ctx, sshdPath, "-T")
}

// editLocalUserKeys changes the keys of an account one operation at a time
// (security remediation, chapter 14.
func (s *Server) editLocalUserKeys(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.LocalUserActionRequest) *helperv1.HelperResponse {
	name := action.GetName()
	account, response := s.requireLocalAccount(name, action.GetSystem())
	if response != nil {
		return response
	}

	managed := action.GetManagedFile()
	if managed {
		// A managed file sshd does not open grants nothing.
		effective, err := effectiveSSHDConfig(ctx)
		if err != nil {
			return reject(ErrorManagedFileNotRead, "the sshd configuration could not be read: "+err.Error())
		}
		if !accounts.ManagedFileReadBySSHD(effective) {
			return reject(ErrorManagedFileNotRead, fmt.Sprintf(
				"sshd on this host does not read %s; add it to AuthorizedKeysFile or edit the user's authorized_keys instead",
				accounts.ManagedKeysPattern))
		}
	}

	content, other, response := s.readKeyFiles(name, account, managed)
	if response != nil {
		return response
	}
	lines := accounts.ParseKeyFile(content)

	var (
		edited []accounts.Line
		change accounts.Change
		err    error
	)
	switch action.GetOperation() {
	case helperv1.LocalUserActionRequest_OPERATION_ADD_SSH_KEYS:
		var inputs []accounts.KeyInput
		for _, key := range action.GetKeys() {
			if err := validatePublicKey(key.GetPublicKey()); err != nil {
				return reject(ErrorInvalidKey, err.Error())
			}
			inputs = append(inputs, accounts.KeyInput{PublicKey: key.GetPublicKey(), Comment: key.GetComment()})
		}
		if len(inputs) == 0 {
			return reject(ErrorMalformed, "an add names at least one key")
		}
		edited, change, err = accounts.AddKeys(lines, inputs)

	case helperv1.LocalUserActionRequest_OPERATION_REMOVE_SSH_KEYS:
		if len(action.GetFingerprints()) == 0 {
			return reject(ErrorMalformed, "a removal names at least one fingerprint")
		}
		edited, change, err = accounts.RemoveKeys(lines, action.GetFingerprints(), action.GetIgnoreMissing())
		var missing *accounts.KeyNotFoundError
		if errors.As(err, &missing) {
			return reject(ErrorKeyNotFound, missing.Error()+"; the account has "+describeFingerprints(accounts.Fingerprints(lines)))
		}

	case helperv1.LocalUserActionRequest_OPERATION_REPLACE_SSH_KEYS,
		helperv1.LocalUserActionRequest_OPERATION_SET_SSH_KEYS:
		// The replace is bound to the list the operator saw.
		expected := action.GetExpectedFingerprints()
		verify := action.GetOperation() == helperv1.LocalUserActionRequest_OPERATION_REPLACE_SSH_KEYS || len(expected) > 0
		if current := accounts.Fingerprints(lines); verify && !accounts.SameFingerprints(current, expected) {
			return reject(ErrorStaleKeyList, fmt.Sprintf(
				"the keys of %s changed since the operator looked: the order expected %s, the host has %s; read the account again and order the replace anew",
				name, describeFingerprints(expected), describeFingerprints(current)))
		}
		var inputs []accounts.KeyInput
		for _, key := range action.GetSshKeys() {
			if err := validatePublicKey(key); err != nil {
				return reject(ErrorInvalidKey, err.Error())
			}
			inputs = append(inputs, accounts.KeyInput{PublicKey: key})
		}
		edited, change, err = accounts.ReplaceKeys(lines, inputs)

	default:
		return reject(ErrorUnknownAction, "unknown key operation")
	}
	if err != nil {
		if errors.Is(err, accounts.ErrInvalidKey) {
			return reject(ErrorInvalidKey, err.Error())
		}
		return reject(ErrorMalformed, err.Error())
	}

	// The lockout guard: the edit leaves the account with no key in either file,
	// and the account has no password login - none set, a locked one, or a state
	// the host could not read, which is not "a password" either.
	if len(change.After) == 0 && len(change.Before) > 0 && other == 0 && !action.GetAllowLockout() {
		if reason := noPasswordLogin(name); reason != "" {
			return reject(ErrorLastKeyLockout, fmt.Sprintf(
				"the order would take the last key of %s and %s, so nobody could log in as it afterwards; "+
					"add the new key first, or order the removal with allow_lockout if cutting the account off is the intent",
				name, reason))
		}
	}

	if change.NoOp() && accounts.Render(edited) == accounts.Render(lines) {
		// Nothing to write: the keys the order names are already as
		// ordered. The result of the agent shows an empty difference.
		s.log.Info("the SSH keys of a local account were already as ordered",
			"task_id", request.GetTaskId(), "account", name, "managed", managed)
		return &helperv1.HelperResponse{Accepted: true}
	}
	if response := s.writeKeyFile(name, account, managed, accounts.Render(edited)); response != nil {
		return response
	}
	s.log.Info("the SSH keys of a local account were edited",
		"task_id", request.GetTaskId(), "account", name, "managed", managed,
		"operation", action.GetOperation().String(),
		"added", len(change.Added), "removed", len(change.Removed), "keys", len(change.After))
	return &helperv1.HelperResponse{Accepted: true}
}

// readKeyFiles returns the file the order edits and the number of keys in the
// other one, so the lockout guard counts every way into the account.
func (s *Server) readKeyFiles(name string, account accountRecord, managed bool) ([]byte, int, *helperv1.HelperResponse) {
	userFile, err := readAuthorizedKeysFile(account.Home)
	if err != nil {
		return nil, 0, rejectKeyFileError(err)
	}
	managedFile, err := readManagedKeysFile(name)
	if err != nil {
		return nil, 0, rejectKeyFileError(err)
	}
	if managed {
		return managedFile, len(accounts.Fingerprints(accounts.ParseKeyFile(userFile))), nil
	}
	return userFile, len(accounts.Fingerprints(accounts.ParseKeyFile(managedFile))), nil
}

// writeKeyFile writes the edited file where the order says: the user's
// authorized_keys under the home, or the panel's managed file.
func (s *Server) writeKeyFile(name string, account accountRecord, managed bool, content string) *helperv1.HelperResponse {
	var err error
	if managed {
		err = writeManagedKeysFile(name, content)
	} else {
		err = writeAuthorizedKeys(account.Home, account.UID, account.GID, content)
	}
	if err != nil {
		return rejectKeyFileError(err)
	}
	return nil
}

func rejectKeyFileError(err error) *helperv1.HelperResponse {
	var symlink *symlinkError
	if errors.As(err, &symlink) {
		return reject(ErrorSymlink, err.Error())
	}
	return reject(ErrorExecFailed, err.Error())
}

// noPasswordLogin says why the account cannot log in with a password, or
// nothing when it can.
func noPasswordLogin(name string) string {
	states, err := shadowReader()
	if err != nil {
		return "its password state could not be read (" + err.Error() + ")"
	}
	state, known := states[name]
	switch {
	case !known:
		return "it has no shadow record"
	case state.locked:
		return "its password is locked"
	case !state.passwordSet:
		return "it has no password"
	}
	return ""
}

func describeFingerprints(fingerprints []string) string {
	if len(fingerprints) == 0 {
		return "no keys"
	}
	return strings.Join(fingerprints, ", ")
}

// managedKeysRoot is where the managed files live; a test points it at a
// directory of its own.
var managedKeysRoot = accounts.ManagedKeysDir

// readManagedKeysFile returns the content of the account's managed file, or
// nothing when there is none.
func readManagedKeysFile(name string) ([]byte, error) {
	path := filepath.Join(managedKeysRoot, name, accounts.ManagedKeysFileName)
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
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

// writeManagedKeysFile replaces the account's managed file atomically: a
// temporary file created exclusively next to it and renamed over it.
func writeManagedKeysFile(name, content string) error {
	root := filepath.Clean(managedKeysRoot)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", root, err)
	}
	rootFD, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
			return &symlinkError{path: root}
		}
		return fmt.Errorf("opening %s: %w", root, err)
	}
	defer unix.Close(rootFD)

	if err := unix.Mkdirat(rootFD, name, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("creating the directory of %s: %w", name, err)
	}
	dirFD, err := unix.Openat2(rootFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOTDIR) {
			return &symlinkError{path: filepath.Join(root, name)}
		}
		return fmt.Errorf("opening the directory of %s: %w", name, err)
	}
	defer unix.Close(dirFD)

	if content == "" {
		if err := unix.Unlinkat(dirFD, accounts.ManagedKeysFileName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("removing the managed file: %w", err)
		}
		return nil
	}

	const temporary = accounts.ManagedKeysFileName + ".flotestro-tmp"
	_ = unix.Unlinkat(dirFD, temporary, 0)
	fileFD, err := unix.Openat(dirFD, temporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return fmt.Errorf("creating the managed file: %w", err)
	}
	file := os.NewFile(uintptr(fileFD), filepath.Join(root, name, temporary))
	written := func() error {
		defer file.Close()
		if _, err := file.WriteString(content); err != nil {
			return err
		}
		if err := file.Chmod(0o644); err != nil {
			return err
		}
		return file.Sync()
	}()
	if written != nil {
		_ = unix.Unlinkat(dirFD, temporary, 0)
		return fmt.Errorf("writing the managed file: %w", written)
	}
	if err := unix.Renameat(dirFD, temporary, dirFD, accounts.ManagedKeysFileName); err != nil {
		_ = unix.Unlinkat(dirFD, temporary, 0)
		return fmt.Errorf("replacing the managed file: %w", err)
	}
	return nil
}
