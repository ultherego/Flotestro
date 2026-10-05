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

// sshdKeyFiles says which of an account's two key files sshd on this host
// opens. Neither answer is a yes by default: a file the configuration does not
// name, a configuration that names no AuthorizedKeysFile and a configuration
// nobody could read are all unknowns.
type sshdKeyFiles struct {
	managed bool
	home    bool
	// stated is false when the effective configuration named no
	// AuthorizedKeysFile at all, so the host said nothing either way.
	stated bool
	err    error
}

// readSSHDKeyFiles asks sshd once, for both files and both directions of an
// edit.
func readSSHDKeyFiles(ctx context.Context) sshdKeyFiles {
	effective, err := effectiveSSHDConfig(ctx)
	if err != nil {
		return sshdKeyFiles{err: err}
	}
	home, stated := accounts.HomeFileReadBySSHD(effective)
	return sshdKeyFiles{
		managed: accounts.ManagedFileReadBySSHD(effective),
		home:    home,
		stated:  stated,
	}
}

// why says, for a refusal an operator reads, why the keys of a file are not a
// way into the account.
func (f sshdKeyFiles) why(path string) string {
	switch {
	case f.err != nil:
		return "the sshd configuration could not be read, so it is not known that sshd opens " +
			path + ": " + f.err.Error()
	case !f.stated:
		return "the sshd configuration names no AuthorizedKeysFile, so it is not known that " +
			"sshd opens " + path
	}
	return "sshd on this host does not read " + path
}

// sshdReadsManagedFile answers whether the effective sshd configuration lists
// the panel's managed key file among the files it takes keys from. The error is
// handed back rather than folded into a false: not being able to ask is not an
// answer, and only the caller knows whether its decision may rest on an
// unknown.
func (s *Server) sshdReadsManagedFile(ctx context.Context) (bool, error) {
	files := readSSHDKeyFiles(ctx)
	return files.managed, files.err
}

// refuseUnreadManagedFile is the refusal shared by every order that writes the
// managed file: it needs a yes, not the absence of a no, because a key in a
// file sshd does not open is not a way into the account.
func refuseUnreadManagedFile(reads bool, err error) *helperv1.HelperResponse {
	switch {
	case err != nil:
		return reject(ErrorManagedFileNotRead,
			"the sshd configuration could not be read, so it cannot be told that sshd opens "+
				accounts.ManagedKeysPattern+": "+err.Error())
	case !reads:
		return reject(ErrorManagedFileNotRead, fmt.Sprintf(
			"sshd on this host does not read %s; add it to AuthorizedKeysFile or edit the user's authorized_keys instead",
			accounts.ManagedKeysPattern))
	}
	return nil
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

	// Which files sshd opens is asked once, for both directions of the edit.
	// It used to be asked only when the order wrote to the managed file, and
	// the lockout guard then counted the keys of that file as a way into the
	// account whether sshd read it or not: removing the last key from
	// ~/.ssh/authorized_keys passed the guard because "there is still the
	// managed file", and the account was left with no way in.
	managed := action.GetManagedFile()
	sshd := readSSHDKeyFiles(ctx)

	if managed {
		if response := refuseUnreadManagedFile(sshd.managed, sshd.err); response != nil {
			return response
		}
	}

	content, other, response := s.readKeyFiles(name, account, managed, sshd)
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
	if len(change.After) == 0 && len(change.Before) > 0 && other.counted == 0 && !action.GetAllowLockout() {
		if reason := noPasswordLogin(name); reason != "" {
			// The keys the other file holds without counting are named: an
			// operator who sees "the account has keys" in the panel has to be
			// told that sshd does not open the file they are in, or that this
			// host could not be asked.
			aside := ""
			if other.uncounted > 0 {
				aside = fmt.Sprintf(" (%s holds %d key(s) that are no way in: %s)",
					other.path, other.uncounted, other.reason)
			}
			return reject(ErrorLastKeyLockout, fmt.Sprintf(
				"the order would take the last key of %s and %s, so nobody could log in as it afterwards%s; "+
					"add the new key first, or order the removal with allow_lockout if cutting the account off is the intent",
				name, reason, aside))
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

// otherKeyFile is the key file an order does not edit: how many of its keys are
// a way into the account, how many it holds without being one, and why, so a
// refusal can say so.
type otherKeyFile struct {
	path      string
	counted   int
	uncounted int
	reason    string
}

// readKeyFiles returns the file the order edits and what the other one
// contributes as a way into the account.
func (s *Server) readKeyFiles(name string, account accountRecord,
	managed bool, sshd sshdKeyFiles) ([]byte, otherKeyFile, *helperv1.HelperResponse) {
	userFile, err := readAuthorizedKeysFile(account.Home)
	if err != nil {
		return nil, otherKeyFile{}, rejectKeyFileError(err)
	}
	managedFile, err := readManagedKeysFile(name)
	if err != nil {
		return nil, otherKeyFile{}, rejectKeyFileError(err)
	}
	// Neither file counts unless sshd opens it on this host. The home file used
	// to count unconditionally, so on a host whose AuthorizedKeysFile names the
	// managed pattern alone the guard let the last key sshd does reach be taken
	// away while an unread home key made the count look non-zero.
	if managed {
		return managedFile, countOtherKeys(filepath.Join(account.Home, accounts.HomeKeysPath),
			userFile, sshd.home, sshd), nil
	}
	return userFile, countOtherKeys(accounts.ManagedKeysPattern, managedFile, sshd.managed, sshd), nil
}

// countOtherKeys splits the keys of the file the order does not edit into the
// ones that are a way into the account and the ones that are not.
func countOtherKeys(path string, content []byte, read bool, sshd sshdKeyFiles) otherKeyFile {
	held := len(accounts.Fingerprints(accounts.ParseKeyFile(content)))
	if read {
		return otherKeyFile{path: path, counted: held}
	}
	return otherKeyFile{path: path, uncounted: held, reason: sshd.why(path)}
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

// removeManagedKeysFile takes the panel's key file of an account away, and the
// directory of that account with it when nothing else is in it. A root that is
// not there holds no file: that is nothing to remove, not something to create.
// The path is walked without following a link, as the write does.
func removeManagedKeysFile(name string) error {
	root := filepath.Clean(managedKeysRoot)
	rootFD, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
		return nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EXDEV):
		return &symlinkError{path: root}
	case err != nil:
		return fmt.Errorf("opening %s: %w", root, err)
	}
	defer unix.Close(rootFD)

	dirFD, err := unix.Openat2(rootFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
		return nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EXDEV):
		return &symlinkError{path: filepath.Join(root, name)}
	case err != nil:
		return fmt.Errorf("opening the directory of %s: %w", name, err)
	}
	if err := unix.Unlinkat(dirFD, accounts.ManagedKeysFileName, 0); err != nil &&
		!errors.Is(err, unix.ENOENT) {
		unix.Close(dirFD)
		return fmt.Errorf("removing the managed file of %s: %w", name, err)
	}
	unix.Close(dirFD)
	// A directory that still holds something is left where it is: what had to
	// go is gone, and the rest is not this order's to decide.
	if err := unix.Unlinkat(rootFD, name, unix.AT_REMOVEDIR); err != nil &&
		!errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTEMPTY) {
		return fmt.Errorf("removing the directory of %s: %w", name, err)
	}
	return nil
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
