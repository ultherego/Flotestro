package files

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Fingerprint computes the digest of file content.
func Fingerprint(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// ValidateMode checks the permissions given as an octal number.
func ValidateMode(mode string) (os.FileMode, error) {
	if mode == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(mode, 8, 32)
	if err != nil || value > 0o7777 {
		return 0, fmt.Errorf("invalid permissions %q", mode)
	}
	// A world-writable configuration file is a way for every user of the
	// host to change the behaviour of a service.
	if value&0o002 != 0 {
		return 0, fmt.Errorf("the permissions %q allow every user of the host to write", mode)
	}
	if value&0o4000 != 0 || value&0o2000 != 0 {
		return 0, fmt.Errorf("the permissions %q set setuid or setgid", mode)
	}
	return os.FileMode(value), nil
}

// Ownership returns the user and group identifiers.
//
// Empty names mean "leave as is": the panel does not rewrite the owner of a
// file whose owner nobody asked about.
func Ownership(username, group string) (int, int, error) {
	uid, gid := -1, -1
	if username != "" {
		entry, err := user.Lookup(username)
		if err != nil {
			return 0, 0, fmt.Errorf("the user %q does not exist on this host", username)
		}
		uid, _ = strconv.Atoi(entry.Uid)
	}
	if group != "" {
		entry, err := user.LookupGroup(group)
		if err != nil {
			return 0, 0, fmt.Errorf("the group %q does not exist on this host", group)
		}
		gid, _ = strconv.Atoi(entry.Gid)
	}
	return uid, gid, nil
}

// WriteAtomically writes a file so that nobody sees it half-written.
//
// The order matters and is the whole point here: the permissions and the
// owner are set on the new file before it takes the place of the old one.
// The reverse order leaves a window in which the configuration file already
// sits in place with default permissions - and that is enough for somebody
// to read or replace it.
//
// At the end the file and the directory are synced: without that the change
// is lost on a power failure, and a configuration file is read precisely
// after such an event.
func WriteAtomically(path string, content []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	temporary := filepath.Join(dir, ".flotestro-"+filepath.Base(path)+".new")
	_ = os.Remove(temporary)

	fileMode := mode
	if fileMode == 0 {
		fileMode = 0o644
		if info, err := os.Stat(path); err == nil {
			// An existing file keeps its permissions when nobody asked for a
			// change: writing content is not a decision about access.
			fileMode = info.Mode().Perm()
		}
	}

	file, err := OpenWithoutSymlinks(temporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, uint32(fileMode))
	if err != nil {
		return err
	}
	removeOnError := func(err error) error {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if _, err := file.Write(content); err != nil {
		return removeOnError(err)
	}
	// The permissions are set explicitly: the host umask trims the mode
	// given at creation.
	if err := file.Chmod(fileMode); err != nil {
		return removeOnError(err)
	}
	if uid >= 0 || gid >= 0 {
		if err := file.Chown(uid, gid); err != nil {
			return removeOnError(err)
		}
	}
	if err := file.Sync(); err != nil {
		return removeOnError(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}

	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	// The rename itself is atomic, but without syncing the directory it may
	// not survive a power failure - and then the old content is left under
	// the new name.
	handle, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer handle.Close()
	return handle.Sync()
}

// Describe gathers the file metadata without reading its content.
func Describe(path string) File {
	description := File{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return description
		}
		description.UnavailableReason = err.Error()
		return description
	}
	description.Exists = true
	description.SizeBytes = info.Size()
	description.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	modified := info.ModTime()
	description.ModifiedAt = &modified
	if stat, ok := info.Sys().(*unix.Stat_t); ok {
		description.Owner = userName(int(stat.Uid))
		description.Group = groupName(int(stat.Gid))
	}
	// A symlink is not a configuration file, only a pointer to another
	// file. The panel does not read it and does not pretend to know its
	// content.
	if info.Mode()&os.ModeSymlink != 0 {
		description.UnavailableReason = "the path is a symbolic link"
	}
	return description
}

func userName(uid int) string {
	if entry, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return entry.Username
	}
	return strconv.Itoa(uid)
}

func groupName(gid int) string {
	if entry, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		return entry.Name
	}
	return strconv.Itoa(gid)
}

// ValidateContent checks what can be checked without running anything.
func ValidateContent(content string) error {
	if len(content) > MaxSize {
		return fmt.Errorf("the content is bigger than %d bytes; this is not a configuration file",
			MaxSize)
	}
	if strings.ContainsRune(content, 0) {
		return fmt.Errorf("the content contains a zero byte; this is not a text file")
	}
	return nil
}
