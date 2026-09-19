//go:build linux

package identitystore

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace moves a directory under a name that must be free.
func renameNoReplace(oldPath, newPath string) error {
	err := unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EEXIST), errors.Is(err, unix.ENOTEMPTY):
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: os.ErrExist}
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.ENOTSUP):
		return renameNoReplaceFallback(oldPath, newPath)
	default:
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: err}
	}
}
