// Package fsmeta reads the file metadata the standard library leaves behind
// an interface value.
package fsmeta

import (
	"os"
	"syscall"
)

// Owner returns the user and group that own the file the description belongs
// to. The last value says whether the host answered at all; an owner that was
// not read is not owner zero, which is root.
//
// Sys() of an os.FileInfo is a *syscall.Stat_t on Linux. The identically
// shaped golang.org/x/sys/unix.Stat_t is a different named type, so asserting
// to it never succeeds - it compiles, it never panics, and every check behind
// it silently stops running.
func Owner(info os.FileInfo) (uid, gid int, ok bool) {
	if info == nil {
		return -1, -1, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
