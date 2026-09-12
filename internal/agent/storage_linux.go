//go:build linux

package agent

import (
	"syscall"

	"github.com/ultherego/flotestro/internal/modules/storage"
)

// fillUsage adds the usage of space and of inodes.
//
// Exhausted inodes look like a full disk although there is still space - and
// the other way round. These are two different failures and the panel is to
// tell them apart instead of showing one number.
func fillUsage(mounts []storage.Mount) {
	for i := range mounts {
		if !mounts[i].Mounted {
			continue
		}
		var stat syscall.Statfs_t
		if err := syscall.Statfs(mounts[i].Target, &stat); err != nil {
			// A filesystem that could not be queried stays without numbers: a
			// zero would look like an empty filesystem.
			continue
		}
		size := stat.Blocks * uint64(stat.Bsize)
		available := stat.Bavail * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		if size > 0 && free <= size {
			used := size - free
			percent := uint32(used * 100 / size)
			mounts[i].UsedPercent = &percent
			mounts[i].SizeBytes = &size
			mounts[i].AvailBytes = &available
		}
		// Network and shared filesystems report an invented number of inodes:
		// vboxsf reports more free than total. A subtraction would then give a
		// meaningless number, so the state stays unknown - because that is what
		// it really is.
		if stat.Files > 0 && stat.Ffree <= stat.Files {
			used := stat.Files - stat.Ffree
			percent := uint32(used * 100 / stat.Files)
			mounts[i].InodesUsedPercent = &percent
		}
	}
}
