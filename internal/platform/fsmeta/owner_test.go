package fsmeta

import (
	"os"
	"path/filepath"
	"testing"
)

// The owner of a file this test has just written is one it knows. A reader
// that cannot name it is a reader every ownership check above it skips, and
// four of those checks went unnoticed for as long as this test did not exist.
func TestTheOwnerOfARealFileIsRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, ok := Owner(info)
	if !ok {
		t.Fatal("the owner of a file written by this test was not read")
	}
	if uid != os.Getuid() || gid != os.Getgid() {
		t.Errorf("owner %d:%d, want %d:%d", uid, gid, os.Getuid(), os.Getgid())
	}
}

// A directory answers the same way: the callers ask about a home directory as
// readily as about a file.
func TestTheOwnerOfADirectoryIsRead(t *testing.T) {
	info, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := Owner(info); !ok {
		t.Fatal("the owner of a directory was not read")
	}
}

// Nothing described means nothing known, and the caller has to be able to see
// the difference between that and ownership by root.
func TestNothingDescribedIsNotOwnedByRoot(t *testing.T) {
	uid, gid, ok := Owner(nil)
	if ok {
		t.Fatal("a missing description answered as if it named an owner")
	}
	if uid != -1 || gid != -1 {
		t.Errorf("unread ownership came back as %d:%d, want -1:-1", uid, gid)
	}
}
