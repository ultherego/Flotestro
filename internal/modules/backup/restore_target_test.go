package backup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The unpacking runs as root and resolves the target by name a second time,
// after the check. A component that is a symbolic link, or a directory above
// the target that somebody other than root may write, is a target that can be
// moved between the two - and root then writes wherever it was pointed.
func TestARestoreTargetThatSomebodyElseCanMoveIsRefused(t *testing.T) {
	root := t.TempDir()

	ordinary := filepath.Join(root, "restore")
	if err := os.Mkdir(ordinary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkTargetPath(ordinary); err != nil {
		t.Fatalf("an ordinary directory was refused: %v", err)
	}

	// A path that does not exist yet is nobody's to hold.
	if err := checkTargetPath(filepath.Join(ordinary, "not-yet")); err != nil {
		t.Errorf("a target that does not exist yet was refused: %v", err)
	}

	// A symbolic link anywhere in the path decides where the bytes land.
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(ordinary, linked); err != nil {
		t.Fatal(err)
	}
	if err := checkTargetPath(filepath.Join(linked, "under")); !errors.Is(err, ErrUnsafeTarget) {
		t.Errorf("a path through a symbolic link was accepted: %v", err)
	}
	if err := checkTargetPath(linked); !errors.Is(err, ErrUnsafeTarget) {
		t.Errorf("a target that is a symbolic link was accepted: %v", err)
	}

	// A directory anybody may write can be swapped between the check and the
	// extraction. A sticky one cannot: there only the owner removes an entry.
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	under := filepath.Join(open, "restore")
	if err := os.Mkdir(under, 0o755); err != nil {
		t.Fatal(err)
	}
	// The test does not run as root, so the directory is owned by the test
	// user: exactly the case the check refuses.
	if err := checkTargetPath(under); !errors.Is(err, ErrUnsafeTarget) {
		t.Errorf("a target under a world-writable directory was accepted: %v", err)
	}
	if err := os.Chmod(open, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := checkTargetPath(under); err != nil {
		t.Errorf("a target under a sticky directory was refused: %v", err)
	}
}
