package app

import (
	"path/filepath"
	"testing"
)

// The backup of a key migration must not live in the directory the migration
// is about to empty. forget-files copies the key files there and then removes
// the originals; a copy in the same directory is not a copy of anything.
func TestABackupInsideTheStateDirectoryIsRefused(t *testing.T) {
	state := t.TempDir()
	elsewhere := t.TempDir()
	for _, test := range []struct {
		name     string
		backupTo string
		refused  bool
	}{
		{"a directory of its own", elsewhere, false},
		{"the state directory itself", state, true},
		{"a directory under it", filepath.Join(state, "backups"), true},
		{"a path that only looks like it", state + "-backups", false},
		{"the way back out of it", filepath.Join(state, "..", filepath.Base(elsewhere)), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			inside, err := within(state, test.backupTo)
			if err != nil {
				t.Fatal(err)
			}
			if inside != test.refused {
				t.Errorf("%s inside %s = %v", test.backupTo, state, inside)
			}
		})
	}
}
