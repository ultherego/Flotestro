package files

import (
	"os"
	"path/filepath"
	"testing"
)

// Describe is where the panel learns who owns a managed file, and an update
// that leaves the owner out falls back on what Describe said. For as long as
// it reported nothing, "not named" meant "given to root" on every write.
func TestDescribeNamesTheOwnerOfTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("x\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	description := Describe(path)
	if description.UnavailableReason != "" {
		t.Fatalf("the file was not described: %s", description.UnavailableReason)
	}
	if !description.Exists {
		t.Fatal("the file this test wrote was described as absent")
	}
	if description.Owner == "" {
		t.Error("the description names no owner, so a write that leaves the owner " +
			"out has nothing to keep it from")
	}
	if description.Group == "" {
		t.Error("the description names no group")
	}
}
