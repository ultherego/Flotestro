package packages

import (
	"os"
	"path/filepath"
	"testing"
)

// A module directory replaced by an empty directory is the signature of a
// namespace with ProtectKernelModules. A transaction in such an environment
// produces an initramfs without drivers, so it has to be rejected before it
// starts.
func TestHiddenKernelModulesAreDetected(t *testing.T) {
	root := t.TempDir()
	proc := writeProc(t, root, "dm_mod 200704 1 - Live 0x0000000000000000\n")

	empty := filepath.Join(root, "modules")
	if err := os.MkdirAll(filepath.Join(empty, "6.12.48"), 0o755); err != nil {
		t.Fatal(err)
	}
	if hidden, dir := modulesHiddenAt(proc, empty, "6.12.48"); !hidden {
		t.Fatalf("an empty module directory was not treated as hidden (%q)", dir)
	}

	missing := filepath.Join(root, "missing")
	if hidden, _ := modulesHiddenAt(proc, missing, "6.12.48"); !hidden {
		t.Fatal("a missing module directory was not treated as hidden")
	}
}

// A visible module tree must not block an upgrade.
func TestVisibleModulesDoNotBlockATransaction(t *testing.T) {
	root := t.TempDir()
	proc := writeProc(t, root, "dm_mod 200704 1 - Live 0x0000000000000000\n")

	modules := filepath.Join(root, "modules", "6.12.48", "kernel")
	if err := os.MkdirAll(modules, 0o755); err != nil {
		t.Fatal(err)
	}
	if hidden, dir := modulesHiddenAt(proc, filepath.Join(root, "modules"), "6.12.48"); hidden {
		t.Fatalf("visible modules were treated as hidden (%q)", dir)
	}
}

// A kernel without modules is a valid environment - a container image or a
// monolithic kernel. Blocking such a host would be a false alarm.
func TestAKernelWithoutModulesIsNotBlocked(t *testing.T) {
	root := t.TempDir()
	proc := writeProc(t, root, "")

	if hidden, _ := modulesHiddenAt(proc, filepath.Join(root, "missing"), "6.12.48"); hidden {
		t.Fatal("a monolithic kernel was treated as an environment with hidden modules")
	}
}

// An unknown kernel version is not proof of hidden modules.
func TestAnUnknownKernelVersionDoesNotBlock(t *testing.T) {
	root := t.TempDir()
	proc := writeProc(t, root, "dm_mod 200704 1 - Live 0x0000000000000000\n")

	if hidden, _ := modulesHiddenAt(proc, filepath.Join(root, "modules"), ""); hidden {
		t.Fatal("a missing kernel version blocked the transaction")
	}
}

func writeProc(t *testing.T, root, content string) string {
	t.Helper()
	path := filepath.Join(root, "proc-modules")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
