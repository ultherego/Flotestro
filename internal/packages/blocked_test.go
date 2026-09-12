package packages

import (
	"os"
	"path/filepath"
	"testing"
)

// TestThePackageStatesFromTheDpkgDatabase guards the recognition of the
// packages that will block every following transaction. The typical case from
// a fleet: a package unpacked but not configured, because its configuration
// question has no answer. As long as it stands like that, the upgrades on this
// host do not go through - also when there is nothing to upgrade.
func TestThePackageStatesFromTheDpkgDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	content := `Package: bash
Status: install ok installed
Version: 5.2

Package: grub-pc
Status: install ok unpacked
Version: 2.12

Package: cpp
Status: deinstall ok config-files
Version: 4:14.2

Package: libfoo
Status: install ok half-configured
Version: 1.0

Package: bar
Status: purge ok not-installed

Package: damaged
Version: without a status
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	blocked := blockedFromStatusFile(path)
	names := map[string]string{}
	for _, pkg := range blocked {
		names[pkg.Name] = pkg.Status
	}

	if len(blocked) != 2 {
		t.Fatalf("recognised %d blocking packages: %v", len(blocked), names)
	}
	if names["grub-pc"] != "install ok unpacked" {
		t.Errorf("grub-pc: status %q", names["grub-pc"])
	}
	if _, ok := names["libfoo"]; !ok {
		t.Error("a package in the half-configured state has to be recognised")
	}
	// A fully installed package and a package after removal block nothing.
	for _, quiet := range []string{"bash", "cpp", "bar"} {
		if _, ok := names[quiet]; ok {
			t.Errorf("the package %s blocks nothing", quiet)
		}
	}

	// A missing file must neither pretend that everything is fine nor topple
	// the read: we return an empty list and go on.
	if blocked := blockedFromStatusFile(filepath.Join(t.TempDir(), "absent")); blocked != nil {
		t.Errorf("a missing file gave %v", blocked)
	}
}
