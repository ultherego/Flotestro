package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ultherego/flotestro/internal/modules/certificates"
)

// The helper's state files carried Polish names before the root was translated
// to English, and a rename leaves the old file on every host that ran the
// earlier build. Measured on all four laboratory agents on 01.10: certyfikaty.json
// beside certificates.json, pliki.json beside files.json. Nothing read the old
// one, which is why it survived unnoticed - the harm is in it existing at all.
func TestWritingARegistryRetiresTheNameItUsedToHave(t *testing.T) {
	for _, c := range []struct {
		name    string
		write   func(*Server)
		current *string
		legacy  *string
	}{
		{
			name:    "files",
			write:   func(s *Server) { _ = s.writeFileRegistry(nil) },
			current: &fileRegistryPath,
			legacy:  &legacyFileRegistryPath,
		},
		{
			name:    "certificates",
			write:   func(s *Server) { s.writeCertificateRegistry([]certificates.Target{}) },
			current: &certificateRegistryPath,
			legacy:  &legacyCertificateRegistryPath,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			keepCurrent, keepLegacy := *c.current, *c.legacy
			*c.current = filepath.Join(dir, "current.json")
			*c.legacy = filepath.Join(dir, "legacy.json")
			t.Cleanup(func() { *c.current, *c.legacy = keepCurrent, keepLegacy })

			if err := os.WriteFile(*c.legacy, []byte("[]"), 0o600); err != nil {
				t.Fatal(err)
			}
			c.write(&Server{})

			if _, err := os.Stat(*c.current); err != nil {
				t.Fatalf("the registry was not written: %v", err)
			}
			if _, err := os.Stat(*c.legacy); !os.IsNotExist(err) {
				t.Errorf("the name the registry used to have is still on disk: %v", err)
			}
		})
	}
}

// The two names being equal is the state of a host that never ran the earlier
// build; removing the file then would delete the registry just written.
func TestRetiringTheLegacyNameLeavesTheCurrentOneAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "files.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	retireLegacyRegistry(path, path)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the registry was removed although the names are the same: %v", err)
	}
}
