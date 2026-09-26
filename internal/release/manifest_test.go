package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "release-manifest.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const good = `{
  "schema_version": 1,
  "version": "0.62.0",
  "commit": "2f6a49f0000000000000000000000000000000ab",
  "created_at": "2026-09-26T20:00:00Z",
  "images": {
    "control_plane": {"reference": "ghcr.io/ultherego/flotestro-control-plane",
      "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
    "relay": {"reference": "ghcr.io/ultherego/flotestro-relay",
      "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"}
  }
}`

func TestAManifestNamesEachImageByDigest(t *testing.T) {
	manifest, err := Load(write(t, good))
	if err != nil {
		t.Fatalf("a manifest this release would publish was refused: %v", err)
	}
	if manifest.Version != "0.62.0" {
		t.Errorf("version = %q", manifest.Version)
	}
	pinned, named := manifest.Image(ComponentRelay)
	if !named {
		t.Fatal("the manifest names a relay image and Image did not find it")
	}
	if want := "ghcr.io/ultherego/flotestro-relay@sha256:2222222222222222222222222222222222222222222222222222222222222222"; pinned != want {
		t.Errorf("pinned = %q", pinned)
	}
	// A component the manifest does not name is unknown, and saying so is the
	// point: a deployment must not be handed a reference nobody wrote down.
	if _, named := manifest.Image(ComponentAdminTools); named {
		t.Error("a component the manifest does not name was reported as named")
	}
}

// TestAManifestNobodyCanVouchForIsRefused: a file that is there and wrong is an
// error. An installation told where its manifest is must not quietly go on
// naming no image, because the answer would be an instruction that cannot work.
func TestAManifestNobodyCanVouchForIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"a later schema": strings.Replace(good, `"schema_version": 1`, `"schema_version": 2`, 1),
		"no version":     strings.Replace(good, `"version": "0.62.0"`, `"version": ""`, 1),
		"a digest that is not sha256": strings.Replace(good,
			"sha256:2222222222222222222222222222222222222222222222222222222222222222", "latest", 1),
		"a reference carrying its own tag": strings.Replace(good,
			`"reference": "ghcr.io/ultherego/flotestro-relay"`,
			`"reference": "ghcr.io/ultherego/flotestro-relay:0.62.0"`, 1),
		"not JSON at all": "{",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a manifest that is not there was accepted")
	}
}
