// Package release reads the manifest a release publishes beside its artefacts:
// which image each component of the installation is, pinned by digest.
//
// The panel does not know its own digest and cannot: the digest exists only once
// the image has been built, so a panel that carried its own would have to be
// built after itself. It is told instead, by a manifest signed with the rest of
// the release.
package release

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// SchemaVersion is the shape this code understands. A manifest from a later
// release may say more, and one that says a different number is refused rather
// than read as if the fields meant the same.
const SchemaVersion = 1

// Image is one component's image: where it lives and which build it is.
type Image struct {
	// Reference is the repository without a tag or a digest.
	Reference string `json:"reference"`
	// Digest is what pins it, as "sha256:" and sixty-four hex digits.
	Digest string `json:"digest"`
}

// Pinned is the reference a deployment uses: the repository and the digest, so
// that a tag moved later changes nothing.
func (i Image) Pinned() string { return i.Reference + "@" + i.Digest }

// Manifest is what a release says about its images.
type Manifest struct {
	SchemaVersion int              `json:"schema_version"`
	Version       string           `json:"version"`
	Commit        string           `json:"commit"`
	CreatedAt     time.Time        `json:"created_at"`
	Images        map[string]Image `json:"images"`
}

// The components a manifest is expected to name.
const (
	ComponentControlPlane = "control_plane"
	ComponentRelay        = "relay"
	ComponentAdminTools   = "admin_tools"
)

// digest is what a manifest may write as one: sha256 and nothing else, because
// a deployment that accepts any algorithm accepts one nobody checked.
var digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Image returns the pinned reference of one component, and whether the manifest
// names it. A component the manifest does not name is unknown, which is not the
// same as absent from the release.
func (m Manifest) Image(component string) (string, bool) {
	image, named := m.Images[component]
	if !named || image.Reference == "" || image.Digest == "" {
		return "", false
	}
	return image.Pinned(), true
}

// Load reads a manifest and refuses one it cannot vouch for. A file that is
// there and wrong is an error, not an absence: an installation told where its
// manifest is must not fall back to naming no image at all.
func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("reading the release manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("the release manifest %s is not valid JSON: %w", path, err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		return Manifest{}, fmt.Errorf(
			"the release manifest %s declares schema_version %d; this panel reads %d",
			path, manifest.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return Manifest{}, fmt.Errorf("the release manifest %s names no version", path)
	}
	if len(manifest.Images) == 0 {
		return Manifest{}, fmt.Errorf("the release manifest %s names no image", path)
	}
	for component, image := range manifest.Images {
		if strings.TrimSpace(image.Reference) == "" {
			return Manifest{}, fmt.Errorf("the release manifest %s gives %s no reference", path, component)
		}
		if strings.ContainsAny(image.Reference, "@: ") {
			return Manifest{}, fmt.Errorf(
				"the reference of %s in %s carries a tag or a digest (%q); the digest is its own field",
				component, path, image.Reference)
		}
		if !digest.MatchString(image.Digest) {
			return Manifest{}, fmt.Errorf(
				"the digest of %s in %s is %q; it has to be sha256 and sixty-four hex digits",
				component, path, image.Digest)
		}
	}
	return manifest, nil
}
