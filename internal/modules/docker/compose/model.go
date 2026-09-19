// Package compose handles Docker Compose projects. The manifest describes the
// desired state of the project, not a command to run.
package compose

import "time"

// Change describes one change the deployment will bring.
type Change struct {
	// Kind is the object kind: container, network, volume, image.
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Action says what happens to it: create, recreate, start, stop, remove
	// or pull.
	Action string `json:"action"`
}

// Service is a project service after the manifest normalisation.
type Service struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	// ImageDigest is the digest the tag resolved to when the plan was computed -
	// from the reference itself when it is pinned, from the registry, or from the
	// image already on the host.
	ImageDigest string `json:"image_digest,omitempty"`
	// DigestSource names where the digest came from: reference, registry
	// or local.
	DigestSource string `json:"digest_source,omitempty"`
	// PinnedImage is the reference the deployment uses: the repository with
	// the digest instead of the tag.
	PinnedImage string `json:"pinned_image,omitempty"`
	Replicas    int    `json:"replicas,omitempty"`
}

// Sources of an image digest.
const (
	DigestFromReference = "reference"
	DigestFromRegistry  = "registry"
	DigestFromLocal     = "local"
)

// Plan describes what the deployment changes on the host.
type Plan struct {
	Project string `json:"project"`
	// Digest binds the deployment to this plan.
	Digest   string    `json:"digest"`
	Services []Service `json:"services"`
	Changes  []Change  `json:"changes"`
	// Warnings tell about things that do not block the deployment, but the
	// operator is meant to know about them before approving.
	Warnings []string `json:"warnings,omitempty"`
	// Current describes the project state before the change.
	Current []Service `json:"current,omitempty"`
	// UnavailableReason says why the plan could not be computed.
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
	ComputedAt        time.Time `json:"computed_at"`
}

// ImageDigests maps every service to the digest the plan bound it to.
func (p Plan) ImageDigests() map[string]string {
	digests := make(map[string]string, len(p.Services))
	for _, service := range p.Services {
		digests[service.Name] = service.ImageDigest
	}
	return digests
}

// Result describes the deployment result.
type Result struct {
	Project string `json:"project"`
	Digest  string `json:"digest"`
	// Applied lists the changes reported by the engine during the
	// deployment.
	Applied []Change  `json:"applied,omitempty"`
	Before  []Service `json:"before,omitempty"`
	After   []Service `json:"after,omitempty"`
	// Output is the tail of the tool output on failure.
	Output []string `json:"output,omitempty"`
}
