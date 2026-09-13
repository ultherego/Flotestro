// Package compose handles Docker Compose projects.
//
// The manifest describes the desired state of the project, not a command
// to run. The plan computes the difference between what runs and what the
// manifest describes; the deployment is bound to a specific plan and
// refuses when the base state changed since approval.
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
	// ImageDigest is filled when the image is already on the host. Empty
	// means an image yet to be pulled - and then it cannot be said up front
	// what exactly will come up.
	ImageDigest string `json:"image_digest,omitempty"`
	Replicas    int    `json:"replicas,omitempty"`
}

// Plan describes what the deployment changes on the host.
type Plan struct {
	Project string `json:"project"`
	// Digest binds the deployment to this plan. Computed from the
	// normalised manifest and the image digests, so a change of either
	// invalidates the approval.
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
