// Package docker is the container engine adapter. The module reads the
// state through the Engine API and runs only typed operations; there is no
// "arbitrary request to Docker" operation.
//
// The agent gets no access to the Docker socket. The socket belongs to
// root, and membership in the docker group is equivalent to root - an agent
// running without privileges cannot have it. The whole conversation with
// the engine goes through the helper.
package docker

import "time"

// Container is one container seen on the host.
type Container struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
	// ImageDigest identifies the image unambiguously. A tag may point at
	// something else tomorrow, a digest does not.
	ImageDigest string    `json:"image_digest,omitempty"`
	State       string    `json:"state"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	// Health is empty when the image defines no check. No check is not the
	// same as a failed check.
	Health string            `json:"health,omitempty"`
	Ports  []Port            `json:"ports,omitempty"`
	Mounts []Mount           `json:"mounts,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
	// Compose is filled for containers managed by Compose.
	Compose *ComposeMembership `json:"compose,omitempty"`
	// Networks lists the networks the container is attached to. This is
	// how it is known which network is in use: the engine's network list
	// does not say.
	Networks []ContainerNetwork `json:"networks,omitempty"`
	// RestartCount helps to tell a healthy container from one that comes up
	// in a loop.
	RestartCount int `json:"restart_count"`
}

// ComposeMembership describes the membership of a container in a Compose
// project.
type ComposeMembership struct {
	Project     string `json:"project"`
	Service     string `json:"service"`
	ConfigFiles string `json:"config_files,omitempty"`
	WorkingDir  string `json:"working_dir,omitempty"`
}

// ContainerNetwork describes the attachment of a container to one network.
type ContainerNetwork struct {
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
	// IPv4 may be empty: a stopped container has no address, and that does
	// not mean it does not belong to the network.
	IPv4    string   `json:"ipv4,omitempty"`
	IPv6    string   `json:"ipv6,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
}

// Port is a published container port.
type Port struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port,omitempty"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// Mount is a container mount point.
type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
	Name        string `json:"name,omitempty"`
}

// Image is an image present on the host.
type Image struct {
	ID        string    `json:"id"`
	Tags      []string  `json:"tags,omitempty"`
	Digests   []string  `json:"digests,omitempty"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	// InUse says whether any container uses the image. Without it the
	// operator does not know what a prune deletes.
	InUse bool `json:"in_use"`
}

// Network is a Docker network.
type Network struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Driver   string   `json:"driver"`
	Scope    string   `json:"scope,omitempty"`
	Subnets  []string `json:"subnets,omitempty"`
	Gateways []string `json:"gateways,omitempty"`
	// Internal marks a network without an exit to the outside, Attachable -
	// a network a container from outside the service may be attached to.
	// Both change what passes through this network, so they are not a
	// detail.
	Internal   bool              `json:"internal"`
	Attachable bool              `json:"attachable"`
	IPv6       bool              `json:"ipv6"`
	Ingress    bool              `json:"ingress,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	CreatedAt  time.Time         `json:"created_at,omitempty"`
	// Predefined marks a network built into the engine - bridge, host,
	// none. The engine does not allow removing it, so the panel must not
	// propose that.
	Predefined bool `json:"predefined"`
	// Compose points at the project that created this network. A project
	// network removed by hand comes back at the next deployment, so that is
	// not cleanup.
	Compose string `json:"compose,omitempty"`
	// Containers lists the attached containers. The engine's network list
	// does not report them, so they are derived from the container list -
	// and it is they, not a flag from the engine, that decide about usage.
	Containers []NetworkMember `json:"containers,omitempty"`
	InUse      bool            `json:"in_use"`
}

// NetworkMember is a container attached to a network.
type NetworkMember struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state,omitempty"`
	IPv4  string `json:"ipv4,omitempty"`
}

// Volume is a Docker volume.
type Volume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint,omitempty"`
	Scope      string            `json:"scope,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	CreatedAt  time.Time         `json:"created_at,omitempty"`
	// Compose points at the project that created the volume.
	Compose string `json:"compose,omitempty"`
	// UsedBy lists the containers that mount this volume - stopped ones
	// included. The volume of a stopped container is not an abandoned
	// volume, and it is the abandoned one that dies in a prune.
	UsedBy []VolumeMount `json:"used_by,omitempty"`
	InUse  bool          `json:"in_use"`
	// SizeBytes may be undetermined: computing the size requires walking
	// the whole volume and the engine does not report it in every query.
	SizeBytes *int64 `json:"size_bytes,omitempty"`
	// SizeReason says why there is no size. Zero would mean an empty
	// volume, ready to be deleted - and that is entirely different
	// information.
	SizeReason string `json:"size_reason,omitempty"`
}

// VolumeMount is a volume mount in a container.
type VolumeMount struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	State         string `json:"state,omitempty"`
	Destination   string `json:"destination"`
	ReadOnly      bool   `json:"read_only"`
}

// Project is a Compose project assembled from the containers of one host.
type Project struct {
	Name        string   `json:"name"`
	ConfigFiles string   `json:"config_files,omitempty"`
	WorkingDir  string   `json:"working_dir,omitempty"`
	Services    []string `json:"services"`
	Running     int      `json:"running"`
	Total       int      `json:"total"`
}

// Summary is a light summary for the inventory. The full lists are fetched
// on request: querying the engine at every heartbeat would load the host
// for no reason.
type Summary struct {
	EngineVersion string `json:"engine_version,omitempty"`
	APIVersion    string `json:"api_version,omitempty"`
	Containers    int    `json:"containers"`
	Running       int    `json:"running"`
	Paused        int    `json:"paused"`
	Stopped       int    `json:"stopped"`
	Unhealthy     int    `json:"unhealthy"`
	// RestartLooping counts the containers that come up over and over. It
	// is a decision signal, not a metric - that is why it is in the
	// inventory.
	RestartLooping int `json:"restart_looping"`
	Images         int `json:"images"`
	Volumes        int `json:"volumes"`
	Networks       int `json:"networks"`
	// Unused volumes and networks are a cleanup signal, not a metric: they
	// take up space and they are the candidates for removal.
	VolumesUnused  int       `json:"volumes_unused"`
	NetworksUnused int       `json:"networks_unused"`
	Projects       []Project `json:"projects,omitempty"`
	// UnavailableReason says why the state could not be determined. An
	// empty engine and an engine not asked are two different pieces of
	// information.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}
