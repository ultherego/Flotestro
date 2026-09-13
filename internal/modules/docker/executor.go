package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Result describes the result of an operation on the container engine.
//
// The state before and after is always recorded, also on error: without it
// the operator does not know what managed to change before the operation
// failed.
type Result struct {
	Before *Container `json:"before,omitempty"`
	After  *Container `json:"after,omitempty"`
	// Removed lists the objects that vanished. A prune is meant to say what
	// exactly it removed, not how many objects.
	Removed []string `json:"removed,omitempty"`
	// ReclaimedBytes is the total reclaimed space. No value means the
	// engine did not report it - zero would mean nothing was reclaimed.
	ReclaimedBytes *int64 `json:"reclaimed_bytes,omitempty"`
	// ImageDigest points at what was really pulled. A tag may point at a
	// different image tomorrow, a digest does not.
	ImageDigest string `json:"image_digest,omitempty"`
}

// StartContainer starts a container.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	return c.post(ctx, "/containers/"+id+"/start", nil)
}

// StopContainer stops a container, giving it time to shut down. Zero means
// the engine default, not an immediate kill.
func (c *Client) StopContainer(ctx context.Context, id string, timeoutSeconds uint32) error {
	query := url.Values{}
	if timeoutSeconds > 0 {
		query.Set("t", strconv.FormatUint(uint64(timeoutSeconds), 10))
	}
	return c.post(ctx, "/containers/"+id+"/stop", query)
}

// RestartContainer restarts a container.
func (c *Client) RestartContainer(ctx context.Context, id string, timeoutSeconds uint32) error {
	query := url.Values{}
	if timeoutSeconds > 0 {
		query.Set("t", strconv.FormatUint(uint64(timeoutSeconds), 10))
	}
	return c.post(ctx, "/containers/"+id+"/restart", query)
}

// RemoveContainer removes a container. Volumes vanish only when the
// operator explicitly asked for it: a volume outlives the container so that
// the data survives.
func (c *Client) RemoveContainer(ctx context.Context, id string, removeVolumes bool) error {
	query := url.Values{}
	if removeVolumes {
		query.Set("v", "1")
	}
	return c.call(ctx, http.MethodDelete, "/containers/"+id, query, nil)
}

// PullImage pulls an image and returns its digest.
func (c *Client) PullImage(ctx context.Context, reference string) (string, error) {
	query := url.Values{}
	query.Set("fromImage", reference)
	// The engine streams the pull progress as a sequence of JSON objects;
	// the content is not needed, so it is read to the end and discarded.
	// Reading to the end matters: breaking the connection half-way aborts
	// the pull.
	if err := c.post(ctx, "/images/create", query); err != nil {
		return "", err
	}
	var details struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
	}
	if err := c.get(ctx, "/images/"+url.PathEscape(reference)+"/json", nil, &details); err != nil {
		// The image was pulled; a missing digest does not invalidate the
		// operation.
		return "", nil
	}
	if len(details.RepoDigests) > 0 {
		return details.RepoDigests[0], nil
	}
	return details.ID, nil
}

// RemoveImage removes an image.
//
// The engine returns the list of layers that vanished, but not their size -
// the reclaimed space is computed from the sizes gathered before removal.
func (c *Client) RemoveImage(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, "/images/"+url.PathEscape(id), nil, nil)
}

// RemoveVolume removes a volume.
func (c *Client) RemoveVolume(ctx context.Context, name string) error {
	return c.call(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(name), nil, nil)
}

// RemoveNetwork removes a network.
func (c *Client) RemoveNetwork(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, "/networks/"+id, nil, nil)
}

// ContainerByID returns the container with the given identifier or nil.
// Used to record the state before and after an operation.
func (c *Client) ContainerByID(ctx context.Context, id string) *Container {
	containers, err := c.Containers(ctx, true)
	if err != nil {
		return nil
	}
	for i := range containers {
		if containers[i].ID == id {
			container := containers[i]
			if health, restarts, err := c.Inspect(ctx, id); err == nil {
				container.Health = health
				container.RestartCount = restarts
			}
			return &container
		}
	}
	return nil
}

// post performs an operation changing the engine state.
func (c *Client) post(ctx context.Context, path string, query url.Values) error {
	return c.call(ctx, http.MethodPost, path, query, nil)
}

// Prune removes only the named objects.
//
// A prune by filter removes what matches at execution time - so also an
// object created after the operator viewed the preview. The list is
// therefore explicit: exactly what was shown is removed.
func Prune(ctx context.Context, client *Client, images, volumes, networks []string) (Result, error) {
	result := Result{}
	var reclaimed int64
	var sizesKnown bool

	// The host state is read before removal - and in order to be able to
	// refuse. The engine would refuse itself, but with an HTTP conflict
	// message; the operator is meant to get the names of the containers
	// that use the object.
	state := Snapshot{}
	if len(volumes) > 0 || len(networks) > 0 {
		var err error
		if state, err = pruneState(ctx, client); err != nil {
			return result, err
		}
		if err := checkPrune(state, volumes, networks); err != nil {
			return result, err
		}
	}

	// Sizes are computed before removal: afterwards there is nothing left
	// to measure.
	sizes := map[string]int64{}
	if list, err := client.Images(ctx); err == nil {
		for _, image := range list {
			sizes[image.ID] = image.SizeBytes
		}
	}
	volumeSizes := map[string]int64{}
	for _, volume := range state.Volumes {
		if volume.SizeBytes != nil {
			volumeSizes[volume.Name] = *volume.SizeBytes
		}
	}

	for _, id := range images {
		if err := client.RemoveImage(ctx, id); err != nil {
			return result, fmt.Errorf("image %s: %w", shortID(id), err)
		}
		result.Removed = append(result.Removed, "image "+shortID(id))
		if size, ok := sizes[id]; ok {
			reclaimed += size
			sizesKnown = true
		}
	}
	for _, name := range volumes {
		if err := client.RemoveVolume(ctx, name); err != nil {
			return result, fmt.Errorf("volume %s: %w", name, err)
		}
		result.Removed = append(result.Removed, "volume "+name)
		if size, ok := volumeSizes[name]; ok {
			reclaimed += size
			sizesKnown = true
		}
	}
	for _, id := range networks {
		if err := client.RemoveNetwork(ctx, id); err != nil {
			return result, fmt.Errorf("network %s: %w", shortID(id), err)
		}
		result.Removed = append(result.Removed, "network "+shortID(id))
	}

	// Unknown reclaimed space stays unknown. Zero would mean the prune
	// gained nothing.
	if sizesKnown {
		result.ReclaimedBytes = &reclaimed
	}
	return result, nil
}

// Prune refusal errors. They are part of the contract: the helper
// translates them into codes the panel shows the operator.
var (
	// ErrInUse means an object a container uses. Removing a volume in use
	// is data loss for a running service.
	ErrInUse = errors.New("the object is in use")
	// ErrPredefinedNetwork means a network belonging to the engine. The
	// engine does not allow removing it and there is no reason to try.
	ErrPredefinedNetwork = errors.New("engine predefined network")
	// ErrNotFound means an object the host does not have. Silence would be
	// worse: the operator would think they removed something.
	ErrNotFound = errors.New("the object does not exist on this host")
)

// pruneState reads what decides the admissibility of a prune: the network
// and volume lists together with the usage derived from the containers.
func pruneState(ctx context.Context, client *Client) (Snapshot, error) {
	state := Snapshot{}
	containers, err := client.Containers(ctx, true)
	if err != nil {
		return state, fmt.Errorf("container list: %w", err)
	}
	state.Containers = containers
	if networks, err := client.Networks(ctx); err == nil {
		state.Networks = networks
	} else {
		return state, fmt.Errorf("network list: %w", err)
	}
	if list, err := client.Volumes(ctx); err == nil {
		state.Volumes = list
	} else {
		return state, fmt.Errorf("volume list: %w", err)
	}
	linkUsage(&state)
	return state, nil
}

// checkPrune refuses before anything vanishes.
//
// A prune is one operation: if the first volume vanished and the second
// turned out to be busy, the operator would be left with a half-way state.
// That is why the whole list is checked up front.
func checkPrune(state Snapshot, volumes, networks []string) error {
	for _, name := range volumes {
		volume := volumeByName(state.Volumes, name)
		if volume == nil {
			return fmt.Errorf("volume %s: %w", name, ErrNotFound)
		}
		if volume.InUse {
			return fmt.Errorf("the volume %s is mounted by %s: %w",
				name, volumeContainerNames(*volume), ErrInUse)
		}
	}
	for _, id := range networks {
		network := networkByID(state.Networks, id)
		if network == nil {
			return fmt.Errorf("network %s: %w", shortID(id), ErrNotFound)
		}
		if network.Predefined {
			return fmt.Errorf("network %s: %w", network.Name, ErrPredefinedNetwork)
		}
		if network.InUse {
			return fmt.Errorf("the network %s has %s attached: %w",
				network.Name, networkContainerNames(*network), ErrInUse)
		}
	}
	return nil
}

func volumeByName(list []Volume, name string) *Volume {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

func networkByID(list []Network, id string) *Network {
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}

func volumeContainerNames(volume Volume) string {
	names := make([]string, 0, len(volume.UsedBy))
	for _, usage := range volume.UsedBy {
		names = append(names, usage.ContainerName)
	}
	return strings.Join(names, ", ")
}

func networkContainerNames(network Network) string {
	names := make([]string, 0, len(network.Containers))
	for _, container := range network.Containers {
		names = append(names, container.Name)
	}
	return strings.Join(names, ", ")
}

// shortID shortens an identifier to a length readable in an operation
// result.
func shortID(id string) string {
	id = trimAlgorithm(id)
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func trimAlgorithm(id string) string {
	if len(id) > 7 && id[:7] == "sha256:" {
		return id[7:]
	}
	return id
}
