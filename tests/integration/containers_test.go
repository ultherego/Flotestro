//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"
)

type containerView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Networks []struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		IPv4 string `json:"ipv4"`
	} `json:"networks"`
	Mounts []struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"mounts"`
}

type dockerNetworkView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Predefined bool   `json:"predefined"`
	InUse      bool   `json:"in_use"`
	Containers []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"containers"`
}

type volumeView struct {
	Name       string `json:"name"`
	InUse      bool   `json:"in_use"`
	SizeBytes  *int64 `json:"size_bytes"`
	SizeReason string `json:"size_reason"`
	UsedBy     []struct {
		ContainerName string `json:"container_name"`
		Destination   string `json:"destination"`
		State         string `json:"state"`
	} `json:"used_by"`
}

type engineState struct {
	Summary struct {
		NetworksUnused int `json:"networks_unused"`
		VolumesUnused  int `json:"volumes_unused"`
	} `json:"summary"`
	Containers []containerView     `json:"containers"`
	Networks   []dockerNetworkView `json:"networks"`
	Volumes    []volumeView        `json:"volumes"`
}

const containersReason = "integration test of networks and volumes"

// TestNetworkAndVolumeUsageFollowsFromContainers guards the property
// without which this tab lies: the engine returns an empty container map in
// the network list, and gives the volume size and reference count only in a
// separate disk usage call. Usage must therefore be computed from the
// containers - otherwise every network and every volume would look
// abandoned and end up under cleanup.
func TestNetworkAndVolumeUsageFollowsFromContainers(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostEngineState(t, h, host.ID)

	// Every attachment reported by a container is to be reflected in the
	// network.
	for _, container := range state.Containers {
		for _, attachment := range container.Networks {
			network := networkByName(state.Networks, attachment.Name)
			if network == nil {
				t.Errorf("container %s is in network %s, which is not on the list",
					container.Name, attachment.Name)
				continue
			}
			if !containsContainer(network.Containers, container.ID) {
				t.Errorf("network %s does not list container %s", network.Name, container.Name)
			}
			if !network.InUse {
				t.Errorf("network %s has container %s, yet is reported as unused",
					network.Name, container.Name)
			}
		}
		for _, mount := range container.Mounts {
			if mount.Type != "volume" || mount.Name == "" {
				continue
			}
			volume := volumeByName(state.Volumes, mount.Name)
			if volume == nil {
				continue
			}
			// A stopped container counts too: its volume is not nobody's.
			if !volume.InUse {
				t.Errorf("volume %s is mounted by %s, yet is reported as free",
					volume.Name, container.Name)
			}
		}
	}

	// Usage without containers would be made up.
	for _, network := range state.Networks {
		if network.InUse && len(network.Containers) == 0 {
			t.Errorf("network %s is in use, but without containers", network.Name)
		}
	}
	for _, volume := range state.Volumes {
		if volume.InUse && len(volume.UsedBy) == 0 {
			t.Errorf("volume %s is in use, but without containers", volume.Name)
		}
		// An unknown size stays unknown, but with a reason: zero would mean
		// an empty volume ready to be deleted.
		if volume.SizeBytes == nil && volume.SizeReason == "" {
			t.Errorf("volume %s without a size and without a reason", volume.Name)
		}
	}

	// The engine's built-in networks are marked: they are never cleanup
	// candidates.
	for _, name := range []string{"bridge", "host", "none"} {
		network := networkByName(state.Networks, name)
		if network == nil {
			t.Errorf("the host did not report the network %s", name)
			continue
		}
		if !network.Predefined {
			t.Errorf("network %s is not marked as built-in", name)
		}
	}

	if count := countUnusedNetworks(state.Networks); count != state.Summary.NetworksUnused {
		t.Errorf("the summary speaks of %d unused networks, the list has %d",
			state.Summary.NetworksUnused, count)
	}
}

// TestCleanupRefusesAnObjectInUse guards the cleanup boundary. The refusal
// is to come from the host and have its own code: an operator who asked to
// remove the volume of a running service is to see that the host refused,
// not that the operation failed.
func TestCleanupRefusesAnObjectInUse(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostEngineState(t, h, host.ID)

	t.Run("network in use", func(t *testing.T) {
		network := firstNetworkInUse(state.Networks)
		if network == nil {
			t.Skip("the host has no network with an attached container")
		}
		refusal(t, h, host, map[string]any{"network_ids": []string{network.ID}},
			"docker_object_in_use")
	})

	t.Run("built-in network", func(t *testing.T) {
		network := networkByName(state.Networks, "bridge")
		if network == nil {
			t.Skip("the host did not report the bridge network")
		}
		refusal(t, h, host, map[string]any{"network_ids": []string{network.ID}},
			"docker_network_predefined")
	})

	t.Run("volume in use", func(t *testing.T) {
		volume := firstVolumeInUse(state.Volumes)
		if volume == nil {
			t.Skip("the host has no volume mounted by a container")
		}
		refusal(t, h, host, map[string]any{"volume_names": []string{volume.Name}},
			"docker_object_in_use")
	})

	// Silence after removing something that does not exist would be worse
	// than a refusal: the operator would assume they cleaned something up.
	t.Run("non-existent volume", func(t *testing.T) {
		refusal(t, h, host, map[string]any{"volume_names": []string{"no-such-volume"}},
			"docker_object_missing")
	})
}

// refusal orders a cleanup and requires the host to refuse with the given
// code.
//
// Cleanup deletes data irreversibly, so it requires two people's approval.
// The test collects both: without the second one the job would stay in
// awaiting_approval and nobody would learn whether the host would refuse at
// all.
func refusal(t *testing.T, h *harness, host hostView, prune map[string]any, code string) {
	t.Helper()
	job := h.createOperation(host.ID, map[string]any{
		"action": "docker.prune", "reason": containersReason,
		"target_confirmation": host.Hostname,
		"payload":             map[string]any{"docker_prune": prune},
	})
	job = h.approve(job.ID, job.PayloadHash)
	if job.CollectedApprovals < job.RequiredApprovals {
		second := h.withToken(h.createPrincipal(uniqueSubject("approver-cleanup"),
			[]map[string]string{
				{"role": "approver", "site": host.Site, "environment": host.Environment},
			}))
		second.approve(job.ID, job.PayloadHash)
	}

	final := h.awaitTerminal(job.ID, 2*time.Minute)
	if final.State == "succeeded" {
		t.Fatalf("the host carried out a cleanup it was to refuse: %v", prune)
	}
	if final.ResultErrorCode != code {
		t.Fatalf("refusal code = %q, expected %q (%s)",
			final.ResultErrorCode, code, lastMessage(h.attempts(job.ID)))
	}
}

func hostEngineState(t *testing.T, h *harness, hostID string) engineState {
	t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "docker.read", "reason": containersReason,
		"payload": map[string]any{"docker_read": map[string]any{}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("engine read: state = %s, %s", job.State, lastMessage(attempts))
	}

	var fragment struct {
		Payload           engineState `json:"payload"`
		UnavailableReason string      `json:"unavailable_reason"`
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/containers.full",
		nil, &fragment, http.StatusOK)
	if fragment.UnavailableReason != "" {
		t.Skipf("the container engine is unavailable: %s", fragment.UnavailableReason)
	}
	return fragment.Payload
}

func networkByName(networks []dockerNetworkView, name string) *dockerNetworkView {
	for i := range networks {
		if networks[i].Name == name {
			return &networks[i]
		}
	}
	return nil
}

func volumeByName(volumes []volumeView, name string) *volumeView {
	for i := range volumes {
		if volumes[i].Name == name {
			return &volumes[i]
		}
	}
	return nil
}

func firstNetworkInUse(networks []dockerNetworkView) *dockerNetworkView {
	for i := range networks {
		if networks[i].InUse && !networks[i].Predefined {
			return &networks[i]
		}
	}
	return nil
}

func firstVolumeInUse(volumes []volumeView) *volumeView {
	for i := range volumes {
		if volumes[i].InUse {
			return &volumes[i]
		}
	}
	return nil
}

func containsContainer(list []struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}, id string) bool {
	for _, item := range list {
		if item.ID == id {
			return true
		}
	}
	return false
}

func countUnusedNetworks(networks []dockerNetworkView) int {
	count := 0
	for _, network := range networks {
		if !network.InUse && !network.Predefined {
			count++
		}
	}
	return count
}

type eventView struct {
	Time       time.Time         `json:"time"`
	Type       string            `json:"type"`
	Action     string            `json:"action"`
	ActorID    string            `json:"actor_id"`
	ActorName  string            `json:"actor_name"`
	Attributes map[string]string `json:"attributes"`
}

type eventsResult struct {
	Kind   string `json:"kind"`
	Events struct {
		Events    []eventView `json:"events"`
		Since     time.Time   `json:"since"`
		Until     time.Time   `json:"until"`
		Types     []string    `json:"types"`
		Truncated bool        `json:"truncated"`
	} `json:"events"`
	UnavailableReason string `json:"unavailable_reason"`
}

// TestEventReadEndsOnItsOwn guards the property without which this
// operation could not exist: the read is closed in a window and ends on its
// own, also when nobody waits for it. A job reading events "until further
// notice" would stay on the host forever.
func TestEventReadEndsOnItsOwn(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	start := time.Now()
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "docker.events", "reason": containersReason,
		"payload": map[string]any{"docker_events": map[string]any{
			"since_seconds": 3600, "follow_seconds": 5, "max_events": 50,
		}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("event read: state = %s, %s", job.State, lastMessage(attempts))
	}
	// Following for 5 seconds is to end within a dozen seconds, not after
	// the job timeout.
	if took := time.Since(start); took > time.Minute {
		t.Errorf("a read with a 5 s follow window took %s", took)
	}

	result := jobEventsResult(t, h, job.ID)
	if result.UnavailableReason != "" {
		t.Skipf("the container engine is unavailable: %s", result.UnavailableReason)
	}
	if result.Kind != "docker_events" {
		t.Fatalf("result kind = %q", result.Kind)
	}
	// The window must come back in the result: without it an empty list
	// says nothing, because silence in the window and no read look the
	// same.
	if result.Events.Since.IsZero() || result.Events.Until.IsZero() {
		t.Fatalf("result without a window: %+v", result.Events)
	}
	if !result.Events.Until.After(result.Events.Since) {
		t.Errorf("the window ends before it starts: %s - %s",
			result.Events.Since, result.Events.Until)
	}
	if len(result.Events.Types) != 4 {
		t.Errorf("no filter was to give four types, there are %v", result.Events.Types)
	}
	for _, event := range result.Events.Events {
		if event.Type == "" || event.Action == "" {
			t.Errorf("event without a type or an action: %+v", event)
		}
		if event.Time.Before(result.Events.Since.Add(-time.Minute)) {
			t.Errorf("event %s outside the window (%s)", event.Time, result.Events.Since)
		}
	}
}

// TestEventReadSeesOperationsOnTheHost checks that the log answers the
// question the host state does not: what happened here. A container restart
// leaves the same container in the state as before, and a trace in the log.
func TestEventReadSeesOperationsOnTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	state := hostEngineState(t, h, host.ID)
	var target *containerView
	for i := range state.Containers {
		if state.Containers[i].State == "running" {
			target = &state.Containers[i]
			break
		}
	}
	if target == nil {
		t.Skip("the host has no running container")
	}

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "docker.container.restart", "reason": containersReason,
		"payload": map[string]any{"docker_container": map[string]any{
			"container_id": target.ID, "name": target.Name, "timeout_seconds": 10,
		}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("container restart: state = %s, %s", job.State, lastMessage(attempts))
	}

	events, attempts := h.runOperation(host.ID, map[string]any{
		"action": "docker.events", "reason": containersReason,
		"payload": map[string]any{"docker_events": map[string]any{
			"since_seconds": 300, "types": []string{"container"}, "max_events": 200,
		}},
	}, 3*time.Minute)
	if events.State != "succeeded" {
		t.Fatalf("event read: state = %s, %s", events.State, lastMessage(attempts))
	}

	result := jobEventsResult(t, h, events.ID)
	if result.UnavailableReason != "" {
		t.Skipf("the container engine is unavailable: %s", result.UnavailableReason)
	}
	found := false
	for _, event := range result.Events.Events {
		if event.Type != "container" {
			t.Errorf("the container filter let %q through", event.Type)
		}
		if event.ActorName == target.Name && event.Action == "restart" {
			found = true
		}
	}
	if !found {
		t.Errorf("the log does not know the restart of container %s", target.Name)
	}
}

// TestEventOrderOutsideTheWindowIsRejected guards that the limits are part
// of the operation contract: the operator learns about them when ordering,
// not through a quiet trim on the host.
func TestEventOrderOutsideTheWindowIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for name, order := range map[string]map[string]any{
		"window back":  {"since_seconds": 7 * 24 * 3600},
		"follow":       {"follow_seconds": 3600},
		"event limit":  {"max_events": 100000},
		"unknown type": {"types": []string{"daemon"}},
	} {
		t.Run(name, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{
					"action": "docker.events", "reason": containersReason,
					"payload": map[string]any{"docker_events": order},
				}, nil, http.StatusBadRequest)
		})
	}
}

func jobEventsResult(t *testing.T, h *harness, jobID string) eventsResult {
	t.Helper()
	var response struct {
		Items []struct {
			Detail eventsResult `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+jobID+"/attempts", nil, &response, http.StatusOK)
	if len(response.Items) == 0 {
		t.Fatal("job without attempts")
	}
	return response.Items[len(response.Items)-1].Detail
}
