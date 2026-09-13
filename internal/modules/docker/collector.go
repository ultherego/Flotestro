package docker

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// Snapshot is a full read of the host container state.
type Snapshot struct {
	Summary    Summary     `json:"summary"`
	Containers []Container `json:"containers"`
	Images     []Image     `json:"images"`
	Networks   []Network   `json:"networks"`
	Volumes    []Volume    `json:"volumes"`
}

// Collect reads the engine state.
//
// The full lists are fetched on the operator's request, and the summary
// goes into the inventory. Querying the engine at every heartbeat would
// load the host for no reason: the container count changes less often than
// every thirty seconds, and the operator looks at this tab only when they
// need it anyway.
func Collect(ctx context.Context, client *Client) Snapshot {
	if client == nil {
		return Snapshot{Summary: Summary{UnavailableReason: "no container engine adapter"}}
	}

	snapshot := Snapshot{}
	engine, api, err := client.Version(ctx)
	if err != nil {
		// An unavailable engine is not the same as a host without
		// containers. An empty list without a reason would look like a tidy
		// host.
		snapshot.Summary.UnavailableReason = unavailableReason(err)
		return snapshot
	}
	snapshot.Summary.EngineVersion = engine
	snapshot.Summary.APIVersion = api

	containers, err := client.Containers(ctx, true)
	if err != nil {
		snapshot.Summary.UnavailableReason = unavailableReason(err)
		return snapshot
	}
	snapshot.Containers = containers

	// The health state and the restart counter need a separate query, so
	// only the containers for which it means anything are asked. A stopped
	// container has no health to check.
	for i := range snapshot.Containers {
		if snapshot.Containers[i].State != "running" && snapshot.Containers[i].State != "restarting" {
			continue
		}
		health, restarts, err := client.Inspect(ctx, snapshot.Containers[i].ID)
		if err != nil {
			continue
		}
		snapshot.Containers[i].Health = health
		snapshot.Containers[i].RestartCount = restarts
	}

	if images, err := client.Images(ctx); err == nil {
		snapshot.Images = images
	}
	if networks, err := client.Networks(ctx); err == nil {
		snapshot.Networks = networks
	}
	if volumes, err := client.Volumes(ctx); err == nil {
		snapshot.Volumes = volumes
	}

	linkUsage(&snapshot)
	snapshot.Summary = summarise(snapshot, snapshot.Summary)
	return snapshot
}

// linkUsage fills the network and volume usage from the container list.
//
// The engine does not answer this question: in the network list it returns
// an empty container map, and it reports the volume size and reference
// count only with a separate disk usage computation. Without this
// derivation every network and every volume would look abandoned - and
// those are the ones that go under the prune.
//
// A stopped container counts too: the volume of a stopped container is not
// nobody's volume.
func linkUsage(snapshot *Snapshot) {
	byName := map[string]int{}
	byID := map[string]int{}
	for i := range snapshot.Networks {
		byName[snapshot.Networks[i].Name] = i
		byID[snapshot.Networks[i].ID] = i
	}
	volumes := map[string]int{}
	for i := range snapshot.Volumes {
		volumes[snapshot.Volumes[i].Name] = i
	}

	for _, container := range snapshot.Containers {
		for _, attachment := range container.Networks {
			index, ok := byName[attachment.Name]
			if !ok {
				index, ok = byID[attachment.ID]
			}
			if !ok {
				// The network vanished between one query and the other. The
				// container tells the truth about it, but there is nothing
				// to attach it to.
				continue
			}
			network := &snapshot.Networks[index]
			network.Containers = append(network.Containers, NetworkMember{
				ID: container.ID, Name: container.Name, State: container.State,
				IPv4: attachment.IPv4,
			})
			network.InUse = true
		}
		for _, mount := range container.Mounts {
			if mount.Type != "volume" || mount.Name == "" {
				continue
			}
			index, ok := volumes[mount.Name]
			if !ok {
				continue
			}
			volume := &snapshot.Volumes[index]
			volume.UsedBy = append(volume.UsedBy, VolumeMount{
				ContainerID: container.ID, ContainerName: container.Name,
				State: container.State, Destination: mount.Destination,
				ReadOnly: mount.ReadOnly,
			})
			volume.InUse = true
		}
	}

	for i := range snapshot.Networks {
		sort.Slice(snapshot.Networks[i].Containers, func(a, b int) bool {
			return snapshot.Networks[i].Containers[a].Name < snapshot.Networks[i].Containers[b].Name
		})
	}
	for i := range snapshot.Volumes {
		sort.Slice(snapshot.Volumes[i].UsedBy, func(a, b int) bool {
			return snapshot.Volumes[i].UsedBy[a].ContainerName < snapshot.Volumes[i].UsedBy[b].ContainerName
		})
	}
}

// summarise computes the decision signals. The summary is not a metric: it
// says whether something needs the operator's attention, not how much of
// what there is at every moment.
func summarise(snapshot Snapshot, base Summary) Summary {
	summary := base
	summary.Containers = len(snapshot.Containers)
	summary.Images = len(snapshot.Images)
	summary.Networks = len(snapshot.Networks)
	summary.Volumes = len(snapshot.Volumes)
	for _, network := range snapshot.Networks {
		// A predefined network is not a cleanup candidate, so it is not in
		// the counter - otherwise every host would have three networks "to
		// remove".
		if !network.InUse && !network.Predefined {
			summary.NetworksUnused++
		}
	}
	for _, volume := range snapshot.Volumes {
		if !volume.InUse {
			summary.VolumesUnused++
		}
	}

	projects := map[string]*Project{}
	for _, container := range snapshot.Containers {
		switch container.State {
		case "running":
			summary.Running++
		case "paused":
			summary.Paused++
		default:
			summary.Stopped++
		}
		if container.Health == "unhealthy" {
			summary.Unhealthy++
		}
		// A container that comes up over and over is fine at every single
		// moment and broken nevertheless. Without this counter it is not
		// visible at all.
		if container.State == "restarting" || container.RestartCount >= restartLoopThreshold {
			summary.RestartLooping++
		}
		if container.Compose == nil {
			continue
		}
		project := projects[container.Compose.Project]
		if project == nil {
			project = &Project{
				Name:        container.Compose.Project,
				ConfigFiles: container.Compose.ConfigFiles,
				WorkingDir:  container.Compose.WorkingDir,
			}
			projects[container.Compose.Project] = project
		}
		project.Total++
		if container.State == "running" {
			project.Running++
		}
		if container.Compose.Service != "" && !contains(project.Services, container.Compose.Service) {
			project.Services = append(project.Services, container.Compose.Service)
		}
	}

	for _, project := range projects {
		sort.Strings(project.Services)
		summary.Projects = append(summary.Projects, *project)
	}
	sort.Slice(summary.Projects, func(i, j int) bool {
		return summary.Projects[i].Name < summary.Projects[j].Name
	})
	return summary
}

// restartLoopThreshold separates a container that came up once from one
// that comes up over and over. The value is deliberately low: the operator
// is meant to see the problem before it grows to hundreds of restarts.
const restartLoopThreshold = 5

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

// unavailableReason translates an error into a sentence for the operator.
func unavailableReason(err error) string {
	if errors.Is(err, ErrUnavailable) {
		return "the container engine does not answer: " + shortenError(err)
	}
	return strings.TrimSpace(err.Error())
}
