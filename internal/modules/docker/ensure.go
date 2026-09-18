package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Carrying a plan out.
//
// Every change recomputes its plan first and compares the digest with the
// one the operator approved. A host that moved on since the approval gets
// no change: the operator approved one change from one base, not whatever
// the host happens to hold now. That is the same rule a Compose deployment
// follows, for the same reason.

// EnsureResult is what a declared change did.
type EnsureResult struct {
	Plan Plan `json:"plan"`
	// Outcome repeats the plan action that was carried out, so a result
	// read on its own says what happened without the plan beside it.
	Outcome string `json:"outcome"`
	Changed bool   `json:"changed"`
	// Container is the state of the container after the change, as the
	// engine reports it. Empty after a removal: a container that is gone
	// has no state, and inventing one would be worse than silence.
	Container *Container `json:"container,omitempty"`
	// Removed lists what vanished on the way - the container that was
	// replaced, the containers a network replacement disconnected.
	Removed []string `json:"removed,omitempty"`
}

// EnsureContainer brings the container to the state the specification
// describes.
//
// A container that differs is replaced rather than changed: the engine can
// alter a handful of a running container's settings and refuses the rest,
// so an operation that promised to change any setting would work
// sometimes and leave a half-changed container the rest of the time. The
// plan said replace before the operator approved it.
func EnsureContainer(ctx context.Context, client *Client, spec ContainerSpec,
	secrets map[string][]byte, approved string) (EnsureResult, error) {
	result := EnsureResult{}
	plan, err := PlanContainer(ctx, client, spec)
	if err != nil {
		return result, err
	}
	result.Plan = plan
	result.Outcome = plan.Action
	if err := checkApproval(plan, approved); err != nil {
		return result, err
	}
	// The digest the plan resolved is what the container is created from,
	// never the tag as the registry serves it at this moment.
	spec.ImageDigest = plan.ImageDigest

	switch plan.Action {
	case PlanNoChange:
		result.Container = containerByName(ctx, client, spec.Name)
		return result, nil

	case PlanStart:
		if err := client.StartContainer(ctx, plan.CurrentID); err != nil {
			return result, err
		}
		result.Changed = true
		result.Container = containerByName(ctx, client, spec.Name)
		return result, nil

	case PlanStop:
		if err := client.StopContainer(ctx, plan.CurrentID, uint32(spec.StopTimeoutSeconds)); err != nil {
			return result, err
		}
		result.Changed = true
		result.Container = containerByName(ctx, client, spec.Name)
		return result, nil
	}

	// A replacement removes the old container first: the engine keeps the
	// name unique, so the new one cannot be created beside it. The image
	// is pulled before anything is removed - a replacement that took the
	// service down and then found out the image is not there would leave
	// the host without it.
	if err := ensureImage(ctx, client, spec); err != nil {
		return result, err
	}
	if plan.Exists {
		if err := client.StopContainer(ctx, plan.CurrentID, uint32(spec.StopTimeoutSeconds)); err != nil &&
			!errors.Is(err, ErrNotFound) {
			return result, fmt.Errorf("stopping the container that is being replaced: %w", err)
		}
		if err := client.RemoveContainer(ctx, plan.CurrentID, false); err != nil {
			return result, fmt.Errorf("removing the container that is being replaced: %w", err)
		}
		result.Removed = append(result.Removed, "container "+spec.Name+" "+shortID(plan.CurrentID))
	}

	id, err := client.CreateContainer(ctx, spec, secrets)
	if err != nil {
		return result, err
	}
	result.Changed = true
	if !spec.Stopped {
		if err := client.StartContainer(ctx, id); err != nil {
			// The container exists and does not run. Saying so is the
			// truth of the moment; removing it would take away the only
			// thing the operator can look at to find out why.
			result.Container = containerByName(ctx, client, spec.Name)
			return result, fmt.Errorf("the container was created and did not start: %w", err)
		}
	}
	result.Container = containerByName(ctx, client, spec.Name)
	return result, nil
}

// ensureImage makes sure the digest the plan bound is on the host.
//
// The pull is by digest, so it fetches exactly what was approved. An image
// already there is not fetched again: a replacement of a container on a
// host without a registry has to work.
func ensureImage(ctx context.Context, client *Client, spec ContainerSpec) error {
	reference := ImageOf(spec)
	if images, err := client.Images(ctx); err == nil {
		for _, image := range images {
			if image.ID == spec.ImageDigest {
				return nil
			}
			for _, digest := range image.Digests {
				if strings.Contains(digest, spec.ImageDigest) {
					return nil
				}
			}
		}
	}
	if _, err := client.PullImage(ctx, reference); err != nil {
		return fmt.Errorf("the image %s could not be fetched: %w", reference, err)
	}
	return nil
}

// EnsureNetwork brings the network to the state the specification
// describes.
func EnsureNetwork(ctx context.Context, client *Client, spec NetworkSpec,
	force bool, approved string) (EnsureResult, error) {
	result := EnsureResult{}
	plan, err := PlanNetwork(ctx, client, spec, force)
	if err != nil {
		return result, err
	}
	result.Plan = plan
	result.Outcome = plan.Action
	if err := checkApproval(plan, approved); err != nil {
		return result, err
	}
	if plan.Action == PlanNoChange {
		return result, nil
	}
	if plan.Exists {
		if err := detachAll(ctx, client, plan); err != nil {
			return result, err
		}
		if err := client.RemoveNetwork(ctx, plan.CurrentID); err != nil {
			return result, fmt.Errorf("removing the network that is being replaced: %w", err)
		}
		result.Removed = append(result.Removed, "network "+spec.Name+" "+shortID(plan.CurrentID))
	}
	if _, err := client.CreateNetwork(ctx, spec); err != nil {
		return result, err
	}
	result.Changed = true
	return result, nil
}

// RemoveNetworkPlanned removes a network the plan named.
func RemoveNetworkPlanned(ctx context.Context, client *Client, name string,
	force bool, approved string) (EnsureResult, error) {
	result := EnsureResult{}
	plan, err := PlanNetworkRemoval(ctx, client, name, force)
	if err != nil {
		return result, err
	}
	result.Plan = plan
	result.Outcome = plan.Action
	if err := checkApproval(plan, approved); err != nil {
		return result, err
	}
	if plan.Action == PlanAbsent {
		return result, nil
	}
	if err := detachAll(ctx, client, plan); err != nil {
		return result, err
	}
	if err := client.RemoveNetwork(ctx, plan.CurrentID); err != nil {
		return result, err
	}
	result.Changed = true
	result.Removed = append(result.Removed, "network "+name+" "+shortID(plan.CurrentID))
	return result, nil
}

// detachAll disconnects every container the plan listed. The engine
// refuses to remove a network with a live endpoint, so a removal the plan
// allowed has to take the endpoints away first - and the plan named each
// of them, so nothing is disconnected that the operator did not see.
func detachAll(ctx context.Context, client *Client, plan Plan) error {
	for _, name := range plan.Detaches {
		if err := client.DisconnectNetwork(ctx, plan.CurrentID, name, true); err != nil &&
			!errors.Is(err, ErrNotFound) {
			return fmt.Errorf("disconnecting %s from the network: %w", name, err)
		}
	}
	return nil
}

// EnsureVolume brings the volume to the state the specification describes.
func EnsureVolume(ctx context.Context, client *Client, spec VolumeSpec,
	force bool, approved string) (EnsureResult, error) {
	result := EnsureResult{}
	plan, err := PlanVolume(ctx, client, spec, force)
	if err != nil {
		return result, err
	}
	result.Plan = plan
	result.Outcome = plan.Action
	if err := checkApproval(plan, approved); err != nil {
		return result, err
	}
	if plan.Action == PlanNoChange {
		return result, nil
	}
	if plan.Exists {
		if err := client.RemoveVolume(ctx, spec.Name); err != nil {
			return result, fmt.Errorf("removing the volume that is being replaced: %w", err)
		}
		result.Removed = append(result.Removed, "volume "+spec.Name)
	}
	if err := client.CreateVolume(ctx, spec); err != nil {
		return result, err
	}
	result.Changed = true
	return result, nil
}

// RemoveVolumePlanned removes a volume the plan named.
func RemoveVolumePlanned(ctx context.Context, client *Client, name string,
	force bool, approved string) (EnsureResult, error) {
	result := EnsureResult{}
	plan, err := PlanVolumeRemoval(ctx, client, name, force)
	if err != nil {
		return result, err
	}
	result.Plan = plan
	result.Outcome = plan.Action
	if err := checkApproval(plan, approved); err != nil {
		return result, err
	}
	if plan.Action == PlanAbsent {
		return result, nil
	}
	if force {
		err = client.RemoveVolumeForced(ctx, name)
	} else {
		err = client.RemoveVolume(ctx, name)
	}
	if err != nil {
		return result, err
	}
	result.Changed = true
	result.Removed = append(result.Removed, "volume "+name)
	return result, nil
}

// checkApproval compares the plan computed now with the one approved.
//
// An order without a digest is one that carries no approval to compare -
// the operation registry decides which operations may be ordered that way,
// and a container is not one of them.
func checkApproval(plan Plan, approved string) error {
	if approved == "" {
		return nil
	}
	if strings.EqualFold(plan.Digest, approved) {
		return nil
	}
	return fmt.Errorf("%w: approved %s, the host now plans %s (%s)",
		ErrPlanMismatch, shortID(approved), shortID(plan.Digest), plan.Action)
}

// containerByName reads the container back after a change. A read that
// fails leaves the state unknown rather than invented: the verifier goes
// to the host itself anyway.
func containerByName(ctx context.Context, client *Client, name string) *Container {
	readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	containers, err := client.Containers(readCtx, true)
	if err != nil {
		return nil
	}
	for i := range containers {
		if containers[i].Name != name {
			continue
		}
		container := containers[i]
		if health, restarts, err := client.Inspect(readCtx, container.ID); err == nil {
			container.Health = health
			container.RestartCount = restarts
		}
		return &container
	}
	return nil
}
