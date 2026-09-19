package compose

import (
	"context"
	"fmt"
	"strings"
)

// Executor deploys a project on the host.
type Executor struct {
	Planner Planner
}

// ErrPlanMismatch means the base state changed since approval.
var ErrPlanMismatch = fmt.Errorf("the deployment plan changed since approval")

// Deploy deploys the manifest, but only the one the operator approved.
func (e Executor) Deploy(ctx context.Context, project, manifest, expectedDigest string,
	approvedDigests map[string]string) (Result, error) {
	result := Result{Project: project}

	plan, err := e.Planner.Plan(ctx, project, manifest)
	if err != nil {
		return result, err
	}
	result.Digest = plan.Digest
	if expectedDigest != "" && !strings.EqualFold(plan.Digest, expectedDigest) {
		return result, fmt.Errorf("%w: approved %s, now %s",
			ErrPlanMismatch, shorten(expectedDigest), shorten(plan.Digest))
	}
	for _, service := range plan.Services {
		approved, named := approvedDigests[service.Name]
		if !named {
			continue
		}
		if !strings.EqualFold(approved, service.ImageDigest) {
			return result, fmt.Errorf("%w: the image of %s moved from %s to %s",
				ErrPlanMismatch, service.Name, shorten(approved), shorten(service.ImageDigest))
		}
	}
	result.Before = e.projectState(ctx, project)

	path, cleanup, err := e.Planner.writeManifest(project, manifest)
	if err != nil {
		return result, err
	}
	defer cleanup()
	override, cleanupOverride, err := e.Planner.writeOverride(project, plan.Services)
	if err != nil {
		return result, err
	}
	defer cleanupOverride()

	// --remove-orphans removes the containers the manifest no longer describes.
	stdout, stderr, err := e.Planner.Runner(ctx,
		"-p", project, "-f", path, "-f", override, "up", "-d", "--remove-orphans")
	result.Applied = changesFromDryRun(stdout + "\n" + stderr)
	result.After = e.projectState(ctx, project)
	if err != nil {
		result.Output = outputTail(stderr, stdout)
		return result, fmt.Errorf("compose up: %s", firstLine(stderr))
	}
	return result, nil
}

// projectState reads the project services running on the host.
func (e Executor) projectState(ctx context.Context, project string) []Service {
	stdout, _, err := e.Planner.Runner(ctx, "-p", project, "ps", "--format", "json", "--all")
	if err != nil {
		return nil
	}
	return servicesFromList(stdout)
}

// outputTail returns the last lines of the tool output.
func outputTail(stderr, stdout string) []string {
	source := strings.TrimSpace(stderr)
	if source == "" {
		source = strings.TrimSpace(stdout)
	}
	var lines []string
	for _, line := range strings.Split(source, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	return lines
}

func shorten(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}
