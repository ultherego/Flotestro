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
//
// The plan is computed again right before the deployment, tags included:
// every tag is resolved once more, and the digest of the whole plan is
// compared with the approved one. A match means the manifest and the
// images are the same the operator viewed; a difference means the
// deployment would bring something else - and then a refusal is the right
// reaction, not running something nobody approved. Where the order names
// the digests per service, each is compared too, so the refusal can say
// which image moved. The containers are started from the pinned
// references, never from the tag as the registry serves it at that moment.
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

	// --remove-orphans removes the containers the manifest no longer
	// describes. Without it the project drifts from its description after
	// every change, and the operator approved a desired state, not an
	// addition to the current one.
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

// projectState reads the project services running on the host. A failed
// read returns nothing, not an error: the state before and after is an
// addition to the result, not a condition of its existence.
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
