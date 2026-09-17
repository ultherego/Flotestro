package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// projectName allows what Compose allows. The name goes into a command
// argument and into container names, so it cannot carry anything more.
var projectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidProjectName checks a project name.
func ValidProjectName(name string) bool {
	return projectName.MatchString(name)
}

// maxManifest bounds the manifest size. A file bigger than this is no
// longer a project configuration, only something the operator will not
// read before approving.
const maxManifest = 256 << 10

// Planner computes the deployment plan on the host.
type Planner struct {
	// Runner runs the compose command. Separated so that the plan can be
	// checked in a test without a container engine.
	Runner Runner
	// Resolver turns an image reference into the digest that will run. A
	// planner without one plans nothing that is not pinned already: a tag
	// left unresolved is a deployment of whatever the registry serves at
	// that moment, which is not what the operator approved.
	Resolver ImageResolver
	// Dir is the working directory for manifests. It belongs to root and
	// is not shared with anything else.
	Dir string
}

// Runner runs the compose command and returns its output.
type Runner func(ctx context.Context, args ...string) (stdout string, stderr string, err error)

// ErrDigestUnresolved means a service names an image by a tag whose digest
// the host could not learn - neither from the registry nor from an image
// already on the host.
var ErrDigestUnresolved = fmt.Errorf("the image digest could not be resolved")

// Plan computes the difference between the project state and the manifest.
func (p Planner) Plan(ctx context.Context, project, manifest string) (Plan, error) {
	plan := Plan{Project: project, ComputedAt: time.Now().UTC()}
	if !ValidProjectName(project) {
		return plan, fmt.Errorf("invalid project name %q", project)
	}
	if len(manifest) == 0 {
		return plan, fmt.Errorf("the manifest is empty")
	}
	if len(manifest) > maxManifest {
		return plan, fmt.Errorf("the manifest is too big (%d bytes)", len(manifest))
	}

	path, cleanup, err := p.writeManifest(project, manifest)
	if err != nil {
		return plan, err
	}
	defer cleanup()

	// Normalisation is validation at the same time: Compose refuses when
	// the manifest is invalid, and does so before anything moves on the
	// host.
	stdout, stderr, err := p.Runner(ctx, "-p", project, "-f", path, "config", "--format", "json")
	if err != nil {
		return plan, fmt.Errorf("manifest rejected by compose: %s", firstLine(stderr))
	}

	services, warnings, err := servicesFromConfiguration(stdout)
	if err != nil {
		return plan, err
	}
	// Every tag is resolved to a digest before the plan exists. The plan
	// is what the operator approves, and it has to name what will run, not
	// what the tag pointed at when they looked.
	if err := p.resolveDigests(ctx, services); err != nil {
		return plan, err
	}
	plan.Services = services
	plan.Warnings = warnings

	override, cleanupOverride, err := p.writeOverride(project, services)
	if err != nil {
		return plan, err
	}
	defer cleanupOverride()

	// The dry run says what will really change. A difference computed from
	// the manifest alone would be guessing: Compose also takes into account
	// whether a container needs recreating because of an image or
	// configuration change. Compose reports the dry run on the diagnostic
	// stream, not on the output, so both are read - otherwise the change
	// list comes out empty and the plan looks as if the deployment changed
	// nothing. The dry run sees the pinned images, the way the deployment
	// will.
	dryOut, dryErr, err := p.Runner(ctx, "-p", project, "-f", path, "-f", override, "up", "-d", "--dry-run")
	if err == nil {
		plan.Changes = changesFromDryRun(dryOut + "\n" + dryErr)
	} else {
		plan.Warnings = append(plan.Warnings,
			"compose could not compute a dry run; the change list may be incomplete")
	}

	plan.Digest = Digest(project, stdout, services)
	return plan, nil
}

// resolveDigests binds every service to the digest of its image.
func (p Planner) resolveDigests(ctx context.Context, services []Service) error {
	for i := range services {
		service := &services[i]
		resolved, err := p.resolve(ctx, service.Image)
		if err != nil {
			return fmt.Errorf("%w: service %s (%s): %v", ErrDigestUnresolved, service.Name, service.Image, err)
		}
		service.ImageDigest = resolved.Digest
		service.DigestSource = resolved.Source
		service.PinnedImage = PinReference(service.Image, resolved.Digest)
	}
	return nil
}

func (p Planner) resolve(ctx context.Context, image string) (ResolvedImage, error) {
	if digest := pinnedDigest(image); digest != "" {
		return ResolvedImage{Digest: digest, Source: DigestFromReference}, nil
	}
	if p.Resolver == nil {
		return ResolvedImage{}, fmt.Errorf("the host resolves no tags; pin a digest in the manifest")
	}
	resolved, err := p.Resolver(ctx, image)
	if err != nil {
		return ResolvedImage{}, err
	}
	if !validDigest(resolved.Digest) {
		return ResolvedImage{}, fmt.Errorf("the resolver returned %q, which is not a sha256 digest", resolved.Digest)
	}
	return resolved, nil
}

// writeOverride writes the file that replaces every tag with the digest
// the plan resolved. Compose merges it over the manifest, so the project
// keeps every other setting the operator wrote and only the image
// references change. The file is JSON, which every YAML reader takes, so
// no hand-written YAML has to escape anything.
//
// The override is the way the digest is bound instead of pulling the image
// and re-tagging it: a re-tag would rewrite what the tag means on this host
// for everything else that uses it, and "docker compose" would still record
// the tag in the container - an operator reading "docker ps" a week later
// would see a tag and not the digest that really runs.
func (p Planner) writeOverride(project string, services []Service) (string, func(), error) {
	type image struct {
		Image string `json:"image"`
	}
	override := struct {
		Services map[string]image `json:"services"`
	}{Services: map[string]image{}}
	for _, service := range services {
		if service.PinnedImage != "" {
			override.Services[service.Name] = image{Image: service.PinnedImage}
		}
	}
	encoded, err := json.Marshal(override)
	if err != nil {
		return "", func() {}, err
	}
	dir := filepath.Join(p.Dir, project)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", func() {}, err
	}
	path := filepath.Join(dir, "digests.override.yml")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return "", func() {}, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

// Digest binds the deployment to the plan.
//
// Computed from the whole normalised project configuration, not from the
// service list alone. A manifest with the same services and images may
// publish a different port or run a different command - the operator
// approved a specific plan, so the digest must cover everything the plan
// describes.
//
// The basis is the "compose config" output, because Compose canonicalises
// it: the same meaning written differently gives the same text, and a
// different meaning always a different one.
func Digest(project string, configuration string, services []Service) string {
	sorted := make([]Service, len(services))
	copy(sorted, services)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	sum := sha256.New()
	fmt.Fprintf(sum, "project=%s\n", project)
	fmt.Fprintf(sum, "config=%s\n", strings.TrimSpace(configuration))
	// The image digests are added separately: the configuration carries a
	// tag, and a tag may point at a different image tomorrow. A change of
	// what will really come up is also meant to invalidate the approval.
	for _, service := range sorted {
		fmt.Fprintf(sum, "image=%s digest=%s\n", service.Image, service.ImageDigest)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// writeManifest writes the manifest in the helper's working directory.
func (p Planner) writeManifest(project, manifest string) (string, func(), error) {
	dir := filepath.Join(p.Dir, project)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", func() {}, err
	}
	path := filepath.Join(dir, "docker-compose.yml")
	// A manifest sometimes carries credentials, so the file is readable
	// only by root and vanishes after the operation.
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		return "", func() {}, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

// servicesFromConfiguration reads the normalised project configuration.
func servicesFromConfiguration(configuration string) ([]Service, []string, error) {
	var data struct {
		Services map[string]struct {
			Image       string         `json:"image"`
			Environment map[string]any `json:"environment"`
			Deploy      struct {
				Replicas *int `json:"replicas"`
			} `json:"deploy"`
			Labels map[string]string `json:"labels"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(configuration), &data); err != nil {
		return nil, nil, fmt.Errorf("unreadable project configuration: %w", err)
	}

	services := make([]Service, 0, len(data.Services))
	var warnings []string
	for name, service := range data.Services {
		entry := Service{Name: name, Image: service.Image, Replicas: 1}
		if service.Deploy.Replicas != nil {
			entry.Replicas = *service.Deploy.Replicas
		}
		// An image named by a tag may mean something else tomorrow. The
		// deployment binds the digest the tag resolves to now, so the
		// warning is information: the operator approves this digest, and a
		// tag that moves before the deployment makes the plan stale.
		if pinnedDigest(service.Image) == "" {
			warnings = append(warnings,
				fmt.Sprintf("service %s uses a mutable tag (%s); the deployment binds the digest it resolves to now",
					name, service.Image))
		}
		for key := range service.Environment {
			if looksLikeSecret(key) {
				// The manifest is stored in the panel together with the
				// version history, so a value written into it directly stops
				// being a secret.
				warnings = append(warnings,
					fmt.Sprintf("service %s sets %s inline; the manifest is stored in the panel, "+
						"so use env_file on the host instead", name, key))
			}
		}
		services = append(services, entry)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	sort.Strings(warnings)
	return services, warnings, nil
}

// dryRunPattern reads lines like:
//
//	DRY-RUN MODE -  Container trial-web-1  Creating
var dryRunPattern = regexp.MustCompile(
	`(?i)(Container|Network|Volume|Image)\s+(\S+)\s+(Creating|Created|Recreate|Recreated|Starting|Started|Stopping|Stopped|Removing|Removed|Pulling|Pulled)`)

// changesFromDryRun extracts the change list from the dry run output.
// Compose reports every step twice - during and after - so the first
// occurrence of an object counts.
func changesFromDryRun(output string) []Change {
	seen := map[string]bool{}
	var changes []Change
	for _, line := range strings.Split(output, "\n") {
		match := dryRunPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		key := match[1] + "/" + match[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		changes = append(changes, Change{
			Kind:   strings.ToLower(match[1]),
			Name:   match[2],
			Action: strings.ToLower(strings.TrimSuffix(match[3], "d")),
		})
	}
	return changes
}

func looksLikeSecret(key string) bool {
	lowered := strings.ToLower(key)
	for _, pattern := range []string{"secret", "password", "passwd", "token", "apikey", "api_key", "credential"} {
		if strings.Contains(lowered, pattern) {
			return true
		}
	}
	return false
}

func firstLine(text string) string {
	text = strings.TrimSpace(text)
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return strings.TrimSpace(text[:index])
	}
	return text
}

// servicesFromList reads the output of "compose ps --format json". Compose
// prints one object per line, not an array, so it is read as a stream.
func servicesFromList(output string) []Service {
	var services []Service
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var entry struct {
			Service string `json:"Service"`
			Image   string `json:"Image"`
			State   string `json:"State"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		services = append(services, Service{Name: entry.Service, Image: entry.Image, Replicas: 1})
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	return services
}
