package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The engine calls that create and change objects.
//
// Every one of them has its own method with its own parameters, like the
// reads: the client never takes a path from outside the module, because a
// helper that relayed a path would be a way to call any Engine API at all -
// and that is root by another name.

// callJSON performs a request with a JSON body.
func (c *Client) callJSON(ctx context.Context, method, path string, query url.Values,
	body any, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	target := "http://docker/" + apiVersion + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnavailable, shortenError(err))
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return engineError(response.StatusCode, string(message))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(out)
}

// engineError turns the engine's answer into an error of this module.
//
// The status carries the meaning the operator needs: 404 is an object that
// is not there, 409 an object something else is holding. Both have their
// own code in the panel, so they must not arrive as one undifferentiated
// failure.
func engineError(status int, body string) error {
	message := strings.TrimSpace(body)
	var payload struct {
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(body), &payload) == nil && payload.Message != "" {
		message = payload.Message
	}
	switch status {
	case http.StatusNotFound:
		return fmt.Errorf("%s: %w", message, ErrNotFound)
	case http.StatusConflict:
		return fmt.Errorf("%s: %w", message, ErrInUse)
	}
	return fmt.Errorf("the engine answered %d: %s", status, message)
}

// ContainerDetail is the full state of one container as the engine keeps
// it. Unlike the container list, it carries what a container was created
// with - the command, the limits, the mounts - which is what a plan
// compares a specification against.
type ContainerDetail struct {
	ID           string
	Name         string
	Image        string
	ImageID      string
	State        string
	RestartCount int
	Health       string
	CreatedAt    time.Time
	// Labels are the container's own, the engine's and the image's
	// together: the engine does not record which came from where.
	Labels map[string]string
	Spec   ContainerSpec
}

// engineContainer is the shape of the engine's inspect answer. Only the
// fields a specification speaks about are read.
type engineContainer struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Image   string `json:"Image"`
	Created string `json:"Created"`
	State   struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
	Config       struct {
		Hostname    string            `json:"Hostname"`
		User        string            `json:"User"`
		Env         []string          `json:"Env"`
		Cmd         []string          `json:"Cmd"`
		Entrypoint  []string          `json:"Entrypoint"`
		Image       string            `json:"Image"`
		Labels      map[string]string `json:"Labels"`
		WorkingDir  string            `json:"WorkingDir"`
		StopTimeout *int              `json:"StopTimeout"`
		Healthcheck *struct {
			Test        []string `json:"Test"`
			Interval    int64    `json:"Interval"`
			Timeout     int64    `json:"Timeout"`
			Retries     int      `json:"Retries"`
			StartPeriod int64    `json:"StartPeriod"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
		Binds        []string `json:"Binds"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
		Memory            int64             `json:"Memory"`
		MemoryReservation int64             `json:"MemoryReservation"`
		NanoCpus          int64             `json:"NanoCpus"`
		PidsLimit         *int64            `json:"PidsLimit"`
		ReadonlyRootfs    bool              `json:"ReadonlyRootfs"`
		Tmpfs             map[string]string `json:"Tmpfs"`
		Mounts            []struct {
			Type         string `json:"Type"`
			Source       string `json:"Source"`
			Target       string `json:"Target"`
			ReadOnly     bool   `json:"ReadOnly"`
			TmpfsOptions *struct {
				SizeBytes int64 `json:"SizeBytes"`
			} `json:"TmpfsOptions"`
		} `json:"Mounts"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID  string   `json:"NetworkID"`
			Aliases    []string `json:"Aliases"`
			IPAMConfig *struct {
				IPv4Address string `json:"IPv4Address"`
			} `json:"IPAMConfig"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// InspectContainer reads the full state of one container.
//
// A container the host does not have is ErrNotFound rather than an empty
// answer: a plan that treated a missing container as "nothing to compare"
// would silently create a second one.
func (c *Client) InspectContainer(ctx context.Context, reference string) (ContainerDetail, error) {
	var raw engineContainer
	if err := c.get(ctx, "/containers/"+url.PathEscape(reference)+"/json", nil, &raw); err != nil {
		if strings.Contains(err.Error(), "404") {
			return ContainerDetail{}, fmt.Errorf("the container %s: %w", reference, ErrNotFound)
		}
		return ContainerDetail{}, err
	}
	return detailFrom(raw), nil
}

// detailFrom turns the engine's answer into the specification the
// container really runs under, so that a plan compares two descriptions of
// the same shape instead of a description against a data structure of the
// daemon.
func detailFrom(raw engineContainer) ContainerDetail {
	detail := ContainerDetail{
		ID:           raw.ID,
		Name:         strings.TrimPrefix(raw.Name, "/"),
		Image:        raw.Config.Image,
		ImageID:      raw.Image,
		State:        raw.State.Status,
		RestartCount: raw.RestartCount,
		Labels:       raw.Config.Labels,
	}
	if raw.State.Health != nil {
		detail.Health = raw.State.Health.Status
	}
	if created, err := time.Parse(time.RFC3339Nano, raw.Created); err == nil {
		detail.CreatedAt = created.UTC()
	}

	spec := ContainerSpec{
		Name:                   detail.Name,
		Image:                  raw.Config.Image,
		ImageDigest:            raw.Image,
		Command:                raw.Config.Cmd,
		Entrypoint:             raw.Config.Entrypoint,
		Labels:                 raw.Config.Labels,
		User:                   raw.Config.User,
		WorkingDir:             raw.Config.WorkingDir,
		Hostname:               raw.Config.Hostname,
		ReadOnlyRootFilesystem: raw.HostConfig.ReadonlyRootfs,
		Stopped:                raw.State.Status != "running" && raw.State.Status != "restarting",
		Restart: RestartSpec{
			Policy:     raw.HostConfig.RestartPolicy.Name,
			MaxRetries: raw.HostConfig.RestartPolicy.MaximumRetryCount,
		},
		Resources: ResourceSpec{
			MemoryBytes:            raw.HostConfig.Memory,
			MemoryReservationBytes: raw.HostConfig.MemoryReservation,
			NanoCPUs:               raw.HostConfig.NanoCpus,
		},
	}
	if raw.Config.StopTimeout != nil {
		spec.StopTimeoutSeconds = *raw.Config.StopTimeout
	}
	if raw.HostConfig.PidsLimit != nil {
		spec.Resources.PidsLimit = *raw.HostConfig.PidsLimit
	}
	spec.Env = map[string]string{}
	for _, entry := range raw.Config.Env {
		name, value, found := strings.Cut(entry, "=")
		if found {
			spec.Env[name] = value
		}
	}
	if check := raw.Config.Healthcheck; check != nil {
		health := &HealthSpec{
			Test:               check.Test,
			IntervalSeconds:    int(time.Duration(check.Interval) / time.Second),
			TimeoutSeconds:     int(time.Duration(check.Timeout) / time.Second),
			Retries:            check.Retries,
			StartPeriodSeconds: int(time.Duration(check.StartPeriod) / time.Second),
		}
		// The engine records a check turned off as the single word NONE.
		if len(check.Test) == 1 && check.Test[0] == "NONE" {
			health = &HealthSpec{Disable: true}
		}
		spec.Health = health
	}
	for port, bindings := range raw.HostConfig.PortBindings {
		number, protocol := splitPort(port)
		if number == 0 {
			continue
		}
		if len(bindings) == 0 {
			spec.Ports = append(spec.Ports, PortSpec{ContainerPort: number, Protocol: protocol})
			continue
		}
		for _, binding := range bindings {
			host, _ := strconv.ParseUint(binding.HostPort, 10, 16)
			spec.Ports = append(spec.Ports, PortSpec{
				HostIP: binding.HostIP, HostPort: uint16(host),
				ContainerPort: number, Protocol: protocol,
			})
		}
	}
	// The mount list of the host configuration is what the container was
	// created with; the top level Mounts is what it ended up with. The
	// first is the description to compare against, and the bind list is
	// the older way of writing the same thing.
	for _, mount := range raw.HostConfig.Mounts {
		entry := MountSpec{
			Type: mount.Type, Source: mount.Source,
			Target: mount.Target, ReadOnly: mount.ReadOnly,
		}
		if mount.TmpfsOptions != nil {
			entry.SizeBytes = mount.TmpfsOptions.SizeBytes
		}
		spec.Mounts = append(spec.Mounts, entry)
	}
	for _, bind := range raw.HostConfig.Binds {
		if mount, ok := mountFromBind(bind); ok {
			spec.Mounts = append(spec.Mounts, mount)
		}
	}
	for target, options := range raw.HostConfig.Tmpfs {
		spec.Mounts = append(spec.Mounts, MountSpec{
			Type: "tmpfs", Target: target, SizeBytes: tmpfsSize(options),
		})
	}
	for name, attachment := range raw.NetworkSettings.Networks {
		entry := AttachmentSpec{Name: name, Aliases: attachment.Aliases}
		if attachment.IPAMConfig != nil {
			entry.IPv4 = attachment.IPAMConfig.IPv4Address
		}
		spec.Networks = append(spec.Networks, entry)
	}
	detail.Spec = spec.Normalized()
	return detail
}

// mountFromBind reads the older "source:target[:options]" form of a mount.
func mountFromBind(bind string) (MountSpec, bool) {
	parts := strings.Split(bind, ":")
	if len(parts) < 2 {
		return MountSpec{}, false
	}
	mount := MountSpec{Source: parts[0], Target: parts[1], Type: "bind"}
	if !strings.HasPrefix(parts[0], "/") {
		mount.Type = "volume"
	}
	if len(parts) > 2 {
		for _, option := range strings.Split(parts[2], ",") {
			if option == "ro" {
				mount.ReadOnly = true
			}
		}
	}
	return mount, true
}

// tmpfsSize reads the size out of the mount options of a tmpfs. An option
// list without one leaves the size unstated rather than zero: zero would
// read as a mount of no size at all.
func tmpfsSize(options string) int64 {
	for _, option := range strings.Split(options, ",") {
		if value, found := strings.CutPrefix(option, "size="); found {
			size, err := strconv.ParseInt(value, 10, 64)
			if err == nil {
				return size
			}
		}
	}
	return 0
}

func splitPort(port string) (uint16, string) {
	number, protocol, found := strings.Cut(port, "/")
	if !found {
		protocol = "tcp"
	}
	value, err := strconv.ParseUint(number, 10, 16)
	if err != nil {
		return 0, protocol
	}
	return uint16(value), protocol
}

// ResolveImageDigest answers with the digest the reference will run from.
//
// The registry is asked first, through the engine's own distribution
// endpoint: it reads the manifest without pulling the image, so a plan
// learns what a tag means today even for an image the host has never seen.
// A registry that does not answer - no credentials, no network - leaves the
// image already on the host, whose digest was recorded when it was pulled.
// A reference neither can resolve is not planned: a tag the plan did not
// bind is a deployment of whatever the registry serves at that moment.
func (c *Client) ResolveImageDigest(ctx context.Context, reference string) (digest, source string, err error) {
	if pinned := PinnedDigest(reference); pinned != "" {
		return pinned, DigestFromReference, nil
	}
	var distribution struct {
		Descriptor struct {
			Digest string `json:"digest"`
		} `json:"Descriptor"`
	}
	registryErr := c.get(ctx, "/distribution/"+url.PathEscape(reference)+"/json", nil, &distribution)
	if registryErr == nil && digestReference.MatchString(distribution.Descriptor.Digest) {
		return distribution.Descriptor.Digest, DigestFromRegistry, nil
	}

	images, listErr := c.Images(ctx)
	if listErr != nil {
		return "", "", fmt.Errorf("the registry did not answer (%v) and the image list could not be read: %w",
			shortenOrNil(registryErr), listErr)
	}
	for _, image := range images {
		if !contains(image.Tags, reference) && !contains(image.Tags, "docker.io/library/"+reference) {
			continue
		}
		for _, entry := range image.Digests {
			if _, pinned, found := strings.Cut(entry, "@"); found && digestReference.MatchString(pinned) {
				return pinned, DigestFromLocal, nil
			}
		}
		// An image built on the host never came from a registry, so no
		// digest names it there. Its own identifier is what the container
		// would run from, and saying so is better than refusing a plan for
		// an image the host really has.
		if digestReference.MatchString(image.ID) {
			return image.ID, DigestFromLocal, nil
		}
	}
	return "", "", fmt.Errorf("the registry did not answer (%v) and the host has no image %s",
		shortenOrNil(registryErr), reference)
}

func shortenOrNil(err error) string {
	if err == nil {
		return "no digest in the manifest"
	}
	return shortenError(err)
}

// Sources of an image digest, as the plan records them.
const (
	DigestFromReference = "reference"
	DigestFromRegistry  = "registry"
	DigestFromLocal     = "local"
)

// PinnedDigest returns the digest a reference carries itself, or nothing
// for a reference by tag.
func PinnedDigest(reference string) string {
	_, digest, found := strings.Cut(reference, "@")
	if !found || !digestReference.MatchString(digest) {
		return ""
	}
	return digest
}

// PinReference replaces the tag of a reference with a digest. The tag is
// the part after the last colon that comes after the last slash - a colon
// before the last slash is the port of a registry.
func PinReference(reference, digest string) string {
	if PinnedDigest(reference) != "" {
		return reference
	}
	repository := reference
	if at := strings.LastIndex(repository, "@"); at >= 0 {
		repository = repository[:at]
	}
	slash := strings.LastIndex(repository, "/")
	if colon := strings.LastIndex(repository, ":"); colon > slash {
		repository = repository[:colon]
	}
	return repository + "@" + digest
}

// CreateContainer creates a container from the specification and returns
// its identifier. The container does not start: starting is a separate
// step, so that a container the order wanted stopped never runs at all.
//
// The environment values of the secret variables come in separately and
// never through the specification: the specification is hashed into the
// plan, stored with the job and read back by the verifier.
func (c *Client) CreateContainer(ctx context.Context, spec ContainerSpec,
	secrets map[string][]byte) (string, error) {
	body := createBody(spec, secrets)
	query := url.Values{}
	query.Set("name", spec.Name)

	var created struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := c.callJSON(ctx, http.MethodPost, "/containers/create", query, body, &created); err != nil {
		return "", err
	}
	// The engine attaches a container to one network at creation; the rest
	// are connected afterwards, one call each.
	for index, attachment := range spec.Normalized().Networks {
		if index == 0 {
			continue
		}
		if err := c.ConnectNetwork(ctx, attachment.Name, created.ID, attachment); err != nil {
			return created.ID, fmt.Errorf("network %s: %w", attachment.Name, err)
		}
	}
	return created.ID, nil
}

// createBody assembles the engine's create request out of the
// specification.
func createBody(spec ContainerSpec, secrets map[string][]byte) map[string]any {
	spec = spec.Normalized()
	config := map[string]any{
		"Image":  ImageOf(spec),
		"Labels": managedLabels(spec),
	}
	if len(spec.Command) > 0 {
		config["Cmd"] = spec.Command
	}
	if len(spec.Entrypoint) > 0 {
		config["Entrypoint"] = spec.Entrypoint
	}
	if spec.User != "" {
		config["User"] = spec.User
	}
	if spec.WorkingDir != "" {
		config["WorkingDir"] = spec.WorkingDir
	}
	if spec.Hostname != "" {
		config["Hostname"] = spec.Hostname
	}
	if spec.StopTimeoutSeconds > 0 {
		config["StopTimeout"] = spec.StopTimeoutSeconds
	}
	config["Env"] = environmentList(spec, secrets)
	if check := healthBody(spec.Health); check != nil {
		config["Healthcheck"] = check
	}

	exposed := map[string]any{}
	bindings := map[string]any{}
	for _, port := range spec.Ports {
		key := strconv.Itoa(int(port.ContainerPort)) + "/" + protocolOf(port)
		exposed[key] = map[string]any{}
		entry := map[string]string{"HostIp": port.HostIP}
		if port.HostPort != 0 {
			entry["HostPort"] = strconv.Itoa(int(port.HostPort))
		}
		list, _ := bindings[key].([]map[string]string)
		bindings[key] = append(list, entry)
	}
	if len(exposed) > 0 {
		config["ExposedPorts"] = exposed
	}

	host := map[string]any{
		"RestartPolicy": map[string]any{
			"Name": spec.Restart.Policy, "MaximumRetryCount": spec.Restart.MaxRetries,
		},
		"ReadonlyRootfs": spec.ReadOnlyRootFilesystem,
	}
	if len(bindings) > 0 {
		host["PortBindings"] = bindings
	}
	if mounts := mountBodies(spec.Mounts); len(mounts) > 0 {
		host["Mounts"] = mounts
	}
	if spec.Resources.MemoryBytes > 0 {
		host["Memory"] = spec.Resources.MemoryBytes
	}
	if spec.Resources.MemoryReservationBytes > 0 {
		host["MemoryReservation"] = spec.Resources.MemoryReservationBytes
	}
	if spec.Resources.NanoCPUs > 0 {
		host["NanoCpus"] = spec.Resources.NanoCPUs
	}
	if spec.Resources.PidsLimit > 0 {
		host["PidsLimit"] = spec.Resources.PidsLimit
	}
	config["HostConfig"] = host

	if len(spec.Networks) > 0 {
		first := spec.Networks[0]
		host["NetworkMode"] = first.Name
		config["NetworkingConfig"] = map[string]any{
			"EndpointsConfig": map[string]any{first.Name: endpointBody(first)},
		}
	}
	return config
}

// ImageOf is the reference a container is created from: the repository
// with the digest the plan bound, never the tag as the registry serves it
// at that moment.
func ImageOf(spec ContainerSpec) string {
	if spec.ImageDigest == "" {
		return spec.Image
	}
	return PinReference(spec.Image, spec.ImageDigest)
}

func endpointBody(attachment AttachmentSpec) map[string]any {
	endpoint := map[string]any{}
	if len(attachment.Aliases) > 0 {
		endpoint["Aliases"] = attachment.Aliases
	}
	if attachment.IPv4 != "" {
		endpoint["IPAMConfig"] = map[string]any{"IPv4Address": attachment.IPv4}
	}
	return endpoint
}

func healthBody(health *HealthSpec) map[string]any {
	if health == nil {
		return nil
	}
	if health.Disable {
		return map[string]any{"Test": []string{"NONE"}}
	}
	body := map[string]any{"Test": health.Test}
	if health.IntervalSeconds > 0 {
		body["Interval"] = int64(health.IntervalSeconds) * int64(time.Second)
	}
	if health.TimeoutSeconds > 0 {
		body["Timeout"] = int64(health.TimeoutSeconds) * int64(time.Second)
	}
	if health.Retries > 0 {
		body["Retries"] = health.Retries
	}
	if health.StartPeriodSeconds > 0 {
		body["StartPeriod"] = int64(health.StartPeriodSeconds) * int64(time.Second)
	}
	return body
}

func mountBodies(mounts []MountSpec) []map[string]any {
	bodies := make([]map[string]any, 0, len(mounts))
	for _, mount := range mounts {
		body := map[string]any{
			"Type": mount.Type, "Target": mount.Target, "ReadOnly": mount.ReadOnly,
		}
		if mount.Source != "" {
			body["Source"] = mount.Source
		}
		if mount.Type == "tmpfs" && mount.SizeBytes > 0 {
			body["TmpfsOptions"] = map[string]any{"SizeBytes": mount.SizeBytes}
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// environmentList assembles the variables in a fixed order, the values of
// the secret ones taken from the store.
//
// A secret whose value did not arrive is left out rather than set empty: a
// container that starts with an empty password reads as a working one and
// is not.
func environmentList(spec ContainerSpec, secrets map[string][]byte) []string {
	names := make([]string, 0, len(spec.Env)+len(spec.EnvSecrets))
	for name := range spec.Env {
		names = append(names, name)
	}
	for name := range spec.EnvSecrets {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]string, 0, len(names))
	for _, name := range names {
		if value, held := secrets[name]; held {
			entries = append(entries, name+"="+string(value))
			continue
		}
		if _, fromStore := spec.EnvSecrets[name]; fromStore {
			continue
		}
		entries = append(entries, name+"="+spec.Env[name])
	}
	return entries
}

// The labels the module puts on what it creates.
const (
	// LabelManaged marks an object created from a specification of the
	// panel. An object without it was made by hand, and its description is
	// unknown - which is not the same as matching.
	LabelManaged = "io.flotestro.managed"
	// LabelSpecDigest carries the digest of the specification the object
	// was created from. It is what lets a plan see a change the engine's
	// own state does not show: a secret rotated to a new version, a
	// variable moved from the order into the store.
	LabelSpecDigest = "io.flotestro.spec"
)

// managedLabels are the operator's labels together with the module's own.
func managedLabels(spec ContainerSpec) map[string]string {
	labels := map[string]string{}
	for key, value := range spec.Labels {
		labels[key] = value
	}
	labels[LabelManaged] = "true"
	labels[LabelSpecDigest] = SpecDigest(spec)
	return labels
}

// SpecDigest is the digest of a specification: what the object is to be,
// in one value the engine can carry as a label.
func SpecDigest(spec ContainerSpec) string {
	normalized := spec.Normalized()
	// The labels are left out of the digest: they carry the digest itself,
	// and a value cannot cover the place it is written into.
	normalized.Labels = nil
	return planDigest("container-spec", "", normalized)
}

// CreateNetwork creates a network and returns its identifier.
func (c *Client) CreateNetwork(ctx context.Context, spec NetworkSpec) (string, error) {
	spec = spec.Normalized()
	var ipam []map[string]any
	if spec.Subnet != "" {
		entry := map[string]any{"Subnet": spec.Subnet}
		if spec.Gateway != "" {
			entry["Gateway"] = spec.Gateway
		}
		if spec.IPRange != "" {
			entry["IPRange"] = spec.IPRange
		}
		ipam = append(ipam, entry)
	}
	if spec.IPv6Subnet != "" {
		entry := map[string]any{"Subnet": spec.IPv6Subnet}
		if spec.IPv6Gateway != "" {
			entry["Gateway"] = spec.IPv6Gateway
		}
		ipam = append(ipam, entry)
	}

	labels := map[string]string{}
	for key, value := range spec.Labels {
		labels[key] = value
	}
	labels[LabelManaged] = "true"

	body := map[string]any{
		"Name": spec.Name, "Driver": spec.Driver, "CheckDuplicate": true,
		"EnableIPv6": spec.IPv6, "Internal": spec.Internal,
		"Attachable": spec.Attachable, "Labels": labels,
	}
	if len(ipam) > 0 {
		body["IPAM"] = map[string]any{"Driver": "default", "Config": ipam}
	}
	if len(spec.Options) > 0 {
		body["Options"] = spec.Options
	}

	var created struct {
		ID      string `json:"Id"`
		Warning string `json:"Warning"`
	}
	if err := c.callJSON(ctx, http.MethodPost, "/networks/create", nil, body, &created); err != nil {
		return "", err
	}
	return created.ID, nil
}

// ConnectNetwork attaches a container to a network.
func (c *Client) ConnectNetwork(ctx context.Context, network, container string,
	attachment AttachmentSpec) error {
	body := map[string]any{
		"Container": container, "EndpointConfig": endpointBody(attachment),
	}
	return c.callJSON(ctx, http.MethodPost,
		"/networks/"+url.PathEscape(network)+"/connect", nil, body, nil)
}

// DisconnectNetwork detaches a container from a network. force detaches a
// container that is running: without it the engine refuses, and a network
// nothing can be detached from cannot be replaced either.
func (c *Client) DisconnectNetwork(ctx context.Context, network, container string, force bool) error {
	body := map[string]any{"Container": container, "Force": force}
	return c.callJSON(ctx, http.MethodPost,
		"/networks/"+url.PathEscape(network)+"/disconnect", nil, body, nil)
}

// CreateVolume creates a volume.
func (c *Client) CreateVolume(ctx context.Context, spec VolumeSpec) error {
	spec = spec.Normalized()
	labels := map[string]string{}
	for key, value := range spec.Labels {
		labels[key] = value
	}
	labels[LabelManaged] = "true"

	body := map[string]any{"Name": spec.Name, "Driver": spec.Driver, "Labels": labels}
	if len(spec.Options) > 0 {
		body["DriverOpts"] = spec.Options
	}
	return c.callJSON(ctx, http.MethodPost, "/volumes/create", nil, body, nil)
}

// RemoveVolumeForced removes a volume, asking the engine to remove one it
// would otherwise keep. The engine still refuses a volume a container
// references, and that refusal is the answer the operator gets.
func (c *Client) RemoveVolumeForced(ctx context.Context, name string) error {
	query := url.Values{}
	query.Set("force", "1")
	return c.call(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(name), query, nil)
}
