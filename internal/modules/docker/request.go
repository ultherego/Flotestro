package docker

import (
	"fmt"
	"strconv"
	"strings"
)

// The container description as an order carries it.
//
// An operator writes a published port as "8080:80/tcp" and a mount as
// "volume:data:/var/lib/data:ro"; that is what the form shows, what the job
// record keeps and what the approval covers. ContainerSpec is the same
// description in the shape the plan compares and the engine takes, and
// Spec is the one place the compact words are read. The panel and the host
// call it with the same text, so the panel refuses exactly what the host
// would - and the field that is wrong is named rather than answered with a
// status from a daemon.
type ContainerRequest struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	// Command replaces the image's own command, Entrypoint its entry point;
	// an empty list leaves the image's own.
	Command    []string `json:"command,omitempty"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	// Env are the variables whose value is not a credential. One that is
	// belongs in the secret references of the order: this map is stored
	// with the job and shown to whoever may read it.
	Env map[string]string `json:"env,omitempty"`
	// EnvSecrets names the variables whose value comes from the panel's
	// secret store, as "name#version". An order does not fill it in - it
	// carries its references in a field of its own, where they are checked
	// as references - and it is written in on the way to the host, so that
	// the description the host reads says which secret feeds which
	// variable. That is what makes a rotated secret a changed description,
	// and a changed description a replacement: the only way a new
	// credential ever reaches a running container.
	EnvSecrets map[string]string `json:"env_secrets,omitempty"`
	// Ports, Mounts and Networks are the compact forms:
	//   [host-address:][host-port:]container-port[/protocol]
	//   volume:<name>:<target>[:ro] | bind:<path>:<target>[:ro] | tmpfs:<target>[:<bytes>]
	//   <network>[=alias,alias][@address]
	Ports    []string `json:"ports,omitempty"`
	Mounts   []string `json:"mounts,omitempty"`
	Networks []string `json:"networks,omitempty"`
	// RestartPolicy is one of RestartPolicies; RestartMaxRetries bounds an
	// on-failure policy and belongs to no other.
	RestartPolicy     string            `json:"restart_policy,omitempty"`
	RestartMaxRetries int               `json:"restart_max_retries,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	// HealthTest replaces the image's own check; HealthDisable turns the
	// image's check off, which is not the same as having none.
	HealthTest               []string `json:"health_test,omitempty"`
	HealthDisable            bool     `json:"health_disable,omitempty"`
	HealthIntervalSeconds    int      `json:"health_interval_seconds,omitempty"`
	HealthTimeoutSeconds     int      `json:"health_timeout_seconds,omitempty"`
	HealthRetries            int      `json:"health_retries,omitempty"`
	HealthStartPeriodSeconds int      `json:"health_start_period_seconds,omitempty"`
	// The limits the container may take from the host. Zero is no limit of
	// that kind, which is the engine's own default.
	MemoryBytes            int64 `json:"memory_bytes,omitempty"`
	MemoryReservationBytes int64 `json:"memory_reservation_bytes,omitempty"`
	NanoCPUs               int64 `json:"nano_cpus,omitempty"`
	PidsLimit              int64 `json:"pids_limit,omitempty"`

	User                   string `json:"user,omitempty"`
	WorkingDir             string `json:"working_dir,omitempty"`
	Hostname               string `json:"hostname,omitempty"`
	ReadOnlyRootFilesystem bool   `json:"read_only_root_filesystem,omitempty"`
	StopTimeoutSeconds     int    `json:"stop_timeout_seconds,omitempty"`
	// Stopped asks for a container that exists and does not run. The
	// default is a running container: an order that creates one means to
	// have the service.
	Stopped bool `json:"stopped,omitempty"`
}

// Spec turns the order into the description the plan and the engine work
// with.
//
// The references given here take the place of the ones written into the
// request, so the panel can compose the description out of an order that
// keeps its references typed and beside it. Either way it is references
// that travel; a value never does.
func (r *ContainerRequest) Spec(secrets map[string]string) (ContainerSpec, error) {
	if r == nil {
		return ContainerSpec{}, fmt.Errorf("the order carries no container description")
	}
	if len(secrets) == 0 {
		secrets = r.EnvSecrets
	}
	spec := ContainerSpec{
		Name:       r.Name,
		Image:      r.Image,
		Command:    r.Command,
		Entrypoint: r.Entrypoint,
		Env:        r.Env,
		EnvSecrets: secrets,
		Labels:     r.Labels,
		Restart: RestartSpec{
			Policy:     r.RestartPolicy,
			MaxRetries: r.RestartMaxRetries,
		},
		Resources: ResourceSpec{
			MemoryBytes:            r.MemoryBytes,
			MemoryReservationBytes: r.MemoryReservationBytes,
			NanoCPUs:               r.NanoCPUs,
			PidsLimit:              r.PidsLimit,
		},
		User:                   r.User,
		WorkingDir:             r.WorkingDir,
		Hostname:               r.Hostname,
		ReadOnlyRootFilesystem: r.ReadOnlyRootFilesystem,
		StopTimeoutSeconds:     r.StopTimeoutSeconds,
		Stopped:                r.Stopped,
	}
	for _, entry := range r.Ports {
		port, err := ParsePort(entry)
		if err != nil {
			return ContainerSpec{}, err
		}
		spec.Ports = append(spec.Ports, port)
	}
	for _, entry := range r.Mounts {
		mount, err := ParseMount(entry)
		if err != nil {
			return ContainerSpec{}, err
		}
		spec.Mounts = append(spec.Mounts, mount)
	}
	for _, entry := range r.Networks {
		attachment, err := ParseAttachment(entry)
		if err != nil {
			return ContainerSpec{}, err
		}
		spec.Networks = append(spec.Networks, attachment)
	}
	// A check the order says nothing about is the image's own. Saying so
	// with nothing rather than with an empty structure matters: an empty
	// structure would read as a check with no command.
	if r.HealthDisable || len(r.HealthTest) > 0 {
		spec.Health = &HealthSpec{
			Disable:            r.HealthDisable,
			Test:               r.HealthTest,
			IntervalSeconds:    r.HealthIntervalSeconds,
			TimeoutSeconds:     r.HealthTimeoutSeconds,
			Retries:            r.HealthRetries,
			StartPeriodSeconds: r.HealthStartPeriodSeconds,
		}
	}
	if err := spec.Validate(); err != nil {
		return ContainerSpec{}, err
	}
	return spec, nil
}

// ParsePort reads a published port:
// [host-address:][host-port:]container-port[/protocol].
//
// A host port left out asks the engine for a free one, and the plan says
// that the port is not fixed. The protocol is tcp when it is not written.
func ParsePort(entry string) (PortSpec, error) {
	value := strings.TrimSpace(entry)
	if value == "" {
		return PortSpec{}, fmt.Errorf("an empty published port")
	}
	port := PortSpec{}
	// The protocol is separated by the only slash the form has; an address
	// of either family carries none.
	if slash := strings.LastIndex(value, "/"); slash >= 0 {
		port.Protocol = value[slash+1:]
		value = value[:slash]
	}

	fields := strings.Split(value, ":")
	switch len(fields) {
	case 1:
		// Only the port inside the container: the engine publishes it on a
		// free port of the host and the plan says which.
	case 2:
		host, err := portNumber(fields[0])
		if err != nil {
			return PortSpec{}, fmt.Errorf("the host port in %q: %w", entry, err)
		}
		port.HostPort = host
	default:
		// Everything before the last two colons is the address. An address
		// of the second family carries colons of its own, so it is written
		// in brackets - the way the engine's own command line takes it;
		// without them there is no telling an address from a third port.
		if len(fields) > 3 && !strings.HasPrefix(value, "[") {
			return PortSpec{}, fmt.Errorf("%q has more parts than a published port has; "+
				"write an IPv6 address in brackets, as [::1]:8080:80", entry)
		}
		host, err := portNumber(fields[len(fields)-2])
		if err != nil {
			return PortSpec{}, fmt.Errorf("the host port in %q: %w", entry, err)
		}
		port.HostPort = host
		port.HostIP = strings.Trim(strings.Join(fields[:len(fields)-2], ":"), "[]")
		// An empty address publishes on every address of the host, which is
		// what the engine does when none is written.
		if port.HostIP != "" && !addressLike(port.HostIP) {
			return PortSpec{}, fmt.Errorf("%q in %q is not an address of the host", port.HostIP, entry)
		}
	}
	inside, err := portNumber(fields[len(fields)-1])
	if err != nil {
		return PortSpec{}, fmt.Errorf("the container port in %q: %w", entry, err)
	}
	if inside == 0 {
		return PortSpec{}, fmt.Errorf("%q names no port inside the container", entry)
	}
	port.ContainerPort = inside
	return port, nil
}

func portNumber(value string) (uint16, error) {
	if value == "" {
		return 0, nil
	}
	number, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number between 1 and 65535", value)
	}
	return uint16(number), nil
}

// ParseMount reads one mount:
// volume:<name>:<target>[:ro], bind:<path>:<target>[:ro] or
// tmpfs:<target>[:<bytes>].
//
// The kind comes first because it decides everything else: a volume name
// and a host path look alike enough that guessing would sooner or later
// bind-mount a directory that was meant to be a volume.
func ParseMount(entry string) (MountSpec, error) {
	value := strings.TrimSpace(entry)
	kind, rest, found := strings.Cut(value, ":")
	if !found || rest == "" {
		return MountSpec{}, fmt.Errorf("%q is not a mount; write it as volume:<name>:<target>, "+
			"bind:<path>:<target> or tmpfs:<target>", entry)
	}
	mount := MountSpec{Type: kind}
	if kind == "tmpfs" {
		target, size, hasSize := strings.Cut(rest, ":")
		mount.Target = target
		if hasSize {
			bytes, err := strconv.ParseInt(size, 10, 64)
			if err != nil || bytes < 0 {
				return MountSpec{}, fmt.Errorf("the size of the tmpfs in %q is a number of bytes", entry)
			}
			mount.SizeBytes = bytes
		}
		return mount, nil
	}
	if !contains(MountTypes, kind) {
		return MountSpec{}, fmt.Errorf("unknown mount type %q in %q; it is volume, bind or tmpfs", kind, entry)
	}
	source, target, hasTarget := strings.Cut(rest, ":")
	if !hasTarget {
		return MountSpec{}, fmt.Errorf("%q names no mount point inside the container", entry)
	}
	mount.Source = source
	mount.Target, mount.ReadOnly = readOnlySuffix(target)
	return mount, nil
}

// readOnlySuffix separates the mount point from the ":ro" that may follow
// it. Anything else after the mount point is refused by the caller through
// the mount point itself, which then is not an absolute path.
func readOnlySuffix(value string) (string, bool) {
	if target, found := strings.CutSuffix(value, ":ro"); found {
		return target, true
	}
	if target, found := strings.CutSuffix(value, ":rw"); found {
		return target, false
	}
	return value, false
}

// ParseAttachment reads one network attachment: <network>[=alias,alias][@address].
//
// The address is the last part, because a network name may carry neither
// an equals sign nor an at sign, and an alias may not either.
func ParseAttachment(entry string) (AttachmentSpec, error) {
	value := strings.TrimSpace(entry)
	attachment := AttachmentSpec{}
	if at := strings.LastIndex(value, "@"); at >= 0 {
		attachment.IPv4 = value[at+1:]
		value = value[:at]
		if !addressLike(attachment.IPv4) {
			return AttachmentSpec{}, fmt.Errorf("%q in %q is not an address", attachment.IPv4, entry)
		}
	}
	name, aliases, hasAliases := strings.Cut(value, "=")
	attachment.Name = name
	if hasAliases {
		for _, alias := range strings.Split(aliases, ",") {
			alias = strings.TrimSpace(alias)
			if alias == "" {
				continue
			}
			attachment.Aliases = append(attachment.Aliases, alias)
		}
	}
	if attachment.Name == "" {
		return AttachmentSpec{}, fmt.Errorf("%q names no network", entry)
	}
	return attachment, nil
}
