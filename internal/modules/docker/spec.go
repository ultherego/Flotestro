package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The desired state of the objects this module creates.

// The shapes the engine accepts.
var (
	// objectName is what the engine allows a container, a network and a
	// volume to be called.
	objectName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	// environmentName is a variable name a shell can carry.
	environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	// imageReference is a reference with an optional registry, tag or digest.
	imageReference = regexp.MustCompile(`^[a-z0-9][A-Za-z0-9._\-/:@]{0,511}$`)
	// digestReference is the sha256 digest an image is pinned by.
	digestReference = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// driverName is what an engine plugin can be called.
	driverName = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,63}$`)
	// labelName is a label key; the engine itself allows anything without
	// whitespace, and the panel keeps it to what a person can read back.
	labelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
)

// The limits of a specification.
const (
	maxSpecEntries = 64
	maxSpecValue   = 4096
	maxCommandArgs = 128
)

// RestartPolicies are the policies the engine knows. An unknown one is a
// refusal here rather than an engine error after the container was created.
var RestartPolicies = []string{"no", "always", "unless-stopped", "on-failure"}

// MountTypes are the mount kinds a specification may name.
var MountTypes = []string{"volume", "bind", "tmpfs"}

// ContainerSpec is the desired state of one container.
type ContainerSpec struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	// ImageDigest is the digest the reference resolves to.
	ImageDigest string `json:"image_digest,omitempty"`
	// DigestSource names where the digest came from: reference, registry
	// or local.
	DigestSource string `json:"digest_source,omitempty"`
	// Command replaces the image's own command, Entrypoint its entry
	// point. An empty list leaves the image's own.
	Command    []string `json:"command,omitempty"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	// Env are the variables whose value is not a secret.
	Env map[string]string `json:"env,omitempty"`
	// EnvSecrets names the variables whose value the host fetches from the
	// panel's secret store right before the container is created.
	EnvSecrets map[string]string `json:"env_secrets,omitempty"`
	Ports      []PortSpec        `json:"ports,omitempty"`
	Mounts     []MountSpec       `json:"mounts,omitempty"`
	Networks   []AttachmentSpec  `json:"networks,omitempty"`
	Restart    RestartSpec       `json:"restart,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	// Health replaces the image's own health check. Nothing means the
	// image's own, which is not the same as no check at all.
	Health    *HealthSpec  `json:"health,omitempty"`
	Resources ResourceSpec `json:"resources,omitempty"`
	// User, WorkingDir and Hostname override what the image declares.
	User       string `json:"user,omitempty"`
	WorkingDir string `json:"working_dir,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	// ReadOnlyRootFilesystem keeps the container's own layer read only;
	// what it has to write goes into a mount.
	ReadOnlyRootFilesystem bool `json:"read_only_root_filesystem,omitempty"`
	// StopTimeoutSeconds is how long the container gets to shut down before the
	// engine kills it, both for a replacement and for a later stop.
	StopTimeoutSeconds int `json:"stop_timeout_seconds,omitempty"`
	// Stopped asks for a container that exists and does not run.
	Stopped bool `json:"stopped,omitempty"`
}

// PortSpec publishes one container port on the host.
type PortSpec struct {
	// HostIP binds the publication to one address of the host. Empty
	// publishes on every address, which is what the engine does.
	HostIP string `json:"host_ip,omitempty"`
	// HostPort is the port on the host. Zero asks the engine for a free
	// one, and the plan says that the port is not fixed.
	HostPort      uint16 `json:"host_port,omitempty"`
	ContainerPort uint16 `json:"container_port"`
	// Protocol is tcp when empty.
	Protocol string `json:"protocol,omitempty"`
}

// MountSpec is one mount of the container.
type MountSpec struct {
	// Type is volume, bind or tmpfs.
	Type string `json:"type"`
	// Source is the volume name for a volume mount and the host path for a
	// bind mount. A tmpfs has none.
	Source string `json:"source,omitempty"`
	Target string `json:"target"`
	// ReadOnly is the difference between a container that reads the data
	// and one that can destroy it.
	ReadOnly bool `json:"read_only,omitempty"`
	// SizeBytes bounds a tmpfs. Zero leaves the engine's own default,
	// which is half of the host's memory.
	SizeBytes int64 `json:"size_bytes,omitempty"`
}

// AttachmentSpec attaches the container to one network.
type AttachmentSpec struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
	// IPv4 asks for a fixed address. It only works on a network with a
	// subnet of its own, and the engine refuses otherwise.
	IPv4 string `json:"ipv4,omitempty"`
}

// RestartSpec is what the engine does with a container that exits.
type RestartSpec struct {
	// Policy is one of RestartPolicies; empty means the engine's own "no".
	Policy string `json:"policy,omitempty"`
	// MaxRetries bounds an on-failure policy. Zero means without a bound,
	// which is what the engine does.
	MaxRetries int `json:"max_retries,omitempty"`
}

// HealthSpec is the check the engine runs inside the container.
type HealthSpec struct {
	// Disable turns off the check the image declares. A container without
	// a check is not an unhealthy container, so the two are separate.
	Disable bool `json:"disable,omitempty"`
	// Test is the check as the engine takes it: the first word is CMD or
	// CMD-SHELL, the rest is the command.
	Test               []string `json:"test,omitempty"`
	IntervalSeconds    int      `json:"interval_seconds,omitempty"`
	TimeoutSeconds     int      `json:"timeout_seconds,omitempty"`
	Retries            int      `json:"retries,omitempty"`
	StartPeriodSeconds int      `json:"start_period_seconds,omitempty"`
}

// ResourceSpec bounds what the container may take from the host. Zero
// means no limit of that kind, which is the engine's own default.
type ResourceSpec struct {
	MemoryBytes            int64 `json:"memory_bytes,omitempty"`
	MemoryReservationBytes int64 `json:"memory_reservation_bytes,omitempty"`
	// NanoCPUs is processor time in billionths of a core: 1500000000 is a
	// core and a half.
	NanoCPUs  int64 `json:"nano_cpus,omitempty"`
	PidsLimit int64 `json:"pids_limit,omitempty"`
}

// NetworkSpec is the desired state of one network.
type NetworkSpec struct {
	Name string `json:"name"`
	// Driver is bridge when empty, which is the only driver a single host
	// has without a plugin.
	Driver string `json:"driver,omitempty"`
	// Subnet and Gateway fix the address range. Empty leaves the choice to
	// the engine's address manager, and the plan says which range it took.
	Subnet  string `json:"subnet,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	// IPRange narrows the part of the subnet the engine hands out.
	IPRange string `json:"ip_range,omitempty"`
	// IPv6 turns on addressing of the second family; IPv6Subnet and
	// IPv6Gateway fix its range.
	IPv6        bool   `json:"ipv6,omitempty"`
	IPv6Subnet  string `json:"ipv6_subnet,omitempty"`
	IPv6Gateway string `json:"ipv6_gateway,omitempty"`
	// Internal is a network without a way out of the host, Attachable one a
	// container outside the service may join.
	Internal   bool              `json:"internal,omitempty"`
	Attachable bool              `json:"attachable,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// VolumeSpec is the desired state of one volume.
type VolumeSpec struct {
	Name string `json:"name"`
	// Driver is local when empty.
	Driver  string            `json:"driver,omitempty"`
	Options map[string]string `json:"options,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// Validate checks a container specification.
func (s *ContainerSpec) Validate() error {
	if s == nil {
		return fmt.Errorf("the order carries no container description")
	}
	if !objectName.MatchString(s.Name) {
		return fmt.Errorf("invalid container name %q", s.Name)
	}
	if !imageReference.MatchString(s.Image) {
		return fmt.Errorf("invalid image reference %q", s.Image)
	}
	if s.ImageDigest != "" && !digestReference.MatchString(s.ImageDigest) {
		return fmt.Errorf("%q is not a sha256 digest", s.ImageDigest)
	}
	if len(s.Command) > maxCommandArgs || len(s.Entrypoint) > maxCommandArgs {
		return fmt.Errorf("a command of more than %d arguments is not a description anyone reads",
			maxCommandArgs)
	}
	if err := checkEnvironment(s.Env, s.EnvSecrets); err != nil {
		return err
	}
	if err := checkLabels(s.Labels); err != nil {
		return err
	}
	if err := checkPorts(s.Ports); err != nil {
		return err
	}
	if err := checkMounts(s.Mounts); err != nil {
		return err
	}
	if err := checkAttachments(s.Networks); err != nil {
		return err
	}
	if err := checkRestart(s.Restart); err != nil {
		return err
	}
	if err := checkHealth(s.Health); err != nil {
		return err
	}
	if s.Resources.MemoryBytes < 0 || s.Resources.MemoryReservationBytes < 0 ||
		s.Resources.NanoCPUs < 0 || s.Resources.PidsLimit < 0 {
		return fmt.Errorf("a resource limit is not a negative number")
	}
	// The engine refuses a reservation above the limit, and it does so
	// after the container was created under another name.
	if s.Resources.MemoryBytes > 0 && s.Resources.MemoryReservationBytes > s.Resources.MemoryBytes {
		return fmt.Errorf("the memory reservation is larger than the memory limit")
	}
	if s.StopTimeoutSeconds < 0 || s.StopTimeoutSeconds > 3600 {
		return fmt.Errorf("the time given to shut the container down has to be between 0 and 3600 seconds")
	}
	if len(s.User) > 64 || strings.ContainsAny(s.User, " \t\n") {
		return fmt.Errorf("invalid user %q", s.User)
	}
	if s.WorkingDir != "" && !strings.HasPrefix(s.WorkingDir, "/") {
		return fmt.Errorf("the working directory %q is not an absolute path", s.WorkingDir)
	}
	if s.Hostname != "" && !objectName.MatchString(s.Hostname) {
		return fmt.Errorf("invalid host name %q", s.Hostname)
	}
	return nil
}

func checkEnvironment(plain map[string]string, secrets map[string]string) error {
	if len(plain)+len(secrets) > maxSpecEntries {
		return fmt.Errorf("more than %d environment variables", maxSpecEntries)
	}
	for name, value := range plain {
		if !environmentName.MatchString(name) {
			return fmt.Errorf("invalid environment variable name %q", name)
		}
		if len(value) > maxSpecValue {
			return fmt.Errorf("the value of %s is longer than %d characters", name, maxSpecValue)
		}
		if strings.ContainsRune(value, 0) {
			return fmt.Errorf("the value of %s carries a null byte", name)
		}
		// A value that looks like a credential in the plain map would be stored with
		// the job and shown to everyone who may read it.
		if looksLikeSecret(name) {
			return fmt.Errorf("%s looks like a credential; name a secret of the store for it "+
				"instead of writing the value into the order", name)
		}
	}
	for name, reference := range secrets {
		if !environmentName.MatchString(name) {
			return fmt.Errorf("invalid environment variable name %q", name)
		}
		if _, defined := plain[name]; defined {
			return fmt.Errorf("%s is given both a value and a secret", name)
		}
		if strings.TrimSpace(reference) == "" {
			return fmt.Errorf("%s names no secret", name)
		}
	}
	return nil
}

func checkLabels(labels map[string]string) error {
	if len(labels) > maxSpecEntries {
		return fmt.Errorf("more than %d labels", maxSpecEntries)
	}
	for key, value := range labels {
		if !labelName.MatchString(key) {
			return fmt.Errorf("invalid label %q", key)
		}
		if len(value) > maxSpecValue {
			return fmt.Errorf("the value of the label %s is longer than %d characters", key, maxSpecValue)
		}
		// The compose labels decide which project a container belongs to.
		if strings.HasPrefix(key, "com.docker.compose.") {
			return fmt.Errorf("the label %s belongs to Compose; a container declared here is not part of a project", key)
		}
		// The module writes its own marks under this prefix; a label from the order
		// that overwrote one would make the plan compare a description against
		// itself.
		if strings.HasPrefix(key, "io.flotestro.") {
			return fmt.Errorf("the label %s belongs to the panel's own marks on the object", key)
		}
		// The engine does not tell a plain label from one carrying a credential, so
		// the inventory hides the value of a label whose name suggests one - and a
		// description whose value could never be read back would be replaced at.
		if looksLikeSecret(key) {
			return fmt.Errorf("the label %s looks like a credential; its value would be hidden "+
				"in the inventory and could never be compared", key)
		}
	}
	return nil
}

func checkPorts(ports []PortSpec) error {
	if len(ports) > maxSpecEntries {
		return fmt.Errorf("more than %d published ports", maxSpecEntries)
	}
	seen := map[string]bool{}
	for _, port := range ports {
		if port.ContainerPort == 0 {
			return fmt.Errorf("a published port without a container port")
		}
		switch port.Protocol {
		case "", "tcp", "udp", "sctp":
		default:
			return fmt.Errorf("unknown protocol %q", port.Protocol)
		}
		if port.HostIP != "" && !addressLike(port.HostIP) {
			return fmt.Errorf("%q is not an address of the host", port.HostIP)
		}
		// The engine takes the second publication of the same host port and
		// fails when it starts the container, leaving it created and down.
		if port.HostPort != 0 {
			key := port.HostIP + "/" + protocolOf(port) + "/" + fmt.Sprint(port.HostPort)
			if seen[key] {
				return fmt.Errorf("the host port %d is published twice", port.HostPort)
			}
			seen[key] = true
		}
	}
	return nil
}

func checkMounts(mounts []MountSpec) error {
	if len(mounts) > maxSpecEntries {
		return fmt.Errorf("more than %d mounts", maxSpecEntries)
	}
	targets := map[string]bool{}
	for _, mount := range mounts {
		if !contains(MountTypes, mount.Type) {
			return fmt.Errorf("unknown mount type %q", mount.Type)
		}
		if !strings.HasPrefix(mount.Target, "/") || strings.Contains(mount.Target, "..") {
			return fmt.Errorf("the mount point %q is not an absolute path", mount.Target)
		}
		if targets[mount.Target] {
			return fmt.Errorf("two mounts share the mount point %s", mount.Target)
		}
		targets[mount.Target] = true
		switch mount.Type {
		case "volume":
			if !objectName.MatchString(mount.Source) {
				return fmt.Errorf("invalid volume name %q", mount.Source)
			}
		case "bind":
			if !strings.HasPrefix(mount.Source, "/") || strings.Contains(mount.Source, "..") {
				return fmt.Errorf("the bind source %q is not an absolute path", mount.Source)
			}
		case "tmpfs":
			if mount.Source != "" {
				return fmt.Errorf("a tmpfs mount has no source")
			}
			if mount.SizeBytes < 0 {
				return fmt.Errorf("the size of a tmpfs is not a negative number")
			}
		}
	}
	return nil
}

func checkAttachments(networks []AttachmentSpec) error {
	if len(networks) > maxSpecEntries {
		return fmt.Errorf("more than %d networks", maxSpecEntries)
	}
	seen := map[string]bool{}
	for _, attachment := range networks {
		if !objectName.MatchString(attachment.Name) {
			return fmt.Errorf("invalid network name %q", attachment.Name)
		}
		if seen[attachment.Name] {
			return fmt.Errorf("the network %s is named twice", attachment.Name)
		}
		seen[attachment.Name] = true
		if attachment.IPv4 != "" && !addressLike(attachment.IPv4) {
			return fmt.Errorf("%q is not an address", attachment.IPv4)
		}
		for _, alias := range attachment.Aliases {
			if !objectName.MatchString(alias) {
				return fmt.Errorf("invalid network alias %q", alias)
			}
		}
	}
	return nil
}

func checkRestart(restart RestartSpec) error {
	if restart.Policy != "" && !contains(RestartPolicies, restart.Policy) {
		return fmt.Errorf("unknown restart policy %q", restart.Policy)
	}
	if restart.MaxRetries < 0 || restart.MaxRetries > 1000 {
		return fmt.Errorf("the retry count has to be between 0 and 1000")
	}
	// The engine refuses a retry count on every policy but on-failure,
	// and it refuses it after the container was created.
	if restart.MaxRetries > 0 && restart.Policy != "on-failure" {
		return fmt.Errorf("a retry count belongs to the on-failure policy alone")
	}
	return nil
}

func checkHealth(health *HealthSpec) error {
	if health == nil {
		return nil
	}
	if health.Disable {
		if len(health.Test) > 0 {
			return fmt.Errorf("a disabled health check carries no command")
		}
		return nil
	}
	if len(health.Test) == 0 {
		return fmt.Errorf("a health check without a command")
	}
	switch health.Test[0] {
	case "CMD", "CMD-SHELL":
	default:
		return fmt.Errorf("a health check starts with CMD or CMD-SHELL, not %q", health.Test[0])
	}
	if len(health.Test) < 2 {
		return fmt.Errorf("a health check without a command")
	}
	if len(health.Test) > maxCommandArgs {
		return fmt.Errorf("a health check of more than %d arguments", maxCommandArgs)
	}
	if health.IntervalSeconds < 0 || health.TimeoutSeconds < 0 ||
		health.Retries < 0 || health.StartPeriodSeconds < 0 {
		return fmt.Errorf("a health check interval is not a negative number")
	}
	// A timeout longer than the interval means the engine starts the next
	// check before the previous one gave an answer.
	if health.IntervalSeconds > 0 && health.TimeoutSeconds > health.IntervalSeconds {
		return fmt.Errorf("the health check timeout is longer than the interval between checks")
	}
	return nil
}

// Validate checks a network specification.
func (s *NetworkSpec) Validate() error {
	if s == nil {
		return fmt.Errorf("the order carries no network description")
	}
	if !objectName.MatchString(s.Name) {
		return fmt.Errorf("invalid network name %q", s.Name)
	}
	if predefinedNetwork(s.Name) {
		return fmt.Errorf("%s is a network of the engine itself and is not declared here", s.Name)
	}
	if s.Driver != "" && !driverName.MatchString(s.Driver) {
		return fmt.Errorf("invalid driver %q", s.Driver)
	}
	for field, value := range map[string]string{"subnet": s.Subnet, "ip_range": s.IPRange} {
		if value != "" && !cidrLike(value) {
			return fmt.Errorf("%s %q is not an address range", field, value)
		}
	}
	if s.Gateway != "" && !addressLike(s.Gateway) {
		return fmt.Errorf("the gateway %q is not an address", s.Gateway)
	}
	// A gateway without a subnet has nothing to belong to, and the engine
	// refuses it.
	if s.Gateway != "" && s.Subnet == "" {
		return fmt.Errorf("a gateway needs the subnet it belongs to")
	}
	if s.IPRange != "" && s.Subnet == "" {
		return fmt.Errorf("an address range needs the subnet it lies in")
	}
	if s.IPv6Subnet != "" && !cidrLike(s.IPv6Subnet) {
		return fmt.Errorf("the IPv6 subnet %q is not an address range", s.IPv6Subnet)
	}
	if s.IPv6Gateway != "" && !addressLike(s.IPv6Gateway) {
		return fmt.Errorf("the IPv6 gateway %q is not an address", s.IPv6Gateway)
	}
	if (s.IPv6Subnet != "" || s.IPv6Gateway != "") && !s.IPv6 {
		return fmt.Errorf("an IPv6 range on a network with IPv6 turned off")
	}
	if s.IPv6Gateway != "" && s.IPv6Subnet == "" {
		return fmt.Errorf("an IPv6 gateway needs the subnet it belongs to")
	}
	if err := checkLabels(s.Labels); err != nil {
		return err
	}
	return checkOptions(s.Options)
}

// Validate checks a volume specification.
func (s *VolumeSpec) Validate() error {
	if s == nil {
		return fmt.Errorf("the order carries no volume description")
	}
	if !objectName.MatchString(s.Name) {
		return fmt.Errorf("invalid volume name %q", s.Name)
	}
	if s.Driver != "" && !driverName.MatchString(s.Driver) {
		return fmt.Errorf("invalid driver %q", s.Driver)
	}
	if err := checkLabels(s.Labels); err != nil {
		return err
	}
	return checkOptions(s.Options)
}

func checkOptions(options map[string]string) error {
	if len(options) > maxSpecEntries {
		return fmt.Errorf("more than %d driver options", maxSpecEntries)
	}
	for key, value := range options {
		if !labelName.MatchString(key) {
			return fmt.Errorf("invalid driver option %q", key)
		}
		if len(value) > maxSpecValue {
			return fmt.Errorf("the value of the option %s is longer than %d characters", key, maxSpecValue)
		}
	}
	return nil
}

// Normalized returns the specification with the engine's own defaults written
// out.
func (s ContainerSpec) Normalized() ContainerSpec {
	normalized := s
	// Where the digest came from is a fact about the plan, not about the
	// container: the same description resolved once at the registry and once from
	// a local image must not read as two different ones.
	normalized.DigestSource = ""
	normalized.Ports = make([]PortSpec, 0, len(s.Ports))
	for _, port := range s.Ports {
		port.Protocol = protocolOf(port)
		normalized.Ports = append(normalized.Ports, port)
	}
	sort.Slice(normalized.Ports, func(i, j int) bool { return portKey(normalized.Ports[i]) < portKey(normalized.Ports[j]) })

	normalized.Mounts = append([]MountSpec(nil), s.Mounts...)
	sort.Slice(normalized.Mounts, func(i, j int) bool { return normalized.Mounts[i].Target < normalized.Mounts[j].Target })

	normalized.Networks = make([]AttachmentSpec, 0, len(s.Networks))
	for _, attachment := range s.Networks {
		aliases := append([]string(nil), attachment.Aliases...)
		sort.Strings(aliases)
		attachment.Aliases = aliases
		normalized.Networks = append(normalized.Networks, attachment)
	}
	sort.Slice(normalized.Networks, func(i, j int) bool { return normalized.Networks[i].Name < normalized.Networks[j].Name })

	if normalized.Restart.Policy == "" {
		normalized.Restart.Policy = "no"
	}
	return normalized
}

// Normalized returns the network specification with the engine's defaults
// written out.
func (s NetworkSpec) Normalized() NetworkSpec {
	normalized := s
	if normalized.Driver == "" {
		normalized.Driver = "bridge"
	}
	return normalized
}

// Normalized returns the volume specification with the engine's defaults
// written out.
func (s VolumeSpec) Normalized() VolumeSpec {
	normalized := s
	if normalized.Driver == "" {
		normalized.Driver = "local"
	}
	return normalized
}

// SecretVariables lists the environment variables whose value comes from
// the store, in a fixed order. The names travel; the values never do.
func (s ContainerSpec) SecretVariables() []string {
	names := make([]string, 0, len(s.EnvSecrets))
	for name := range s.EnvSecrets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// planDigest binds a change to the plan that described it.
func planDigest(kind, action string, spec any, base ...string) string {
	sum := sha256.New()
	fmt.Fprintf(sum, "kind=%s\n", kind)
	fmt.Fprintf(sum, "action=%s\n", action)
	// The specification is hashed as canonical JSON: the Go marshaller writes map
	// keys in sorted order and the fields in declaration order, so the same
	// description always gives the same text.
	encoded, err := json.Marshal(spec)
	if err != nil {
		// A specification that does not marshal cannot be described, and a
		// digest over nothing must not look like a digest over something.
		encoded = []byte("unencodable")
	}
	fmt.Fprintf(sum, "spec=%s\n", encoded)
	for _, value := range base {
		fmt.Fprintf(sum, "base=%s\n", value)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// protocolOf is the protocol of a published port; the engine's own default
// is tcp.
func protocolOf(port PortSpec) string {
	if port.Protocol == "" {
		return "tcp"
	}
	return port.Protocol
}

func portKey(port PortSpec) string {
	return fmt.Sprintf("%05d/%s/%s/%05d", port.ContainerPort, protocolOf(port), port.HostIP, port.HostPort)
}

// addressLike says whether a value reads as an IP address.
func addressLike(value string) bool {
	if value == "" {
		return false
	}
	if strings.Contains(value, ":") {
		return len(value) <= 45 && strings.IndexFunc(value, func(r rune) bool {
			return !strings.ContainsRune("0123456789abcdefABCDEF:.", r)
		}) < 0
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return false
			}
		}
	}
	return true
}

// cidrLike says whether a value reads as an address range.
func cidrLike(value string) bool {
	address, mask, found := strings.Cut(value, "/")
	if !found || !addressLike(address) || mask == "" || len(mask) > 3 {
		return false
	}
	for _, digit := range mask {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
