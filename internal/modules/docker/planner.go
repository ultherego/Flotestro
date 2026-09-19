package docker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The plan of a declared object: what stands on the host, what is to stand
// there, and what the change between the two would be.

// The kinds of object a plan can be about.
const (
	KindContainer = "container"
	KindNetwork   = "network"
	KindVolume    = "volume"
)

// What a plan says would happen.
const (
	// PlanNoChange: the host already matches the description.
	PlanNoChange = "no_change"
	// PlanCreate: the object is not there and would be created.
	PlanCreate = "create"
	// PlanReplace: the object is there and differs in something that cannot be
	// changed in place, so it would be removed and created again.
	PlanReplace = "replace"
	// PlanStart: the object matches its description and is not running.
	PlanStart = "start"
	// PlanStop: the object matches its description and runs, and the
	// description asks for a container that does not run.
	PlanStop = "stop"
	// PlanRemove: the object is there and would be removed.
	PlanRemove = "remove"
	// PlanAbsent: the object is not there, so a removal has nothing to do.
	PlanAbsent = "absent"
)

// ErrObjectConflict means an object that exists and differs in something that
// can only be changed by destroying it - a volume's driver, a network's
// address range while containers are attached.
var ErrObjectConflict = errors.New("the object on the host differs in a setting that cannot be changed in place")

// ErrDigestUnresolved means a reference by tag the host could resolve
// neither at the registry nor from an image it already has.
var ErrDigestUnresolved = errors.New("the image digest could not be resolved")

// ErrPlanMismatch means the host is no longer in the state the approved
// plan described.
var ErrPlanMismatch = errors.New("the plan changed since it was approved")

// Change is one difference between the host and the description.
type Change struct {
	Field   string `json:"field"`
	Current string `json:"current"`
	Desired string `json:"desired"`
}

// Plan is what a change of one declared object would do.
type Plan struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Action is one of the constants above.
	Action string `json:"action"`
	Exists bool   `json:"exists"`
	// Changes lists every difference found. A replacement without a change
	// list would leave the operator approving a word.
	Changes []Change `json:"changes,omitempty"`
	// Warnings are things that do not stop the change and that the
	// operator is meant to know before approving it.
	Warnings []string `json:"warnings,omitempty"`
	// ImageDigest is what the container would really run, DigestSource where that
	// answer came from and PinnedImage the reference the container is created
	// from.
	ImageDigest  string `json:"image_digest,omitempty"`
	DigestSource string `json:"digest_source,omitempty"`
	PinnedImage  string `json:"pinned_image,omitempty"`
	// Digest binds the change to this plan.
	Digest string `json:"digest"`
	// CurrentID is the engine's identifier of the object that is there
	// now, so the operator can see which object the plan is about.
	CurrentID string `json:"current_id,omitempty"`
	// Detaches lists the containers a network replacement or removal would
	// disconnect. It is the whole reason an order carries force.
	Detaches []string `json:"detaches,omitempty"`
	// UnavailableReason says why the plan could not be computed.
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
	ComputedAt        time.Time `json:"computed_at"`
}

// Changed says whether carrying the plan out would touch the host.
func (p Plan) Changed() bool {
	switch p.Action {
	case PlanNoChange, PlanAbsent:
		return false
	}
	return true
}

// PlanContainer computes the plan of one declared container.
func PlanContainer(ctx context.Context, client *Client, spec ContainerSpec) (Plan, error) {
	if err := spec.Validate(); err != nil {
		return Plan{Kind: KindContainer, Name: spec.Name, ComputedAt: time.Now().UTC()}, err
	}
	// Every tag is bound to a digest before the plan exists.
	digest, source, err := client.ResolveImageDigest(ctx, spec.Image)
	if err != nil {
		return Plan{Kind: KindContainer, Name: spec.Name, ComputedAt: time.Now().UTC()},
			fmt.Errorf("%w: %s: %v", ErrDigestUnresolved, spec.Image, err)
	}

	var current *ContainerDetail
	detail, err := client.InspectContainer(ctx, spec.Name)
	switch {
	case err == nil:
		current = &detail
	case !errors.Is(err, ErrNotFound):
		return Plan{Kind: KindContainer, Name: spec.Name, ComputedAt: time.Now().UTC()}, err
	}
	return planContainerFrom(spec, digest, source, current), nil
}

// planContainerFrom is the plan itself, separated from the reads so that it
// can be checked against a state written down in a test rather than against a
// container engine.
func planContainerFrom(spec ContainerSpec, digest, source string, current *ContainerDetail) Plan {
	plan := Plan{
		Kind: KindContainer, Name: spec.Name, ComputedAt: time.Now().UTC(),
		ImageDigest: digest, DigestSource: source,
		PinnedImage: PinReference(spec.Image, digest),
	}
	if PinnedDigest(spec.Image) == "" {
		plan.Warnings = append(plan.Warnings, "the image is named by a tag ("+spec.Image+
			"); the plan binds the digest it resolves to now, and a tag that moves before the change makes the plan stale")
	}
	spec.ImageDigest = digest
	desired := spec.Normalized()

	if current == nil {
		plan.Action = PlanCreate
		plan.Digest = planDigest(KindContainer, PlanCreate, desired, "none")
		return plan
	}
	plan.Exists = true
	plan.CurrentID = current.ID
	plan.Changes = containerChanges(*current, desired)
	switch {
	case len(plan.Changes) > 0:
		plan.Action = PlanReplace
	case desired.Stopped && !current.Spec.Stopped:
		plan.Action = PlanStop
	case !desired.Stopped && current.Spec.Stopped:
		plan.Action = PlanStart
	default:
		plan.Action = PlanNoChange
	}
	plan.Digest = planDigest(KindContainer, plan.Action, desired, current.ID, current.ImageID)
	return plan
}

// containerChanges lists what differs between the container on the host and
// the description.
func containerChanges(detail ContainerDetail, desired ContainerSpec) []Change {
	current := detail.Spec
	var changes []Change
	add := func(field, was, wanted string) {
		if was != wanted {
			changes = append(changes, Change{Field: field, Current: was, Desired: wanted})
		}
	}
	// A declaration is a statement about what it names, and some of what a
	// container has comes from the image or from the engine rather than from
	// anybody's order: the command baked into the image, the network the engine.
	stated := func(field, was, wanted string) {
		if wanted == "" {
			return
		}
		add(field, was, wanted)
	}

	// The image is compared by digest, not by reference: two containers
	// created from the same tag on different days run different images.
	if desired.ImageDigest != "" && !sameImage(detail.ImageID, current.Image, desired.ImageDigest) {
		changes = append(changes, Change{
			Field: "image", Current: shortID(detail.ImageID), Desired: shortID(desired.ImageDigest),
		})
	}
	stated("command", strings.Join(current.Command, " "), strings.Join(desired.Command, " "))
	stated("entrypoint", strings.Join(current.Entrypoint, " "), strings.Join(desired.Entrypoint, " "))
	stated("user", current.User, desired.User)
	stated("working_dir", current.WorkingDir, desired.WorkingDir)
	if desired.Hostname != "" {
		add("hostname", current.Hostname, desired.Hostname)
	}
	add("read_only_root_filesystem", yesOrNo(current.ReadOnlyRootFilesystem), yesOrNo(desired.ReadOnlyRootFilesystem))
	add("restart_policy", restartText(current.Restart), restartText(desired.Restart))
	add("ports", portsText(current.Ports), portsText(desired.Ports))
	add("mounts", mountsText(current.Mounts), mountsText(desired.Mounts))
	stated("networks", networksText(current.Networks), networksText(desired.Networks))
	add("resources", resourcesText(current.Resources), resourcesText(desired.Resources))
	add("health", healthText(current.Health), healthText(desired.Health))
	if desired.StopTimeoutSeconds > 0 {
		add("stop_timeout_seconds", strconv.Itoa(current.StopTimeoutSeconds),
			strconv.Itoa(desired.StopTimeoutSeconds))
	}

	for _, name := range sortedKeys(desired.Env) {
		add("env "+name, current.Env[name], desired.Env[name])
	}
	for _, name := range desired.SecretVariables() {
		// The value of a secret variable is never compared: it is not in the
		// description and must not be read out of the container.
		if _, set := current.Env[name]; !set {
			changes = append(changes, Change{Field: "env " + name, Current: "not set", Desired: "from the secret store"})
		}
	}
	for _, key := range sortedKeys(desired.Labels) {
		add("label "+key, current.Labels[key], desired.Labels[key])
	}

	// The specification digest catches what the engine's own state cannot show: a
	// secret rotated to another version, a variable moved from the order into the
	// store.
	wanted := SpecDigest(desired)
	switch recorded := detail.Labels[LabelSpecDigest]; {
	case recorded == "":
		changes = append(changes, Change{
			Field: "specification", Current: "not declared here", Desired: shortID(wanted),
		})
	case recorded != wanted && len(changes) == 0:
		// The field list already explains a difference the engine shows.
		changes = append(changes, Change{
			Field: "specification", Current: shortID(recorded), Desired: shortID(wanted),
		})
	}
	return changes
}

// sameImage says whether the container runs the image the description names.
func sameImage(imageID, reference, digest string) bool {
	if imageID == digest {
		return true
	}
	return strings.Contains(reference, digest)
}

// PlanNetwork computes the plan of one declared network.
func PlanNetwork(ctx context.Context, client *Client, spec NetworkSpec, force bool) (Plan, error) {
	if err := spec.Validate(); err != nil {
		return Plan{Kind: KindNetwork, Name: spec.Name, ComputedAt: time.Now().UTC()}, err
	}
	state, err := pruneState(ctx, client)
	if err != nil {
		return Plan{Kind: KindNetwork, Name: spec.Name, ComputedAt: time.Now().UTC()}, err
	}
	return planNetworkFrom(state, spec, force)
}

// planNetworkFrom is the plan itself, separated from the reads.
func planNetworkFrom(state Snapshot, spec NetworkSpec, force bool) (Plan, error) {
	plan := Plan{Kind: KindNetwork, Name: spec.Name, ComputedAt: time.Now().UTC()}
	desired := spec.Normalized()

	current := networkByNetworkName(state.Networks, spec.Name)
	if current == nil {
		plan.Action = PlanCreate
		plan.Digest = planDigest(KindNetwork, PlanCreate, desired, "none")
		return plan, nil
	}
	plan.Exists = true
	plan.CurrentID = current.ID
	plan.Changes = networkChanges(*current, desired)
	if len(plan.Changes) == 0 {
		plan.Action = PlanNoChange
		plan.Digest = planDigest(KindNetwork, PlanNoChange, desired, current.ID)
		return plan, nil
	}

	plan.Action = PlanReplace
	plan.Detaches = memberNames(*current)
	if len(plan.Detaches) > 0 && !force {
		return plan, fmt.Errorf("the network %s has %s attached and would be recreated: %w",
			spec.Name, strings.Join(plan.Detaches, ", "), ErrInUse)
	}
	if len(plan.Detaches) > 0 {
		plan.Warnings = append(plan.Warnings, "the containers "+strings.Join(plan.Detaches, ", ")+
			" lose this network and are not reattached; recreate them from their own descriptions afterwards")
	}
	plan.Digest = planDigest(KindNetwork, PlanReplace, desired, current.ID)
	return plan, nil
}

// networkChanges lists what differs between the network on the host and the
// description.
func networkChanges(current Network, desired NetworkSpec) []Change {
	var changes []Change
	add := func(field, was, wanted string) {
		if was != wanted {
			changes = append(changes, Change{Field: field, Current: was, Desired: wanted})
		}
	}
	add("driver", current.Driver, desired.Driver)
	add("internal", yesOrNo(current.Internal), yesOrNo(desired.Internal))
	add("attachable", yesOrNo(current.Attachable), yesOrNo(desired.Attachable))
	add("ipv6", yesOrNo(current.IPv6), yesOrNo(desired.IPv6))
	if desired.Subnet != "" && !contains(current.Subnets, desired.Subnet) {
		add("subnet", strings.Join(current.Subnets, ", "), desired.Subnet)
	}
	if desired.IPv6Subnet != "" && !contains(current.Subnets, desired.IPv6Subnet) {
		add("ipv6_subnet", strings.Join(current.Subnets, ", "), desired.IPv6Subnet)
	}
	if desired.Gateway != "" && !contains(current.Gateways, desired.Gateway) {
		add("gateway", strings.Join(current.Gateways, ", "), desired.Gateway)
	}
	for _, key := range sortedKeys(desired.Labels) {
		add("label "+key, current.Labels[key], desired.Labels[key])
	}
	return changes
}

// PlanNetworkRemoval computes the plan of removing a network.
func PlanNetworkRemoval(ctx context.Context, client *Client, name string, force bool) (Plan, error) {
	plan := Plan{Kind: KindNetwork, Name: name, ComputedAt: time.Now().UTC()}
	if !objectName.MatchString(name) {
		return plan, fmt.Errorf("invalid network name %q", name)
	}
	if predefinedNetwork(name) {
		return plan, fmt.Errorf("network %s: %w", name, ErrPredefinedNetwork)
	}
	state, err := pruneState(ctx, client)
	if err != nil {
		return plan, err
	}
	return planNetworkRemovalFrom(state, name, force)
}

// planNetworkRemovalFrom is the plan itself, separated from the reads.
func planNetworkRemovalFrom(state Snapshot, name string, force bool) (Plan, error) {
	plan := Plan{Kind: KindNetwork, Name: name, ComputedAt: time.Now().UTC()}
	current := networkByNetworkName(state.Networks, name)
	if current == nil {
		// A removal with nothing to remove is not a failure and not a success
		// either: the operator gets to see that the host never had the object.
		plan.Action = PlanAbsent
		plan.Digest = planDigest(KindNetwork, PlanAbsent, name, "none")
		return plan, nil
	}
	plan.Exists = true
	plan.CurrentID = current.ID
	plan.Action = PlanRemove
	plan.Detaches = memberNames(*current)
	if len(plan.Detaches) > 0 && !force {
		return plan, fmt.Errorf("the network %s has %s attached: %w",
			name, strings.Join(plan.Detaches, ", "), ErrInUse)
	}
	if len(plan.Detaches) > 0 {
		plan.Warnings = append(plan.Warnings, "the containers "+strings.Join(plan.Detaches, ", ")+
			" are disconnected from this network and keep running without it")
	}
	plan.Digest = planDigest(KindNetwork, PlanRemove, name, current.ID)
	return plan, nil
}

// PlanVolume computes the plan of one declared volume.
func PlanVolume(ctx context.Context, client *Client, spec VolumeSpec, force bool) (Plan, error) {
	if err := spec.Validate(); err != nil {
		return Plan{Kind: KindVolume, Name: spec.Name, ComputedAt: time.Now().UTC()}, err
	}
	state, err := pruneState(ctx, client)
	if err != nil {
		return Plan{Kind: KindVolume, Name: spec.Name, ComputedAt: time.Now().UTC()}, err
	}
	return planVolumeFrom(state, spec, force)
}

// planVolumeFrom is the plan itself, separated from the reads.
func planVolumeFrom(state Snapshot, spec VolumeSpec, force bool) (Plan, error) {
	plan := Plan{Kind: KindVolume, Name: spec.Name, ComputedAt: time.Now().UTC()}
	desired := spec.Normalized()

	current := volumeByName(state.Volumes, spec.Name)
	if current == nil {
		plan.Action = PlanCreate
		plan.Digest = planDigest(KindVolume, PlanCreate, desired, "none")
		return plan, nil
	}
	plan.Exists = true
	plan.CurrentID = current.Name
	plan.Changes = volumeChanges(*current, desired)
	if len(plan.Changes) == 0 {
		plan.Action = PlanNoChange
		plan.Digest = planDigest(KindVolume, PlanNoChange, desired, current.Name)
		return plan, nil
	}

	plan.Action = PlanReplace
	if !force {
		return plan, fmt.Errorf("the volume %s differs in %s and recreating it destroys what is stored in it: %w",
			spec.Name, plan.Changes[0].Field, ErrObjectConflict)
	}
	if current.InUse {
		return plan, fmt.Errorf("the volume %s is mounted by %s: %w",
			spec.Name, volumeContainerNames(*current), ErrInUse)
	}
	plan.Warnings = append(plan.Warnings,
		"everything stored in the volume "+spec.Name+" is lost when it is recreated")
	plan.Digest = planDigest(KindVolume, PlanReplace, desired, current.Name)
	return plan, nil
}

func volumeChanges(current Volume, desired VolumeSpec) []Change {
	var changes []Change
	add := func(field, was, wanted string) {
		if was != wanted {
			changes = append(changes, Change{Field: field, Current: was, Desired: wanted})
		}
	}
	add("driver", current.Driver, desired.Driver)
	for _, key := range sortedKeys(desired.Options) {
		add("option "+key, current.Options[key], desired.Options[key])
	}
	for _, key := range sortedKeys(desired.Labels) {
		add("label "+key, current.Labels[key], desired.Labels[key])
	}
	return changes
}

// PlanVolumeRemoval computes the plan of removing a volume.
func PlanVolumeRemoval(ctx context.Context, client *Client, name string, force bool) (Plan, error) {
	plan := Plan{Kind: KindVolume, Name: name, ComputedAt: time.Now().UTC()}
	if !objectName.MatchString(name) {
		return plan, fmt.Errorf("invalid volume name %q", name)
	}
	state, err := pruneState(ctx, client)
	if err != nil {
		return plan, err
	}
	return planVolumeRemovalFrom(state, name, force)
}

// planVolumeRemovalFrom is the plan itself, separated from the reads.
func planVolumeRemovalFrom(state Snapshot, name string, force bool) (Plan, error) {
	plan := Plan{Kind: KindVolume, Name: name, ComputedAt: time.Now().UTC()}
	current := volumeByName(state.Volumes, name)
	if current == nil {
		plan.Action = PlanAbsent
		plan.Digest = planDigest(KindVolume, PlanAbsent, name, "none")
		return plan, nil
	}
	plan.Exists = true
	plan.CurrentID = current.Name
	plan.Action = PlanRemove
	if current.InUse {
		names := volumeContainerNames(*current)
		if !force {
			return plan, fmt.Errorf("the volume %s is mounted by %s: %w", name, names, ErrInUse)
		}
		// The engine refuses a volume a container still references, whether that
		// container runs or not.
		plan.Warnings = append(plan.Warnings, "the volume is mounted by "+names+
			"; the engine refuses to remove a volume a container references, whatever the order says")
	}
	plan.Digest = planDigest(KindVolume, PlanRemove, name, current.Name)
	return plan, nil
}

// networkByNetworkName finds a network by the name the operator uses.
func networkByNetworkName(list []Network, name string) *Network {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

func memberNames(network Network) []string {
	names := make([]string, 0, len(network.Containers))
	for _, member := range network.Containers {
		names = append(names, member.Name)
	}
	sort.Strings(names)
	return names
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func yesOrNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func restartText(restart RestartSpec) string {
	policy := restart.Policy
	if policy == "" {
		policy = "no"
	}
	if restart.MaxRetries > 0 {
		return policy + ":" + strconv.Itoa(restart.MaxRetries)
	}
	return policy
}

func portsText(ports []PortSpec) string {
	entries := make([]string, 0, len(ports))
	for _, port := range ports {
		entry := strconv.Itoa(int(port.ContainerPort)) + "/" + protocolOf(port)
		if port.HostPort != 0 {
			host := strconv.Itoa(int(port.HostPort))
			if port.HostIP != "" {
				host = port.HostIP + ":" + host
			}
			entry = host + "->" + entry
		}
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	return strings.Join(entries, " ")
}

func mountsText(mounts []MountSpec) string {
	entries := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		entry := mount.Type + ":" + mount.Source + "->" + mount.Target
		if mount.ReadOnly {
			entry += ":ro"
		}
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	return strings.Join(entries, " ")
}

func networksText(networks []AttachmentSpec) string {
	entries := make([]string, 0, len(networks))
	for _, attachment := range networks {
		entry := attachment.Name
		if len(attachment.Aliases) > 0 {
			entry += "(" + strings.Join(attachment.Aliases, ",") + ")"
		}
		if attachment.IPv4 != "" {
			entry += "@" + attachment.IPv4
		}
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	return strings.Join(entries, " ")
}

func resourcesText(resources ResourceSpec) string {
	return fmt.Sprintf("memory=%d reservation=%d nanocpus=%d pids=%d",
		resources.MemoryBytes, resources.MemoryReservationBytes,
		resources.NanoCPUs, resources.PidsLimit)
}

// healthText renders a health check for the change list.
func healthText(health *HealthSpec) string {
	if health == nil {
		return "from the image"
	}
	if health.Disable {
		return "disabled"
	}
	return fmt.Sprintf("%s interval=%d timeout=%d retries=%d start=%d",
		strings.Join(health.Test, " "), health.IntervalSeconds,
		health.TimeoutSeconds, health.Retries, health.StartPeriodSeconds)
}
