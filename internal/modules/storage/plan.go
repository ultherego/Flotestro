package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MountPlan describes the difference between the mount found and the one
// requested on a single host.
//
// The order "mount /dev/sdb at /data" means something different on every
// host: /dev/sdb is a different partition with a different UUID, and /data
// is at times already mounted, written in fstab or empty. The plan resolves
// the source to the UUID of the filesystem this host really has, and that
// UUID goes in the change. Thanks to that a disk that got a different path
// after a reboot is not mounted in somebody else's place - a mount by UUID
// finds the right one or none.
type MountPlan struct {
	Target string `json:"target"`
	// Action names what would happen: create, update, no_change, remove or
	// remove_absent.
	Action string `json:"action"`

	// The state found. No Current means a target the host knows neither as
	// a mount nor as an fstab entry.
	Current *Mount `json:"current,omitempty"`

	// RequestedSource is the source from the order; ResolvedSource - the
	// same source after resolving to a UUID on this host. The latter goes in
	// the change. If the order was already by UUID, both are equal. The
	// requested source stays out of the fingerprint: the change comes back
	// with the resolved one, and the plan it is compared against has to be
	// the same plan.
	RequestedSource string `json:"requested_source,omitempty"`
	ResolvedSource  string `json:"resolved_source,omitempty"`
	// SourceUUID and SourcePartUUID are the identity of the filesystem and
	// of the partition it sits on: together with the target and the type
	// they say what the plan is about, whatever path the source has today.
	SourceUUID     string `json:"source_uuid,omitempty"`
	SourcePartUUID string `json:"source_part_uuid,omitempty"`
	// Device describes the device the host has under the source, without
	// the usage counters, which change between two reads and would make
	// every plan stale on nothing.
	Device *Device `json:"device,omitempty"`

	DesiredFSType  string `json:"desired_fs_type,omitempty"`
	DesiredOptions string `json:"desired_options,omitempty"`
	DesiredPersist bool   `json:"desired_persist,omitempty"`

	// FstabRevision is the digest of /etc/fstab the plan was computed
	// against. The change is compared with a plan computed again on the
	// host: an fstab edited in between gives another revision, another
	// fingerprint, and a refusal to write into a file nobody approved.
	FstabRevision string `json:"fstab_revision,omitempty"`
	// TargetState is what stat says about the mount point: missing,
	// directory or not_a_directory. A target that appeared or vanished
	// since the plan is a changed base.
	TargetState string `json:"target_state,omitempty"`

	// Changes lists in human terms what will change.
	Changes []string `json:"changes,omitempty"`
	// Refusal names the reason the change will not land on this host: the
	// source is absent, the filesystem is of a different type than
	// requested, the target is already taken by another device. A plan with
	// a refusal is an answer the operator is meant to see before approving.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Plan action names.
const (
	PlanCreate       = "create"
	PlanUpdate       = "update"
	PlanNoChange     = "no_change"
	PlanRemove       = "remove"
	PlanRemoveAbsent = "remove_absent"
)

// ComputeMount computes the difference for ensuring a mount.
func ComputeMount(state Snapshot, source, target, fsType, options string,
	persist bool) MountPlan {
	plan := MountPlan{
		Target: target, RequestedSource: source, DesiredFSType: fsType,
		DesiredOptions: options, DesiredPersist: persist,
		FstabRevision: state.FstabRevision,
	}

	device := state.SourceDevice(source)
	if device == nil {
		plan.Refusal = "the host does not see the source " + source
		plan.PlanHash = mountPlanFingerprint(plan)
		return plan
	}
	copied := *device
	copied.FSUsedBytes, copied.FSAvailBytes = nil, nil
	plan.Device = &copied
	plan.SourceUUID = device.UUID
	plan.SourcePartUUID = device.PartUUID
	switch {
	case device.UUID == "":
		// Without a UUID there is nothing to bind the change to: the
		// /dev/sdX path points at something else after a reboot, and an
		// order by path would then mount somebody else's disk.
		plan.Refusal = "the filesystem on " + source + " has no UUID; it cannot be bound to the change"
	case fsType != "" && device.FSType != "" && device.FSType != fsType:
		plan.Refusal = "the source has the filesystem " + device.FSType + ", and the order requests " + fsType
	}
	if plan.Refusal != "" {
		plan.PlanHash = mountPlanFingerprint(plan)
		return plan
	}
	plan.ResolvedSource = "UUID=" + device.UUID

	current := state.MountAt(target)
	switch {
	case current == nil:
		plan.Action = PlanCreate
		plan.Changes = []string{"the mount will be created"}
		if persist {
			plan.Changes = append(plan.Changes, "the fstab entry will be created")
		}
	case !sameSource(current.Source, device):
		// The target is already taken by another filesystem. Mounting a
		// second one on it would cover the first - that is not a change
		// allowed to happen quietly in a campaign.
		found := *current
		plan.Current = &found
		plan.Refusal = "the target " + target + " is taken by " + current.Source
	default:
		found := *current
		plan.Current = &found
		plan.Changes = mountDifferences(*current, options, persist)
		plan.Action = PlanUpdate
		if len(plan.Changes) == 0 {
			plan.Action = PlanNoChange
		}
	}
	plan.PlanHash = mountPlanFingerprint(plan)
	return plan
}

// ComputeUnmount computes the difference for removing a mount.
func ComputeUnmount(state Snapshot, target string) MountPlan {
	plan := MountPlan{Target: target, FstabRevision: state.FstabRevision}
	current := state.MountAt(target)
	if current == nil {
		plan.Action = PlanRemoveAbsent
	} else {
		found := *current
		plan.Current = &found
		plan.Action = PlanRemove
		if current.Mounted {
			plan.Changes = append(plan.Changes, "the filesystem will be unmounted")
		}
		if current.InFstab {
			plan.Changes = append(plan.Changes, "the fstab entry will be removed")
		}
	}
	plan.PlanHash = mountPlanFingerprint(plan)
	return plan
}

// Refuse records in the plan a refusal reason learned after the
// differences were computed - for example processes holding the filesystem
// - and recomputes the fingerprint, because a plan with a refusal is a
// different answer than a plan without one.
func (p *MountPlan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = mountPlanFingerprint(*p)
}

// Mount point states as stat reports them.
const (
	TargetMissing       = "missing"
	TargetDirectory     = "directory"
	TargetNotADirectory = "not_a_directory"
)

// ObserveTarget records what stat says about the mount point and
// recomputes the fingerprint. The host calls it on the plan and again
// before the change, so a target that appeared, vanished or turned into a
// file in between is a different plan.
func (p *MountPlan) ObserveTarget(state string) {
	p.TargetState = state
	p.PlanHash = mountPlanFingerprint(*p)
}

// SourceDevice resolves the order source to a host device.
//
// The source may be a path, UUID= or LABEL=. Each points at a device
// differently, and the plan needs one: the one the host has.
func (s Snapshot) SourceDevice(source string) *Device {
	switch {
	case strings.HasPrefix(source, "UUID="):
		uuid := strings.TrimPrefix(source, "UUID=")
		for i := range s.Devices {
			if s.Devices[i].UUID == uuid {
				return &s.Devices[i]
			}
		}
	case strings.HasPrefix(source, "LABEL="):
		label := strings.TrimPrefix(source, "LABEL=")
		for i := range s.Devices {
			if s.Devices[i].Label != "" && s.Devices[i].Label == label {
				return &s.Devices[i]
			}
		}
	default:
		return s.DeviceAt(source)
	}
	return nil
}

// sameSource says whether the mount found points at the same device.
func sameSource(found string, device *Device) bool {
	switch {
	case found == device.Path:
		return true
	case strings.HasPrefix(found, "UUID="):
		return strings.TrimPrefix(found, "UUID=") == device.UUID
	case strings.HasPrefix(found, "LABEL="):
		return device.Label != "" && strings.TrimPrefix(found, "LABEL=") == device.Label
	}
	return false
}

// mountDifferences lists the changes visible to a human.
func mountDifferences(current Mount, options string, persist bool) []string {
	var changes []string
	if !current.Mounted {
		changes = append(changes, "the filesystem will be mounted")
	}
	if persist && !current.InFstab {
		changes = append(changes, "the fstab entry will be created")
	}
	if persist && current.InFstab && !sameOptions(current.FstabOptions, options) {
		changes = append(changes, "fstab options from "+orDefaults(current.FstabOptions)+
			" to "+orDefaults(options))
	}
	sort.Strings(changes)
	return changes
}

// sameOptions compares mount options as a set: the order is not the
// operator's decision.
func sameOptions(a, b string) bool {
	return strings.Join(optionSet(a), ",") == strings.Join(optionSet(b), ",")
}

func optionSet(options string) []string {
	parts := []string{}
	for _, part := range strings.Split(options, ",") {
		part = strings.TrimSpace(part)
		if part != "" && part != "defaults" {
			parts = append(parts, part)
		}
	}
	sort.Strings(parts)
	return parts
}

func orDefaults(options string) string {
	if strings.TrimSpace(options) == "" {
		return "defaults"
	}
	return options
}

// mountPlanFingerprint computes the plan fingerprint excluding the
// fingerprint itself and the requested source: the change carries the
// resolved source, and the plan it is compared against on the host has to
// come out the same.
func mountPlanFingerprint(plan MountPlan) string {
	stripped := plan
	stripped.PlanHash = ""
	stripped.RequestedSource = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
