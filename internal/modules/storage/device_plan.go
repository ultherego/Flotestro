package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// DevicePlan describes what a check, a filesystem resize or a volume
// extension does on a single host.
//
// "Extend /dev/vg0/data by 10G" is backed by free space in the group on one
// host and not on another; "check /dev/sdb1" is unmounted on one and holds
// production data on another. The plan says so before approval, not
// half-way through the fleet.
type DevicePlan struct {
	// Operation names what was planned: check, resize or lvm_extend.
	Operation string `json:"operation"`
	Device    string `json:"device"`
	// Action names what would happen: run (the operation runs) or
	// no_change when there is nothing to do.
	Action string `json:"action"`

	// The state found: the device the host has under the path, and whether
	// it is mounted.
	Found      bool     `json:"found"`
	FSType     string   `json:"fs_type,omitempty"`
	UUID       string   `json:"uuid,omitempty"`
	SizeBytes  uint64   `json:"size_bytes,omitempty"`
	Mountpoint string   `json:"mountpoint,omitempty"`
	Group      string   `json:"group,omitempty"`
	FreeBytes  uint64   `json:"group_free_bytes,omitempty"`
	Size       string   `json:"size,omitempty"`
	Changes    []string `json:"changes,omitempty"`

	Refusal  string `json:"refusal,omitempty"`
	PlanHash string `json:"plan_hash"`
}

// Device plan operation and action names.
const (
	PlanCheck    = "check"
	PlanFSResize = "resize"
	PlanLVExtend = "lvm_extend"

	PlanRun = "run"
)

// ComputeCheck computes an fsck plan.
func ComputeCheck(state Snapshot, device string, repair bool) DevicePlan {
	plan := DevicePlan{Operation: PlanCheck, Device: device}
	if err := ValidateSource(device); err != nil {
		return plan.withRefusal(err.Error())
	}
	if state.UnavailableReason != "" {
		return plan.withRefusal(state.UnavailableReason)
	}
	found := state.DeviceAt(device)
	if found == nil {
		return plan.withRefusal("the host does not see the device " + device)
	}
	plan.describe(found)
	if found.FSType == "" {
		return plan.withRefusal("there is no filesystem to check on " + device)
	}
	// fsck on a mounted filesystem can damage it: that is not a warning but
	// a refusal - and better in the plan than at execution.
	if plan.Mountpoint != "" {
		return plan.withRefusal("the filesystem is mounted at " + plan.Mountpoint +
			"; the check requires unmounting")
	}
	plan.Action = PlanRun
	mode := "without repair (fsck -n)"
	if repair {
		mode = "with repair (fsck -y)"
	}
	plan.Changes = []string{"the filesystem " + found.FSType + " on " + device +
		" will be checked " + mode}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// ComputeFSResize computes a plan for growing a filesystem to the device
// size.
func ComputeFSResize(state Snapshot, device string) DevicePlan {
	plan := DevicePlan{Operation: PlanFSResize, Device: device}
	if err := ValidateSource(device); err != nil {
		return plan.withRefusal(err.Error())
	}
	if state.UnavailableReason != "" {
		return plan.withRefusal(state.UnavailableReason)
	}
	found := state.DeviceAt(device)
	if found == nil {
		return plan.withRefusal("the host does not see the device " + device)
	}
	plan.describe(found)
	arguments, err := FSResizeArguments(device, found.FSType, plan.Mountpoint)
	if err != nil {
		return plan.withRefusal(err.Error())
	}
	plan.Action = PlanRun
	plan.Changes = []string{"the filesystem " + found.FSType + " on " + device +
		" will be grown to the device size (" + strings.Join(arguments, " ") + ")"}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// ComputeLVExtend computes a plan for extending a logical volume.
func ComputeLVExtend(state Snapshot, device, size string) DevicePlan {
	plan := DevicePlan{Operation: PlanLVExtend, Device: device, Size: size}
	if _, err := LVExtendArguments(device, size, true); err != nil {
		return plan.withRefusal(err.Error())
	}
	if state.LVMUnavailableReason != "" {
		return plan.withRefusal(state.LVMUnavailableReason)
	}
	var volume *LogicalVolume
	for i := range state.Volumes {
		if MatchesVolume(state.Volumes[i], device) {
			volume = &state.Volumes[i]
			break
		}
	}
	if volume == nil {
		return plan.withRefusal("the host has no logical volume " + device)
	}
	plan.Found = true
	plan.Group = volume.Group
	plan.SizeBytes = volume.SizeBytes
	if found := state.DeviceAt(volume.Path); found != nil {
		plan.describe(found)
	}
	for _, group := range state.Groups {
		if group.Name == volume.Group {
			plan.FreeBytes = group.FreeBytes
		}
	}
	// A group without free space extends no volume; this is the most common
	// difference between hosts and is meant to stand in the plan.
	if plan.FreeBytes == 0 {
		return plan.withRefusal("the group " + volume.Group + " has no free space; " +
			"the volume cannot be extended without adding a disk")
	}
	plan.Action = PlanRun
	plan.Changes = []string{fmt.Sprintf("the volume %s will be extended by %s from the group %s (%d MiB free)",
		device, size, volume.Group, plan.FreeBytes>>20)}
	if plan.FSType != "" {
		plan.Changes = append(plan.Changes, "the filesystem "+plan.FSType+" will be grown together with the volume")
	}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// Refuse records a refusal reason and recomputes the fingerprint.
func (p *DevicePlan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = devicePlanFingerprint(*p)
}

func (p DevicePlan) withRefusal(reason string) DevicePlan {
	p.Refusal = reason
	p.PlanHash = devicePlanFingerprint(p)
	return p
}

func (p *DevicePlan) describe(device *Device) {
	p.Found = true
	p.FSType = device.FSType
	p.UUID = device.UUID
	if p.SizeBytes == 0 {
		p.SizeBytes = device.SizeBytes
	}
	if len(device.Mountpoints) > 0 {
		p.Mountpoint = device.Mountpoints[0]
	}
}

// devicePlanFingerprint computes the plan fingerprint excluding the
// fingerprint itself.
func devicePlanFingerprint(plan DevicePlan) string {
	stripped := plan
	stripped.PlanHash = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
