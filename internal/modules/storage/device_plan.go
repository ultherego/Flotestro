package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	// The identity of the device the plan binds to. ByID, WWN and Serial
	// are what the host compares again right before a destructive change;
	// the size above is a signal for the operator reading the plan, never
	// an identity. Model and Parent describe; Holders and the three flags
	// say what stands on the device.
	ByID                      string   `json:"by_id,omitempty"`
	WWN                       string   `json:"wwn,omitempty"`
	Serial                    string   `json:"serial,omitempty"`
	Model                     string   `json:"model,omitempty"`
	Parent                    string   `json:"parent,omitempty"`
	Holders                   []string `json:"holders,omitempty"`
	RootDevice                bool     `json:"root_device,omitempty"`
	HasMountedChildren        bool     `json:"has_mounted_children,omitempty"`
	HasOpenHolders            bool     `json:"has_open_holders,omitempty"`
	IdentityUnavailableReason string   `json:"identity_unavailable_reason,omitempty"`
	// FSType and Label of a format plan: what the device will carry.
	DesiredFSType string `json:"desired_fs_type,omitempty"`
	DesiredLabel  string `json:"desired_label,omitempty"`

	// The LVM identity a volume operation binds to. A group and a volume
	// are known by their UUID: a name can be given to another group or
	// another volume tomorrow, and a plan that named one by name would
	// carry the consent over to whatever holds the name at execution time.
	GroupUUID  string `json:"group_uuid,omitempty"`
	VolumeName string `json:"volume_name,omitempty"`
	VolumeUUID string `json:"volume_uuid,omitempty"`
	// OriginName and OriginUUID name the volume a snapshot is taken of.
	OriginName string `json:"origin_name,omitempty"`
	OriginUUID string `json:"origin_uuid,omitempty"`
	// ExtentSizeBytes is the grain the group allocates in, and
	// RequestedBytes what the order asks for once it is read as a number of
	// bytes. A request smaller than one extent becomes one extent, and the
	// plan says so rather than surprising the operator with the size after.
	ExtentSizeBytes uint64 `json:"extent_size_bytes,omitempty"`
	RequestedBytes  uint64 `json:"requested_bytes,omitempty"`

	// The array identity a member operation binds to. The UUID out of the
	// superblock is the only name of an array that survives a reboot;
	// /dev/md0 is whichever array the kernel assembled first.
	Array          string `json:"array,omitempty"`
	ArrayUUID      string `json:"array_uuid,omitempty"`
	ArrayLevel     string `json:"array_level,omitempty"`
	ArrayState     string `json:"array_state,omitempty"`
	ArrayDegraded  bool   `json:"array_degraded,omitempty"`
	ArrayRedundant bool   `json:"array_redundant,omitempty"`
	ArraySync      string `json:"array_sync,omitempty"`
	RaidDevices    int    `json:"raid_devices,omitempty"`
	ActiveDevices  int    `json:"active_devices,omitempty"`
	SpareDevices   int    `json:"spare_devices,omitempty"`
	// MemberRole is what the array thinks the member is now, and
	// RedundancyAfter what the array is left with once the change lands -
	// the sentence the operator is really approving.
	MemberRole      string `json:"member_role,omitempty"`
	RedundancyAfter string `json:"redundancy_after,omitempty"`

	Refusal string `json:"refusal,omitempty"`
	// RefusalCode is the typed code of the refusal where one exists:
	// stable_identity_required, disk_changed, disk_in_use. A refusal
	// without a code is a plain description of why nothing will happen.
	RefusalCode string `json:"refusal_code,omitempty"`
	PlanHash    string `json:"plan_hash"`
}

// Device plan operation and action names.
const (
	PlanCheck    = "check"
	PlanFSResize = "resize"
	PlanLVExtend = "lvm_extend"
	PlanFormat   = "format"
	PlanWipe     = "wipe"

	// The LVM operations beyond growing a volume: a new volume in an
	// existing group, a new disk under a group, a snapshot and its removal,
	// and the removal of a volume, which deletes everything on it.
	PlanLVCreate       = "lvm_lv_create"
	PlanLVRemove       = "lvm_lv_remove"
	PlanVGExtend       = "lvm_vg_extend"
	PlanSnapshotCreate = "lvm_snapshot_create"
	PlanSnapshotRemove = "lvm_snapshot_remove"

	// The member operations of a software array. Creating and destroying an
	// array is deliberately not among them: that is a decision about a
	// machine's whole disk layout, taken once when the machine is built,
	// not an operation on a running fleet.
	PlanRAIDMemberFail   = "raid_member_fail"
	PlanRAIDMemberRemove = "raid_member_remove"
	PlanRAIDMemberAdd    = "raid_member_add"

	PlanRun = "run"
)

// KnownPlanKind says whether the panel knows a plan by that name.
//
// A plan kind the host does not know would come back as a refusal from the
// far end of a job. Refusing it where it is typed says the same thing
// earlier and to the person who can fix it.
func KnownPlanKind(kind string) bool {
	switch kind {
	case PlanCheck, PlanFSResize, PlanLVExtend, PlanFormat, PlanWipe,
		PlanLVCreate, PlanLVRemove, PlanVGExtend, PlanSnapshotCreate, PlanSnapshotRemove,
		PlanRAIDMemberFail, PlanRAIDMemberRemove, PlanRAIDMemberAdd:
		return true
	}
	return false
}

// Destructive says whether the plan kind loses the data on the device.
//
// Removing a logical volume belongs here: the extents go back to the group
// and the filesystem on them is gone, which is the same loss as a format
// and gets the same treatment - two approvals and the target typed out.
func Destructive(kind string) bool {
	return kind == PlanFormat || kind == PlanWipe || kind == PlanLVRemove || kind == PlanVGExtend
}

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

// ComputeFormat computes the plan of creating a filesystem on a device.
//
// The plan carries the identity the host has for the device now; the
// change comes back with that identity and the host compares it once more
// under the storage lock. A device without a stable identity, or with
// anything standing on it, is refused here - before the consent, with the
// reason in the plan.
func ComputeFormat(state Snapshot, device, fsType, label string) DevicePlan {
	plan := DevicePlan{Operation: PlanFormat, Device: device, DesiredFSType: fsType, DesiredLabel: label}
	arguments, err := FormatArguments(device, fsType, label)
	if err != nil {
		return plan.withRefusal(err.Error())
	}
	found, refusal := plan.destructiveTarget(state)
	if refusal != "" {
		return plan.withRefusal(refusal)
	}
	if err := ValidateDestructiveTarget(plan, *found); err != nil {
		return plan.withTypedRefusal(err)
	}
	plan.Action = PlanRun
	plan.Changes = []string{describeContent(found) + " on " + device + " will be destroyed and a " +
		fsType + " filesystem created (" + strings.Join(arguments, " ") + ")"}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// ComputeWipe computes the plan of removing the filesystem signatures.
func ComputeWipe(state Snapshot, device string) DevicePlan {
	plan := DevicePlan{Operation: PlanWipe, Device: device}
	arguments, err := WipeArguments(device)
	if err != nil {
		return plan.withRefusal(err.Error())
	}
	found, refusal := plan.destructiveTarget(state)
	if refusal != "" {
		return plan.withRefusal(refusal)
	}
	if err := ValidateDestructiveTarget(plan, *found); err != nil {
		return plan.withTypedRefusal(err)
	}
	plan.Action = PlanRun
	plan.Changes = []string{"the signatures of " + describeContent(found) + " on " + device +
		" will be removed (" + strings.Join(arguments, " ") + "); the content stays on the medium"}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// destructiveTarget finds the device and copies its identity into the
// plan; a state that could not be read or a device the host does not see
// is a refusal.
func (p *DevicePlan) destructiveTarget(state Snapshot) (*Device, string) {
	if state.UnavailableReason != "" {
		return nil, state.UnavailableReason
	}
	found := state.DeviceAt(p.Device)
	if found == nil {
		return nil, "the host does not see the device " + p.Device
	}
	p.describe(found)
	return found, ""
}

func describeContent(device *Device) string {
	switch {
	case device.FSType != "" && device.Label != "":
		return "the " + device.FSType + " filesystem " + device.Label
	case device.FSType != "":
		return "the " + device.FSType + " filesystem"
	case len(device.Children) > 0:
		return fmt.Sprintf("the partition table (%d partitions)", len(device.Children))
	}
	return "whatever is"
}

// Refuse records a refusal reason and recomputes the fingerprint.
func (p *DevicePlan) Refuse(reason string) {
	p.Refusal = reason
	p.RefusalCode = ""
	p.PlanHash = devicePlanFingerprint(*p)
}

func (p DevicePlan) withTypedRefusal(err error) DevicePlan {
	p.Refusal = err.Error()
	var refusal *Refusal
	if errors.As(err, &refusal) {
		p.RefusalCode = refusal.Code
	}
	p.PlanHash = devicePlanFingerprint(p)
	return p
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
	p.ByID = device.ByID
	p.WWN = device.WWN
	p.Serial = device.Serial
	p.Model = device.Model
	p.Parent = device.Parent
	p.Holders = device.Holders
	p.RootDevice = device.RootDevice
	p.HasMountedChildren = device.HasMountedChildren
	p.HasOpenHolders = device.HasOpenHolders
	p.IdentityUnavailableReason = device.IdentityUnavailableReason
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
