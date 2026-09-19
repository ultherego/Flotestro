package storage

import (
	"fmt"
	"strconv"
	"strings"
)

// The plans of the layers above a bare disk: the software array and the volume
// manager.

// Refusal codes of the array and volume operations.
const (
	// CodeArrayUnknown: the host has no such array, or the array carries no
	// UUID to bind the operation to.
	CodeArrayUnknown = "array_unknown"
	// CodeArrayMemberUnknown: the device is not a member of that array.
	CodeArrayMemberUnknown = "array_member_unknown"
	// CodeArrayRedundancyLost: the change would leave the array without a copy of
	// the data - a level that keeps none, an array already degraded, or the last
	// member that still carries data.
	CodeArrayRedundancyLost = "array_redundancy_lost"
	// CodeArrayRebuilding: the array is putting a member back.
	CodeArrayRebuilding = "array_rebuilding"
	// CodeArrayLifecycleOutOfScope: creating or destroying an array is a decision
	// about a machine's whole disk layout, not an operation the panel runs over a
	// fleet.
	CodeArrayLifecycleOutOfScope = "array_lifecycle_out_of_scope"
	// CodeVolumeUnknown: the host has no such volume group or logical
	// volume.
	CodeVolumeUnknown = "volume_unknown"
	// CodeVolumeGroupFull: the group has no free extents for what the order
	// asks.
	CodeVolumeGroupFull = "volume_group_full"
	// CodeSnapshotOfSnapshot: the volume named as the origin is itself a
	// snapshot.
	CodeSnapshotOfSnapshot = "snapshot_of_snapshot"
)

// ArrayLifecycleRefusal is the answer to an order that would create or destroy
// an array.
const ArrayLifecycleRefusal = "the panel manages the members of an array that exists; " +
	"creating an array and destroying one are decisions about a machine's whole disk layout, " +
	"taken on the machine when it is built, not operations run over a running fleet"

// arrayLifecycleKinds are the plan names somebody reaches for when they expect
// the panel to build or tear down an array.
var arrayLifecycleKinds = map[string]bool{
	"raid_create": true, "raid_destroy": true, "raid_stop": true, "raid_assemble": true,
	"array_create": true, "array_destroy": true, "array_stop": true,
}

// ArrayLifecycleRefusalFor answers a plan asked for under one of those
// names, and nothing otherwise.
func ArrayLifecycleRefusalFor(kind string) *Refusal {
	if !arrayLifecycleKinds[strings.ToLower(strings.TrimSpace(kind))] {
		return nil
	}
	return &Refusal{Code: CodeArrayLifecycleOutOfScope, Reason: ArrayLifecycleRefusal}
}

// ComputeRAIDMemberFail computes the plan of marking a member bad.
func ComputeRAIDMemberFail(state Snapshot, arrayPath, member string) DevicePlan {
	plan, array, found := raidTarget(state, PlanRAIDMemberFail, arrayPath, member)
	if plan.Refusal != "" {
		return plan
	}
	if found.Failed() {
		// The array has written this member off already; ordering it again
		// changes nothing on the host.
		plan.Action = PlanNoChange
		plan.RedundancyAfter = redundancyAfter(*array, 0)
		plan.Changes = []string{"the member " + member + " is already marked failed"}
		plan.PlanHash = devicePlanFingerprint(plan)
		return plan
	}
	if found.Role == MemberSpare {
		plan.Action = PlanRun
		plan.RedundancyAfter = redundancyAfter(*array, 0)
		plan.Changes = []string{"the spare " + member + " will be marked failed; the array keeps every copy it has"}
		plan.PlanHash = devicePlanFingerprint(plan)
		return plan
	}
	if refusal := redundancyRefusal(*array); refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	if array.DataMembers() <= 1 {
		return plan.withTypedRefusal(&Refusal{Code: CodeArrayRedundancyLost,
			Reason: "the array " + array.Path + " has one member carrying data; failing it leaves no copy"})
	}
	plan.Action = PlanRun
	plan.RedundancyAfter = redundancyAfter(*array, 1)
	plan.Changes = []string{
		"the member " + member + " will be marked failed and the array " + array.Path + " will stop reading from it",
		plan.RedundancyAfter,
	}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// ComputeRAIDMemberRemove computes the plan of taking a member out of an
// array.
func ComputeRAIDMemberRemove(state Snapshot, arrayPath, member string) DevicePlan {
	plan, array, found := raidTarget(state, PlanRAIDMemberRemove, arrayPath, member)
	if plan.Refusal != "" {
		return plan
	}
	if found.CarriesData() {
		return plan.withTypedRefusal(&Refusal{Code: CodeArrayRedundancyLost,
			Reason: "the member " + member + " still carries data in " + array.Path +
				"; mark it failed first, then remove it"})
	}
	if array.Rebuilding() && found.Role != MemberFaulty {
		return plan.withTypedRefusal(&Refusal{Code: CodeArrayRebuilding,
			Reason: "the array " + array.Path + " is rebuilding (" + array.SyncAction +
				"); removing a member now interrupts it"})
	}
	plan.Action = PlanRun
	plan.RedundancyAfter = redundancyAfter(*array, 0)
	plan.Changes = []string{
		"the " + roleWords(found.Role) + " " + member + " will be taken out of " + array.Path,
		plan.RedundancyAfter,
	}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// ComputeRAIDMemberAdd computes the plan of adding a device to an array. The
// device joins as a spare; a degraded array starts rebuilding onto it at once.
func ComputeRAIDMemberAdd(state Snapshot, arrayPath, device string) DevicePlan {
	plan := DevicePlan{Operation: PlanRAIDMemberAdd, Array: arrayPath, Device: device}
	if _, err := RAIDMemberArguments(arrayPath, device, RAIDAdd); err != nil {
		return plan.withRefusal(err.Error())
	}
	array, refusal := arrayOf(state, arrayPath)
	if refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	plan.describeArray(*array)
	if existing := array.MemberAt(device); existing != nil {
		plan.Action = PlanNoChange
		plan.MemberRole = existing.Role
		plan.Changes = []string{device + " is already a " + roleWords(existing.Role) + " of " + array.Path}
		plan.PlanHash = devicePlanFingerprint(plan)
		return plan
	}
	if state.UnavailableReason != "" {
		return plan.withRefusal(state.UnavailableReason)
	}
	observed := state.DeviceAt(device)
	if observed == nil {
		return plan.withRefusal("the host does not see the device " + device)
	}
	plan.describe(observed)
	// Adding a device to an array overwrites it. The identity check is the
	// same one a format runs, for the same reason.
	if err := ValidateDestructiveTarget(plan, *observed); err != nil {
		return plan.withTypedRefusal(err)
	}
	if smallest := largestMemberSize(*array); smallest > 0 && observed.SizeBytes < smallest {
		return plan.withRefusal(fmt.Sprintf(
			"the device %s holds %d MiB and the members of %s hold %d MiB; a smaller device cannot take a slot",
			device, observed.SizeBytes>>20, array.Path, smallest>>20))
	}
	plan.Action = PlanRun
	plan.RedundancyAfter = redundancyAfter(*array, 0)
	changes := []string{"whatever is on " + device + " will be overwritten with an array superblock and the device will join " +
		array.Path + " as a spare"}
	if array.Degraded {
		changes = append(changes, "the array is degraded, so it will start rebuilding onto the new member at once")
	}
	plan.Changes = append(changes, plan.RedundancyAfter)
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// raidTarget resolves the array and the member an operation names, and copies
// the identity of both into the plan.
func raidTarget(state Snapshot, kind, arrayPath, member string) (DevicePlan, *RAIDArray, RAIDMember) {
	plan := DevicePlan{Operation: kind, Array: arrayPath, Device: member}
	verb := RAIDFail
	if kind == PlanRAIDMemberRemove {
		verb = RAIDRemove
	}
	if _, err := RAIDMemberArguments(arrayPath, member, verb); err != nil {
		return plan.withRefusal(err.Error()), nil, RAIDMember{}
	}
	array, refusal := arrayOf(state, arrayPath)
	if refusal != nil {
		return plan.withTypedRefusal(refusal), nil, RAIDMember{}
	}
	plan.describeArray(*array)
	found := array.MemberAt(member)
	if found == nil {
		return plan.withTypedRefusal(&Refusal{Code: CodeArrayMemberUnknown,
			Reason: "the device " + member + " is not a member of " + array.Path}), nil, RAIDMember{}
	}
	plan.MemberRole = found.Role
	plan.ByID, plan.WWN, plan.Serial = found.ByID, found.WWN, found.Serial
	plan.IdentityUnavailableReason = found.IdentityUnavailableReason
	plan.SizeBytes = found.SizeBytes
	if plan.ByID == "" {
		reason := found.IdentityUnavailableReason
		if reason == "" {
			reason = "no /dev/disk/by-id link names " + member
		}
		return plan.withTypedRefusal(&Refusal{Code: CodeStableIdentityRequired,
			Reason: "the member " + member + " has no stable identity to bind the change to: " + reason}), nil, RAIDMember{}
	}
	return plan, array, *found
}

// arrayOf finds the array and insists it carries a UUID: the path is the order
// the kernel assembled the arrays in, and an operation bound to that is bound
// to nothing.
func arrayOf(state Snapshot, path string) (*RAIDArray, *Refusal) {
	if state.RAIDUnavailableReason != "" {
		return nil, &Refusal{Code: CodeArrayUnknown, Reason: state.RAIDUnavailableReason}
	}
	array := state.ArrayAt(path)
	if array == nil {
		return nil, &Refusal{Code: CodeArrayUnknown, Reason: "the host has no array " + path}
	}
	if array.UUID == "" {
		reason := array.DetailUnavailableReason
		if reason == "" {
			reason = "the array reports no UUID"
		}
		return nil, &Refusal{Code: CodeArrayUnknown,
			Reason: "the array " + path + " has no UUID to bind the change to: " + reason}
	}
	return array, nil
}

// redundancyRefusal answers whether the array can afford to lose a member
// at all.
func redundancyRefusal(array RAIDArray) *Refusal {
	if !array.Redundant {
		return &Refusal{Code: CodeArrayRedundancyLost,
			Reason: "the array " + array.Path + " is " + orUnknownLevel(array.Level) +
				", which keeps no copy of the data; losing a member loses the array"}
	}
	if array.Rebuilding() {
		return &Refusal{Code: CodeArrayRebuilding,
			Reason: "the array " + array.Path + " is rebuilding (" + array.SyncAction +
				"); it cannot afford to lose another member now"}
	}
	if array.Degraded {
		return &Refusal{Code: CodeArrayRedundancyLost,
			Reason: "the array " + array.Path + " is already degraded (" +
				strconv.Itoa(array.ActiveDevices) + " of " + strconv.Itoa(array.RaidDevices) +
				" slots filled); failing another member loses the data"}
	}
	return nil
}

// redundancyAfter says in one sentence what the array is left with once
// the change lands.
func redundancyAfter(array RAIDArray, losing int) string {
	remaining := array.DataMembers() - losing
	if array.RaidDevices == 0 {
		return fmt.Sprintf("the array %s will carry %d member(s) with data", array.Path, remaining)
	}
	sentence := fmt.Sprintf("the array %s will have %d of %d slots filled", array.Path, remaining, array.RaidDevices)
	switch {
	case !array.Redundant:
		return sentence + "; this level keeps no copy"
	case remaining < array.RaidDevices:
		return sentence + "; one more failure loses the data until a member is added and rebuilt"
	default:
		return sentence + "; the redundancy is intact"
	}
}

func roleWords(role string) string {
	switch role {
	case MemberSpare:
		return "spare"
	case MemberFaulty:
		return "failed member"
	case MemberRebuilding:
		return "rebuilding member"
	case MemberJournal:
		return "journal device"
	case MemberWriteMostly:
		return "write-mostly member"
	case MemberActive:
		return "active member"
	case MemberRemoved:
		return "empty slot"
	}
	return "member"
}

func orUnknownLevel(level string) string {
	if level == "" {
		return "of a level the host did not report"
	}
	return level
}

func largestMemberSize(array RAIDArray) uint64 {
	largest := uint64(0)
	for _, member := range array.Members {
		if member.SizeBytes > largest {
			largest = member.SizeBytes
		}
	}
	return largest
}

// describeArray copies the array identity into the plan.
func (p *DevicePlan) describeArray(array RAIDArray) {
	p.Found = true
	p.Array = array.Path
	p.ArrayUUID = array.UUID
	p.ArrayLevel = array.Level
	p.ArrayState = array.State
	p.ArrayDegraded = array.Degraded
	p.ArrayRedundant = array.Redundant
	p.ArraySync = array.SyncAction
	p.RaidDevices = array.RaidDevices
	p.ActiveDevices = array.ActiveDevices
	p.SpareDevices = array.SpareDevices
}

// ComputeLVCreate computes the plan of creating a logical volume in an
// existing group.
func ComputeLVCreate(state Snapshot, group, name, size string) DevicePlan {
	plan := DevicePlan{Operation: PlanLVCreate, Group: group, VolumeName: name, Size: size}
	if _, err := LVCreateArguments(group, name, size); err != nil {
		return plan.withRefusal(err.Error())
	}
	found, refusal := groupOf(state, group)
	if refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	plan.describeGroup(*found)
	for _, volume := range state.Volumes {
		if volume.Group == group && volume.Name == name {
			plan.Device = volume.Path
			plan.VolumeUUID = volume.UUID
			plan.SizeBytes = volume.SizeBytes
			return plan.withRefusal("the group " + group + " already holds a volume named " + name)
		}
	}
	if refusal := spaceRefusal(*found, size, &plan); refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	plan.Action = PlanRun
	plan.Device = "/dev/" + group + "/" + name
	plan.Changes = []string{fmt.Sprintf("the volume %s of %s will be created in %s (%d MiB free)",
		name, size, group, found.FreeBytes>>20)}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// ComputeLVRemove computes the plan of deleting a logical volume. The extents
// go back to the group and the filesystem on them is gone.
func ComputeLVRemove(state Snapshot, path string) DevicePlan {
	plan := DevicePlan{Operation: PlanLVRemove, Device: path}
	if _, err := LVRemoveArguments(path); err != nil {
		return plan.withRefusal(err.Error())
	}
	volume, refusal := volumeOf(state, path)
	if refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	plan.describeVolume(*volume, state)
	// A volume with snapshots on it takes them with it. Two decisions, two
	// orders: the snapshots go first.
	var dependents []string
	for _, other := range state.Volumes {
		if other.Group == volume.Group && other.Origin == volume.Name {
			dependents = append(dependents, other.Name)
		}
	}
	if len(dependents) > 0 {
		return plan.withRefusal("the volume " + path + " is the origin of " +
			strings.Join(dependents, ", ") + "; removing it removes them too, so remove the snapshots first")
	}
	if observed := state.DeviceForVolume(*volume); observed != nil {
		plan.describe(observed)
		if err := ValidateDestructiveTarget(plan, *observed); err != nil {
			return plan.withTypedRefusal(err)
		}
	} else if plan.Mountpoint != "" {
		return plan.withTypedRefusal(&Refusal{Code: CodeDiskInUse,
			Reason: "the volume " + path + " is mounted at " + plan.Mountpoint})
	}
	plan.Action = PlanRun
	plan.Changes = []string{fmt.Sprintf("the volume %s (%d MiB) will be deleted and its extents go back to %s; "+
		"whatever it carried is gone", path, volume.SizeBytes>>20, volume.Group)}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// ComputeVGExtend computes the plan of adding a disk to a volume group.
func ComputeVGExtend(state Snapshot, group, device string) DevicePlan {
	plan := DevicePlan{Operation: PlanVGExtend, Group: group, Device: device}
	if _, err := VGExtendArguments(group, device); err != nil {
		return plan.withRefusal(err.Error())
	}
	found, refusal := groupOf(state, group)
	if refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	plan.describeGroup(*found)
	if physical := state.PhysicalVolumeAt(device); physical != nil {
		if physical.Group == group {
			plan.Action = PlanNoChange
			plan.Changes = []string{device + " is already a physical volume of " + group}
			plan.PlanHash = devicePlanFingerprint(plan)
			return plan
		}
		if physical.Group != "" {
			return plan.withRefusal("the device " + device + " already belongs to the group " + physical.Group)
		}
	}
	if state.UnavailableReason != "" {
		return plan.withRefusal(state.UnavailableReason)
	}
	observed := state.DeviceAt(device)
	if observed == nil {
		return plan.withRefusal("the host does not see the device " + device)
	}
	plan.describe(observed)
	if err := ValidateDestructiveTarget(plan, *observed); err != nil {
		return plan.withTypedRefusal(err)
	}
	plan.Action = PlanRun
	plan.Changes = []string{fmt.Sprintf(
		"whatever is on %s will be overwritten with an LVM label and the device will join %s, taking it from %d to about %d MiB",
		device, group, found.SizeBytes>>20, (found.SizeBytes+observed.SizeBytes)>>20)}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// ComputeSnapshotCreate computes the plan of taking a snapshot of a volume.
func ComputeSnapshotCreate(state Snapshot, origin, name, size string) DevicePlan {
	plan := DevicePlan{Operation: PlanSnapshotCreate, Device: origin, VolumeName: name, Size: size}
	if _, err := SnapshotArguments(origin, name, size); err != nil {
		return plan.withRefusal(err.Error())
	}
	volume, refusal := volumeOf(state, origin)
	if refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	plan.describeVolume(*volume, state)
	plan.OriginName, plan.OriginUUID = volume.Name, volume.UUID
	if volume.IsSnapshot() {
		return plan.withTypedRefusal(&Refusal{Code: CodeSnapshotOfSnapshot,
			Reason: "the volume " + origin + " is itself a snapshot of " + orUnknownOrigin(volume.Origin) +
				"; a snapshot is taken of a volume, not of another snapshot"})
	}
	group := state.GroupAt(volume.Group)
	if group == nil {
		return plan.withTypedRefusal(&Refusal{Code: CodeVolumeUnknown,
			Reason: "the host does not report the group " + volume.Group + " the volume " + origin + " belongs to"})
	}
	plan.describeGroup(*group)
	for _, other := range state.Volumes {
		if other.Group == volume.Group && other.Name == name {
			return plan.withRefusal("the group " + volume.Group + " already holds a volume named " + name)
		}
	}
	if refusal := spaceRefusal(*group, size, &plan); refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	plan.Action = PlanRun
	plan.Changes = []string{fmt.Sprintf(
		"a snapshot %s of %s will be created with %s of copy-on-write space in %s (%d MiB free); "+
			"a snapshot that fills up is dropped by the kernel",
		name, origin, size, volume.Group, group.FreeBytes>>20)}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// ComputeSnapshotRemove computes the plan of dropping a snapshot.
func ComputeSnapshotRemove(state Snapshot, path string) DevicePlan {
	plan := DevicePlan{Operation: PlanSnapshotRemove, Device: path}
	if _, err := LVRemoveArguments(path); err != nil {
		return plan.withRefusal(err.Error())
	}
	volume, refusal := volumeOf(state, path)
	if refusal != nil {
		return plan.withTypedRefusal(refusal)
	}
	plan.describeVolume(*volume, state)
	if !volume.IsSnapshot() {
		return plan.withRefusal("the volume " + path + " is not a snapshot; " +
			"deleting an ordinary volume is a separate operation that needs two approvals")
	}
	plan.OriginName = volume.Origin
	if plan.Mountpoint != "" {
		return plan.withTypedRefusal(&Refusal{Code: CodeDiskInUse,
			Reason: "the snapshot " + path + " is mounted at " + plan.Mountpoint})
	}
	plan.Action = PlanRun
	plan.Changes = []string{fmt.Sprintf("the snapshot %s of %s will be dropped and its %d MiB go back to %s",
		path, orUnknownOrigin(volume.Origin), volume.SizeBytes>>20, volume.Group)}
	plan.PlanHash = devicePlanFingerprint(plan)
	return plan
}

// groupOf finds the volume group and insists it carries a UUID.
func groupOf(state Snapshot, name string) (*VolumeGroup, *Refusal) {
	if state.LVMUnavailableReason != "" {
		return nil, &Refusal{Code: CodeVolumeUnknown, Reason: state.LVMUnavailableReason}
	}
	group := state.GroupAt(name)
	if group == nil {
		return nil, &Refusal{Code: CodeVolumeUnknown, Reason: "the host has no volume group " + name}
	}
	if group.UUID == "" {
		return nil, &Refusal{Code: CodeVolumeUnknown,
			Reason: "the group " + name + " reports no UUID to bind the change to"}
	}
	return group, nil
}

// volumeOf finds the logical volume and insists it carries a UUID.
func volumeOf(state Snapshot, path string) (*LogicalVolume, *Refusal) {
	if state.LVMUnavailableReason != "" {
		return nil, &Refusal{Code: CodeVolumeUnknown, Reason: state.LVMUnavailableReason}
	}
	volume := state.VolumeAt(path)
	if volume == nil {
		return nil, &Refusal{Code: CodeVolumeUnknown, Reason: "the host has no logical volume " + path}
	}
	if volume.UUID == "" {
		return nil, &Refusal{Code: CodeVolumeUnknown,
			Reason: "the volume " + path + " reports no UUID to bind the change to"}
	}
	return volume, nil
}

// spaceRefusal answers whether the group has room for the size asked. A group
// with no free extent at all refuses whatever the shape of the request.
func spaceRefusal(group VolumeGroup, size string, plan *DevicePlan) *Refusal {
	if group.FreeBytes == 0 {
		return &Refusal{Code: CodeVolumeGroupFull,
			Reason: "the group " + group.Name + " has no free space; " +
				"add a disk to the group first"}
	}
	requested, absolute := SizeInBytes(size)
	if !absolute {
		return nil
	}
	plan.RequestedBytes = requested
	if requested > group.FreeBytes {
		return &Refusal{Code: CodeVolumeGroupFull,
			Reason: fmt.Sprintf("the group %s has %d MiB free and the order asks for %d MiB",
				group.Name, group.FreeBytes>>20, requested>>20)}
	}
	return nil
}

// SizeInBytes reads an LVM size written with a unit.
func SizeInBytes(size string) (uint64, bool) {
	size = strings.TrimPrefix(strings.TrimSpace(size), "+")
	if size == "" || strings.Contains(size, "%") {
		return 0, false
	}
	unit := size[len(size)-1]
	number, err := strconv.ParseUint(size[:len(size)-1], 10, 64)
	if err != nil {
		return 0, false
	}
	switch unit {
	case 'K', 'k':
		return number << 10, true
	case 'M', 'm':
		return number << 20, true
	case 'G', 'g':
		return number << 30, true
	case 'T', 't':
		return number << 40, true
	}
	return 0, false
}

// describeGroup copies the identity and the room of the group into the
// plan.
func (p *DevicePlan) describeGroup(group VolumeGroup) {
	p.Found = true
	p.Group = group.Name
	p.GroupUUID = group.UUID
	p.FreeBytes = group.FreeBytes
	p.ExtentSizeBytes = group.ExtentSizeBytes
}

// describeVolume copies the identity of the volume and what stands on it
// into the plan.
func (p *DevicePlan) describeVolume(volume LogicalVolume, state Snapshot) {
	p.Found = true
	p.Device = volume.Path
	p.Group = volume.Group
	p.VolumeName = volume.Name
	p.VolumeUUID = volume.UUID
	p.SizeBytes = volume.SizeBytes
	if group := state.GroupAt(volume.Group); group != nil {
		p.GroupUUID = group.UUID
		p.FreeBytes = group.FreeBytes
		p.ExtentSizeBytes = group.ExtentSizeBytes
	}
	if device := state.DeviceForVolume(volume); device != nil {
		p.FSType = device.FSType
		p.UUID = device.UUID
		if len(device.Mountpoints) > 0 {
			p.Mountpoint = device.Mountpoints[0]
		}
		if p.Mountpoint == "" {
			p.Mountpoint = InUse(state, device.Path)
		}
	}
}

// orUnknownOrigin names the volume a snapshot was taken of, or says the
// host did not report one.
func orUnknownOrigin(origin string) string {
	if origin == "" {
		return "a volume the host did not name"
	}
	return origin
}
