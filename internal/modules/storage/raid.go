package storage

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Software RAID: what the kernel and mdadm say about the arrays of the host.
// Two sources answer two different questions.

// The paths of the software RAID sources. Fixed, not looked up in PATH.
const (
	MDStatPath = "/proc/mdstat"
	MDAdmPath  = "/usr/sbin/mdadm"
)

// Member roles as the array reports them.
const (
	// MemberActive is a member carrying data in a slot of the array.
	MemberActive = "active"
	// MemberSpare stands by and carries nothing until a rebuild starts.
	MemberSpare = "spare"
	// MemberFaulty was marked failed by the kernel or by an operator; the
	// array no longer reads from it.
	MemberFaulty = "faulty"
	// MemberRebuilding is being written back into a slot.
	MemberRebuilding = "rebuilding"
	// MemberRemoved is a slot with no device in it: the array knows the
	// slot exists and has nothing to put there.
	MemberRemoved = "removed"
	// MemberWriteMostly is an active member the kernel reads from only when
	// it has to; a write-mostly leg is still redundancy.
	MemberWriteMostly = "write_mostly"
	// MemberJournal carries the write journal of the array rather than
	// data.
	MemberJournal = "journal"
)

// redundantLevels lists the levels that survive the loss of a member.
var redundantLevels = map[string]bool{
	"raid1": true, "raid4": true, "raid5": true, "raid6": true, "raid10": true,
}

// RAIDMember is one device of an array. The path is what mdadm prints; the
// identity is what an operation binds to.
type RAIDMember struct {
	Path       string `json:"path"`
	KernelName string `json:"kernel_name,omitempty"`
	// Slot is the position in the array, as mdadm calls RaidDevice. A spare
	// has no slot, and no value means exactly that.
	Slot *int `json:"slot,omitempty"`
	// Number is the device number inside the array's metadata.
	Number *int `json:"number,omitempty"`
	// Role is one of the member roles above. An empty role means the source
	// did not say - it is never read as active.
	Role string `json:"role"`
	// State is what mdadm printed in the state column, word for word, for
	// the operator who wants the original.
	State string `json:"state,omitempty"`
	// The identity the device has outside the array. It is filled from the
	// block device list, because mdadm knows nothing about by-id links.
	ByID                      string `json:"by_id,omitempty"`
	WWN                       string `json:"wwn,omitempty"`
	Serial                    string `json:"serial,omitempty"`
	IdentityUnavailableReason string `json:"identity_unavailable_reason,omitempty"`
	SizeBytes                 uint64 `json:"size_bytes,omitempty"`
}

// Failed says whether the array has already written this member off.
func (m RAIDMember) Failed() bool { return m.Role == MemberFaulty }

// CarriesData says whether the array would lose a copy by losing this member
// now.
func (m RAIDMember) CarriesData() bool {
	switch m.Role {
	case MemberActive, MemberWriteMostly, MemberRebuilding:
		return true
	}
	return false
}

// RAIDArray is one software array of the host.
type RAIDArray struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// UUID is the identity of the array out of its superblock: the one name that
	// means the same array after a reboot, after a rename and on another
	// controller.
	UUID string `json:"uuid,omitempty"`
	// Level is raid0, raid1, raid5, raid6, raid10 or linear, as the kernel
	// names it.
	Level string `json:"level,omitempty"`
	// State is the array state in the kernel's words: active, inactive,
	// clean, clean degraded, and so on.
	State     string `json:"state,omitempty"`
	Metadata  string `json:"metadata,omitempty"`
	SizeBytes uint64 `json:"size_bytes,omitempty"`
	// RaidDevices is how many slots the array has; ActiveDevices how many are
	// filled with a working member.
	RaidDevices    int  `json:"raid_devices"`
	ActiveDevices  int  `json:"active_devices"`
	WorkingDevices int  `json:"working_devices"`
	FailedDevices  int  `json:"failed_devices"`
	SpareDevices   int  `json:"spare_devices"`
	Degraded       bool `json:"degraded"`
	// Redundant says whether the level survives the loss of one member at all.
	Redundant bool `json:"redundant"`
	// The rebuild in progress, where there is one: recovery, resync, reshape or
	// check, with how far it has got.
	SyncAction  string       `json:"sync_action,omitempty"`
	SyncPercent *float64     `json:"sync_percent,omitempty"`
	SyncFinish  string       `json:"sync_finish,omitempty"`
	SyncSpeed   string       `json:"sync_speed,omitempty"`
	Members     []RAIDMember `json:"members,omitempty"`
	// DetailUnavailableReason says why the array carries no UUID and no
	// per-member state: mdadm is not installed, or the read failed.
	DetailUnavailableReason string `json:"detail_unavailable_reason,omitempty"`
}

// MemberAt returns the member with the given path, or nil.
func (a RAIDArray) MemberAt(path string) *RAIDMember {
	for i := range a.Members {
		if a.Members[i].Path == path {
			return &a.Members[i]
		}
	}
	return nil
}

// DataMembers counts the members that still carry a copy.
func (a RAIDArray) DataMembers() int {
	count := 0
	for _, member := range a.Members {
		if member.CarriesData() {
			count++
		}
	}
	return count
}

// Rebuilding says whether the array is busy putting a member back.
func (a RAIDArray) Rebuilding() bool {
	switch a.SyncAction {
	case "recovery", "resync", "reshape", "repair":
		return true
	}
	return false
}

// ArrayAt returns the array with the given path or name, or nil.
func (s Snapshot) ArrayAt(path string) *RAIDArray {
	name := strings.TrimPrefix(path, "/dev/")
	for i := range s.Arrays {
		if s.Arrays[i].Path == path || s.Arrays[i].Name == name {
			return &s.Arrays[i]
		}
	}
	return nil
}

var (
	// "md0 : active raid1 sdb1[1] sda1[0]" - the header of one array.
	mdstatHeader = regexp.MustCompile(`^(md[0-9A-Za-z_]+)\s*:\s*(.*)$`)
	// "sdb1[1](S)" - a member with its number in the array and its flags.
	mdstatMember = regexp.MustCompile(`^([A-Za-z0-9._!/-]+)\[(\d+)\]((?:\([A-Z]\))*)$`)
	// "1048512 blocks super 1.2 [2/2] [UU]" - the size and the slot map.
	mdstatBlocks = regexp.MustCompile(`^(\d+)\s+blocks`)
	mdstatSlots  = regexp.MustCompile(`\[(\d+)/(\d+)\]`)
	mdstatMap    = regexp.MustCompile(`\[([U_]+)\]`)
	mdstatSuper  = regexp.MustCompile(`super\s+(\S+)`)
	// "recovery = 21.5% (225792/1047552) finish=0.5min speed=25088K/sec"
	mdstatSync = regexp.MustCompile(
		`\b(recovery|resync|reshape|check|repair)\s*=\s*([0-9.]+)%`)
	mdstatFinish = regexp.MustCompile(`finish=(\S+)`)
	mdstatSpeed  = regexp.MustCompile(`speed=(\S+)`)
)

// ParseMDStat reads /proc/mdstat.
func ParseMDStat(content string) ([]RAIDArray, error) {
	var arrays []RAIDArray
	var current *RAIDArray
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			current = nil
			continue
		}
		if strings.HasPrefix(trimmed, "Personalities") || strings.HasPrefix(trimmed, "unused devices") {
			current = nil
			continue
		}
		if match := mdstatHeader.FindStringSubmatch(trimmed); match != nil {
			arrays = append(arrays, arrayFromHeader(match[1], match[2]))
			current = &arrays[len(arrays)-1]
			continue
		}
		if current == nil {
			continue
		}
		if match := mdstatBlocks.FindStringSubmatch(trimmed); match != nil {
			// mdstat counts in kibibytes, and every other size in the module
			// is in bytes.
			if blocks, err := strconv.ParseUint(match[1], 10, 64); err == nil {
				current.SizeBytes = blocks * 1024
			}
			if slots := mdstatSlots.FindStringSubmatch(trimmed); slots != nil {
				current.RaidDevices, _ = strconv.Atoi(slots[1])
				current.ActiveDevices, _ = strconv.Atoi(slots[2])
			}
			if layout := mdstatMap.FindStringSubmatch(trimmed); layout != nil {
				current.Degraded = strings.Contains(layout[1], "_")
			}
			if super := mdstatSuper.FindStringSubmatch(trimmed); super != nil {
				current.Metadata = super[1]
			}
			continue
		}
		if match := mdstatSync.FindStringSubmatch(trimmed); match != nil {
			current.SyncAction = match[1]
			if percent, err := strconv.ParseFloat(match[2], 64); err == nil {
				current.SyncPercent = &percent
			}
			if finish := mdstatFinish.FindStringSubmatch(trimmed); finish != nil {
				current.SyncFinish = finish[1]
			}
			if speed := mdstatSpeed.FindStringSubmatch(trimmed); speed != nil {
				current.SyncSpeed = speed[1]
			}
		}
	}
	for i := range arrays {
		completeArray(&arrays[i])
	}
	return arrays, nil
}

// arrayFromHeader reads "active raid1 sdb1[1] sda1[0]".
func arrayFromHeader(name, rest string) RAIDArray {
	array := RAIDArray{Name: name, Path: "/dev/" + name}
	var state []string
	for _, field := range strings.Fields(rest) {
		if member := mdstatMember.FindStringSubmatch(field); member != nil {
			array.Members = append(array.Members, memberFromField(member))
			continue
		}
		if array.Level == "" && isLevel(field) {
			array.Level = field
			continue
		}
		// Everything before the level is the state: "active",
		// "(auto-read-only)", "inactive".
		if array.Level == "" {
			state = append(state, field)
		}
	}
	array.State = strings.Join(state, " ")
	return array
}

// isLevel says whether the word names a RAID level rather than a state.
func isLevel(field string) bool {
	if strings.HasPrefix(field, "raid") {
		return true
	}
	switch field {
	case "linear", "multipath", "faulty":
		return true
	}
	return false
}

// memberFromField reads one member of the header line: the device, its
// number in the array and the flags the kernel appends.
func memberFromField(match []string) RAIDMember {
	member := RAIDMember{Path: "/dev/" + match[1], KernelName: match[1], Role: MemberActive}
	if number, err := strconv.Atoi(match[2]); err == nil {
		member.Number = &number
	}
	// The flags are cumulative: a member can be write-mostly and faulty at
	// once, and the worse of the two decides what the member is.
	flags := match[3]
	member.State = strings.TrimSpace(strings.NewReplacer("(", "", ")", " ").Replace(flags))
	switch {
	case strings.Contains(flags, "(F)"):
		member.Role = MemberFaulty
	case strings.Contains(flags, "(J)"):
		member.Role = MemberJournal
	case strings.Contains(flags, "(S)"):
		member.Role = MemberSpare
	case strings.Contains(flags, "(W)"):
		member.Role = MemberWriteMostly
	}
	return member
}

// completeArray derives what the two sources do not print directly: how many
// members carry data, how many stand by, and whether the level has any
// redundancy to lose.
func completeArray(array *RAIDArray) {
	array.Redundant = redundantLevels[array.Level]
	spares, failed := 0, 0
	for _, member := range array.Members {
		switch {
		case member.Failed():
			failed++
		case member.Role == MemberSpare:
			spares++
		}
	}
	if array.SpareDevices == 0 {
		array.SpareDevices = spares
	}
	if array.FailedDevices == 0 {
		array.FailedDevices = failed
	}
	if array.ActiveDevices == 0 && array.RaidDevices == 0 {
		array.ActiveDevices = array.DataMembers()
	}
	// The slot map decides first, because the kernel prints it; where there
	// is none, a slot without a working member is the same answer.
	if !array.Degraded && array.RaidDevices > 0 && array.ActiveDevices < array.RaidDevices {
		array.Degraded = true
	}
	if !array.Degraded && failed > 0 {
		array.Degraded = true
	}
}

var (
	mdadmPair       = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z ]*[A-Za-z])\s*:\s*(.*)$`)
	mdadmDeviceRow  = regexp.MustCompile(`^\s*(\d+|-)\s+(\d+)\s+(\d+)\s+(\d+|-)\s+(.*)$`)
	mdadmScanArray  = regexp.MustCompile(`^ARRAY\s+(\S+)(.*)$`)
	mdadmScanFields = regexp.MustCompile(`([A-Za-z_]+)=(\S+)`)
)

// ParseMDAdmDetail reads the output of "mdadm --detail /dev/mdN".
func ParseMDAdmDetail(output string) (RAIDArray, error) {
	array := RAIDArray{}
	inDevices := false
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "/dev/") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			array.Path = strings.TrimSuffix(strings.TrimSpace(line), ":")
			array.Name = strings.TrimPrefix(array.Path, "/dev/")
			continue
		}
		if strings.Contains(line, "Number") && strings.Contains(line, "RaidDevice") {
			inDevices = true
			continue
		}
		if inDevices {
			if member, ok := memberFromDetailRow(line); ok {
				array.Members = append(array.Members, member)
			}
			continue
		}
		match := mdadmPair.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		applyDetailField(&array, strings.TrimSpace(match[1]), strings.TrimSpace(match[2]))
	}
	if array.Path == "" {
		return RAIDArray{}, fmt.Errorf("the output names no array")
	}
	completeArray(&array)
	return array, nil
}

// applyDetailField copies one "Key : value" pair of the detail into the
// array.
func applyDetailField(array *RAIDArray, key, value string) {
	switch key {
	case "Raid Level":
		array.Level = value
	case "UUID":
		array.UUID = value
	case "Version":
		array.Metadata = value
	case "State":
		array.State = value
		array.Degraded = strings.Contains(value, "degraded")
	case "Raid Devices":
		array.RaidDevices = atoiOrZero(value)
	case "Active Devices":
		array.ActiveDevices = atoiOrZero(value)
	case "Working Devices":
		array.WorkingDevices = atoiOrZero(value)
	case "Failed Devices":
		array.FailedDevices = atoiOrZero(value)
	case "Spare Devices":
		array.SpareDevices = atoiOrZero(value)
	case "Array Size":
		// "1048512 (1023.94 MiB 1073.68 MB)" - the first number is in
		// kibibytes, like everything else mdadm prints.
		if fields := strings.Fields(value); len(fields) > 0 {
			if blocks := atoiOrZero(fields[0]); blocks > 0 {
				array.SizeBytes = uint64(blocks) * 1024
			}
		}
	case "Resync Status", "Rebuild Status", "Reshape Status", "Check Status":
		array.SyncAction = strings.ToLower(strings.TrimSuffix(key, " Status"))
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return
		}
		if percent := strings.TrimSuffix(fields[0], "%"); percent != "" {
			if number, err := strconv.ParseFloat(percent, 64); err == nil {
				array.SyncPercent = &number
			}
		}
	}
}

// memberFromDetailRow reads one row of the device table:
// "   0     8      17        0      active sync   /dev/sdb1".
func memberFromDetailRow(line string) (RAIDMember, bool) {
	match := mdadmDeviceRow.FindStringSubmatch(line)
	if match == nil {
		return RAIDMember{}, false
	}
	state := strings.TrimSpace(match[5])
	member := RAIDMember{State: state}
	if number, err := strconv.Atoi(match[1]); err == nil {
		member.Number = &number
	}
	if slot, err := strconv.Atoi(match[4]); err == nil {
		member.Slot = &slot
	}
	// The device path is the last field when there is one; a removed slot
	// has none, and that is exactly what makes it a removed slot.
	fields := strings.Fields(state)
	if len(fields) > 0 && strings.HasPrefix(fields[len(fields)-1], "/dev/") {
		member.Path = fields[len(fields)-1]
		member.KernelName = strings.TrimPrefix(member.Path, "/dev/")
		member.State = strings.TrimSpace(strings.Join(fields[:len(fields)-1], " "))
	}
	member.Role = roleFromDetailState(member.State, member.Path)
	return member, true
}

// roleFromDetailState reads mdadm's state words.
func roleFromDetailState(state, path string) string {
	lowered := strings.ToLower(state)
	switch {
	case strings.Contains(lowered, "faulty"):
		return MemberFaulty
	case path == "" || strings.Contains(lowered, "removed"):
		return MemberRemoved
	case strings.Contains(lowered, "journal"):
		return MemberJournal
	case strings.Contains(lowered, "spare") && strings.Contains(lowered, "rebuilding"):
		return MemberRebuilding
	case strings.Contains(lowered, "rebuilding"):
		return MemberRebuilding
	case strings.Contains(lowered, "spare"):
		return MemberSpare
	case strings.Contains(lowered, "writemostly"), strings.Contains(lowered, "write-mostly"):
		return MemberWriteMostly
	case strings.Contains(lowered, "active"):
		return MemberActive
	}
	return ""
}

// ParseMDAdmScan reads "mdadm --detail --scan": one ARRAY line per array,
// with the UUID and the metadata version of each.
func ParseMDAdmScan(output string) map[string]RAIDArray {
	arrays := map[string]RAIDArray{}
	for _, line := range strings.Split(output, "\n") {
		match := mdadmScanArray.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		array := RAIDArray{Path: match[1], Name: strings.TrimPrefix(match[1], "/dev/")}
		for _, field := range mdadmScanFields.FindAllStringSubmatch(match[2], -1) {
			switch strings.ToLower(field[1]) {
			case "uuid":
				array.UUID = field[2]
			case "metadata":
				array.Metadata = field[2]
			}
		}
		arrays[array.Path] = array
	}
	return arrays
}

// MergeArrayDetail completes the kernel's view with what the superblock
// carries.
func MergeArrayDetail(arrays []RAIDArray, detail map[string]RAIDArray, unavailableReason string) {
	for i := range arrays {
		found, ok := detail[arrays[i].Path]
		if !ok {
			if arrays[i].UUID == "" {
				arrays[i].DetailUnavailableReason = unavailableReason
				if arrays[i].DetailUnavailableReason == "" {
					arrays[i].DetailUnavailableReason = "mdadm reported no detail for " + arrays[i].Path
				}
			}
			continue
		}
		merged := &arrays[i]
		merged.UUID = found.UUID
		if found.Level != "" {
			merged.Level = found.Level
		}
		if found.State != "" {
			merged.State = found.State
		}
		if found.Metadata != "" {
			merged.Metadata = found.Metadata
		}
		if found.SizeBytes > 0 {
			merged.SizeBytes = found.SizeBytes
		}
		if found.RaidDevices > 0 {
			merged.RaidDevices = found.RaidDevices
		}
		if found.WorkingDevices > 0 {
			merged.WorkingDevices = found.WorkingDevices
		}
		if found.ActiveDevices > 0 {
			merged.ActiveDevices = found.ActiveDevices
		}
		merged.FailedDevices = found.FailedDevices
		merged.SpareDevices = found.SpareDevices
		if found.SyncAction != "" {
			merged.SyncAction, merged.SyncPercent = found.SyncAction, found.SyncPercent
		}
		if len(found.Members) > 0 {
			merged.Members = mergeMembers(merged.Members, found.Members)
		}
		merged.Degraded = found.Degraded || merged.Degraded
		merged.DetailUnavailableReason = ""
		completeArray(merged)
	}
}

// mergeMembers keeps the detail's rows - they carry the slots and the
// removed ones - and takes from the kernel's list what only it knows.
func mergeMembers(kernel, detail []RAIDMember) []RAIDMember {
	byPath := map[string]RAIDMember{}
	for _, member := range kernel {
		byPath[member.Path] = member
	}
	merged := make([]RAIDMember, 0, len(detail))
	for _, member := range detail {
		if known, ok := byPath[member.Path]; ok && member.Path != "" {
			if member.Number == nil {
				member.Number = known.Number
			}
			if member.SizeBytes == 0 {
				member.SizeBytes = known.SizeBytes
			}
		}
		merged = append(merged, member)
	}
	return merged
}

// FillMemberIdentity copies the stable identity of every member out of the
// block device list.
func FillMemberIdentity(arrays []RAIDArray, devices []Device) {
	byPath := map[string]*Device{}
	for i := range devices {
		byPath[devices[i].Path] = &devices[i]
	}
	for i := range arrays {
		for j := range arrays[i].Members {
			member := &arrays[i].Members[j]
			if member.Path == "" {
				continue
			}
			device, ok := byPath[member.Path]
			if !ok {
				member.IdentityUnavailableReason = "the host does not list the device " + member.Path
				continue
			}
			member.ByID = device.ByID
			member.WWN = device.WWN
			member.Serial = device.Serial
			if member.SizeBytes == 0 {
				member.SizeBytes = device.SizeBytes
			}
			member.IdentityUnavailableReason = device.IdentityUnavailableReason
		}
	}
}

// ValidateArray checks the name of an array before it reaches a root tool.
func ValidateArray(path string) error {
	if !mdDevicePath.MatchString(path) {
		return fmt.Errorf("the array %q is not a path such as /dev/md0", path)
	}
	return nil
}

// mdDevicePath allows the two shapes the kernel gives an array: /dev/md0
// and the named /dev/md/data.
var mdDevicePath = regexp.MustCompile(`^/dev/md[0-9]{1,4}$|^/dev/md/[A-Za-z0-9._-]{1,64}$`)

func atoiOrZero(value string) int {
	number, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return number
}
