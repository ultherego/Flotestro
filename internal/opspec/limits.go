package opspec

import "fmt"

// ResourceFamily groups the operations by the kind of tools they start on the
// host.
type ResourceFamily string

const (
	// FamilyNone marks an operation that starts no heavy tool: a unit
	// restart, a read of the journal, a sysctl. It gets no scope.
	FamilyNone ResourceFamily = ""
	// FamilyPackages is a package transaction: the manager, its scriptlets
	// and the initramfs it may rebuild.
	FamilyPackages ResourceFamily = "packages"
	// FamilyBackups is a backup tool walking the file system and hashing
	// what it finds.
	FamilyBackups ResourceFamily = "backups"
	// FamilyStorage is a filesystem check or resize.
	FamilyStorage ResourceFamily = "storage"
	// FamilyCompose is a Compose deployment: image pulls and container
	// starts.
	FamilyCompose ResourceFamily = "compose"
	// FamilySecurity is a scan of the host's protection state.
	FamilySecurity ResourceFamily = "security"
)

// ResourceLimits is the transient scope an operation runs in on the host.
type ResourceLimits struct {
	CPUWeight       uint32 `json:"cpu_weight,omitempty"`
	IOWeight        uint32 `json:"io_weight,omitempty"`
	MemoryHighBytes uint64 `json:"memory_high_bytes,omitempty"`
}

// Empty says whether the limits ask for no scope at all.
func (l ResourceLimits) Empty() bool {
	return l.CPUWeight == 0 && l.IOWeight == 0 && l.MemoryHighBytes == 0
}

// Properties renders the limits as systemd unit properties, in a fixed order.
func (l ResourceLimits) Properties() []string {
	var properties []string
	if l.CPUWeight > 0 {
		properties = append(properties, fmt.Sprintf("CPUWeight=%d", l.CPUWeight))
	}
	if l.IOWeight > 0 {
		properties = append(properties, fmt.Sprintf("IOWeight=%d", l.IOWeight))
	}
	if l.MemoryHighBytes > 0 {
		properties = append(properties, fmt.Sprintf("MemoryHigh=%d", l.MemoryHighBytes))
	}
	return properties
}

// familyLimits is the default scope of every family.
var familyLimits = map[ResourceFamily]ResourceLimits{
	FamilyPackages: {CPUWeight: 50, IOWeight: 50, MemoryHighBytes: 512 << 20},
	FamilyBackups:  {CPUWeight: 30, IOWeight: 30, MemoryHighBytes: 1 << 30},
}

// resourceFamilies assigns the heavy operations to their families. An
// operation outside the table starts nothing worth a scope.
var resourceFamilies = map[ActionType]ResourceFamily{
	ActionPackageUpgrade: FamilyPackages,
	ActionPackageInstall: FamilyPackages,
	ActionPackageRemove:  FamilyPackages,
	ActionPackageRepair:  FamilyPackages,
	ActionAgentUpgrade:   FamilyPackages,

	ActionBackupRun:     FamilyBackups,
	ActionBackupVerify:  FamilyBackups,
	ActionBackupRestore: FamilyBackups,

	ActionFilesystemCheck:  FamilyStorage,
	ActionFilesystemResize: FamilyStorage,
	ActionLVMExtend:        FamilyStorage,

	ActionComposeDeploy: FamilyCompose,

	ActionSecurityRemediate: FamilySecurity,
}

// ResourceFamily returns the family of an operation.
func (a ActionType) ResourceFamily() ResourceFamily {
	return resourceFamilies[a]
}

// ResourceLimits returns the scope an operation runs in: the default of its
// family.
func (a ActionType) ResourceLimits() ResourceLimits {
	return FamilyLimits(a.ResourceFamily())
}

// FamilyLimits returns the default scope of a family.
func FamilyLimits(family ResourceFamily) ResourceLimits {
	return familyLimits[family]
}
