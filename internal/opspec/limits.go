package opspec

import "fmt"

// ResourceFamily groups the operations by the kind of tools they start on
// the host. The resource scope of an operation is decided per family, not
// per operation: every package transaction is the same kind of load, whoever
// ordered it and whatever its payload.
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
//
// The values are the systemd resource controls: a CPU and an I/O weight
// against the default of a hundred, and a memory ceiling above which the
// kernel starts to reclaim. Zero everywhere means no scope. A scope slows
// the operation down on a busy host rather than the host - a package
// transaction on a database server must not take the database's cache.
type ResourceLimits struct {
	CPUWeight       uint32 `json:"cpu_weight,omitempty"`
	IOWeight        uint32 `json:"io_weight,omitempty"`
	MemoryHighBytes uint64 `json:"memory_high_bytes,omitempty"`
}

// Empty says whether the limits ask for no scope at all.
func (l ResourceLimits) Empty() bool {
	return l.CPUWeight == 0 && l.IOWeight == 0 && l.MemoryHighBytes == 0
}

// Properties renders the limits as systemd unit properties, in a fixed
// order. Only the set ones are named: a property of zero is not "no limit"
// to systemd but the tightest one.
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

// familyLimits is the default scope of every family. The families without
// an entry run without a scope: a filesystem check has the disk to itself
// anyway, and a scan reads more than it computes.
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
// family. The scheduler writes it into the task envelope, and the host
// wraps the tools of the operation in a transient scope with these
// controls when it has systemd-run.
func (a ActionType) ResourceLimits() ResourceLimits {
	return FamilyLimits(a.ResourceFamily())
}

// FamilyLimits returns the default scope of a family. The host helper reads
// it for the families whose tools it starts itself, so the panel and the
// host agree on the numbers from one table.
func FamilyLimits(family ResourceFamily) ResourceLimits {
	return familyLimits[family]
}
