// Package opspec defines the typed operations shared by the control plane, the
// agent and the helper.
package opspec

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/buildinfo"
	"github.com/ultherego/flotestro/internal/jcs"
	"github.com/ultherego/flotestro/internal/modules/accounts"
	backupmodule "github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/dns"
	"github.com/ultherego/flotestro/internal/modules/docker"
	filesmodule "github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/modules/hostname"
	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/modules/logs"
	monitoringmodul "github.com/ultherego/flotestro/internal/modules/monitoring"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/modules/schedules"
	"github.com/ultherego/flotestro/internal/modules/security"
	sshmodule "github.com/ultherego/flotestro/internal/modules/ssh"
	"github.com/ultherego/flotestro/internal/modules/storage"
	hosttime "github.com/ultherego/flotestro/internal/modules/time"
	packagestore "github.com/ultherego/flotestro/internal/packages"
)

// ActionType is the type of an operation. Every type has a contract version
// and its own permission; there is no "arbitrary command" type.
type ActionType string

const (
	ActionUnitStart   ActionType = "unit.start"
	ActionUnitStop    ActionType = "unit.stop"
	ActionUnitRestart ActionType = "unit.restart"
	ActionUnitReload  ActionType = "unit.reload"
	// Clearing the failed state of a unit touches no process: it changes what the
	// host says about the unit, so the next failure is told from the old one.
	ActionUnitResetFailed ActionType = "unit.reset_failed"
	ActionReadJournal     ActionType = "journal.read"
	// Reading a log file is limited by the host administrator's allowlist.
	ActionReadLogFile ActionType = "logfile.read"
	// A live view of the journal. The stream is short-lived and bounded from
	// above: by time, by rate and by the number of lines.
	ActionFollowJournal ActionType = "journal.follow"

	// Process diagnostics. A snapshot is taken on request and has an upper bound;
	// a continuous stream of metrics belongs to Prometheus, not to the panel.
	ActionProcessList   ActionType = "process.list"
	ActionProcessSignal ActionType = "process.signal"

	// Scheduled jobs. A managed entry describes the target state, not a
	// command to run once.
	ActionNetworkPlan         ActionType = "network.plan"
	ActionNetworkProfileApply ActionType = "network.profile.apply"
	ActionNetworkRouteEnsure  ActionType = "network.route.ensure"
	ActionNetworkMTUSet       ActionType = "network.mtu.set"
	ActionNetworkRollback     ActionType = "network.rollback"
	// A layered interface: a bond, a bridge or a VLAN.
	ActionNetworkLinkApply  ActionType = "network.link.apply"
	ActionNetworkLinkRemove ActionType = "network.link.remove"

	ActionDNSResolveTest ActionType = "dns.resolve.test"
	ActionDNSPlan        ActionType = "dns.plan"
	ActionDNSHostApply   ActionType = "dns.host.apply"

	ActionFirewallPlan           ActionType = "firewall.plan"
	ActionFirewallRuleEnsure     ActionType = "firewall.rule.ensure"
	ActionFirewallRuleRemove     ActionType = "firewall.rule.remove"
	ActionFirewallZonePort       ActionType = "firewall.zone.port"
	ActionFirewallZoneService    ActionType = "firewall.zone.service"
	ActionFirewallRulesetRestore ActionType = "firewall.ruleset.restore"

	ActionStoragePlan      ActionType = "storage.plan"
	ActionMountEnsure      ActionType = "mount.ensure"
	ActionMountRemove      ActionType = "mount.remove"
	ActionFilesystemCheck  ActionType = "filesystem.check"
	ActionLVMExtend        ActionType = "lvm.extend"
	ActionFilesystemResize ActionType = "filesystem.resize"
	ActionFilesystemCreate ActionType = "filesystem.create"
	ActionDiskWipe         ActionType = "disk.wipe"
	// ActionStorageSmartRead reads the SMART health and attributes of one device.
	ActionStorageSmartRead ActionType = "storage.smart.read"

	// Software RAID. The panel manages the members of an array that exists:
	// marking one bad, taking it out and putting a new one in.
	ActionRAIDMemberFail   ActionType = "raid.member.fail"
	ActionRAIDMemberRemove ActionType = "raid.member.remove"
	ActionRAIDMemberAdd    ActionType = "raid.member.add"

	// LVM beyond growing a volume: a new volume in an existing group, a new disk
	// under a group, a snapshot and its removal, and the removal of a volume.
	ActionLVMVolumeCreate   ActionType = "lvm.volume.create"
	ActionLVMVolumeRemove   ActionType = "lvm.volume.remove"
	ActionLVMGroupExtend    ActionType = "lvm.group.extend"
	ActionLVMSnapshotCreate ActionType = "lvm.snapshot.create"
	ActionLVMSnapshotRemove ActionType = "lvm.snapshot.remove"

	ActionSSHConfigPlan    ActionType = "ssh.config.plan"
	ActionSSHConfigApply   ActionType = "ssh.config.apply"
	ActionSSHHostKeyRotate ActionType = "ssh.hostkey.rotate"

	// Security. A scan collects facts from the host; the compliance verdict is
	// formed in the panel, because that is where the checks are versioned.
	ActionSecurityScan   ActionType = "security.scan"
	ActionSELinuxModeSet ActionType = "selinux.mode.set"
	// A fleet remediation is the composite of the module operations that remove
	// the chosen findings, run host by host as a campaign.
	ActionSecurityRemediate ActionType = "security.remediate"
	// Reloading the audit rules is a separate operation, because a rule that is
	// written and not loaded records nothing.
	ActionAuditRulesReload ActionType = "security.audit.reload"

	// Certificates.
	ActionCertificateScan ActionType = "certificate.scan"
	ActionCertificatePlan ActionType = "certificate.plan"
	// Rotating the authority is a sequence of states, not one change: the host
	// first trusts the old and the new authority at once, then drops the old.
	ActionCertificateTrustPlan   ActionType = "certificate.trust.plan"
	ActionCertificateTrustEnsure ActionType = "certificate.trust.ensure"
	ActionCertificateTrustRemove ActionType = "certificate.trust.remove"
	ActionCertificateDeploy      ActionType = "certificate.deploy"
	// A renewal is a separate operation, because the host does it with its own
	// daemon: the panel asks certmonger instead of sending a certificate.
	ActionCertificateRenew ActionType = "certificate.renew"

	// Time and synchronisation.
	ActionTimeSyncTest    ActionType = "time.sync.test"
	ActionTimePlan        ActionType = "time.plan"
	ActionTimeConfigApply ActionType = "time.config.apply"
	ActionTimezoneSet     ActionType = "time.timezone.set"

	ActionSysctlPlan            ActionType = "sysctl.plan"
	ActionSysctlEnsure          ActionType = "sysctl.ensure"
	ActionKernelModuleLoad      ActionType = "kernel.module.load"
	ActionKernelModulePlan      ActionType = "kernel.module.plan"
	ActionKernelModuleBlacklist ActionType = "kernel.module.blacklist"

	ActionFileRead     ActionType = "file.read"
	ActionFilePlan     ActionType = "file.plan"
	ActionFileEnsure   ActionType = "file.ensure"
	ActionFileRemove   ActionType = "file.remove"
	ActionFileRollback ActionType = "file.rollback"

	ActionScheduleEnsure  ActionType = "schedule.ensure"
	ActionScheduleDisable ActionType = "schedule.disable"
	ActionScheduleRemove  ActionType = "schedule.remove"
	ActionScheduleRunNow  ActionType = "schedule.run_now"
	ActionSchedulePreview ActionType = "schedule.preview"

	// The full package list is fetched on request rather than in every inventory
	// cycle: it is a few hundred kilobytes per host and changes rarely.
	ActionPackageList ActionType = "packages.list"

	ActionPackagePlan    ActionType = "packages.plan"
	ActionPackageUpgrade ActionType = "packages.upgrade"
	// A repair unblocks package operations on the host: it sets the operator's
	// answers to configuration questions and finishes configuring the packages.
	ActionPackageRepair ActionType = "packages.repair"

	// The full package lifecycle. An install adds software, a removal takes
	// it away together with its dependencies, a hold freezes the version.
	ActionPackageInstall ActionType = "packages.install"
	ActionPackageRemove  ActionType = "packages.remove"
	ActionPackageHoldSet ActionType = "packages.hold.set"
	// Package sources.
	ActionRepositorySet ActionType = "packages.repository.set"
	// ActionAgentUpgrade replaces the agent itself.
	ActionAgentUpgrade ActionType = "agent.upgrade"

	// Backup.
	ActionMonitoringProbe ActionType = "monitoring.probe.run"

	ActionBackupPlan    ActionType = "backup.plan"
	ActionBackupRun     ActionType = "backup.run"
	ActionBackupVerify  ActionType = "backup.verify"
	ActionBackupRestore ActionType = "backup.restore"

	ActionSystemReboot ActionType = "system.reboot"
	// Shutting a host down is an operation the panel cannot bring it back from:
	// powering it on needs out-of-band access.
	ActionSystemShutdown ActionType = "system.shutdown"
	// Renaming a host changes its identity towards everything that knows it by
	// name: DNS, Kerberos and the certificates of its services.
	ActionSystemHostnameSet ActionType = "system.hostname.set"
	ActionUnitStatus        ActionType = "unit.status"
	// Enabling and masking change what the host will do after a reboot, not its
	// state now.
	ActionUnitEnableSet ActionType = "unit.enable.set"
	ActionUnitMaskSet   ActionType = "unit.mask.set"

	ActionDomainEnroll    ActionType = "identity.host.enroll"
	ActionDomainPreflight ActionType = "identity.host.preflight"
	// Leaving the domain is a decision of its own, not the join undone: it
	// cuts every directory user off the host at once.
	ActionDomainLeave ActionType = "identity.host.leave"
	// Renewing a service keytab is the host's half of a rotation: the directory
	// has retired the old keytab, and the host fetches a new one.
	ActionIdentityKeytabRenew ActionType = "identity.keytab.renew"

	ActionLocalUserCreate ActionType = "localuser.create"
	ActionLocalUserLock   ActionType = "localuser.lock"
	ActionLocalUserUnlock ActionType = "localuser.unlock"
	// The keys of an account are edited one at a time (security remediation,
	// chapter 14.
	ActionLocalSSHKeysAdd        ActionType = "localuser.sshkeys.add"
	ActionLocalSSHKeysRemove     ActionType = "localuser.sshkeys.remove"
	ActionLocalSSHKeysReplaceAll ActionType = "localuser.sshkeys.replace_all"
	ActionLocalSSHKeysSet        ActionType = "localuser.sshkeys.set"
	// The groups of an account decide what it may do on the host: a membership in
	// sudo or docker is root by another name, so the set operation ranks critical
	ActionLocalUserGroupsSet ActionType = "localuser.groups.set"
	// An expiry date is a change of access with a date attached; clearing it
	// restores access.
	ActionLocalUserExpirySet ActionType = "localuser.expiry.set"
	// Deleting an account is destructive: the home directory, when removed,
	// does not come back, and neither does the UID's ownership of files.
	ActionLocalUserDelete ActionType = "localuser.delete"

	// ActionInventoryRefresh orders the inventory to be read again.
	ActionInventoryRefresh ActionType = "inventory.refresh"

	// Reading the state of the container engine. Full lists are fetched at
	// the operator's request; the inventory carries only the summary.
	ActionDockerRead ActionType = "docker.read"

	ActionDockerStart   ActionType = "docker.container.start"
	ActionDockerStop    ActionType = "docker.container.stop"
	ActionDockerRestart ActionType = "docker.container.restart"
	ActionDockerRemove  ActionType = "docker.container.remove"
	ActionDockerPull    ActionType = "docker.image.pull"
	// Pruning removes the objects it is pointed at, not everything matching a
	// filter.
	ActionDockerPrune ActionType = "docker.prune"
	// ActionDockerEvents reads the engine's event journal.
	ActionDockerEvents ActionType = "docker.events"
	// ActionDockerLogs reads the tail of one container's log.
	ActionDockerLogs ActionType = "docker.container.logs"

	// ActionDockerPlan computes the difference between what stands on the host
	// and the description of a container, a network or a volume.
	ActionDockerPlan ActionType = "docker.plan"
	// ActionDockerContainerEnsure declares a container: the description of what
	// is to run rather than the steps that would put it there.
	ActionDockerContainerEnsure ActionType = "docker.container.ensure"
	// Networks and volumes are declared the same way.
	ActionDockerNetworkEnsure ActionType = "docker.network.ensure"
	ActionDockerNetworkRemove ActionType = "docker.network.remove"
	ActionDockerVolumeEnsure  ActionType = "docker.volume.ensure"
	ActionDockerVolumeRemove  ActionType = "docker.volume.remove"

	// The plan of a Compose project computes the difference between the
	// host's state and the manifest.
	ActionComposePlan ActionType = "docker.compose.plan"
	// Deploying a project is bound to one specific plan.
	ActionComposeDeploy ActionType = "docker.compose.deploy"
)

// ActionVersion is the version of the payload contract. Changing the meaning
// of a field requires raising the version, not a silent reinterpretation.
const ActionVersion = 1

// RiskLevel describes what an operation threatens.
type RiskLevel string

const (
	// RiskLow is a read or a plan: it changes nothing.
	RiskLow RiskLevel = "low"
	// RiskMedium changes state reversibly and locally.
	RiskMedium RiskLevel = "medium"
	// RiskHigh interrupts a service or changes the content of the system.
	RiskHigh RiskLevel = "high"
	// RiskCritical can cut off access to the host or change its identity.
	// It requires fresh operator authentication.
	RiskCritical RiskLevel = "critical"
	// RiskDestructive destroys data irreversibly. It requires typing the
	// target name and by default does not run in bulk.
	RiskDestructive RiskLevel = "destructive"
)

// LockClass names the host resource an operation uses exclusively.
const (
	LockNone       = ""
	LockPackages   = "packages"
	LockUnits      = "units"
	LockContainers = "containers"
	LockIdentity   = "identity"
	LockAccounts   = "accounts"
	// The network is one host resource: two parallel configuration changes
	// would leave a state that neither rollback plan describes.
	LockNetwork = "network"
	// Storage is one resource: two parallel operations on the same
	// filesystem can damage it.
	LockStorage = "storage"
	// A backup repository is one resource: the tools hold their own lock on it,
	// and a second operation would wait under that lock anyway.
	LockBackup = "backup"
	// The trust store is one per host and the tool rewrites the whole bundle:
	// two anchor changes at once give a bundle neither of them asked for.
	LockCertificates = "certificates"
	// The whole host: a rename collides with every other mutation the way a
	// reboot does, because afterwards the host answers to a different name.
	LockHost = "host"
)

// CampaignMode says whether and how an operation may run on many hosts at
// once.
type CampaignMode string

const (
	// CampaignNone marks an operation that is not allowed in bulk.
	CampaignNone CampaignMode = "none"
	// CampaignSamePayload marks an operation whose intent carries over: the same
	// payload means the same thing on every host.
	CampaignSamePayload CampaignMode = "same_payload"
	// CampaignPerHostPlan marks a shared target state from which every host
	// computes its own plan.
	CampaignPerHostPlan CampaignMode = "per_host_plan"
	// CampaignSpecialized marks an operation with its own state machine: a reboot
	// is settled by the host coming back, enrollment has its own stages.
	CampaignSpecialized CampaignMode = "specialized"
)

// Spec is the full contract of one operation.
type Spec struct {
	Action         ActionType `json:"action"`
	Version        uint32     `json:"version"`
	Capability     string     `json:"capability,omitempty"`
	Permission     string     `json:"permission"`
	Mutating       bool       `json:"mutating"`
	Risk           RiskLevel  `json:"risk"`
	DefaultTimeout int        `json:"default_timeout_seconds"`
	MaxOutputBytes uint64     `json:"max_output_bytes"`
	LockClass      string     `json:"lock_class,omitempty"`
	// CampaignMode says whether the operation may run in bulk and on what
	// terms. A missing declaration means a refusal.
	CampaignMode CampaignMode `json:"campaign_mode"`
	// OfflinePolicy says what a campaign does with a host that is not connected
	// when its turn comes.
	OfflinePolicy OfflinePolicy `json:"offline_policy"`
	// FanOutLimit says how many hosts one diagnostic read may cover at
	// once. Zero means a read kept to one host - and every mutation.
	FanOutLimit int `json:"fanout_limit"`
	// RequiresPlan marks an operation that must not be ordered without a plan
	// approved by a human.
	RequiresPlan bool `json:"requires_plan"`
	// The second half of the contract: what a cancel does to an operation under
	// way, whether it may be repeated, what way back exists and how it is checked.
	CancelMode     CancelMode      `json:"cancel_mode"`
	RetryClass     RetryPolicy     `json:"retry_class"`
	Rollback       RollbackClass   `json:"rollback"`
	Verification   Verification    `json:"verification"`
	ResourceClaims []ResourceClaim `json:"resource_claims"`
	// Verifier names the read of the host that confirms the change after the
	// apply; only it turns the change into a success.
	Verifier     Verifier         `json:"verifier"`
	OnUnverified UnverifiedPolicy `json:"on_unverified"`
	// ReplacedBy names the operation that took this one's place.
	ReplacedBy ActionType `json:"replaced_by,omitempty"`
}

// replacedActions lists the deprecated operations and their successors.
var replacedActions = map[ActionType]ActionType{
	ActionLocalSSHKeysSet: ActionLocalSSHKeysReplaceAll,
}

// ReplacedBy returns the operation that took this one's place, or an empty
// type for an operation that is current.
func (a ActionType) ReplacedBy() ActionType {
	return replacedActions[a]
}

// Describe returns the full contract of an operation.
func (a ActionType) Describe() Spec {
	spec := actionSpecs[a]
	declared := a.Contract()
	return Spec{
		ReplacedBy:     replacedActions[a],
		Action:         a,
		Version:        ActionVersion,
		Capability:     spec.capability,
		Permission:     spec.permission,
		Mutating:       spec.mutating,
		Risk:           spec.risk,
		DefaultTimeout: spec.timeoutSeconds,
		MaxOutputBytes: spec.maxOutputBytes,
		LockClass:      spec.lockClass,
		CampaignMode:   a.CampaignMode(),
		OfflinePolicy:  a.OfflinePolicy(),
		FanOutLimit:    a.FanOutLimit(),
		RequiresPlan:   spec.requiresPlan,
		CancelMode:     declared.CancelMode,
		RetryClass:     declared.RetryClass,
		Rollback:       declared.Rollback,
		Verification:   declared.Verification,
		ResourceClaims: declared.ResourceClaims,
		Verifier:       a.Verifier(),
		OnUnverified:   a.OnUnverified(),
	}
}

// Risk returns the risk level of an operation.
func (a ActionType) Risk() RiskLevel {
	if spec, ok := actionSpecs[a]; ok {
		return spec.risk
	}
	// An unknown operation is not a safe operation. The default level cannot
	// be the lowest one just because something went undescribed.
	return RiskCritical
}

// LockClass returns the class of the host resource used exclusively.
func (a ActionType) LockClass() string {
	return actionSpecs[a].lockClass
}

// CampaignMode returns the bulk-operation mode.
func (a ActionType) CampaignMode() CampaignMode {
	if mode, ok := campaignModes[a]; ok {
		return mode
	}
	return CampaignNone
}

// MaxOutputBytes bounds the size of an operation's result.
func (a ActionType) MaxOutputBytes() uint64 {
	if spec, ok := actionSpecs[a]; ok && spec.maxOutputBytes > 0 {
		return spec.maxOutputBytes
	}
	return defaultOutputLimit
}

// RequiresPlan says whether an operation must not be ordered without an
// approved plan.
func (a ActionType) RequiresPlan() bool {
	return actionSpecs[a].requiresPlan
}

// reverseActions names, for every change that has a declared way back, the
// operation that takes it.
var reverseActions = map[ActionType]ActionType{
	// A managed file keeps its previous versions: the rollback writes the
	// version named per host, bound to the digest the host has now.
	ActionFileEnsure: ActionFileRollback,
	// The network and the firewall keep a rollback plan on the host under
	// the identifier the change reported; the rollback names it.
	ActionNetworkProfileApply: ActionNetworkRollback,
	// A layered change keeps the same kind of plan: the mechanism's
	// document from before it, named by the identifier the change reported.
	ActionNetworkLinkApply:   ActionNetworkRollback,
	ActionNetworkLinkRemove:  ActionNetworkRollback,
	ActionFirewallRuleEnsure: ActionFirewallRulesetRestore,
}

// ReverseAction returns the operation that undoes the given change, and
// whether there is one.
func ReverseAction(action ActionType) (ActionType, bool) {
	reverse, ok := reverseActions[action]
	return reverse, ok
}

// RequiresFreshAuth says whether the operator has to confirm their identity
// right before ordering.
func (a ActionType) RequiresFreshAuth() bool {
	switch a.Risk() {
	case RiskCritical, RiskDestructive:
		return true
	}
	return false
}

// RequiresTargetConfirmation says whether the operator has to type the target
// name. A click is not decision enough for an irreversible operation.
func (a ActionType) RequiresTargetConfirmation() bool {
	// A shutdown destroys no data, but it is irreversible remotely: nobody will
	// power this host back on through the panel.
	if a == ActionSystemShutdown {
		return true
	}
	// A rename destroys no data, but every system that knows the host by name
	// loses it at once: the operator types the name they are taking away.
	if a == ActionSystemHostnameSet {
		return true
	}
	// Leaving a domain destroys no data, but every directory account loses the
	// host at once, and the join back needs a new credential from the directory:
	if a == ActionDomainLeave {
		return true
	}
	return a.Risk() == RiskDestructive
}

// ConfirmationTarget says what the operator has to type to confirm an
// operation: the hostname, or the account name when an account is deleted.
func ConfirmationTarget(action ActionType, payload Payload, host string) string {
	if action == ActionLocalUserDelete && payload.LocalUser != nil {
		return payload.LocalUser.Name
	}
	return host
}

// PrivilegedGroupsIn returns the privileged groups the list names: the ones
// the installation treats as root by another name, sudo and wheel among them.
func PrivilegedGroupsIn(groups []string) []string {
	return accounts.PrivilegedGroupsIn(groups)
}

// PutsIntoPrivilegedGroup says whether one order creates an account in, or
// moves an account into, a privileged group.
func PutsIntoPrivilegedGroup(action ActionType, payload Payload) bool {
	if action != ActionLocalUserCreate && action != ActionLocalUserGroupsSet {
		return false
	}
	return payload.LocalUser != nil && len(PrivilegedGroupsIn(payload.LocalUser.Groups)) > 0
}

// PayloadRisk returns the risk of one order: the registry's level for the
// operation, raised where the content of the order calls for it.
func PayloadRisk(action ActionType, payload Payload) RiskLevel {
	risk := action.Risk()
	if PutsIntoPrivilegedGroup(action, payload) {
		return RiskCritical
	}
	return risk
}

// Permissions an order needs on top of the one of its operation.
const (
	// PermissionScheduleRootExec lets an entry run as root.
	PermissionScheduleRootExec = "schedule.root.exec"
	// PermissionFileWriteUnvalidated lets a file be written when the host lacks
	// the validator the order relies on.
	PermissionFileWriteUnvalidated = "file.write.unvalidated"
	// PermissionPrivilegedGroups lets an account be created in, or moved into, a
	// group that is root by another name.
	PermissionPrivilegedGroups = "accounts.privileged_groups"
)

// PayloadPermissions returns the permissions the content of one order requires
// beyond the operation's own: an entry for root, a write without a validator.
func PayloadPermissions(action ActionType, payload Payload) []string {
	var required []string
	if action == ActionScheduleEnsure && payload.Schedule != nil && payload.Schedule.User == "root" {
		required = append(required, PermissionScheduleRootExec)
	}
	if (action == ActionFileEnsure || action == ActionFileRollback) &&
		payload.File != nil && payload.File.AllowMissingValidator {
		required = append(required, PermissionFileWriteUnvalidated)
	}
	if PutsIntoPrivilegedGroup(action, payload) {
		required = append(required, PermissionPrivilegedGroups)
	}
	return required
}

// PayloadRequiresFreshAuth says whether one order needs a fresh confirmation
// of the operator's identity: a critical or destructive risk needs one.
func PayloadRequiresFreshAuth(action ActionType, payload Payload) bool {
	switch PayloadRisk(action, payload) {
	case RiskCritical, RiskDestructive:
		return true
	}
	return false
}

// defaultOutputLimit applies to operations that do not state their own.
const defaultOutputLimit = 64 << 10

// Known checks whether the operation type is supported.
func (a ActionType) Known() bool {
	_, ok := actionSpecs[a]
	return ok
}

// Mutating says whether the operation changes the state of the host.
func (a ActionType) Mutating() bool {
	spec, ok := actionSpecs[a]
	return ok && spec.mutating
}

// RequiredCapability returns the host capability without which the operation
// makes no sense.
func (a ActionType) RequiredCapability() string {
	return actionSpecs[a].capability
}

// Permission returns the permission required to order the operation.
func (a ActionType) Permission() string {
	return actionSpecs[a].permission
}

// DefaultTimeout returns the default execution time limit in seconds.
func (a ActionType) DefaultTimeout() int {
	return actionSpecs[a].timeoutSeconds
}

type actionSpec struct {
	mutating       bool
	capability     string
	permission     string
	timeoutSeconds int
	risk           RiskLevel
	lockClass      string
	maxOutputBytes uint64
	requiresPlan   bool
	// verifier is the read that confirms a mutation after the apply; a mutating
	// operation declares it (ValidateVerifiers), a read never.
	verifier     Verifier
	onUnverified UnverifiedPolicy
}

// The risk levels and lock classes follow chapters 6. 1 and 8 of the
// specification.
var actionSpecs = map[ActionType]actionSpec{
	ActionUnitStart: {mutating: true, capability: "systemd", permission: "unit.start",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockUnits, verifier: VerifierUnitState},
	// Stopping a service interrupts it, so it ranks higher than starting.
	ActionUnitStop: {mutating: true, capability: "systemd", permission: "unit.stop",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockUnits, verifier: VerifierUnitState},
	ActionUnitRestart: {mutating: true, capability: "systemd", permission: "unit.restart",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockUnits, verifier: VerifierUnitState},
	ActionUnitReload: {mutating: true, capability: "systemd", permission: "unit.reload",
		timeoutSeconds: 60, risk: RiskMedium, lockClass: LockUnits, verifier: VerifierUnitState},
	// Clearing the failed state runs nothing and stops nothing; it is a
	// change of the record, so it ranks with starting a unit.
	ActionUnitResetFailed: {mutating: true, capability: "systemd", permission: "unit.reset_failed",
		timeoutSeconds: 60, risk: RiskMedium, lockClass: LockUnits, verifier: VerifierUnitState},
	ActionReadJournal: {mutating: false, capability: "journald", permission: "journal.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Creating a scheduled entry means something will run without the
	// operator - including when nobody is watching.
	ActionScheduleEnsure: {mutating: true, capability: "schedules", permission: "schedule.write",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockUnits, verifier: VerifierScheduleEntry},
	// Disabling leaves the content on the host and is reversible.
	ActionScheduleDisable: {mutating: true, capability: "schedules", permission: "schedule.disable",
		timeoutSeconds: 60, risk: RiskMedium, lockClass: LockUnits, verifier: VerifierScheduleEntry},
	ActionScheduleRemove: {mutating: true, capability: "schedules", permission: "schedule.remove",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockUnits, verifier: VerifierScheduleEntry},
	// Running now executes the same command outside the schedule.
	ActionScheduleRunNow: {mutating: true, capability: "schedules", permission: "schedule.run",
		timeoutSeconds: 900, risk: RiskHigh, lockClass: LockUnits, verifier: VerifierNone},
	// A preview of the next runs of an expression, computed on the host in its
	// time zone.
	ActionSchedulePreview: {mutating: false, capability: "schedules", permission: "schedule.preview",
		timeoutSeconds: 30, risk: RiskLow, maxOutputBytes: 64 << 10},

	// Reading NetworkManager profiles before a change. The plan does not
	// touch the host.
	ActionNetworkPlan: {mutating: false, capability: "network", permission: "network.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Changing the address profile means changing the branch the panel sits on: a
	// wrongly set address cuts the host off and no further order reaches it.
	ActionNetworkProfileApply: {mutating: true, capability: "network.write", permission: "network.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierNetworkState},
	// Routes are a separate permission: changing the default route redirects
	// all of the host's traffic, not just its address.
	ActionNetworkRouteEnsure: {mutating: true, capability: "network.write", permission: "network.route.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierNetworkState},
	// MTU has its own permission, because it is a change of a different weight
	// from rewriting an address: a wrong MTU breaks only large packets.
	ActionNetworkMTUSet: {mutating: true, capability: "network.write", permission: "network.mtu.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockNetwork, verifier: VerifierNetworkState},
	// A rollback on request returns to the state from before the change, so
	// it is itself a network change - and just as risky as the one it undoes.
	ActionNetworkRollback: {mutating: true, capability: "network.write", permission: "network.rollback",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockNetwork, verifier: VerifierNetworkState},
	// Building a layer moves the addressing of every member onto the layer above:
	// the members lose theirs the moment they are enslaved.
	ActionNetworkLinkApply: {mutating: true, capability: "network.write", permission: "network.link.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierNetworkState},
	// Taking a layer away gives the members back their own traffic and takes the
	// layer's address with it.
	ActionNetworkLinkRemove: {mutating: true, capability: "network.write", permission: "network.link.remove",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierNetworkState},

	// The name resolution test asks from the host, because the panel's answer
	// says nothing about what the host will see. The query changes nothing.
	ActionDNSResolveTest: {mutating: false, capability: "dns", permission: "dns.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 64 << 10},
	// The resolver plan: the difference between the profile found and the one
	// requested.
	ActionDNSPlan: {mutating: false, capability: "dns", permission: "dns.plan",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 64 << 10},
	// A bad resolver cuts the host off from the directory and from Kerberos, and
	// therefore from logging in, which is why the change ranks critical.
	ActionDNSHostApply: {mutating: true, capability: "dns.write", permission: "dns.host.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierResolver},

	// Reading the ruleset before a change. The plan does not touch the host.
	ActionFirewallPlan: {mutating: false, capability: "firewall", permission: "firewall.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 512 << 10},
	// A bad rule cuts the panel off from the host and there is nothing left to
	// undo the change with, so every firewall change is critical.
	ActionFirewallRuleEnsure: {mutating: true, capability: "firewall.write", permission: "firewall.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierFirewallRuleset},
	ActionFirewallRuleRemove: {mutating: true, capability: "firewall.write", permission: "firewall.rule.remove",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierFirewallRuleset},
	// firewalld zones describe access differently from rules: the question is
	// "what is open", not "which rule matches first".
	ActionFirewallZonePort: {mutating: true, capability: "firewall.zones", permission: "firewall.zone.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierFirewallRuleset},
	ActionFirewallZoneService: {mutating: true, capability: "firewall.zones", permission: "firewall.service.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierFirewallRuleset},
	ActionFirewallRulesetRestore: {mutating: true, capability: "firewall.write", permission: "firewall.restore",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork, verifier: VerifierFirewallRuleset},

	// Reading the topology on request.
	ActionStoragePlan: {mutating: false, capability: "storage", permission: "storage.read",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 512 << 10},
	// Mounting is reversible, but the fstab entry decides whether the host
	// comes back from a reboot the way it stands now.
	ActionMountEnsure: {mutating: true, capability: "storage", permission: "storage.mount.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockStorage, verifier: VerifierMountState},
	ActionMountRemove: {mutating: true, capability: "storage", permission: "storage.mount.remove",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockStorage, verifier: VerifierMountState},
	// A filesystem check takes long and requires that nobody is using it.
	ActionFilesystemCheck: {mutating: true, capability: "storage", permission: "storage.fsck",
		timeoutSeconds: 3600, risk: RiskHigh, lockClass: LockStorage, verifier: VerifierStorageLayout},
	// The SMART read changes nothing and takes no lock: the tool asks the device
	// for its own log.
	ActionStorageSmartRead: {mutating: false, capability: "storage", permission: "storage.smart.read",
		timeoutSeconds: 120, risk: RiskLow, lockClass: LockNone, maxOutputBytes: 256 << 10},

	// Extending a volume and a filesystem is reversible only in theory: shrinking
	// requires getting the data below a boundary nobody planned for.
	ActionLVMExtend: {mutating: true, capability: "storage.lvm", permission: "storage.lvm.write",
		timeoutSeconds: 900, risk: RiskCritical, lockClass: LockStorage, verifier: VerifierStorageLayout},
	ActionFilesystemResize: {mutating: true, capability: "storage", permission: "storage.filesystem.write",
		timeoutSeconds: 1800, risk: RiskCritical, lockClass: LockStorage, verifier: VerifierStorageLayout},
	// Formatting and wiping destroy data irreversibly: they require fresh
	// authentication, typing the target name and the consent of two people.
	ActionFilesystemCreate: {mutating: true, capability: "storage", permission: "storage.destructive",
		timeoutSeconds: 1800, risk: RiskDestructive, lockClass: LockStorage, verifier: VerifierStorageLayout},
	ActionDiskWipe: {mutating: true, capability: "storage", permission: "storage.wipe",
		timeoutSeconds: 1800, risk: RiskDestructive, lockClass: LockStorage, verifier: VerifierStorageLayout},

	// Software RAID.
	ActionRAIDMemberFail: {mutating: true, capability: "storage", permission: "storage.raid.fail",
		timeoutSeconds: 300, risk: RiskDestructive, lockClass: LockStorage, verifier: VerifierStorageLayout},
	ActionRAIDMemberRemove: {mutating: true, capability: "storage", permission: "storage.raid.remove",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockStorage, verifier: VerifierStorageLayout},
	ActionRAIDMemberAdd: {mutating: true, capability: "storage", permission: "storage.raid.add",
		timeoutSeconds: 900, risk: RiskDestructive, lockClass: LockStorage, verifier: VerifierStorageLayout},

	// LVM.
	ActionLVMVolumeCreate: {mutating: true, capability: "storage.lvm", permission: "storage.lvm.volume.create",
		timeoutSeconds: 600, risk: RiskHigh, lockClass: LockStorage, verifier: VerifierStorageLayout},
	ActionLVMVolumeRemove: {mutating: true, capability: "storage.lvm", permission: "storage.lvm.volume.remove",
		timeoutSeconds: 600, risk: RiskDestructive, lockClass: LockStorage, verifier: VerifierStorageLayout},
	ActionLVMGroupExtend: {mutating: true, capability: "storage.lvm", permission: "storage.lvm.group.extend",
		timeoutSeconds: 900, risk: RiskDestructive, lockClass: LockStorage, verifier: VerifierStorageLayout},
	ActionLVMSnapshotCreate: {mutating: true, capability: "storage.lvm", permission: "storage.lvm.snapshot.create",
		timeoutSeconds: 600, risk: RiskHigh, lockClass: LockStorage, verifier: VerifierStorageLayout},
	ActionLVMSnapshotRemove: {mutating: true, capability: "storage.lvm", permission: "storage.lvm.snapshot.remove",
		timeoutSeconds: 600, risk: RiskHigh, lockClass: LockStorage, verifier: VerifierStorageLayout},

	// Reading the sshd configuration before a change. The plan does not touch
	// the host.
	ActionSSHConfigPlan: {mutating: false, capability: "sshd", permission: "ssh.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 128 << 10},
	// A bad sshd configuration cuts off administration of the host and there
	// is nothing to fix it with remotely - exactly like a bad firewall rule.
	ActionSSHConfigApply: {mutating: true, capability: "sshd", permission: "ssh.config.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockUnits, verifier: VerifierSSHDConfig},
	// Replacing the host key changes the identity every client sees: everyone
	// gets a known_hosts warning, and pinned fingerprints stop matching.
	ActionSSHHostKeyRotate: {mutating: true, capability: "sshd", permission: "ssh.hostkey.rotate",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockUnits, verifier: VerifierSSHHostKey},

	// The scan does not change the host, but it collects reconnaissance material:
	// a list of what the host exposes to the outside.
	ActionSecurityScan: {mutating: false, capability: "security", permission: "security.scan",
		timeoutSeconds: 120, risk: RiskMedium, maxOutputBytes: 512 << 10},
	// Switching to permissive takes protection off the whole host and does it
	// immediately.
	ActionSELinuxModeSet: {mutating: true, capability: "security.mac", permission: "security.mac.write",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockNone, verifier: VerifierMACMode},
	// The composite carries no adapter requirement and no lock of its own: both
	// belong to the steps.
	ActionSecurityRemediate: {mutating: true, capability: "", permission: "security.remediate",
		timeoutSeconds: 3600, risk: RiskCritical, lockClass: LockNone, verifier: VerifierNone},
	// Reloading the audit rules changes what the host records. It is
	// reversible and local, but it is not a read.
	ActionAuditRulesReload: {mutating: true, capability: "security.audit", permission: "security.audit.reload",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockUnits, verifier: VerifierAuditRules},

	// The scan looks at the files it is pointed at and does not change the host.
	ActionCertificateScan: {mutating: false, capability: "certificates", permission: "certificate.read",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 256 << 10},
	// A deployment replaces the identity a service shows to the world and ends
	// with reloading that service.
	ActionCertificatePlan: {mutating: false, capability: "certificates", permission: "certificate.plan",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 256 << 10},
	ActionCertificateTrustPlan: {mutating: false, capability: "certificates", permission: "certificate.trust.plan",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 512 << 10},
	// Trusting an authority is a decision wider than one file: from that
	// moment the host accepts every certificate this authority signs.
	ActionCertificateTrustEnsure: {mutating: true, capability: "certificates", permission: "certificate.trust.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockCertificates, verifier: VerifierTrustAnchor},
	// Withdrawing trust breaks connections nobody changed, if the authority
	// still signs anything. The host checks that at its own end.
	ActionCertificateTrustRemove: {mutating: true, capability: "certificates", permission: "certificate.trust.remove",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockCertificates, verifier: VerifierTrustAnchor},
	ActionCertificateDeploy: {mutating: true, capability: "certificates", permission: "certificate.deploy",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockUnits, verifier: VerifierCertificate},
	// A renewal ends the same way a deployment does: with a new file and a
	// service that reads it.
	ActionCertificateRenew: {mutating: true, capability: "certificates.renew", permission: "certificate.renew",
		timeoutSeconds: 600, risk: RiskCritical, lockClass: LockUnits, verifier: VerifierCertificate},

	// The synchronisation test does not change the host, but it sends packets
	// from it to the named servers: that is the only way to test a time source.
	ActionTimeSyncTest: {mutating: false, capability: "time", permission: "time.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 128 << 10},
	// The time-source plan: the difference between the panel's file and the
	// order, together with whether the daemon will be restarted.
	ActionTimePlan: {mutating: false, capability: "time", permission: "time.plan",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Changing the time sources can step the clock, and then databases, tokens
	// and certificates see time that went backwards.
	ActionTimeConfigApply: {mutating: true, capability: "time", permission: "time.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockUnits, verifier: VerifierTimeSource},
	// The timezone changes what the host shows to people and writes to the
	// journal; it does not change the moment the host lives in.
	ActionTimezoneSet: {mutating: true, capability: "time", permission: "time.timezone.write",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockNone, verifier: VerifierTimezone},

	// Reading kernel settings.
	ActionSysctlPlan: {mutating: false, capability: "kernel", permission: "kernel.read",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 256 << 10},
	// A kernel setting changes the behaviour of the whole host, but it can be
	// undone the same way it was set.
	ActionSysctlEnsure: {mutating: true, capability: "kernel", permission: "kernel.sysctl.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockNone, verifier: VerifierSysctl, onUnverified: UnverifiedRollback},
	ActionKernelModuleLoad: {mutating: true, capability: "kernel", permission: "kernel.module.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockNone, verifier: VerifierKernelModule},
	// The module blacklist plan: the difference between the blacklist found
	// and the one requested. It does not touch the host.
	ActionKernelModulePlan: {mutating: false, capability: "kernel", permission: "kernel.module.plan",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Blacklisting a module takes effect only after a reboot, and for modules
	// from the initramfs only after it is rebuilt as well.
	ActionKernelModuleBlacklist: {mutating: true, capability: "kernel", permission: "kernel.module.blacklist",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNone, verifier: VerifierKernelModule},

	// Reading a configuration file reaches for content that is often sensitive
	// even when the file itself is not a secret: addresses and account names.
	ActionFileRead: {mutating: false, capability: "files.managed", permission: "file.read",
		timeoutSeconds: 60, risk: RiskHigh, maxOutputBytes: 1 << 20},
	ActionFilePlan: {mutating: false, capability: "files.managed", permission: "file.plan",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Writing a configuration file changes the behaviour of a service once it
	// is reloaded - including when nobody planned for that.
	ActionFileEnsure: {mutating: true, capability: "files.managed", permission: "file.write",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockNone, verifier: VerifierFileContent, onUnverified: UnverifiedRollback},
	ActionFileRemove: {mutating: true, capability: "files.managed", permission: "file.remove",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockNone, verifier: VerifierFileContent},
	// Going back to an earlier version is a write of content that was once on
	// the host - but it is still a write.
	ActionFileRollback: {mutating: true, capability: "files.managed", permission: "file.rollback",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockNone, verifier: VerifierFileContent, onUnverified: UnverifiedRollback},

	ActionProcessList: {mutating: false, capability: "", permission: "process.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 1 << 20},
	// Sending a signal stops somebody's work: a signal has no before and
	// after state that could be undone.
	ActionProcessSignal: {mutating: true, capability: "", permission: "process.signal",
		timeoutSeconds: 30, risk: RiskHigh, verifier: VerifierNone},
	// A live view keeps a process on the host for the whole time it lasts, so
	// it ranks higher than a one-off read and has its own permission.
	ActionFollowJournal: {mutating: false, capability: "journald", permission: "journal.follow",
		timeoutSeconds: 300, risk: RiskMedium, maxOutputBytes: 1 << 20},
	// Reading a file reaches beyond the system journal, so it carries a higher
	// risk and its own permission: the allowlist behind it is sometimes wide.
	ActionReadLogFile: {mutating: false, capability: "", permission: "logfile.read",
		timeoutSeconds: 60, risk: RiskMedium, maxOutputBytes: 1 << 20},

	// Planning does not change the state of the system, but refreshing the
	// metadata does, so the plan has its own permission too.
	ActionPackageList: {mutating: false, capability: "packages", permission: "packages.read",
		timeoutSeconds: 300, risk: RiskLow, maxOutputBytes: 8 << 20},

	ActionPackagePlan: {mutating: false, capability: "packages", permission: "packages.plan",
		timeoutSeconds: 300, risk: RiskLow, lockClass: LockPackages},
	// A package transaction is the riskiest operation in the system.
	ActionPackageUpgrade: {mutating: true, capability: "packages", permission: "packages.upgrade",
		timeoutSeconds: 1800, risk: RiskHigh, lockClass: LockPackages, requiresPlan: true, verifier: VerifierPackageVersions},
	ActionAgentUpgrade: {mutating: true, capability: "packages", permission: "agent.upgrade",
		timeoutSeconds: 1800, risk: RiskHigh, lockClass: LockPackages, verifier: VerifierAgentVersion},

	// A repair changes the state of the host and can touch packages of great
	// importance, the bootloader included, so it has its own permission.
	ActionPackageRepair: {mutating: true, capability: "packages.repair", permission: "packages.repair",
		timeoutSeconds: 1800, risk: RiskCritical, lockClass: LockPackages, verifier: VerifierPackageDatabase},
	// An install adds software to the host that will start running right
	// away.
	ActionPackageInstall: {mutating: true, capability: "packages", permission: "packages.install",
		timeoutSeconds: 1800, risk: RiskHigh, lockClass: LockPackages, requiresPlan: true, verifier: VerifierPackageVersions},
	// A removal takes everything that depends on the package with it, and no
	// restore of state undoes it: what disappeared has to be installed again.
	ActionPackageRemove: {mutating: true, capability: "packages", permission: "packages.remove",
		timeoutSeconds: 1800, risk: RiskDestructive, lockClass: LockPackages, requiresPlan: true, verifier: VerifierPackageVersions},
	// A hold freezes the package version. It is reversible and local, but a
	// held package will not get security fixes either.
	ActionPackageHoldSet: {mutating: true, capability: "packages", permission: "packages.hold.write",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockPackages, verifier: VerifierPackageHold},
	// A reboot is a separate, approved campaign phase, not a side effect of an
	// upgrade.
	ActionMonitoringProbe: {mutating: false, capability: "monitoring", permission: "monitoring.probe",
		timeoutSeconds: 120, risk: RiskMedium, maxOutputBytes: 64 << 10},

	// The plan reads the backup repository: the list of copies and their size.
	ActionBackupPlan: {mutating: false, capability: "backup", permission: "backup.read",
		timeoutSeconds: 600, risk: RiskLow, lockClass: LockBackup, maxOutputBytes: 512 << 10},
	// A copy reads the whole named range of the host and sends it to the
	// repository.
	ActionBackupRun: {mutating: true, capability: "backup", permission: "backup.run",
		timeoutSeconds: 7200, risk: RiskHigh, lockClass: LockBackup, maxOutputBytes: 512 << 10, verifier: VerifierBackupRun},
	// Verification reads the repository and does not change the host; with
	// the data read it costs as much as restoring part of a copy.
	ActionBackupVerify: {mutating: true, capability: "backup", permission: "backup.verify",
		timeoutSeconds: 3600, risk: RiskMedium, lockClass: LockBackup, maxOutputBytes: 512 << 10, verifier: VerifierNone},
	// A restore unpacks old state onto a running system.
	ActionBackupRestore: {mutating: true, capability: "backup", permission: "backup.restore",
		timeoutSeconds: 7200, risk: RiskCritical, lockClass: LockBackup, maxOutputBytes: 512 << 10, verifier: VerifierRestoreTarget},

	// A package source is a decision about trust, not about a version: from that
	// moment the host takes software from there as well.
	ActionRepositorySet: {mutating: true, capability: "packages", permission: "packages.repository.write",
		timeoutSeconds: 600, risk: RiskCritical, lockClass: LockPackages, verifier: VerifierRepository},

	ActionSystemReboot: {mutating: true, capability: "systemd", permission: "system.reboot",
		timeoutSeconds: 120, risk: RiskCritical, verifier: VerifierReboot},
	// Shutting a host down ends in a state the panel cannot undo: nobody will
	// power this machine on remotely.
	ActionSystemShutdown: {mutating: true, capability: "systemd", permission: "system.shutdown",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockUnits, verifier: VerifierReboot},
	// A rename changes the host's identity towards everything that knows it by
	// name.
	ActionSystemHostnameSet: {mutating: true, capability: "systemd", permission: "system.hostname.write",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockHost, verifier: VerifierHostname},
	// Reading unit state is non-mutating and serves campaign health checks.
	ActionUnitStatus: {mutating: false, capability: "systemd", permission: "unit.status",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 1 << 20},
	// Enabling a unit changes the behaviour of the host after every following
	// reboot, so it ranks higher than starting it now.
	ActionUnitEnableSet: {mutating: true, capability: "systemd", permission: "unit.enable.write",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockUnits, verifier: VerifierUnitState},
	// Masking takes away a unit's ability to start even manually and survives
	// a reboot of the host - the furthest-reaching change in this module.
	ActionUnitMaskSet: {mutating: true, capability: "systemd", permission: "unit.mask.write",
		timeoutSeconds: 60, risk: RiskCritical, lockClass: LockUnits, verifier: VerifierUnitState},

	// Joining a domain changes authentication for the whole host.
	ActionDomainEnroll: {mutating: true, capability: "systemd", permission: "identity.host.enroll",
		timeoutSeconds: 900, risk: RiskCritical, lockClass: LockIdentity, verifier: VerifierDomainMembership},
	// Preflight changes nothing, so it needs no approval.
	ActionDomainPreflight: {mutating: false, capability: "systemd", permission: "identity.read",
		timeoutSeconds: 120, risk: RiskLow, lockClass: LockIdentity},
	// Leaving changes authentication for the whole host the same way the join
	// does, in the other direction: every directory account loses it at once.
	ActionDomainLeave: {mutating: true, capability: "systemd", permission: "identity.host.leave",
		timeoutSeconds: 900, risk: RiskCritical, lockClass: LockIdentity, verifier: VerifierDomainMembership},
	// A keytab renewal replaces the credential a service authenticates with:
	// until it lands, the service the principal names cannot prove who it is.
	ActionIdentityKeytabRenew: {mutating: true, capability: "systemd", permission: "identity.keytab.rotate",
		timeoutSeconds: 180, risk: RiskCritical, lockClass: LockIdentity, verifier: VerifierKeytab},

	// Local accounts depend neither on systemd nor on a directory: the module
	// works also where the customer stays with plain SSH authorisation.
	ActionLocalUserCreate: {mutating: true, capability: "", permission: "localuser.create",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockAccounts, verifier: VerifierLocalAccount},
	ActionLocalUserLock: {mutating: true, capability: "", permission: "localuser.lock",
		timeoutSeconds: 60, risk: RiskMedium, lockClass: LockAccounts, verifier: VerifierLocalAccount},
	// Restoring access is always more serious than taking it away.
	ActionLocalUserUnlock: {mutating: true, capability: "", permission: "localuser.unlock",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockAccounts, verifier: VerifierLocalAccount},
	// Adding a key grants access and ranks high; removing one takes it away and
	// ranks high too, because the account may have been left with no way in.
	ActionLocalSSHKeysAdd: {mutating: true, capability: "", permission: "localuser.sshkeys.add",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockAccounts, verifier: VerifierLocalAccount},
	ActionLocalSSHKeysRemove: {mutating: true, capability: "", permission: "localuser.sshkeys.remove",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockAccounts, verifier: VerifierLocalAccount},
	ActionLocalSSHKeysReplaceAll: {mutating: true, capability: "", permission: "localuser.sshkeys.replace",
		timeoutSeconds: 60, risk: RiskCritical, lockClass: LockAccounts, verifier: VerifierLocalAccount},
	// The previous name of the replace, deprecated: same semantics and the same
	// risk, the expected list optional.
	ActionLocalSSHKeysSet: {mutating: true, capability: "", permission: "localuser.sshkeys.write",
		timeoutSeconds: 60, risk: RiskCritical, lockClass: LockAccounts, verifier: VerifierLocalAccount},
	// The registry lists the base risk of a groups change.
	ActionLocalUserGroupsSet: {mutating: true, capability: "", permission: "localuser.groups.write",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockAccounts, verifier: VerifierLocalAccount},
	ActionLocalUserExpirySet: {mutating: true, capability: "", permission: "localuser.expiry.write",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockAccounts, verifier: VerifierLocalAccount},
	// Deleting an account is irreversible: a removed home directory does not come
	// back, and neither does the UID's ownership of what it left behind.
	ActionLocalUserDelete: {mutating: true, capability: "", permission: "localuser.delete",
		timeoutSeconds: 120, risk: RiskDestructive, lockClass: LockAccounts, verifier: VerifierLocalAccount},

	// Reading containers changes nothing, but it can be heavy: the full list of
	// images on a build host is megabytes, so the output has a ceiling.
	ActionInventoryRefresh: {mutating: false, permission: "inventory.refresh",
		timeoutSeconds: 300, risk: RiskLow, lockClass: LockNone, maxOutputBytes: 1 << 20},

	ActionDockerRead: {mutating: false, capability: "docker", permission: "docker.read",
		timeoutSeconds: 120, risk: RiskLow, lockClass: LockContainers, maxOutputBytes: 4 << 20},

	// Starting a container restores a service; stopping interrupts one, so
	// stop and restart rank higher than start.
	ActionDockerStart: {mutating: true, capability: "docker", permission: "docker.container.start",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockContainers, verifier: VerifierContainerState},
	ActionDockerStop: {mutating: true, capability: "docker", permission: "docker.container.stop",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockContainers, verifier: VerifierContainerState},
	ActionDockerRestart: {mutating: true, capability: "docker", permission: "docker.container.restart",
		timeoutSeconds: 180, risk: RiskHigh, lockClass: LockContainers, verifier: VerifierContainerState},
	// Removing a container is irreversible: data outside volumes dies with
	// it, so the operator types the target name before the operation starts.
	ActionDockerRemove: {mutating: true, capability: "docker", permission: "docker.container.remove",
		timeoutSeconds: 120, risk: RiskDestructive, lockClass: LockContainers, verifier: VerifierContainerState},
	// Pulling an image changes what will come up at the next start, but by
	// itself it does not touch running containers.
	ActionDockerPull: {mutating: true, capability: "docker", permission: "docker.image.pull",
		timeoutSeconds: 1800, risk: RiskMedium, lockClass: LockContainers, verifier: VerifierImagePresent},
	// Pruning removes data for good and by default does not run in bulk.
	ActionDockerPrune: {mutating: true, capability: "docker", permission: "docker.prune",
		timeoutSeconds: 900, risk: RiskDestructive, lockClass: LockContainers, verifier: VerifierNone},
	// The event journal changes nothing and takes no container lock: a read
	// lasting the follow window must not hold back a restart.
	ActionDockerEvents: {mutating: false, capability: "docker", permission: "docker.events",
		timeoutSeconds: 180, risk: RiskLow, lockClass: LockNone, maxOutputBytes: 1 << 20},
	// A log read changes nothing and takes no container lock: reading what a
	// container wrote must not wait for its restart.
	ActionDockerLogs: {mutating: false, capability: "docker", permission: "docker.container.logs",
		timeoutSeconds: 60, risk: RiskLow, lockClass: LockNone, maxOutputBytes: 1 << 20},

	// The plan of a declared object changes nothing, but it inspects the
	// container and asks the registry about the tag, so it takes the lock.
	ActionDockerPlan: {mutating: false, capability: "docker", permission: "docker.plan",
		timeoutSeconds: 300, risk: RiskLow, lockClass: LockContainers, maxOutputBytes: 1 << 20},
	// Declaring a container replaces the container that is there when it differs,
	// so the service goes down and comes back from another image.
	ActionDockerContainerEnsure: {mutating: true, capability: "docker",
		permission: "docker.container.ensure", timeoutSeconds: 1800,
		risk: RiskCritical, lockClass: LockContainers, requiresPlan: true,
		maxOutputBytes: 1 << 20, verifier: VerifierContainerSpec},
	// A network and a volume carry the permission that removes one: an ensure
	// that finds an object differing from its description replaces it.
	ActionDockerNetworkEnsure: {mutating: true, capability: "docker", permission: "docker.network.ensure",
		timeoutSeconds: 300, risk: RiskMedium, lockClass: LockContainers, requiresPlan: true,
		maxOutputBytes: 1 << 20, verifier: VerifierDockerNetwork},
	ActionDockerNetworkRemove: {mutating: true, capability: "docker", permission: "docker.network.remove",
		timeoutSeconds: 300, risk: RiskDestructive, lockClass: LockContainers, requiresPlan: true,
		maxOutputBytes: 1 << 20, verifier: VerifierDockerNetwork},
	ActionDockerVolumeEnsure: {mutating: true, capability: "docker", permission: "docker.volume.ensure",
		timeoutSeconds: 300, risk: RiskMedium, lockClass: LockContainers, requiresPlan: true,
		maxOutputBytes: 1 << 20, verifier: VerifierDockerVolume},
	// Removing a volume erases what is stored in it, so the operator types
	// the target name before the operation starts.
	ActionDockerVolumeRemove: {mutating: true, capability: "docker", permission: "docker.volume.remove",
		timeoutSeconds: 300, risk: RiskDestructive, lockClass: LockContainers, requiresPlan: true,
		maxOutputBytes: 1 << 20, verifier: VerifierDockerVolume},

	// The plan changes nothing, but it runs compose on the host and fetches
	// image metadata, so it has its own permission.
	ActionComposePlan: {mutating: false, capability: "docker.compose",
		permission: "docker.compose.plan", timeoutSeconds: 300,
		risk: RiskLow, lockClass: LockContainers, maxOutputBytes: 1 << 20},
	// Deploying a manifest starts the images the operator named on the host.
	ActionComposeDeploy: {mutating: true, capability: "docker.compose",
		permission: "docker.compose.deploy", timeoutSeconds: 1800,
		risk: RiskCritical, lockClass: LockContainers, requiresPlan: true,
		maxOutputBytes: 1 << 20, verifier: VerifierComposeServices},
}

// AllActions returns a sorted list of the supported operations.
func AllActions() []ActionType {
	actions := make([]ActionType, 0, len(actionSpecs))
	for action := range actionSpecs {
		actions = append(actions, action)
	}
	for i := 1; i < len(actions); i++ {
		for j := i; j > 0 && actions[j] < actions[j-1]; j-- {
			actions[j], actions[j-1] = actions[j-1], actions[j]
		}
	}
	return actions
}

// maxFollowSeconds bounds a single live view.
const maxFollowSeconds = 900

// validateJournalPayload checks the filters shared by a read and a live view.
func validateJournalPayload(payload *JournalPayload) error {
	if priority := payload.MaxPriority; priority != nil && *priority > 7 {
		return fmt.Errorf("the syslog priority has to be in the range 0-7")
	}
	if payload.BootID != "" {
		normalised, err := logs.NormalizeBootID(payload.BootID)
		if err != nil {
			return err
		}
		payload.BootID = normalised
	}
	if payload.Unit != "" {
		if err := validateUnitName(payload.Unit); err != nil {
			return err
		}
	}
	// The "since" and "until" values go into journalctl arguments. They do not
	// pass through a shell, but narrower validation is still cheaper than trust.
	if payload.Since != "" && !periodPattern.MatchString(payload.Since) {
		return fmt.Errorf("invalid time range %q", payload.Since)
	}
	if payload.Until != "" && !periodPattern.MatchString(payload.Until) {
		return fmt.Errorf("invalid time range %q", payload.Until)
	}
	// A cursor is what journalctl printed: a handful of key=value pairs
	// separated by semicolons. Anything else is not a cursor.
	if payload.AfterCursor != "" && !cursorPattern.MatchString(payload.AfterCursor) {
		return fmt.Errorf("invalid journal cursor")
	}
	return nil
}

// cursorPattern matches a journal cursor as journalctl prints it with
// --show-cursor: "s=.
var cursorPattern = regexp.MustCompile(`^[A-Za-z0-9=;:+/._-]{1,512}$`)

// maxDetailUnits bounds one detail read of units.
const maxDetailUnits = 5

// periodPattern allows the formats journalctl accepts: a timestamp, a relative
// expression and keywords.
var periodPattern = regexp.MustCompile(
	`^(-?\d+ ?(s|sec|second|seconds|m|min|minute|minutes|h|hour|hours|d|day|days|w|week|weeks)( ago)?` +
		`|yesterday|today|now` +
		`|\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?( UTC)?)?)$`)

// scheduleIdentifier repeats the pattern from the schedules module. The name
// becomes the name of a file in /etc/cron.
var scheduleIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// interfaceName allows the names the kernel accepts at all. The length limit
// is IFNAMSIZ minus the terminator.
var interfaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)

// checkFilePath rejects paths the panel will not write - before the task even
// comes into being.
func checkFilePath(path string) error {
	// Paths the panel never touches are rejected already at ordering time: the
	// host would refuse anyway, and no such task belongs in the queue.
	if err := filesmodule.Forbidden(path); err != nil {
		return err
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("the path %q is not absolute", path)
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("the path %q leaves the named directory", path)
	}
	if strings.ContainsAny(path, "\n\t*?") {
		return fmt.Errorf("the path %q contains a forbidden character", path)
	}
	if len(path) > 4096 {
		return fmt.Errorf("the path is longer than 4096 characters")
	}
	return nil
}

// firstPort returns the single port of a zone operation.
func firstPort(ports []string) string {
	if len(ports) != 1 {
		return ""
	}
	return ports[0]
}

// checkNetworkChange rejects a configuration the host will not accept or one
// that would cut it off from the panel.
func checkNetworkChange(action ActionType, change *NetworkPayload) error {
	switch action {
	case ActionNetworkMTUSet:
		if change.MTU == "" {
			return fmt.Errorf("an MTU change requires a value")
		}
		return network.ValidateMTU(change.MTU)

	case ActionNetworkRouteEnsure:
		// An empty list is a valid target state here: it means "a profile without
		// routes of its own".
		if change.Routes == nil {
			return fmt.Errorf("a route operation requires a list of routes; an empty list clears the profile's routes")
		}
		for _, route := range change.Routes {
			if err := network.ValidateRoute(route); err != nil {
				return err
			}
		}
		return nil

	case ActionNetworkLinkApply:
		if change.Link == nil {
			return fmt.Errorf("a layered change requires the description of the bond, the bridge or the VLAN")
		}
		// The shape is checked here so that an order the kernel would never take is
		// refused before it is ever sent.
		if change.Link.Name != change.Interface && change.Interface != "" {
			return fmt.Errorf("the layered order names the interface %q and the layer %q; they are the same interface",
				change.Interface, change.Link.Name)
		}
		// A refusal the module names with a code keeps that code all the way to the
		// API, so the operator reads the same word here as in the plan.
		if err := network.ValidateLinkSpec(*change.Link); err != nil {
			var refusal *network.LinkRefusal
			if errors.As(err, &refusal) {
				return &RefusalError{Code: refusal.Code, Err: err}
			}
			return err
		}
		return nil

	case ActionNetworkLinkRemove:
		if change.Link != nil {
			return fmt.Errorf("a removal names the layer in the interface field; it does not describe what is about to disappear")
		}
		return network.ValidateInterfaceName(change.Interface)

	case ActionNetworkProfileApply:
		switch change.Method {
		case "", "auto", "manual":
		default:
			return fmt.Errorf("unsupported method %q; the panel sets auto or manual", change.Method)
		}
		// An order that names neither family changes nothing and would
		// still take the network lock and arm a rescue timer.
		if change.Method == "" && change.Method6 == "" && change.AcceptRA == "" && change.Privacy == "" {
			return fmt.Errorf("an address profile requires a method for at least one family")
		}
		if err := checkNetworkIPv6(change); err != nil {
			return err
		}
		// The manual method without an address would leave the interface without
		// one, and so cut the host off.
		if change.Method == "manual" && len(change.Addresses) == 0 {
			return fmt.Errorf("the manual method requires at least one address")
		}
		for _, address := range change.Addresses {
			if err := network.ValidateAddress(address); err != nil {
				return err
			}
		}
		if change.Gateway != "" {
			if err := network.ValidateIPAddress(change.Gateway); err != nil {
				return fmt.Errorf("gateway: %w", err)
			}
		}
		for _, server := range change.DNS {
			if err := network.ValidateIPAddress(server); err != nil {
				return fmt.Errorf("DNS server: %w", err)
			}
		}
		return nil
	}
	return nil
}

// checkNetworkIPv6 holds the second family to the first one's standard: a
// method the mechanisms know, valid addresses and a valid gateway.
func checkNetworkIPv6(change *NetworkPayload) error {
	switch change.Method6 {
	case "", "auto", "manual", "disabled":
	default:
		return fmt.Errorf("unsupported IPv6 method %q; the panel sets auto, manual or disabled", change.Method6)
	}
	if change.Method6 == "manual" && len(change.Addresses6) == 0 {
		return fmt.Errorf("the manual IPv6 method requires at least one address")
	}
	for _, address := range change.Addresses6 {
		if err := network.ValidateIPv6Address(address); err != nil {
			return err
		}
	}
	if change.Gateway6 != "" {
		if err := network.ValidateIPv6Gateway(change.Gateway6); err != nil {
			return fmt.Errorf("IPv6 gateway: %w", err)
		}
	}
	if !network.ValidAcceptRA(change.AcceptRA) {
		return fmt.Errorf("unsupported router advertisement setting %q; the panel sets off, on or on-forwarding", change.AcceptRA)
	}
	if !network.ValidPrivacy(change.Privacy) {
		return fmt.Errorf("unsupported IPv6 privacy setting %q; the panel sets off, prefer-public or prefer-temporary", change.Privacy)
	}
	return nil
}

// scheduleShellCharacters are forbidden in command arguments.
var scheduleShellCharacters = `|&;<>()$` + "`" + `\"'` + "\n\r\t" + `*?[]{}~!#%`

func checkScheduleCommand(arguments []string) error {
	if !strings.HasPrefix(arguments[0], "/") {
		return fmt.Errorf("the command has to be an absolute path, it is %q", arguments[0])
	}
	for _, argument := range arguments {
		if argument == "" {
			return fmt.Errorf("empty command argument")
		}
		if strings.ContainsAny(argument, scheduleShellCharacters) {
			return fmt.Errorf("the argument %q contains a shell character", argument)
		}
		// A zero byte ends the string for the tools that read the line; it
		// is not a shell character and the list above would not see it.
		if strings.ContainsRune(argument, 0) {
			return fmt.Errorf("the argument %q contains a zero byte", argument)
		}
	}
	return nil
}

// checkScheduleUser refuses an account name that would not stay in the user
// field of a cron line, and an entry that names none.
func checkScheduleKind(payload *SchedulePayload) error {
	switch payload.Kind {
	case "", ScheduleKindCron, ScheduleKindAny:
		return nil
	case ScheduleKindTimer:
		if payload.Expression == "" {
			return nil
		}
		if _, err := schedules.CalendarFromCron(payload.Expression); err != nil {
			if errors.Is(err, schedules.ErrCalendarUnsupported) {
				return &RefusalError{Code: RefusalCalendarUnsupported, Err: err}
			}
			return fmt.Errorf("schedule expression: %w", err)
		}
		return nil
	}
	return fmt.Errorf("unknown schedule kind %q: it is cron, timer, or any", payload.Kind)
}

func checkScheduleUser(name string) error {
	if name == "" {
		return fmt.Errorf("a schedule requires a user; root is not a default")
	}
	if !schedules.ValidUser(name) {
		return fmt.Errorf("invalid user %q: an account name is lower-case letters, digits, underscore and hyphen", name)
	}
	return nil
}

// protectedPackages repeats the list from the packages module.
func protectedPackages(packages []string) []string {
	seen := map[string]bool{}
	names := map[string]bool{
		"flotestro-agent": true, "openssh-server": true, "systemd": true, "sudo": true,
	}
	prefixes := []string{"linux-image", "kernel", "grub", "apt", "dpkg", "dnf", "rpm", "systemd-"}

	var result []string
	for _, pkg := range packages {
		name := strings.ToLower(strings.TrimSpace(pkg))
		if index := strings.IndexByte(name, ':'); index > 0 {
			name = name[:index]
		}
		// The same package appears both on the ordered list and among the
		// dependants.
		if seen[name] {
			continue
		}
		seen[name] = true
		if names[name] {
			result = append(result, pkg)
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(name, prefix) {
				result = append(result, pkg)
				break
			}
		}
	}
	return result
}

// validateLogPath rejects paths the host will not accept anyway.
func validateLogPath(path string) error {
	if path == "" {
		return fmt.Errorf("the log file path is empty")
	}
	if len(path) > 4096 {
		return fmt.Errorf("the log file path is too long")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("the log file path has to be absolute")
	}
	// Walking up a directory would allow matching the allowlist pattern and
	// still reading a file outside it.
	if strings.Contains(path, "..") {
		return fmt.Errorf("the log file path must not contain \"..\"")
	}
	if strings.ContainsAny(path, "\x00\n") {
		return fmt.Errorf("the log file path contains a forbidden character")
	}
	return nil
}

// unitPattern repeats the pattern from the systemd module.
var unitPattern = regexp.MustCompile(
	`^[A-Za-z0-9:_.\\@-]+\.(service|socket|timer|target|path|mount|automount|swap|slice|scope)$`)

func validateUnitName(unit string) error {
	if unit == "" {
		return fmt.Errorf("the unit name is empty")
	}
	if len(unit) > 256 {
		return fmt.Errorf("the unit name is too long")
	}
	if !unitPattern.MatchString(unit) {
		return fmt.Errorf("invalid unit name %q", unit)
	}
	return nil
}

// composeProjectName repeats the pattern of the containers module. The name
// goes into a command argument and into container names.
var composeProjectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// maxComposeManifest bounds the size of a manifest.
const maxComposeManifest = 256 << 10

// containerIdentifier allows only the engine's hexadecimal identifier.
var containerIdentifier = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

func validContainerIdentifier(id string) bool {
	return containerIdentifier.MatchString(id)
}

// imageReference allows a repository name with an optional registry, tag or
// digest.
var imageReference = regexp.MustCompile(
	`^[a-z0-9]+([._\-/][a-z0-9]+)*(:[0-9]{2,5})?(/[a-z0-9]+([._\-/][a-z0-9]+)*)*` +
		`(:[\w][\w.\-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

func validImageReference(reference string) error {
	if reference == "" {
		return fmt.Errorf("the image reference is empty")
	}
	if len(reference) > 512 {
		return fmt.Errorf("the image reference is too long")
	}
	if !imageReference.MatchString(reference) {
		return fmt.Errorf("invalid image reference %q", reference)
	}
	return nil
}

// imageIdentifier allows the engine identifier with its algorithm prefix.
var imageIdentifier = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// volumeName allows the names Docker and Compose create.
var volumeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$`)

// maxPruneObjects bounds a single prune operation. A list longer than this is
// no longer an operator's decision, but a filter in disguise.
const maxPruneObjects = 200

// checkEventsRead guards the window boundaries.
func checkEventsRead(payload *DockerEventsPayload) error {
	if payload == nil {
		// A missing payload is valid: the default window is the most common
		// way.
		return nil
	}
	if payload.SinceSeconds < 0 || payload.SinceSeconds > maxEventWindow {
		return fmt.Errorf("the event read window is out of range (%d s)", payload.SinceSeconds)
	}
	if payload.FollowSeconds < 0 || payload.FollowSeconds > maxEventFollow {
		return fmt.Errorf("event following is out of range (%d s)", payload.FollowSeconds)
	}
	if payload.MaxEvents < 0 || payload.MaxEvents > maxEvents {
		return fmt.Errorf("the event count limit is out of range (%d)", payload.MaxEvents)
	}
	seen := map[string]bool{}
	for _, kind := range payload.Types {
		if !docker.KnownEventType(kind) {
			return fmt.Errorf("unknown event kind %q", kind)
		}
		if seen[kind] {
			return fmt.Errorf("event kind %q repeated", kind)
		}
		seen[kind] = true
	}
	return nil
}

func checkPruneList(payload *DockerPrunePayload) error {
	total := len(payload.ImageIDs) + len(payload.VolumeName) + len(payload.NetworkIDs)
	if total == 0 {
		return fmt.Errorf("the prune operation names no object")
	}
	if total > maxPruneObjects {
		return fmt.Errorf("the list of objects to remove is too long (%d)", total)
	}
	for _, id := range payload.ImageIDs {
		if !imageIdentifier.MatchString(id) {
			return fmt.Errorf("invalid image identifier %q", id)
		}
	}
	for _, name := range payload.VolumeName {
		if !volumeName.MatchString(name) {
			return fmt.Errorf("invalid volume name %q", name)
		}
	}
	for _, id := range payload.NetworkIDs {
		if !containerIdentifier.MatchString(id) {
			return fmt.Errorf("invalid network identifier %q", id)
		}
	}
	return nil
}

// checkDockerDeclaration checks an order about a declared object.
func checkDockerDeclaration(action ActionType, payload *DockerEnsurePayload) error {
	if payload == nil {
		return fmt.Errorf("the operation %s requires a docker_ensure payload", action)
	}
	described := 0
	for _, present := range []bool{payload.Container != nil, payload.Network != nil, payload.Volume != nil} {
		if present {
			described++
		}
	}
	if described > 1 {
		return fmt.Errorf("an order describes one object; this one describes %d", described)
	}

	// A description already says what the object is and what it is called, so an
	// order that also writes the kind or the name in by hand says it twice.
	if described > 0 && (payload.Kind != "" || payload.Name != "") {
		return fmt.Errorf("the description already says what this object is and what it is called; " +
			"the kind and the name travel by themselves only in a removal")
	}

	switch action {
	case ActionDockerNetworkRemove, ActionDockerVolumeRemove:
		// A removal names an object and describes none: there is nothing to
		// declare about an object that is to be gone.
		if described > 0 {
			return fmt.Errorf("a removal names the object; it does not describe it")
		}
		kind := DockerKindNetwork
		if action == ActionDockerVolumeRemove {
			kind = DockerKindVolume
		}
		if payload.Kind != "" && payload.Kind != kind {
			return fmt.Errorf("the operation %s is about a %s, not a %s", action, kind, payload.Kind)
		}
		if payload.Name == "" {
			return fmt.Errorf("the operation %s names no object", action)
		}
	case ActionDockerContainerEnsure:
		if payload.Container == nil {
			return fmt.Errorf("the operation %s requires a container description", action)
		}
	case ActionDockerNetworkEnsure:
		if payload.Network == nil {
			return fmt.Errorf("the operation %s requires a network description", action)
		}
	case ActionDockerVolumeEnsure:
		if payload.Volume == nil {
			return fmt.Errorf("the operation %s requires a volume description", action)
		}
	case ActionDockerPlan:
		// A plan is about a description or about a name: the plan of a
		// removal has nothing but the name of what would go.
		if described == 0 && payload.Name == "" {
			return fmt.Errorf("a plan is about an object; this one names none")
		}
		if described == 0 && !validDockerKind(payload.Kind) {
			return fmt.Errorf("a plan that only names an object has to say what kind it is: "+
				"%s, %s or %s", DockerKindContainer, DockerKindNetwork, DockerKindVolume)
		}
	}

	switch {
	case payload.Container != nil:
		// The references belong beside the description, where they are references
		// and are checked as such.
		if len(payload.Container.EnvSecrets) > 0 {
			return fmt.Errorf("the secrets of the variables travel beside the description, " +
				"under env_secrets of the order")
		}
		for name, reference := range payload.EnvSecrets {
			if !environmentVariable.MatchString(name) {
				return fmt.Errorf("invalid environment variable name %q", name)
			}
			if err := reference.Validate(); err != nil {
				return fmt.Errorf("the secret of %s: %w", name, err)
			}
		}
		if _, err := payload.SpecWithSecrets(); err != nil {
			return err
		}
	case payload.Network != nil:
		if err := payload.Network.Validate(); err != nil {
			return err
		}
	case payload.Volume != nil:
		if err := payload.Volume.Validate(); err != nil {
			return err
		}
	}
	if len(payload.EnvSecrets) > 0 && payload.Container == nil {
		return fmt.Errorf("only a container takes variables from the secret store")
	}
	// Every change here has to name the plan it was approved from.
	if action != ActionDockerPlan && payload.PlanDigest == "" {
		return fmt.Errorf("the operation %s requires the digest of an approved plan", action)
	}
	return nil
}

// validDockerKind says whether the payload names a kind of object the
// module declares.
func validDockerKind(kind string) bool {
	switch kind {
	case DockerKindContainer, DockerKindNetwork, DockerKindVolume:
		return true
	}
	return false
}

// environmentVariable is a variable name a shell can carry.
var environmentVariable = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// UnitPayload describes an operation on a systemd unit.
type UnitPayload struct {
	Unit string `json:"unit"`
}

// JournalPayload describes a journal read.
type JournalPayload struct {
	Unit string `json:"unit,omitempty"`
	// Lines bounds the size of the result; a read without a limit is not
	// allowed.
	Lines uint32 `json:"lines"`
	// MaxPriority follows syslog: 0 emerg ... 7 debug. Empty means no filter.
	MaxPriority *uint32 `json:"max_priority,omitempty"`
	Since       string  `json:"since,omitempty"`
	// Until ends the read, in the same forms as Since.
	Until string `json:"until,omitempty"`
	// BootID narrows the view to one boot of the host, in either spelling the
	// kernel and the journal use; normalised before it travels.
	BootID string `json:"boot_id,omitempty"`
	// FollowSeconds bounds the live view.
	FollowSeconds uint32 `json:"follow_seconds,omitempty"`
	// AfterCursor starts the read right after a journal position.
	AfterCursor string `json:"after_cursor,omitempty"`
}

// PackageChangePayload describes an install, a removal or a hold.
type PackageChangePayload struct {
	Packages []string `json:"packages"`
	// ExpectedRemovals is the set the operator approved for a removal.
	ExpectedRemovals []string `json:"expected_removals,omitempty"`
	// Hold concerns holds only: true freezes, false releases.
	Hold bool `json:"hold,omitempty"`
	// PlanHash binds the install to the plan computed on this host: the host
	// computes the plan once more and refuses when it no longer matches.
	PlanHash string `json:"plan_hash,omitempty"`
	// Plan is the approved plan envelope the change is bound to: the header the
	// host rebuilds the envelope with and the elements the operator approved.
	Plan *PlanReference `json:"plan,omitempty"`
}

// PlanReference is what an execution carries of the approved plan envelope
// (chapter 7 of the security remediation plan).
type PlanReference struct {
	SchemaVersion     uint32 `json:"schema_version,omitempty"`
	PlannerVersion    string `json:"planner_version,omitempty"`
	InventoryRevision string `json:"inventory_revision,omitempty"`
	ResourceRevision  string `json:"resource_revision,omitempty"`
	// ExpiresAt is the expiry of the plan in RFC 3339; it is part of the
	// digest, so the host needs the same moment to compute the same one.
	ExpiresAt string            `json:"expires_at,omitempty"`
	Changes   []PlanChangeEntry `json:"changes,omitempty"`
}

// PlanChangeEntry is one approved element of a package plan: the version,
// architecture and origin of a package and the direction of its change.
type PlanChangeEntry struct {
	Name             string `json:"name"`
	CurrentVersion   string `json:"current_version,omitempty"`
	CandidateVersion string `json:"candidate_version,omitempty"`
	Architecture     string `json:"architecture,omitempty"`
	Origin           string `json:"origin,omitempty"`
	Action           string `json:"action,omitempty"`
}

// PackagePlanPayload describes planning an upgrade.
type PackagePlanPayload struct {
	// Mode picks the kind of plan: upgrade (the default), install or remove.
	Mode string `json:"mode,omitempty"`
	// RefreshMetadata requires root and the repository lock, so it is an
	// explicit choice rather than a side effect of every plan.
	RefreshMetadata bool     `json:"refresh_metadata"`
	OnlyPackages    []string `json:"only_packages,omitempty"`
	SecurityOnly    bool     `json:"security_only,omitempty"`
}

// PackageUpgradePayload describes carrying out an upgrade transaction.
type PackageUpgradePayload struct {
	// PlanHash binds the execution to one specific plan. Empty means no
	// verification and is allowed outside a campaign only.
	PlanHash     string   `json:"plan_hash,omitempty"`
	Packages     []string `json:"packages,omitempty"`
	SecurityOnly bool     `json:"security_only,omitempty"`
	// Plan is the approved plan envelope the execution is bound to, see
	// PlanReference.
	Plan *PlanReference `json:"plan,omitempty"`
}

// AgentUpgradePayload describes replacing the agent with a named version.
type AgentUpgradePayload struct {
	// TargetVersion is the version that has to report in after the restart.
	TargetVersion string `json:"target_version"`
	// PackageSHA256 is the checksum of the package from the release.
	PackageSHA256 string `json:"package_sha256,omitempty"`
	// PackageSigner is the key the artefact must carry the signature of, as a
	// fingerprint or a long key ID. The checksum says the bytes are the ones the
	// release published; the key says who built them. A plan for a host of the
	// apt family leaves it empty on purpose - see ArtefactCarriesSignature.
	PackageSigner string `json:"package_signer,omitempty"`
	// RollbackVersion says what to return to when the host does not come back
	// with the new version. Empty means no prepared return.
	RollbackVersion string `json:"rollback_version,omitempty"`
	// ReleaseRollback orders the host to drop the artefact it kept for a return.
	// The panel sends it once the replacement is confirmed.
	ReleaseRollback bool `json:"release_rollback,omitempty"`
}

// OSFamilyDebian is the family whose package file carries no signature of its
// own: the proof of a package's origin there is the signed repository index.
const OSFamilyDebian = "debian"

// ArtefactCarriesSignature says whether a package file of that OS family can
// carry a signature of its own, so a plan may name the key it must bear.
func ArtefactCarriesSignature(osFamily string) bool {
	return !strings.EqualFold(strings.TrimSpace(osFamily), OSFamilyDebian)
}

// validAgentVersion guards that the version is a package version rather than
// arbitrary text landing on the package manager's command line.
func validAgentVersion(version string) bool {
	if version == "" || len(version) > 64 {
		return false
	}
	for _, char := range version {
		switch {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char == '.' || char == '-' || char == '+' || char == '~' || char == ':' || char == '_':
		default:
			return false
		}
	}
	return true
}

// validSignerIdentity checks the notation of a key identity: a long key ID, a
// version 4 fingerprint or a version 6 one. Anything shorter is not accepted.
func validSignerIdentity(identity string) bool {
	switch len(identity) {
	case 16, 40, 64:
	default:
		return false
	}
	for _, char := range identity {
		switch {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'f':
		case char >= 'A' && char <= 'F':
		default:
			return false
		}
	}
	return true
}

// validChecksum checks the SHA-256 notation.
func validChecksum(sum string) bool {
	if len(sum) != 64 {
		return false
	}
	for _, char := range sum {
		switch {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'f':
		default:
			return false
		}
	}
	return true
}

// RebootPayload describes a controlled reboot of the host.
type RebootPayload struct {
	// DelaySeconds gives time to close the session and send the result back
	// before the host disappears from the network.
	DelaySeconds uint32 `json:"delay_seconds,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// UnitStatusPayload describes a read of unit state. An empty list means the
// full list of the host's units.
type UnitStatusPayload struct {
	Units []string `json:"units"`
	// All orders the full list. Without it an empty list of units is an
	// error.
	All bool `json:"all,omitempty"`
	// Detail asks for the full picture of the named units: dependencies, drop-ins
	// with their content, the last journal lines.
	Detail bool `json:"detail,omitempty"`
}

// UnitToggle turns a property of a unit on or off.
type UnitToggle struct {
	Unit string `json:"unit"`
	// Enabled for unit. enable. set, Masked for unit. mask. set.
	Enabled bool `json:"enabled"`
}

// Payload is the sum of the payload types. Exactly one field is filled in.
type Payload struct {
	Unit            *UnitPayload            `json:"unit,omitempty"`
	Journal         *JournalPayload         `json:"journal,omitempty"`
	PackagePlan     *PackagePlanPayload     `json:"package_plan,omitempty"`
	PackageUpgrade  *PackageUpgradePayload  `json:"package_upgrade,omitempty"`
	Reboot          *RebootPayload          `json:"reboot,omitempty"`
	UnitStatus      *UnitStatusPayload      `json:"unit_status,omitempty"`
	DomainEnroll    *DomainEnrollPayload    `json:"domain_enroll,omitempty"`
	DomainLeave     *DomainLeavePayload     `json:"domain_leave,omitempty"`
	Keytab          *KeytabPayload          `json:"keytab,omitempty"`
	LocalUser       *LocalUserPayload       `json:"local_user,omitempty"`
	PackageRepair   *PackageRepairPayload   `json:"package_repair,omitempty"`
	DockerRead      *DockerReadPayload      `json:"docker_read,omitempty"`
	DockerContainer *DockerContainerPayload `json:"docker_container,omitempty"`
	DockerImage     *DockerImagePayload     `json:"docker_image,omitempty"`
	DockerPrune     *DockerPrunePayload     `json:"docker_prune,omitempty"`
	DockerEvents    *DockerEventsPayload    `json:"docker_events,omitempty"`
	DockerLogs      *DockerLogsPayload      `json:"docker_logs,omitempty"`
	DockerEnsure    *DockerEnsurePayload    `json:"docker_ensure,omitempty"`
	Compose         *ComposePayload         `json:"compose,omitempty"`
	UnitToggle      *UnitToggle             `json:"unit_toggle,omitempty"`
	LogFile         *LogFilePayload         `json:"logfile,omitempty"`
	ProcessList     *ProcessListPayload     `json:"process_list,omitempty"`
	ProcessSignal   *ProcessSignalPayload   `json:"process_signal,omitempty"`
	Schedule        *SchedulePayload        `json:"schedule,omitempty"`
	Network         *NetworkPayload         `json:"network,omitempty"`
	DNS             *DNSPayload             `json:"dns,omitempty"`
	Firewall        *FirewallPayload        `json:"firewall,omitempty"`
	Storage         *StoragePayload         `json:"storage,omitempty"`
	SSH             *SSHPayload             `json:"ssh,omitempty"`
	Kernel          *KernelPayload          `json:"kernel,omitempty"`
	File            *FilePayload            `json:"file,omitempty"`
	PackageChange   *PackageChangePayload   `json:"package_change,omitempty"`
	Time            *TimePayload            `json:"time,omitempty"`
	Power           *PowerPayload           `json:"power,omitempty"`
	Security        *SecurityPayload        `json:"security,omitempty"`
	AgentUpgrade    *AgentUpgradePayload    `json:"agent_upgrade,omitempty"`
	Certificate     *CertificatePayload     `json:"certificate,omitempty"`
	Repository      *RepositoryPayload      `json:"repository,omitempty"`
	Backup          *BackupPayload          `json:"backup,omitempty"`
	Monitoring      *MonitoringPayload      `json:"monitoring,omitempty"`
	Inventory       *InventoryPayload       `json:"inventory,omitempty"`
	Hostname        *HostnamePayload        `json:"hostname,omitempty"`
}

// maxRefreshModules bounds the length of the scope. An order with a list
// longer than the set of modules is not a partial order, it is a wrong one.
const maxRefreshModules = 32

// InventoryModules lists the modules the panel can refresh on request.
var InventoryModules = []string{
	"system", "packages", "services", "identity", "accounts", "network",
	"dns", "firewall", "storage", "ssh", "kernel", "time", "power",
	"security", "certificates", "backups", "files", "containers", "schedules",
	"sudoers",
}

// IsInventoryModule says whether a name describes an inventory module.
func IsInventoryModule(name string) bool {
	for _, module := range InventoryModules {
		if module == name {
			return true
		}
	}
	return false
}

// InventoryPayload describes the scope of an inventory refresh.
type InventoryPayload struct {
	// Modules narrows the read.
	Modules []string `json:"modules,omitempty"`
}

// SecurityPayload describes an operation of the security module.
type SecurityPayload struct {
	// Mode is the mode of mandatory access control.
	Mode string `json:"mode,omitempty"`
	// CheckIDs names the compliance checks a fleet remediation removes the
	// findings of.
	CheckIDs []string `json:"check_ids,omitempty"`
}

// MonitoringPayload describes a probe carried out from the host.
type MonitoringPayload struct {
	Kind string `json:"kind"`
	// Target is the address: a URL for an HTTP probe, host:port for TCP.
	Target string `json:"target"`
	// ExpectStatus and ExpectBody describe what we treat as a good answer.
	// Empty means "anything in the 2xx and 3xx range".
	ExpectStatus   int    `json:"expect_status,omitempty"`
	ExpectBody     string `json:"expect_body,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// BackupPayload describes a backup operation. The credentials are references
// to the store: the repository password and the tool's environment variables.
type BackupPayload struct {
	ID   string `json:"id"`
	Tool string `json:"tool"`
	// Repository is a reference to the backup target; the data flows there
	// straight from the host and never through the panel.
	Repository  string   `json:"repository,omitempty"`
	Paths       []string `json:"paths,omitempty"`
	Excludes    []string `json:"excludes,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	KeepLast    int      `json:"keep_last,omitempty"`
	KeepDaily   int      `json:"keep_daily,omitempty"`
	KeepWeekly  int      `json:"keep_weekly,omitempty"`
	KeepMonthly int      `json:"keep_monthly,omitempty"`
	Prune       bool     `json:"prune,omitempty"`
	// Runbook points at a script the host administrator put there earlier.
	// The panel does not send its content and cannot create it.
	Runbook string `json:"runbook,omitempty"`
	// Initialize is the consent to create the repository on the first copy.
	Initialize bool `json:"initialize,omitempty"`

	PasswordSecret *SecretRef `json:"password_secret,omitempty"`
	// EnvSecrets assigns secrets from the store to environment variables:
	// that is how credentials reach a cloud backup backend.
	EnvSecrets map[string]SecretRef `json:"env_secrets,omitempty"`
	// ReadData turns on verification that reads the data rather than the
	// structure alone.
	ReadData bool `json:"read_data,omitempty"`
	// Plan names the kind of planned operation: run or verify.
	Plan string `json:"plan,omitempty"`
	// PlanHash binds the copy to the plan computed on this host: a scope or a
	// repository changed since planning stops the operation.
	PlanHash string `json:"plan_hash,omitempty"`

	// A restore. The target and the overwrite plan are mandatory: an
	// operation without them has an effect nobody knows.
	SnapshotID string   `json:"snapshot_id,omitempty"`
	Target     string   `json:"target,omitempty"`
	Include    []string `json:"include,omitempty"`
	Overwrite  string   `json:"overwrite,omitempty"`
}

// RepositoryPayload describes a package source.
type RepositoryPayload struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	URL           string   `json:"url,omitempty"`
	Suites        []string `json:"suites,omitempty"`
	Components    []string `json:"components,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Enabled       bool     `json:"enabled,omitempty"`
	Priority      int      `json:"priority,omitempty"`
	// GPGKey is the public key of the source in an ASCII frame.
	GPGKey string `json:"gpg_key,omitempty"`
	// AllowUnsigned is the consent to a source whose signatures the host does not
	// check.
	AllowUnsigned bool   `json:"allow_unsigned,omitempty"`
	Username      string `json:"username,omitempty"`
	// PasswordSecret points at the password in the store. The value is in
	// neither the order, nor the audit trail, nor the inventory.
	PasswordSecret *SecretRef `json:"password_secret,omitempty"`
	// Remove deletes the source together with its key and its password.
	Remove bool `json:"remove,omitempty"`
}

// CertificateTarget points at a certificate file together with what the panel
// knows about it.
type CertificateTarget struct {
	Path    string `json:"path"`
	KeyPath string `json:"key_path,omitempty"`
	Service string `json:"service,omitempty"`
}

// CertificatePayload describes an operation of the certificates module.
type CertificatePayload struct {
	// Targets sets the scope of the scan.
	Targets []CertificateTarget `json:"targets,omitempty"`

	// Path and KeyPath are the target of a deployment.
	Path    string `json:"path,omitempty"`
	KeyPath string `json:"key_path,omitempty"`
	// Certificate is content in the clear: the certificate together with its
	// chain.
	Certificate string `json:"certificate,omitempty"`
	// KeySecret points at the private key in the store.
	KeySecret *SecretRef `json:"key_secret,omitempty"`
	Owner     string     `json:"owner,omitempty"`
	Group     string     `json:"group,omitempty"`
	Mode      string     `json:"mode,omitempty"`
	KeyMode   string     `json:"key_mode,omitempty"`
	// ReloadUnit is the service that has to read the new file.
	ReloadUnit string `json:"reload_unit,omitempty"`
	// ProbeTarget is the address at which the host will check the result of the
	// deployment.
	ProbeTarget string `json:"probe_target,omitempty"`
	// Request points at the certmonger request during a renewal.
	Request string `json:"request,omitempty"`
	// AnchorID names the panel's anchor in the host's trust store.
	AnchorID string `json:"anchor_id,omitempty"`
	// PlanHash binds the deployment to the plan computed on this host; the
	// host computes the plan once more before swapping the files.
	PlanHash string `json:"plan_hash,omitempty"`
}

// PowerPayload describes shutting a host down.
type PowerPayload struct {
	// Mode distinguishes cutting the power from halting the system.
	Mode string `json:"mode,omitempty"`
	// DelaySeconds gives time to send the result back before the host
	// disappears.
	DelaySeconds uint32 `json:"delay_seconds,omitempty"`
	// Reason is required: nobody will power this host on remotely, so the
	// audit trail is the only thing left after the operation.
	Reason string `json:"reason"`
	// IgnoreInhibitors overrides logind's inhibitors. By default a host with
	// an inhibitor sends it back as the reason for a refusal.
	IgnoreInhibitors bool `json:"ignore_inhibitors,omitempty"`
}

// TimePayload describes an operation on the host's time.
type TimePayload struct {
	// Servers are the target time servers.
	Servers []string `json:"servers,omitempty"`
	// Probe names the servers to check without changing the configuration.
	Probe    []string `json:"probe,omitempty"`
	Timezone string   `json:"timezone,omitempty"`
	// AllowStep is the consent to step the clock. Without it the host
	// rejects a change that would move time by more than the threshold.
	AllowStep bool `json:"allow_step,omitempty"`
	// EnableDropIn is the consent to add the panel's source directory to the
	// daemon's main file.
	EnableDropIn bool `json:"enable_dropin,omitempty"`
	// PlanHash binds the change to the plan computed on this host; the host
	// computes the plan once more before writing.
	PlanHash string `json:"plan_hash,omitempty"`
}

// SecretRef points at a secret in the panel's store. The task payload carries
// only the reference.
type SecretRef struct {
	Name string `json:"name"`
	// Version equal to zero means the version current at the moment the task
	// is delivered.
	Version int `json:"version,omitempty"`
}

// secretName repeats the store's rule, so that an order with a name the store
// would not accept anyway falls out already at ordering time.
var secretName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

// Validate checks the reference to a secret.
func (r *SecretRef) Validate() error {
	if r == nil || r.Name == "" {
		return fmt.Errorf("a reference to a secret without a name")
	}
	if !secretName.MatchString(r.Name) {
		return fmt.Errorf("invalid secret name %q", r.Name)
	}
	if r.Version < 0 {
		return fmt.Errorf("the secret version must not be negative")
	}
	return nil
}

// Empty says whether the reference points at nothing.
func (r *SecretRef) Empty() bool { return r == nil || r.Name == "" }

// String describes the reference as "name#version".
func (r *SecretRef) String() string {
	if r.Empty() {
		return ""
	}
	if r.Version <= 0 {
		return r.Name + "#current"
	}
	return r.Name + "#" + strconv.Itoa(r.Version)
}

// FilePayload describes an operation on a configuration file.
type FilePayload struct {
	Path string `json:"path"`
	// Content is the target content. The panel sends it in the order, so the
	// plan and what reaches the host are the same thing.
	Content string `json:"content,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Group   string `json:"group,omitempty"`
	// ExpectedSHA256 binds the write to the content the operator reviewed.
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	Validator      string `json:"validator,omitempty"`
	// VersionSHA256 points at the version from the history when going back to
	// it.
	VersionSHA256 string `json:"version_sha256,omitempty"`
	// ContentSecret points at the secret whose value is to land in the file.
	ContentSecret *SecretRef `json:"content_secret,omitempty"`
	// AllowMissingValidator lets the write go on when the host lacks the
	// validator; without it a missing validator refuses the write.
	AllowMissingValidator bool `json:"allow_missing_validator,omitempty"`
}

// Secrets lists the references the host will have to reach for.
func (p Payload) Secrets() []SecretRef {
	var references []SecretRef
	if p.File != nil && !p.File.ContentSecret.Empty() {
		references = append(references, *p.File.ContentSecret)
	}
	if p.Certificate != nil && !p.Certificate.KeySecret.Empty() {
		references = append(references, *p.Certificate.KeySecret)
	}
	if p.Repository != nil && !p.Repository.PasswordSecret.Empty() {
		references = append(references, *p.Repository.PasswordSecret)
	}
	if p.Backup != nil {
		if !p.Backup.PasswordSecret.Empty() {
			references = append(references, *p.Backup.PasswordSecret)
		}
		// The order is fixed so that two identical orders issue their leases
		// in the same order.
		names := make([]string, 0, len(p.Backup.EnvSecrets))
		for name := range p.Backup.EnvSecrets {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			reference := p.Backup.EnvSecrets[name]
			references = append(references, reference)
		}
	}
	return references
}

// KernelPayload describes an operation on kernel settings.
type KernelPayload struct {
	// Settings are sysctl keys together with their target values.
	Settings map[string]string `json:"settings,omitempty"`
	// Keys names additional keys to read beyond the profile.
	Keys   []string `json:"keys,omitempty"`
	Module string   `json:"module,omitempty"`
	// Blacklist says whether the module is to be blocked or unblocked.
	Blacklist bool `json:"blacklist,omitempty"`
	// PlanHash binds the blacklist entry to the plan computed on this host;
	// the host computes the plan once more before writing.
	PlanHash string `json:"plan_hash,omitempty"`
}

// SSHPayload describes a change to the sshd server configuration.
type SSHPayload struct {
	Port                   string   `json:"port,omitempty"`
	PermitRootLogin        string   `json:"permit_root_login,omitempty"`
	PasswordAuthentication string   `json:"password_authentication,omitempty"`
	PubkeyAuthentication   string   `json:"pubkey_authentication,omitempty"`
	KbdInteractive         string   `json:"kbd_interactive_authentication,omitempty"`
	MaxAuthTries           string   `json:"max_auth_tries,omitempty"`
	AllowUsers             []string `json:"allow_users,omitempty"`
	AllowGroups            []string `json:"allow_groups,omitempty"`
	DenyUsers              []string `json:"deny_users,omitempty"`
	// AllowLockout permits writing a configuration after which no working
	// authentication method is left.
	AllowLockout bool   `json:"allow_lockout,omitempty"`
	KeyType      string `json:"key_type,omitempty"`
	// PlanHash binds the change to the plan computed on this host; the host
	// computes the plan once more before writing.
	PlanHash string `json:"plan_hash,omitempty"`
}

// DescribesChange says whether the payload carries settings to plan.
func (p SSHPayload) DescribesChange() bool {
	return p.Port != "" || p.PermitRootLogin != "" || p.PasswordAuthentication != "" ||
		p.PubkeyAuthentication != "" || p.KbdInteractive != "" || p.MaxAuthTries != "" ||
		len(p.AllowUsers) > 0 || len(p.AllowGroups) > 0 || len(p.DenyUsers) > 0
}

// StoragePayload describes an operation on storage.
type StoragePayload struct {
	Source  string `json:"source,omitempty"`
	Target  string `json:"target,omitempty"`
	FSType  string `json:"fs_type,omitempty"`
	Options string `json:"options,omitempty"`
	// Persist writes an entry in fstab. Without it the mount disappears after a
	// reboot - and the operator is to know that before the outage, not after.
	Persist bool   `json:"persist,omitempty"`
	Device  string `json:"device,omitempty"`
	// ExpectedSerial and ExpectedSizeBytes bind the operation to the device the
	// operator reviewed.
	ExpectedSerial    string `json:"expected_serial,omitempty"`
	ExpectedSizeBytes uint64 `json:"expected_size_bytes,omitempty"`
	// ExpectedByID and ExpectedWWN are the stable identity of the device a
	// destructive operation binds to; the host refuses without them.
	ExpectedByID string `json:"expected_by_id,omitempty"`
	ExpectedWWN  string `json:"expected_wwn,omitempty"`
	// Size is the increment of the volume, e.g. "+10G".
	Size  string `json:"size,omitempty"`
	Label string `json:"label,omitempty"`
	// ExpectedUUID binds the operation to one specific filesystem.
	ExpectedUUID string `json:"expected_uuid,omitempty"`
	Repair       bool   `json:"repair,omitempty"`
	// Plan names the kind of operation storage. plan is planning on the device:
	// check, resize or lvm_extend.
	Plan string `json:"plan,omitempty"`
	// PlanHash binds the change to the plan computed on this host; the host
	// computes the plan once more before the operation.
	PlanHash string `json:"plan_hash,omitempty"`

	// Array is the software array a member operation acts on, and
	// ExpectedArrayUUID the identity out of its superblock.
	Array             string `json:"array,omitempty"`
	ExpectedArrayUUID string `json:"expected_array_uuid,omitempty"`

	// Group is the LVM volume group an operation acts in, and ExpectedGroupUUID
	// its identity: a name can move to another group, a UUID cannot.
	Group             string `json:"group,omitempty"`
	ExpectedGroupUUID string `json:"expected_group_uuid,omitempty"`
	// Volume is the name of the logical volume being created, and
	// ExpectedVolumeUUID the identity of the volume an operation acts on.
	Volume             string `json:"volume,omitempty"`
	ExpectedVolumeUUID string `json:"expected_volume_uuid,omitempty"`
}

// FirewallPayload describes an operation on the host's firewall.
type FirewallPayload struct {
	RuleID    string   `json:"rule_id,omitempty"`
	Chain     string   `json:"chain,omitempty"`
	Action    string   `json:"action,omitempty"`
	Protocol  string   `json:"protocol,omitempty"`
	Ports     []string `json:"ports,omitempty"`
	Sources   []string `json:"sources,omitempty"`
	Interface string   `json:"interface,omitempty"`
	Comment   string   `json:"comment,omitempty"`
	// Zone and Service concern hosts with firewalld.
	Zone    string `json:"zone,omitempty"`
	Service string `json:"service,omitempty"`
	Enable  bool   `json:"enable,omitempty"`
	// BreakGlass overrides the protection of the management channel.
	BreakGlass      bool   `json:"break_glass,omitempty"`
	RollbackSeconds uint32 `json:"rollback_seconds,omitempty"`
	RollbackID      string `json:"rollback_id,omitempty"`
	// ExpectedHash binds the change to the ruleset the operator reviewed.
	ExpectedHash string `json:"expected_hash,omitempty"`
}

// DNSPayload describes an operation on the host's resolver.
type DNSPayload struct {
	// Interface names the connection profile the change goes through.
	Interface     string   `json:"interface,omitempty"`
	Servers       []string `json:"servers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
	// IgnoreAutoDNS rejects the servers from DHCP.
	IgnoreAutoDNS   bool     `json:"ignore_auto_dns,omitempty"`
	RollbackSeconds uint32   `json:"rollback_seconds,omitempty"`
	Names           []string `json:"names,omitempty"`
	// PlanHash binds the change to the plan computed on this host; the host
	// computes the plan once more before the change.
	PlanHash string `json:"plan_hash,omitempty"`
}

// NetworkPayload describes a change to the network configuration. The payload
// describes the target state of the interface, not commands to run.
type NetworkPayload struct {
	Interface string `json:"interface"`
	// MTU is text, because "auto" is an equally valid value here: zero would
	// mean a link with an MTU of zero.
	MTU string `json:"mtu,omitempty"`
	// Routes is the profile's complete list of routes, not an addition: the
	// operator saw one set in the plan and that is what stays on the host.
	Routes    []string `json:"routes,omitempty"`
	Method    string   `json:"method,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	// RollbackSeconds is the window in which the agent has to confirm
	// connectivity.
	RollbackSeconds uint32 `json:"rollback_seconds,omitempty"`
	// RollbackID points at the rollback plan in a network.rollback operation.
	RollbackID string `json:"rollback_id,omitempty"`
	// PlanHash binds the change to the plan computed on this host.
	PlanHash string `json:"plan_hash,omitempty"`
	// The second family, ordered to the same standard as the first.
	Method6    string   `json:"method6,omitempty"`
	Addresses6 []string `json:"addresses6,omitempty"`
	// Gateway6 may be a link-local address: that is how an IPv6 router ordinarily
	// announces itself, and a check written for IPv4 would refuse it.
	Gateway6 string `json:"gateway6,omitempty"`
	// AcceptRA is off, on or on-forwarding; Privacy is off, prefer-public or
	// prefer-temporary.
	AcceptRA string `json:"accept_ra,omitempty"`
	Privacy  string `json:"privacy,omitempty"`
	// Link is the layered interface ordered: a bond, a bridge or a VLAN with what
	// it is made of.
	Link *network.LinkSpec `json:"link,omitempty"`
	// LinkRemove marks a plan that is about a removal.
	LinkRemove bool `json:"link_remove,omitempty"`
}

// DescribesChange says whether the payload carries a change to plan: an MTU, a
// list of routes, an address profile of either family, or a layer.
func (p NetworkPayload) DescribesChange() bool {
	if p.Link != nil || p.LinkRemove {
		return true
	}
	return p.Interface != "" && (p.MTU != "" || p.Routes != nil || p.Method != "" ||
		p.Method6 != "" || p.AcceptRA != "" || p.Privacy != "")
}

// DescribesLayer says whether the order is about the layering rather than
// about what an interface carries.
func (p NetworkPayload) DescribesLayer() bool {
	return p.Link != nil || p.LinkRemove
}

// SchedulePayload describes a scheduled job.
type SchedulePayload struct {
	// ID is the stable identifier of a managed entry. An entry found on the
	// host has no such identifier and cannot be named here.
	ID string `json:"id"`
	// Expression is the cron expression. Checked on both sides: an entry the
	// host will not understand would never run.
	Expression string `json:"expression,omitempty"`
	// Command is an array of arguments, never a shell line.
	Command []string `json:"command,omitempty"`
	// User is the account the entry runs as. It is required for schedule. ensure
	// and root is not a default: an entry for root needs the permission schedule.
	User    string `json:"user,omitempty"`
	Comment string `json:"comment,omitempty"`
	// Enabled concerns schedule.disable only: true enables, false disables.
	// Disabling does not delete the content of the entry.
	Enabled bool `json:"enabled,omitempty"`
	// Adopt allows taking over an entry found on the host. Without it the
	// panel does not overwrite work nobody entered into the panel.
	Adopt bool `json:"adopt,omitempty"`
	// Kind names the mechanism a managed entry is written with: "cron" for a file
	// in /etc/cron.
	Kind string `json:"kind,omitempty"`
}

// The mechanisms a managed entry can be ordered as. The names are the ones the
// schedules module uses, so a payload and a snapshot speak one vocabulary.
const (
	ScheduleKindCron  = "cron"
	ScheduleKindTimer = "timer"
	ScheduleKindAny   = "any"
)

// RefusalCalendarUnsupported refuses a cron expression that cannot be written
// as a timer.
const RefusalCalendarUnsupported = "timer_calendar_unsupported"

// ProcessListPayload describes a snapshot of processes.
type ProcessListPayload struct {
	// SortBy decides which processes land in the result when there are more
	// of them than the limit: rss, cpu, pid or started.
	SortBy string `json:"sort_by,omitempty"`
	Limit  uint32 `json:"limit,omitempty"`
}

// ProcessSignalPayload describes a signal to a process.
type ProcessSignalPayload struct {
	PID           int32  `json:"pid"`
	ExpectedStart uint64 `json:"expected_start_ticks"`
	Signal        string `json:"signal"`
	// Command serves confirmation and the audit trail: the operator has the
	// command in the dialog, and what they saw stays in the trail.
	Command string `json:"command,omitempty"`
}

// LogFilePayload describes reading a log file.
type LogFilePayload struct {
	Path string `json:"path"`
	// Lines bounds the size of the result; a read without a limit is not
	// allowed.
	Lines uint32 `json:"lines"`
}

// ComposePayload carries the manifest of a Compose project.
type ComposePayload struct {
	Project  string `json:"project"`
	Manifest string `json:"manifest"`
	// PlanDigest binds the deployment to a plan. An empty one is allowed only
	// while planning; a deployment without it has no basis.
	PlanDigest string `json:"plan_digest,omitempty"`
	// ImageDigests are the digests the plan bound, by service; the host
	// refuses the deployment when a tag has moved since.
	ImageDigests map[string]string `json:"image_digests,omitempty"`
}

// DockerContainerPayload names the container of an operation. The target is an
// identifier, not a name.
type DockerContainerPayload struct {
	ContainerID string `json:"container_id"`
	// Name serves confirmation and the audit trail only: the operator has the
	// name in the dialog, and what they saw stays in the trail.
	Name string `json:"name,omitempty"`
	// TimeoutSeconds gives the container time to shut down before being
	// killed.
	TimeoutSeconds uint32 `json:"timeout_seconds,omitempty"`
	// RemoveVolumes concerns removal only and is off by default: a volume
	// outlives its container precisely so that the data outlives it.
	RemoveVolumes bool `json:"remove_volumes,omitempty"`
}

// DockerImagePayload describes the image to pull.
type DockerImagePayload struct {
	// Reference is the full image reference, e.g. "nginx:1.27".
	Reference string `json:"reference"`
}

// The kinds of object a declaration is about.
const (
	DockerKindContainer = "container"
	DockerKindNetwork   = "network"
	DockerKindVolume    = "volume"
)

// DockerEnsurePayload carries the description of one declared object.
type DockerEnsurePayload struct {
	// Container is the description in the words an operator writes it in -
	// "8080:80/tcp", "volume:data:/var/lib/data:ro" - not the engine's own form.
	Container *docker.ContainerRequest `json:"container,omitempty"`
	Network   *docker.NetworkSpec      `json:"network,omitempty"`
	Volume    *docker.VolumeSpec       `json:"volume,omitempty"`
	// Kind and Name describe a removal, which names an object rather than
	// describing one. A plan of a removal carries them too.
	Kind string `json:"kind,omitempty"`
	Name string `json:"name,omitempty"`
	// EnvSecrets maps a container environment variable to the secret whose
	// value it takes. The reference travels; the value never does.
	EnvSecrets map[string]SecretRef `json:"env_secrets,omitempty"`
	// PlanDigest binds the change to a plan. A change without it has no
	// basis, and the registry says which operations may go without one.
	PlanDigest string `json:"plan_digest,omitempty"`
	// Force says the order accepts what the host would otherwise refuse, such as
	// a network recreated under the containers attached to it.
	Force bool `json:"force,omitempty"`
}

// SpecWithSecrets returns the container description as it travels to the host:
// the secret references stand under the names of the variables they fill.
func (p *DockerEnsurePayload) SpecWithSecrets() (docker.ContainerSpec, error) {
	if p == nil || p.Container == nil {
		return docker.ContainerSpec{}, fmt.Errorf("the order carries no container description")
	}
	references := make(map[string]string, len(p.EnvSecrets))
	for name, reference := range p.EnvSecrets {
		references[name] = reference.String()
	}
	if len(references) == 0 {
		references = nil
	}
	return p.Container.Spec(references)
}

// ObjectKind says which object the payload is about.
func (p *DockerEnsurePayload) ObjectKind() string {
	switch {
	case p == nil:
		return ""
	case p.Container != nil:
		return DockerKindContainer
	case p.Network != nil:
		return DockerKindNetwork
	case p.Volume != nil:
		return DockerKindVolume
	}
	return p.Kind
}

// ObjectName is the object the payload is about, whether it describes it
// or only names it.
func (p *DockerEnsurePayload) ObjectName() string {
	switch {
	case p == nil:
		return ""
	case p.Container != nil:
		return p.Container.Name
	case p.Network != nil:
		return p.Network.Name
	case p.Volume != nil:
		return p.Volume.Name
	}
	return p.Name
}

// DockerPrunePayload lists the objects to remove.
type DockerPrunePayload struct {
	ImageIDs   []string `json:"image_ids,omitempty"`
	VolumeName []string `json:"volume_names,omitempty"`
	NetworkIDs []string `json:"network_ids,omitempty"`
}

// The boundaries of an event journal read.
const (
	maxEventWindow = 24 * 60 * 60
	maxEventFollow = 60
	maxEvents      = 1000
)

// DockerEventsPayload describes a closed window of an event journal read.
type DockerEventsPayload struct {
	// SinceSeconds says how far back to reach.
	SinceSeconds int `json:"since_seconds,omitempty"`
	// FollowSeconds extends the read past the present moment. Zero means the
	// past journal alone - the task ends right away.
	FollowSeconds int `json:"follow_seconds,omitempty"`
	// Types narrows the kinds of events. An empty list means all known ones.
	Types []string `json:"types,omitempty"`
	// MaxEvents bounds the number of events in the result.
	MaxEvents int `json:"max_events,omitempty"`
}

// DockerReadPayload describes a read of the container engine's state.
type DockerReadPayload struct{}

// PackageRepairPayload carries the operator's answers to package configuration
// questions that block package operations.
type PackageRepairPayload struct {
	Answers []DebconfAnswer `json:"answers,omitempty"`
}

// DebconfAnswer is one answer to a package configuration question.
type DebconfAnswer struct {
	Package  string `json:"package"`
	Question string `json:"question"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

// DomainEnrollPayload describes joining the host to a domain.
type DomainEnrollPayload struct {
	Domain   string `json:"domain"`
	Realm    string `json:"realm"`
	Server   string `json:"server,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// DomainLeavePayload describes taking the host out of a domain.
type DomainLeavePayload struct {
	Domain string `json:"domain"`
	Realm  string `json:"realm"`
}

// KeytabPayload names the service principal whose keytab the host renews, as
// service/host.
type KeytabPayload struct {
	Principal string `json:"principal"`
}

// LocalUserPayload describes a change to a local account. The payload contains
// neither a password nor a hash.
type LocalUserPayload struct {
	Name   string   `json:"name"`
	Gecos  string   `json:"gecos,omitempty"`
	Shell  string   `json:"shell,omitempty"`
	Groups []string `json:"groups,omitempty"`
	// SSHKeys is the complete, intended list of keys of a create or a replace.
	SSHKeys    []string `json:"ssh_keys,omitempty"`
	CreateHome bool     `json:"create_home,omitempty"`
	// ExpiresAt is the expiry date as YYYY-MM-DD. Empty in an expiry
	// operation clears the expiry - a deliberate change, not missing data.
	ExpiresAt string `json:"expires_at,omitempty"`
	// RemoveHome concerns deletion only: the home directory goes with the
	// account only when the operator says so.
	RemoveHome bool `json:"remove_home,omitempty"`

	// The key operations of chapter 14. 1 of the security remediation.
	Keys []SSHKeyInput `json:"keys,omitempty"`
	// Fingerprints names the keys a remove takes away and nothing else.
	Fingerprints  []string `json:"fingerprints,omitempty"`
	IgnoreMissing bool     `json:"ignore_missing,omitempty"`
	// ExpectedFingerprints is what the operator saw when they ordered a replace:
	// the list of keys the account has now.
	ExpectedFingerprints []string `json:"expected_fingerprints,omitempty"`
	// AllowLockout permits taking the last key of an account that has no password
	// login: after it nobody enters as that account.
	AllowLockout bool `json:"allow_lockout,omitempty"`
	// ManagedFile edits the panel's own key file under /etc/ssh/authorized_keys.
	ManagedFile bool `json:"managed_file,omitempty"`
	// System says the order means a system account - one outside the UID range of
	// people in the host's login.
	System bool `json:"system,omitempty"`
	// Inactive acknowledges that a created account has no way in: no key and,
	// since the panel sets no passwords, no password.
	Inactive bool `json:"inactive,omitempty"`
}

// SSHKeyInput is a key an add appends: the public key as the file takes it,
// options included, and an optional comment.
type SSHKeyInput struct {
	PublicKey string `json:"public_key"`
	Comment   string `json:"comment,omitempty"`
}

// HostnamePayload describes a rename of the host.
type HostnamePayload struct {
	// Hostname is the static name: an RFC 1123 label or a fully qualified
	// name.
	Hostname string `json:"hostname"`
	// Pretty is the human-readable name hostnamectl shows. Optional.
	Pretty string `json:"pretty,omitempty"`
}

// DockerLogsPayload describes a bounded read of one container's log. The
// target may be an identifier or a name.
type DockerLogsPayload struct {
	ContainerID string `json:"container_id"`
	// Lines is the tail to read; zero means the module default of 200.
	Lines uint32 `json:"lines,omitempty"`
	// Since narrows the read: an RFC 3339 timestamp or a duration such as
	// 15m. Empty means the whole tail.
	Since string `json:"since,omitempty"`
	// Timestamps prefixes every line with the engine's timestamp.
	Timestamps bool `json:"timestamps,omitempty"`
}

// Validate checks that the operation type and the payload agree.
func Validate(action ActionType, payload Payload) error {
	if !action.Known() {
		return fmt.Errorf("unknown operation type %q", action)
	}
	switch action {
	case ActionPackagePlan:
		if payload.PackagePlan == nil {
			return fmt.Errorf("the operation %s requires a package_plan payload", action)
		}
		switch payload.PackagePlan.Mode {
		case "", "upgrade":
		case "install", "remove":
			if len(payload.PackagePlan.OnlyPackages) == 0 {
				return fmt.Errorf("a %s plan requires a list of packages", payload.PackagePlan.Mode)
			}
		default:
			return fmt.Errorf("unsupported plan kind %q", payload.PackagePlan.Mode)
		}
		return validatePackageNames(payload.PackagePlan.OnlyPackages)

	case ActionPackageInstall, ActionPackageRemove, ActionPackageHoldSet:
		if payload.PackageChange == nil {
			return fmt.Errorf("the operation %s requires a package_change payload", action)
		}
		if len(payload.PackageChange.Packages) == 0 {
			return fmt.Errorf("the operation %s requires a list of packages", action)
		}
		if err := validatePackageNames(payload.PackageChange.Packages); err != nil {
			return err
		}
		if err := validatePackageNames(payload.PackageChange.ExpectedRemovals); err != nil {
			return err
		}
		// A removal without an approved set has no basis: the operator would
		// be approving a change they did not see.
		if action == ActionPackageRemove && len(payload.PackageChange.ExpectedRemovals) == 0 {
			return fmt.Errorf("a removal requires an approved set of packages")
		}
		// A protected package is not rejected only on the host: the operator
		// is to know when ordering that this operation has no chance.
		if action == ActionPackageRemove {
			together := append(append([]string{}, payload.PackageChange.Packages...),
				payload.PackageChange.ExpectedRemovals...)
			if protected := protectedPackages(together); len(protected) > 0 {
				return fmt.Errorf("protected packages must not be removed: %s",
					strings.Join(protected, ", "))
			}
		}
		return nil

	case ActionPackageRepair:
		if payload.PackageRepair == nil {
			return fmt.Errorf("the operation %s requires a package_repair payload", action)
		}
		for _, answer := range payload.PackageRepair.Answers {
			if err := validatePackageNames([]string{answer.Package}); err != nil {
				return err
			}
			if !debconfQuestionPattern.MatchString(answer.Question) {
				return fmt.Errorf("invalid question name %q", answer.Question)
			}
			if !debconfTypePattern.MatchString(answer.Type) {
				return fmt.Errorf("unsupported question type %q", answer.Type)
			}
			// A newline would allow appending settings nobody asked for:
			// every line of debconf input is a separate entry.
			if strings.ContainsAny(answer.Value, "\n\r") {
				return fmt.Errorf("the answer value must not contain a newline")
			}
		}
		return nil

	case ActionLocalUserCreate, ActionLocalUserLock, ActionLocalUserUnlock, ActionLocalSSHKeysSet,
		ActionLocalSSHKeysAdd, ActionLocalSSHKeysRemove, ActionLocalSSHKeysReplaceAll,
		ActionLocalUserGroupsSet, ActionLocalUserExpirySet, ActionLocalUserDelete:
		if payload.LocalUser == nil {
			return fmt.Errorf("the operation %s requires a local_user payload", action)
		}
		if !localUserNamePattern.MatchString(payload.LocalUser.Name) {
			return fmt.Errorf("invalid account name %q", payload.LocalUser.Name)
		}
		if err := validateLocalUserKeyFields(action, payload.LocalUser); err != nil {
			return err
		}
		// The accounts below the user range and the account the agent runs under
		// are refused here as well: the host refuses them too, but only later.
		if action == ActionLocalUserDelete && protectedAccount(payload.LocalUser.Name) {
			return fmt.Errorf("the account %s is not deleted through the panel", payload.LocalUser.Name)
		}
		if payload.LocalUser.RemoveHome && action != ActionLocalUserDelete {
			return fmt.Errorf("the operation %s does not remove a home directory", action)
		}
		if payload.LocalUser.ExpiresAt != "" {
			if action != ActionLocalUserExpirySet {
				return fmt.Errorf("the operation %s does not set an expiry date", action)
			}
			if err := validateExpiryDate(payload.LocalUser.ExpiresAt); err != nil {
				return err
			}
		}
		if len(payload.LocalUser.Groups) > 64 {
			return fmt.Errorf("too many groups: %d", len(payload.LocalUser.Groups))
		}
		if len(payload.LocalUser.SSHKeys) > 64 {
			return fmt.Errorf("too many SSH keys: %d", len(payload.LocalUser.SSHKeys))
		}
		for _, key := range payload.LocalUser.SSHKeys {
			if err := validatePublicKeyShape(key); err != nil {
				return err
			}
		}
		for _, group := range payload.LocalUser.Groups {
			if !localUserNamePattern.MatchString(group) {
				return fmt.Errorf("invalid group name %q", group)
			}
		}
		if shell := payload.LocalUser.Shell; shell != "" && !strings.HasPrefix(shell, "/") {
			return fmt.Errorf("the shell has to be an absolute path, got %q", shell)
		}
		if strings.ContainsAny(payload.LocalUser.Gecos, ":\n") {
			return fmt.Errorf("the description field must not contain a colon or a newline")
		}
		return nil

	case ActionDomainEnroll, ActionDomainPreflight:
		if payload.DomainEnroll == nil {
			return fmt.Errorf("the operation %s requires a domain_enroll payload", action)
		}
		if payload.DomainEnroll.Domain == "" || payload.DomainEnroll.Realm == "" {
			return fmt.Errorf("joining requires a domain and a realm")
		}
		if !domainPattern.MatchString(payload.DomainEnroll.Domain) {
			return fmt.Errorf("invalid domain name %q", payload.DomainEnroll.Domain)
		}
		return nil

	case ActionIdentityKeytabRenew:
		if payload.Keytab == nil {
			return fmt.Errorf("the operation %s requires a keytab payload", action)
		}
		return ValidateServicePrincipal(payload.Keytab.Principal)

	case ActionDomainLeave:
		if payload.DomainLeave == nil {
			return fmt.Errorf("the operation %s requires a domain_leave payload", action)
		}
		if payload.DomainLeave.Domain == "" || payload.DomainLeave.Realm == "" {
			return fmt.Errorf("leaving requires the domain and the realm the host is in")
		}
		if !domainPattern.MatchString(payload.DomainLeave.Domain) {
			return fmt.Errorf("invalid domain name %q", payload.DomainLeave.Domain)
		}
		return nil

	case ActionInventoryRefresh:
		// The payload is optional: no scope means the whole inventory.
		if payload.Inventory == nil {
			return nil
		}
		if len(payload.Inventory.Modules) > maxRefreshModules {
			return fmt.Errorf("a refresh covers at most %d modules", maxRefreshModules)
		}
		seen := map[string]bool{}
		for _, module := range payload.Inventory.Modules {
			// An unknown module name must not pass as "nothing to do": a typo would end
			// in a refresh that refreshes nothing and looks like a success.
			if !IsInventoryModule(module) {
				return fmt.Errorf("unknown inventory module %q", module)
			}
			if seen[module] {
				return fmt.Errorf("the module %q was given twice", module)
			}
			seen[module] = true
		}
		return nil

	case ActionDockerRead:
		if payload.DockerRead == nil {
			return fmt.Errorf("the operation %s requires a docker_read payload", action)
		}
		return nil

	case ActionDockerStart, ActionDockerStop, ActionDockerRestart, ActionDockerRemove:
		if payload.DockerContainer == nil {
			return fmt.Errorf("the operation %s requires a docker_container payload", action)
		}
		if !validContainerIdentifier(payload.DockerContainer.ContainerID) {
			return fmt.Errorf("invalid container identifier %q",
				payload.DockerContainer.ContainerID)
		}
		if payload.DockerContainer.TimeoutSeconds > 3600 {
			return fmt.Errorf("the time given to shut the container down is too long")
		}
		if payload.DockerContainer.RemoveVolumes && action != ActionDockerRemove {
			return fmt.Errorf("the operation %s does not remove volumes", action)
		}
		return nil

	case ActionDockerLogs:
		if payload.DockerLogs == nil {
			return fmt.Errorf("the operation %s requires a docker_logs payload", action)
		}
		if err := docker.ValidateContainerReference(payload.DockerLogs.ContainerID); err != nil {
			return err
		}
		if payload.DockerLogs.Lines > docker.MaxLogLines {
			return fmt.Errorf("the number of lines has to be in the range 1-%d", docker.MaxLogLines)
		}
		_, err := docker.ParseLogsSince(payload.DockerLogs.Since, time.Now())
		return err

	case ActionDockerPull:
		if payload.DockerImage == nil {
			return fmt.Errorf("the operation %s requires a docker_image payload", action)
		}
		return validImageReference(payload.DockerImage.Reference)

	case ActionComposePlan, ActionComposeDeploy:
		if payload.Compose == nil {
			return fmt.Errorf("the operation %s requires a compose payload", action)
		}
		if !composeProjectName.MatchString(payload.Compose.Project) {
			return fmt.Errorf("invalid project name %q", payload.Compose.Project)
		}
		if strings.TrimSpace(payload.Compose.Manifest) == "" {
			return fmt.Errorf("the project manifest is empty")
		}
		if len(payload.Compose.Manifest) > maxComposeManifest {
			return fmt.Errorf("the project manifest is too large (%d bytes)",
				len(payload.Compose.Manifest))
		}
		// A deployment without a plan has no basis: the operator would be
		// approving a change they did not see.
		if action == ActionComposeDeploy && payload.Compose.PlanDigest == "" {
			return fmt.Errorf("deploying a project requires the hash of an approved plan")
		}
		return nil

	case ActionDockerPlan, ActionDockerContainerEnsure,
		ActionDockerNetworkEnsure, ActionDockerVolumeEnsure,
		ActionDockerNetworkRemove, ActionDockerVolumeRemove:
		return checkDockerDeclaration(action, payload.DockerEnsure)

	case ActionDockerPrune:
		if payload.DockerPrune == nil {
			return fmt.Errorf("the operation %s requires a docker_prune payload", action)
		}
		return checkPruneList(payload.DockerPrune)

	case ActionDockerEvents:
		return checkEventsRead(payload.DockerEvents)

	case ActionSchedulePreview:
		if payload.Schedule == nil {
			return fmt.Errorf("the operation %s requires a schedule payload", action)
		}
		if strings.TrimSpace(payload.Schedule.Expression) == "" {
			return fmt.Errorf("a preview requires an expression")
		}
		// The same parser the host uses: an expression it would refuse is
		// refused here, with the same words.
		if _, err := schedules.ParseExpression(payload.Schedule.Expression); err != nil {
			return fmt.Errorf("schedule expression: %w", err)
		}
		// A preview of a timer shows the units that would be written, so
		// the expression has to have a calendar form at all.
		return checkScheduleKind(payload.Schedule)

	case ActionScheduleEnsure, ActionScheduleDisable, ActionScheduleRemove, ActionScheduleRunNow:
		if payload.Schedule == nil {
			return fmt.Errorf("the operation %s requires a schedule payload", action)
		}
		if !scheduleIdentifier.MatchString(payload.Schedule.ID) {
			return fmt.Errorf("invalid schedule identifier %q", payload.Schedule.ID)
		}
		if action != ActionScheduleEnsure {
			return nil
		}
		if strings.TrimSpace(payload.Schedule.Expression) == "" {
			return fmt.Errorf("a schedule requires an expression")
		}
		// We check the expression here rather than only on the host: an entry cron
		// will not understand would never run, and nobody would notice.
		if _, err := schedules.ParseExpression(payload.Schedule.Expression); err != nil {
			return fmt.Errorf("schedule expression: %w", err)
		}
		if len(payload.Schedule.Command) == 0 {
			return fmt.Errorf("a schedule requires a command")
		}
		if err := checkScheduleCommand(payload.Schedule.Command); err != nil {
			return err
		}
		if err := checkScheduleKind(payload.Schedule); err != nil {
			return err
		}
		return checkScheduleUser(payload.Schedule.User)

	case ActionFilePlan:
		return nil

	case ActionFileRead, ActionFileRemove:
		if payload.File == nil || payload.File.Path == "" {
			return fmt.Errorf("the operation %s requires a path", action)
		}
		return checkFilePath(payload.File.Path)

	case ActionFileEnsure, ActionFileRollback:
		if payload.File == nil || payload.File.Path == "" {
			return fmt.Errorf("the operation %s requires a path", action)
		}
		if err := checkFilePath(payload.File.Path); err != nil {
			return err
		}
		if err := filesmodule.ValidateContent(payload.File.Content); err != nil {
			return err
		}
		if _, err := filesmodule.ValidateMode(payload.File.Mode); err != nil {
			return err
		}
		// Clear content and content from the store exclude each other: otherwise it
		// is unknown what really lands in the file.
		if !payload.File.ContentSecret.Empty() {
			if payload.File.Content != "" {
				return fmt.Errorf("the file is to have content or a secret, not both at once")
			}
			if err := payload.File.ContentSecret.Validate(); err != nil {
				return err
			}
		}
		if payload.File.Validator != "" {
			if _, _, err := filesmodule.SelectValidator(payload.File.Path, payload.File.Validator); err != nil {
				return err
			}
		}
		// A version is named only by a return to one, and it names a content by its
		// digest.
		if payload.File.VersionSHA256 != "" {
			if action != ActionFileRollback {
				return fmt.Errorf("only %s names a version to go back to", ActionFileRollback)
			}
			if !validChecksum(payload.File.VersionSHA256) {
				return fmt.Errorf("the version is named by a sha256 digest of 64 hexadecimal characters")
			}
			if payload.File.Content != "" &&
				filesmodule.Fingerprint([]byte(payload.File.Content)) != payload.File.VersionSHA256 {
				return fmt.Errorf("the order names a version and carries content that is not that version")
			}
		}
		// A return to a version has to say which one: without a digest and without
		// content it is an order to write nothing, which is not a return.
		if action == ActionFileRollback && payload.File.VersionSHA256 == "" &&
			payload.File.Content == "" && payload.File.ContentSecret.Empty() {
			return fmt.Errorf("a return to a version requires the digest of that version")
		}
		return nil

	case ActionPackageList:
		return nil

	case ActionSecurityScan, ActionAuditRulesReload:
		return nil

	case ActionMonitoringProbe:
		if payload.Monitoring == nil {
			return fmt.Errorf("the operation %s requires a monitoring payload", action)
		}
		return monitoringmodul.Request{
			Kind: payload.Monitoring.Kind, Target: payload.Monitoring.Target,
			ExpectStatus:   payload.Monitoring.ExpectStatus,
			ExpectBody:     payload.Monitoring.ExpectBody,
			TimeoutSeconds: payload.Monitoring.TimeoutSeconds,
		}.Validate()

	case ActionBackupPlan, ActionBackupRun, ActionBackupVerify, ActionBackupRestore:
		if payload.Backup == nil {
			return fmt.Errorf("the operation %s requires a backup payload", action)
		}
		copyPayload := payload.Backup
		definition := backupmodule.Definition{
			ID: copyPayload.ID, Tool: copyPayload.Tool, Repository: copyPayload.Repository,
			Paths: copyPayload.Paths, Excludes: copyPayload.Excludes, Tags: copyPayload.Tags,
			KeepLast: copyPayload.KeepLast, KeepDaily: copyPayload.KeepDaily,
			KeepWeekly: copyPayload.KeepWeekly, KeepMonthly: copyPayload.KeepMonthly,
			Prune: copyPayload.Prune, Runbook: copyPayload.Runbook,
			Initialize: copyPayload.Initialize,
		}
		if err := definition.Validate(); err != nil {
			return err
		}
		if !copyPayload.PasswordSecret.Empty() {
			if err := copyPayload.PasswordSecret.Validate(); err != nil {
				return err
			}
		}
		variableNames := make([]string, 0, len(copyPayload.EnvSecrets))
		for name, reference := range copyPayload.EnvSecrets {
			variableNames = append(variableNames, name)
			referenceCopy := reference
			if err := referenceCopy.Validate(); err != nil {
				return err
			}
		}
		if err := backupmodule.ValidateEnvironment(variableNames); err != nil {
			return err
		}
		if action == ActionBackupRun && len(copyPayload.Paths) == 0 &&
			copyPayload.Tool != backupmodule.ToolRunbook {
			return fmt.Errorf("a copy requires being told what to back up")
		}
		if action == ActionBackupRestore {
			return backupmodule.ValidateRestore(backupmodule.Restore{
				SnapshotID: copyPayload.SnapshotID, Target: copyPayload.Target,
				Include: copyPayload.Include, Overwrite: copyPayload.Overwrite,
			})
		}
		return nil

	case ActionRepositorySet:
		if payload.Repository == nil {
			return fmt.Errorf("the operation %s requires a repository payload", action)
		}
		repo := payload.Repository
		source := packagestore.Repository{
			ID: repo.ID, Name: repo.Name, URL: repo.URL,
			Suites: repo.Suites, Components: repo.Components,
			Architectures: repo.Architectures, Enabled: repo.Enabled,
			Priority: repo.Priority, Signed: !repo.AllowUnsigned,
			Username: repo.Username,
		}
		if repo.Remove {
			source.URL = ""
		}
		withSecret := !repo.PasswordSecret.Empty()
		if withSecret {
			if err := repo.PasswordSecret.Validate(); err != nil {
				return err
			}
		}
		// The panel knows the manager from the host's inventory, but the order has
		// to be checkable without it, so the fields present name the manager.
		manager := "dnf"
		if len(repo.Suites) > 0 || len(repo.Components) > 0 {
			manager = "apt"
		}
		if err := packagestore.ValidateRepository(source, manager, withSecret); err != nil {
			return err
		}
		if repo.Remove {
			return nil
		}
		// A source we trust has to have something to show for itself.
		if !repo.AllowUnsigned {
			if repo.GPGKey == "" {
				return fmt.Errorf("a source with signature checking requires a public key")
			}
			if _, err := packagestore.KeyFingerprint(repo.GPGKey); err != nil {
				return err
			}
		}
		return nil

	case ActionCertificateScan:
		if payload.Certificate == nil {
			return nil
		}
		if len(payload.Certificate.Targets) > certificates.MaxCertificates {
			return fmt.Errorf("a scan covers at most %d files",
				certificates.MaxCertificates)
		}
		for _, target := range payload.Certificate.Targets {
			if err := certificates.ValidatePath(target.Path); err != nil {
				return err
			}
			if target.KeyPath != "" {
				if err := certificates.ValidatePath(target.KeyPath); err != nil {
					return err
				}
			}
			if err := certificates.ValidateUnit(target.Service); err != nil {
				return err
			}
		}
		return nil

	case ActionCertificateTrustPlan:
		return nil

	case ActionCertificateTrustEnsure:
		if payload.Certificate == nil {
			return fmt.Errorf("the operation %s requires a certificate payload", action)
		}
		if err := certificates.ValidateAnchor(payload.Certificate.AnchorID); err != nil {
			return err
		}
		_, _, err := certificates.ComposeAnchor(payload.Certificate.Certificate, time.Now())
		return err

	case ActionCertificateTrustRemove:
		if payload.Certificate == nil {
			return fmt.Errorf("the operation %s requires a certificate payload", action)
		}
		return certificates.ValidateAnchor(payload.Certificate.AnchorID)

	case ActionCertificatePlan:
		// The plan accepts what a deployment does and names by itself what the host
		// will not accept: a refusal is the content of the plan, not an error.
		return nil

	case ActionCertificateDeploy:
		if payload.Certificate == nil {
			return fmt.Errorf("the operation %s requires a certificate payload", action)
		}
		cert := payload.Certificate
		if err := certificates.ValidatePath(cert.Path); err != nil {
			return err
		}
		if cert.Certificate == "" {
			return fmt.Errorf("a deployment requires the content of the certificate")
		}
		// We check the material here with the same code the host will use: an order
		// with a broken chain falls out at ordering time rather than after approval
		parsed, err := certificates.ParsePEM([]byte(cert.Certificate))
		if err != nil {
			return err
		}
		if err := certificates.CheckChain(parsed); err != nil {
			return err
		}
		if !cert.KeySecret.Empty() {
			if cert.KeyPath == "" {
				return fmt.Errorf("a key from the store requires the path it is to land at")
			}
			if err := cert.KeySecret.Validate(); err != nil {
				return err
			}
		}
		if cert.KeyPath != "" {
			if err := certificates.ValidatePath(cert.KeyPath); err != nil {
				return err
			}
		}
		if err := certificates.ValidateUnit(cert.ReloadUnit); err != nil {
			return err
		}
		return certificates.ValidateTarget(cert.ProbeTarget)

	case ActionCertificateRenew:
		if payload.Certificate == nil {
			return fmt.Errorf("the operation %s requires a certificate payload", action)
		}
		// The request is named by an identifier or by a file path.
		if payload.Certificate.Request == "" {
			if payload.Certificate.Path == "" {
				return fmt.Errorf("a renewal requires a request identifier or a certificate path")
			}
			if err := certificates.ValidatePath(payload.Certificate.Path); err != nil {
				return err
			}
		} else if err := certificates.ValidateRequest(payload.Certificate.Request); err != nil {
			return err
		}
		if err := certificates.ValidateUnit(payload.Certificate.ReloadUnit); err != nil {
			return err
		}
		return certificates.ValidateTarget(payload.Certificate.ProbeTarget)

	case ActionSELinuxModeSet:
		if payload.Security == nil {
			return fmt.Errorf("the operation %s requires a security payload", action)
		}
		return security.ValidateMode(payload.Security.Mode)

	case ActionSecurityRemediate:
		// The composite is never one task on one host: its steps are the tasks.
		return fmt.Errorf("the operation %s is a fleet remediation: it is ordered from the "+
			"security view as a campaign of per-host plans, not as a task on one host", action)

	case ActionSystemHostnameSet:
		if payload.Hostname == nil {
			return fmt.Errorf("the operation %s requires a hostname payload", action)
		}
		if err := hostname.Validate(payload.Hostname.Hostname); err != nil {
			return err
		}
		return hostname.ValidatePretty(payload.Hostname.Pretty)

	case ActionSystemShutdown:
		if payload.Power == nil {
			return fmt.Errorf("the operation %s requires a power payload", action)
		}
		switch payload.Power.Mode {
		case "", power.ModePoweroff, power.ModeHalt:
		default:
			return fmt.Errorf("unsupported shutdown mode %q", payload.Power.Mode)
		}
		if err := power.ValidateDelay(payload.Power.DelaySeconds); err != nil {
			return err
		}
		return power.ValidateShutdownReason(payload.Power.Reason)

	case ActionTimeSyncTest:
		if payload.Time == nil {
			return nil
		}
		if len(payload.Time.Probe) > hosttime.ServerLimit {
			return fmt.Errorf("a test covers at most %d servers", hosttime.ServerLimit)
		}
		for _, server := range payload.Time.Probe {
			if err := hosttime.ValidateServer(server); err != nil {
				return err
			}
		}
		return nil

	case ActionTimePlan:
		// The plan accepts the same thing a change does and names by itself what the
		// host will not accept: a refusal is the content of the plan, not an error
		return nil

	case ActionTimeConfigApply:
		if payload.Time == nil {
			return fmt.Errorf("the operation %s requires a time payload", action)
		}
		return hosttime.ValidateServers(payload.Time.Servers)

	case ActionTimezoneSet:
		if payload.Time == nil {
			return fmt.Errorf("the operation %s requires a time payload", action)
		}
		return hosttime.ValidateZone(payload.Time.Timezone)

	case ActionSysctlPlan:
		if payload.Kernel != nil {
			for _, key := range payload.Kernel.Keys {
				if err := kernel.ValidateKey(key); err != nil {
					return err
				}
			}
		}
		return nil

	case ActionSysctlEnsure:
		if payload.Kernel == nil || len(payload.Kernel.Settings) == 0 {
			return fmt.Errorf("the operation %s requires settings", action)
		}
		if len(payload.Kernel.Settings) > 50 {
			return fmt.Errorf("one operation covers at most 50 settings")
		}
		_, err := kernel.ComposeSysctlFile(payload.Kernel.Settings)
		return err

	case ActionKernelModulePlan:
		// The plan accepts the same thing a change does and names by itself what the
		// host will not accept: a refusal is the content of the plan, not an error
		return nil

	case ActionKernelModuleLoad, ActionKernelModuleBlacklist:
		if payload.Kernel == nil || payload.Kernel.Module == "" {
			return fmt.Errorf("the operation %s requires a module name", action)
		}
		return kernel.ValidateModule(payload.Kernel.Module)

	case ActionSSHConfigPlan:
		return nil

	case ActionSSHConfigApply:
		if payload.SSH == nil {
			return fmt.Errorf("the operation %s requires an ssh payload", action)
		}
		return sshmodule.Validate(sshmodule.Settings{
			Port:                   payload.SSH.Port,
			PermitRootLogin:        payload.SSH.PermitRootLogin,
			PasswordAuthentication: payload.SSH.PasswordAuthentication,
			PubkeyAuthentication:   payload.SSH.PubkeyAuthentication,
			KbdInteractive:         payload.SSH.KbdInteractive,
			MaxAuthTries:           payload.SSH.MaxAuthTries,
			AllowUsers:             payload.SSH.AllowUsers,
			AllowGroups:            payload.SSH.AllowGroups,
			DenyUsers:              payload.SSH.DenyUsers,
		})

	case ActionSSHHostKeyRotate:
		if payload.SSH == nil || payload.SSH.KeyType == "" {
			return fmt.Errorf("replacing a key requires its type")
		}
		switch payload.SSH.KeyType {
		case "ed25519", "rsa", "ecdsa":
			return nil
		}
		return fmt.Errorf("the panel replaces ed25519, rsa or ecdsa keys, not %q", payload.SSH.KeyType)

	case ActionStoragePlan:
		// A plan is a read and needs nothing but a kind the host knows.
		if payload.Storage != nil && payload.Storage.Plan != "" {
			// Building or tearing down an array is outside the panel on purpose, so it
			// gets that sentence and its own code rather than "no such plan".
			if refusal := storage.ArrayLifecycleRefusalFor(payload.Storage.Plan); refusal != nil {
				return &RefusalError{Code: refusal.Code, Err: refusal}
			}
			if !storage.KnownPlanKind(payload.Storage.Plan) {
				return fmt.Errorf("the panel computes no plan called %q", payload.Storage.Plan)
			}
		}
		return nil

	case ActionStorageSmartRead:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		return storage.ValidateSmartDevice(payload.Storage.Device)

	case ActionMountEnsure:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		if err := storage.ValidateSource(payload.Storage.Source); err != nil {
			return err
		}
		if err := storage.ValidateTarget(payload.Storage.Target); err != nil {
			return err
		}
		return storage.ValidateOptions(payload.Storage.Options, payload.Storage.FSType)

	case ActionMountRemove:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		return storage.ValidateTarget(payload.Storage.Target)

	case ActionFilesystemCheck:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		return storage.ValidateSource(payload.Storage.Device)

	case ActionLVMExtend:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		_, err := storage.LVExtendArguments(payload.Storage.Device, payload.Storage.Size, true)
		return err

	case ActionFilesystemResize:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		return storage.ValidateSource(payload.Storage.Device)

	case ActionFilesystemCreate:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		// A destructive operation has to know what it aims at: the path alone is not
		// enough, because /dev/sdX points at a different disk after a reboot.
		if payload.Storage.ExpectedByID == "" {
			return &RefusalError{Code: "stable_identity_required",
				Err: fmt.Errorf("formatting requires the stable identity of the device (its /dev/disk/by-id link); the size is not an identity")}
		}
		_, err := storage.FormatArguments(payload.Storage.Device,
			payload.Storage.FSType, payload.Storage.Label)
		return err

	case ActionDiskWipe:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		if payload.Storage.ExpectedByID == "" {
			return &RefusalError{Code: "stable_identity_required",
				Err: fmt.Errorf("wiping requires the stable identity of the device (its /dev/disk/by-id link); the size is not an identity")}
		}
		_, err := storage.WipeArguments(payload.Storage.Device)
		return err

	case ActionRAIDMemberFail, ActionRAIDMemberRemove, ActionRAIDMemberAdd:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		verb := storage.RAIDFail
		switch action {
		case ActionRAIDMemberRemove:
			verb = storage.RAIDRemove
		case ActionRAIDMemberAdd:
			verb = storage.RAIDAdd
		}
		if _, err := storage.RAIDMemberArguments(payload.Storage.Array,
			payload.Storage.Device, verb); err != nil {
			return err
		}
		// An array is named by the UUID of its superblock.
		if payload.Storage.ExpectedArrayUUID == "" {
			return &RefusalError{Code: storage.CodeArrayUnknown,
				Err: fmt.Errorf("an array operation requires the UUID of the array; the path /dev/mdN is the order the kernel assembled them in")}
		}
		if payload.Storage.ExpectedByID == "" {
			return &RefusalError{Code: "stable_identity_required",
				Err: fmt.Errorf("an array member is named by its /dev/disk/by-id link; a path in /dev points at another device after a reboot")}
		}
		return nil

	case ActionLVMVolumeCreate:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		if _, err := storage.LVCreateArguments(payload.Storage.Group,
			payload.Storage.Volume, payload.Storage.Size); err != nil {
			return err
		}
		return requireGroupUUID(payload.Storage)

	case ActionLVMSnapshotCreate:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		if _, err := storage.SnapshotArguments(payload.Storage.Device,
			payload.Storage.Volume, payload.Storage.Size); err != nil {
			return err
		}
		return requireVolumeUUID(payload.Storage)

	case ActionLVMSnapshotRemove:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		if _, err := storage.LVRemoveArguments(payload.Storage.Device); err != nil {
			return err
		}
		return requireVolumeUUID(payload.Storage)

	case ActionLVMVolumeRemove:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		if _, err := storage.LVRemoveArguments(payload.Storage.Device); err != nil {
			return err
		}
		// Deleting a volume destroys what was on it, so it binds to the same two
		// identities a format does: the volume's own UUID and the device-mapper link
		if payload.Storage.ExpectedByID == "" {
			return &RefusalError{Code: "stable_identity_required",
				Err: fmt.Errorf("deleting a volume requires its stable identity (its /dev/disk/by-id link); a volume path is a name another volume can carry tomorrow")}
		}
		return requireVolumeUUID(payload.Storage)

	case ActionLVMGroupExtend:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		if _, err := storage.VGExtendArguments(payload.Storage.Group,
			payload.Storage.Device); err != nil {
			return err
		}
		// Adding a disk to a group writes an LVM label over it: the same loss as a
		// format, so it asks for the same stable identity.
		if payload.Storage.ExpectedByID == "" {
			return &RefusalError{Code: "stable_identity_required",
				Err: fmt.Errorf("adding a disk to a group requires the stable identity of the disk (its /dev/disk/by-id link); the size is not an identity")}
		}
		return requireGroupUUID(payload.Storage)

	case ActionFirewallPlan:
		return nil

	case ActionFirewallRulesetRestore:
		if payload.Firewall == nil || payload.Firewall.RollbackID == "" {
			return fmt.Errorf("a restore requires the identifier of a plan")
		}
		return nil

	case ActionFirewallRuleEnsure:
		if payload.Firewall == nil {
			return fmt.Errorf("the operation %s requires a firewall payload", action)
		}
		return firewall.RuleSpec{
			ID: payload.Firewall.RuleID, Chain: payload.Firewall.Chain,
			Action: payload.Firewall.Action, Protocol: payload.Firewall.Protocol,
			Ports: payload.Firewall.Ports, Sources: payload.Firewall.Sources,
			Interface: payload.Firewall.Interface, Comment: payload.Firewall.Comment,
		}.Validate()

	case ActionFirewallRuleRemove:
		if payload.Firewall == nil || payload.Firewall.RuleID == "" {
			return fmt.Errorf("a removal requires the name of the rule")
		}
		return nil

	case ActionFirewallZonePort:
		if payload.Firewall == nil {
			return fmt.Errorf("the operation %s requires a firewall payload", action)
		}
		_, err := firewall.PortArguments(payload.Firewall.Zone,
			firstPort(payload.Firewall.Ports), payload.Firewall.Protocol, payload.Firewall.Enable)
		return err

	case ActionFirewallZoneService:
		if payload.Firewall == nil {
			return fmt.Errorf("the operation %s requires a firewall payload", action)
		}
		_, err := firewall.ServiceArguments(payload.Firewall.Zone,
			payload.Firewall.Service, payload.Firewall.Enable)
		return err

	case ActionDNSResolveTest:
		if payload.DNS == nil || len(payload.DNS.Names) == 0 {
			return fmt.Errorf("a test requires at least one name")
		}
		if len(payload.DNS.Names) > 20 {
			return fmt.Errorf("a test covers at most 20 names at once")
		}
		for _, name := range payload.DNS.Names {
			if !dns.ValidTestName(name) {
				return fmt.Errorf("invalid name %q", name)
			}
		}
		return nil

	case ActionDNSPlan:
		// The plan accepts the same thing a change does and names by itself what the
		// host will not accept: a refusal is the content of the plan, not an error
		return nil

	case ActionDNSHostApply:
		if payload.DNS == nil {
			return fmt.Errorf("the operation %s requires a dns payload", action)
		}
		if !interfaceName.MatchString(payload.DNS.Interface) {
			return fmt.Errorf("invalid interface name %q", payload.DNS.Interface)
		}
		// A resolver without a server resolves nothing, and a host without
		// name resolution loses the directory, Kerberos and logging in.
		if len(payload.DNS.Servers) == 0 {
			return fmt.Errorf("a resolver change requires at least one server")
		}
		for _, server := range payload.DNS.Servers {
			if err := network.ValidateIPAddress(server); err != nil {
				return fmt.Errorf("DNS server: %w", err)
			}
		}
		for _, domain := range payload.DNS.SearchDomains {
			if !dns.ValidTestName(domain) {
				return fmt.Errorf("invalid search domain %q", domain)
			}
		}
		return nil

	case ActionNetworkPlan:
		// A plan of a layered change is checked for shape here as well: the panel
		// refuses a VLAN identifier of 5000 rather than sending it to the fleet.
		if payload.Network != nil && payload.Network.Link != nil {
			return network.ValidateLinkSpec(*payload.Network.Link)
		}
		if payload.Network != nil && payload.Network.LinkRemove {
			return network.ValidateInterfaceName(payload.Network.Interface)
		}
		return nil

	case ActionNetworkRollback:
		if payload.Network == nil || payload.Network.RollbackID == "" {
			return fmt.Errorf("a rollback requires the identifier of a plan")
		}
		return nil

	case ActionNetworkMTUSet, ActionNetworkRouteEnsure, ActionNetworkProfileApply,
		ActionNetworkLinkRemove:
		if payload.Network == nil {
			return fmt.Errorf("the operation %s requires a network payload", action)
		}
		if !interfaceName.MatchString(payload.Network.Interface) {
			return fmt.Errorf("invalid interface name %q", payload.Network.Interface)
		}
		return checkNetworkChange(action, payload.Network)

	// A layered order names the layer in the description, and the interface field
	// repeats it: the panel and the host then work on one and the same name.
	case ActionNetworkLinkApply:
		if payload.Network == nil || payload.Network.Link == nil {
			return fmt.Errorf("the operation %s requires the description of the layer", action)
		}
		return checkNetworkChange(action, payload.Network)

	case ActionProcessList:
		if payload.ProcessList == nil {
			return fmt.Errorf("the operation %s requires a process_list payload", action)
		}
		switch payload.ProcessList.SortBy {
		case "", "rss", "cpu", "pid", "started":
		default:
			return fmt.Errorf("unsupported sorting %q", payload.ProcessList.SortBy)
		}
		if payload.ProcessList.Limit > 500 {
			return fmt.Errorf("the process limit must not exceed 500")
		}
		return nil

	case ActionProcessSignal:
		if payload.ProcessSignal == nil {
			return fmt.Errorf("the operation %s requires a process_signal payload", action)
		}
		if payload.ProcessSignal.PID <= 1 {
			// PID 1 is the init system; zero and negative values mean process
			// groups in the kernel rather than one process.
			return fmt.Errorf("invalid PID %d", payload.ProcessSignal.PID)
		}
		switch payload.ProcessSignal.Signal {
		case "TERM", "KILL", "HUP":
		default:
			return fmt.Errorf("unsupported signal %q", payload.ProcessSignal.Signal)
		}
		// Without the start time the signal could hit a process that took
		// over the PID.
		if payload.ProcessSignal.ExpectedStart == 0 {
			return fmt.Errorf("a signal requires the start time of the process")
		}
		return nil

	case ActionReadLogFile:
		if payload.LogFile == nil {
			return fmt.Errorf("the operation %s requires a logfile payload", action)
		}
		return validateLogPath(payload.LogFile.Path)

	case ActionUnitEnableSet, ActionUnitMaskSet:
		if payload.UnitToggle == nil {
			return fmt.Errorf("the operation %s requires a unit_toggle payload", action)
		}
		return validateUnitName(payload.UnitToggle.Unit)

	case ActionUnitStatus:
		if payload.UnitStatus == nil {
			return fmt.Errorf("the operation %s requires a unit_status payload", action)
		}
		// The full list is ordered explicitly; an empty list without that
		// order is a mistake in the call, not a request for everything.
		if payload.UnitStatus.All {
			if len(payload.UnitStatus.Units) > 0 {
				return fmt.Errorf("the full list of units does not take a list of names")
			}
			return nil
		}
		if len(payload.UnitStatus.Units) == 0 {
			return fmt.Errorf("the operation %s requires a list of units", action)
		}
		if len(payload.UnitStatus.Units) > 50 {
			return fmt.Errorf("the list of units is too long")
		}
		// A detail read starts several processes per unit and reads files: it serves
		// one open row in the panel, not a sweep of the host.
		if payload.UnitStatus.Detail {
			if len(payload.UnitStatus.Units) > maxDetailUnits {
				return fmt.Errorf("a detail read takes at most %d units", maxDetailUnits)
			}
			for _, unit := range payload.UnitStatus.Units {
				if err := validateUnitName(unit); err != nil {
					return err
				}
			}
		}
		return nil

	case ActionSystemReboot:
		if payload.Reboot == nil {
			return fmt.Errorf("the operation %s requires a reboot payload", action)
		}
		if payload.Reboot.DelaySeconds > 3600 {
			return fmt.Errorf("the reboot delay must not exceed an hour")
		}
		return nil

	case ActionPackageUpgrade:
		if payload.PackageUpgrade == nil {
			return fmt.Errorf("the operation %s requires a package_upgrade payload", action)
		}
		return validatePackageNames(payload.PackageUpgrade.Packages)

	case ActionAgentUpgrade:
		if payload.AgentUpgrade == nil {
			return fmt.Errorf("the operation %s requires an agent_upgrade payload", action)
		}
		if !validAgentVersion(payload.AgentUpgrade.TargetVersion) {
			return fmt.Errorf("the target version %q is not a package version",
				payload.AgentUpgrade.TargetVersion)
		}
		if version := payload.AgentUpgrade.RollbackVersion; version != "" {
			if !validAgentVersion(version) {
				return fmt.Errorf("the rollback version %q is not a package version", version)
			}
			// A return to the version being installed is no return at all, and the host
			// would keep an artefact of it under the name of a way back.
			if version == payload.AgentUpgrade.TargetVersion {
				return fmt.Errorf("the rollback version is the version being installed (%s)", version)
			}
		}
		if sum := payload.AgentUpgrade.PackageSHA256; sum != "" && !validChecksum(sum) {
			return fmt.Errorf("the package checksum is not a hexadecimal SHA-256")
		}
		if signer := payload.AgentUpgrade.PackageSigner; signer != "" {
			if !validSignerIdentity(signer) {
				return fmt.Errorf("the package signer %q is neither a key fingerprint nor a long key ID",
					signer)
			}
			// A named key without a digest would have no file to belong to: the host
			// would install whatever the repository resolved and check its signature.
			if payload.AgentUpgrade.PackageSHA256 == "" {
				return fmt.Errorf("a package signer requires the package checksum of the release")
			}
		}
		// Releasing the kept artefact is the end of a replacement, not the start of
		// one: it installs nothing and prepares no return.
		if payload.AgentUpgrade.ReleaseRollback && payload.AgentUpgrade.RollbackVersion != "" {
			return fmt.Errorf("an order releasing the kept artefact does not also prepare a return")
		}
		// The target has to speak a protocol this panel speaks.
		if err := buildinfo.CheckProtocol(payload.AgentUpgrade.TargetVersion); err != nil {
			return &RefusalError{Code: RefusalProtocolIncompatible, Err: err}
		}
		return nil

	case ActionFollowJournal:
		if payload.Journal == nil {
			return fmt.Errorf("the operation %s requires a journal payload", action)
		}
		if payload.Journal.FollowSeconds > maxFollowSeconds {
			return fmt.Errorf("a live view must not last longer than %d s", maxFollowSeconds)
		}
		// A live view takes the narrowing a read takes, so watching a unit and
		// reading it are the same question asked twice.
		if payload.Journal.Until != "" {
			return fmt.Errorf("a live view has no end date; it ends by its own time limit, so until belongs to journal.read")
		}
		return validateJournalPayload(payload.Journal)

	case ActionReadJournal:
		if payload.Journal == nil {
			return fmt.Errorf("the operation %s requires a journal payload", action)
		}
		if payload.Journal.Lines == 0 || payload.Journal.Lines > 10000 {
			return fmt.Errorf("the number of lines has to be in the range 1-10000")
		}
		return validateJournalPayload(payload.Journal)
	default:
		if payload.Unit == nil {
			return fmt.Errorf("the operation %s requires a unit payload", action)
		}
		if strings.TrimSpace(payload.Unit.Unit) == "" {
			return fmt.Errorf("the unit name is empty")
		}
	}
	return nil
}

// packageNamePattern matches Debian and RPM package names.
var localUserNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)

// protectedAccounts are never deleted through the panel: the superuser, the
// accounts the agent and the helper run under, and nobody.
var protectedAccounts = map[string]bool{
	"root": true, "flotestro": true, "flotestro-agent": true, "flotestro-relay": true,
	"nobody": true,
}

func protectedAccount(name string) bool {
	return protectedAccounts[name]
}

// requireGroupUUID insists that an order acting inside a volume group names
// the group by its UUID.
func requireGroupUUID(payload *StoragePayload) error {
	if payload.ExpectedGroupUUID == "" {
		return &RefusalError{Code: storage.CodeVolumeUnknown,
			Err: fmt.Errorf("an operation inside a volume group requires the UUID of the group; the name alone is a label")}
	}
	return nil
}

// requireVolumeUUID insists that an order acting on a logical volume names
// it by its UUID, for the same reason.
func requireVolumeUUID(payload *StoragePayload) error {
	if payload.ExpectedVolumeUUID == "" {
		return &RefusalError{Code: storage.CodeVolumeUnknown,
			Err: fmt.Errorf("an operation on a logical volume requires the UUID of the volume; the path is a name another volume can carry tomorrow")}
	}
	return nil
}

// validateExpiryDate accepts a calendar date the way chage takes it.
func validateExpiryDate(value string) error {
	if _, err := time.Parse("2006-01-02", value); err != nil {
		return fmt.Errorf("invalid expiry date %q; expected YYYY-MM-DD", value)
	}
	return nil
}

// RefusalAccountWithoutCredential refuses a create that gives the account
// no way in without saying so.
const RefusalAccountWithoutCredential = "account_without_credential"

// fingerprintPattern is the form sshd and ssh-keygen print: SHA256: and
// the digest in base64 without padding.
var fingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// validateLocalUserKeyFields checks the fields of the key operations of
// chapter 14.
func validateLocalUserKeyFields(action ActionType, user *LocalUserPayload) error {
	if len(user.Keys) > 0 && action != ActionLocalSSHKeysAdd {
		return fmt.Errorf("the operation %s takes no keys to add; use %s", action, ActionLocalSSHKeysAdd)
	}
	if len(user.Fingerprints) > 0 && action != ActionLocalSSHKeysRemove {
		return fmt.Errorf("the operation %s takes no fingerprints to remove; use %s", action, ActionLocalSSHKeysRemove)
	}
	if user.IgnoreMissing && action != ActionLocalSSHKeysRemove {
		return fmt.Errorf("ignore_missing belongs to %s", ActionLocalSSHKeysRemove)
	}
	if len(user.ExpectedFingerprints) > 0 && action != ActionLocalSSHKeysReplaceAll && action != ActionLocalSSHKeysSet {
		return fmt.Errorf("expected_fingerprints belongs to %s", ActionLocalSSHKeysReplaceAll)
	}
	if user.AllowLockout && action != ActionLocalSSHKeysRemove &&
		action != ActionLocalSSHKeysReplaceAll && action != ActionLocalSSHKeysSet {
		return fmt.Errorf("allow_lockout belongs to a key removal or a replace")
	}
	if user.ManagedFile && action != ActionLocalSSHKeysAdd && action != ActionLocalSSHKeysRemove &&
		action != ActionLocalSSHKeysReplaceAll && action != ActionLocalSSHKeysSet && action != ActionLocalUserCreate {
		return fmt.Errorf("managed_file belongs to a key operation")
	}
	if user.Inactive && action != ActionLocalUserCreate {
		return fmt.Errorf("inactive belongs to %s", ActionLocalUserCreate)
	}
	if len(user.SSHKeys) > 0 && action != ActionLocalUserCreate &&
		action != ActionLocalSSHKeysReplaceAll && action != ActionLocalSSHKeysSet {
		return fmt.Errorf("the operation %s takes no full key list", action)
	}

	switch action {
	case ActionLocalSSHKeysAdd:
		if len(user.Keys) == 0 {
			return fmt.Errorf("an add names at least one key")
		}
		if len(user.Keys) > 64 {
			return fmt.Errorf("too many keys: %d", len(user.Keys))
		}
		for _, key := range user.Keys {
			if err := validatePublicKeyShape(key.PublicKey); err != nil {
				return err
			}
			if strings.ContainsAny(key.Comment, "\n\r") {
				return fmt.Errorf("a key comment must not contain a newline")
			}
		}
	case ActionLocalSSHKeysRemove:
		if len(user.Fingerprints) == 0 {
			return fmt.Errorf("a removal names at least one fingerprint")
		}
		if len(user.Fingerprints) > 64 {
			return fmt.Errorf("too many fingerprints: %d", len(user.Fingerprints))
		}
		for _, fingerprint := range user.Fingerprints {
			if !fingerprintPattern.MatchString(strings.TrimSpace(fingerprint)) {
				return fmt.Errorf("invalid fingerprint %q; expected SHA256:<digest>", fingerprint)
			}
		}
	case ActionLocalSSHKeysReplaceAll, ActionLocalSSHKeysSet:
		// The replace is bound to the list the operator saw.
		if action == ActionLocalSSHKeysReplaceAll && user.ExpectedFingerprints == nil {
			return fmt.Errorf("a replace carries expected_fingerprints: the keys the account has now, an empty list for none")
		}
		if len(user.ExpectedFingerprints) > 256 {
			return fmt.Errorf("too many expected fingerprints: %d", len(user.ExpectedFingerprints))
		}
		for _, fingerprint := range user.ExpectedFingerprints {
			if !fingerprintPattern.MatchString(strings.TrimSpace(fingerprint)) {
				return fmt.Errorf("invalid expected fingerprint %q", fingerprint)
			}
		}
	case ActionLocalUserCreate:
		// An account with no key has no way in: the panel sets no password.
		if len(user.SSHKeys) == 0 && !user.Inactive {
			return &RefusalError{Code: RefusalAccountWithoutCredential, Err: fmt.Errorf(
				"the account would have no key and no password, so nobody could log in; " +
					"give it a key or say inactive: true to create it without a way in")}
		}
		if user.Inactive && len(user.SSHKeys) > 0 {
			return fmt.Errorf("an inactive account takes no keys; leave the list empty or drop inactive")
		}
	}
	return nil
}

// validatePublicKeyShape rejects material that is not a public key. The panel
// does not accept a private key even by an operator's mistake.
func validatePublicKeyShape(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("empty SSH key")
	}
	if strings.ContainsAny(trimmed, "\n\r") {
		return fmt.Errorf("an SSH key must not contain a newline")
	}
	if strings.Contains(trimmed, "PRIVATE KEY") {
		return fmt.Errorf("a private key was passed; the panel accepts public keys only")
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return fmt.Errorf("an SSH key has to have the form \"type material [comment]\"")
	}
	if !allowedKeyTypes[fields[0]] {
		return fmt.Errorf("unsupported key type %q", fields[0])
	}
	if len(trimmed) > 16384 {
		return fmt.Errorf("the SSH key is too long")
	}
	return nil
}

// allowedKeyTypes excludes withdrawn types, including ssh-dss and ssh-rsa
// with SHA-1.
var allowedKeyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// debconfQuestionPattern matches the names of configuration questions, for
// example grub-pc/install_devices.
var debconfQuestionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9._+-]+)+$`)

// debconfTypePattern limits the types to those that make sense in an answer
// passed from the panel.
var debconfTypePattern = regexp.MustCompile(`^(select|multiselect|boolean|string|password|note)$`)

// domainPattern rejects names that cannot be a DNS domain.
var domainPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)

// servicePrincipalPattern is service/host. fqdn with an optional realm: the
// shape ipa-getkeytab takes.
var servicePrincipalPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}/[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+(@[A-Za-z0-9.-]+)?$`)

// ValidateServicePrincipal checks that a principal names a service of a host
// and not the host itself: the host's own keytab is replaced by a re-join.
func ValidateServicePrincipal(principal string) error {
	if !servicePrincipalPattern.MatchString(principal) {
		return fmt.Errorf("invalid service principal %q: expected service/host.example.test", principal)
	}
	if strings.HasPrefix(strings.ToLower(principal), "host/") {
		return fmt.Errorf("the principal %s is the host's own; its keytab is replaced by a re-join, not a renewal", principal)
	}
	return nil
}

var packageNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._-]*$`)

func validatePackageNames(names []string) error {
	if len(names) > 500 {
		return fmt.Errorf("the list of packages is too long")
	}
	for _, name := range names {
		if !packageNamePattern.MatchString(name) {
			return fmt.Errorf("invalid package name %q", name)
		}
	}
	return nil
}

// withoutEmpty removes sub-payloads that carry no content.
func (p Payload) withoutEmpty() Payload {
	value := reflect.ValueOf(&p).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() != reflect.Pointer || field.IsNil() {
			continue
		}
		zero := reflect.New(field.Type().Elem())
		if reflect.DeepEqual(field.Interface(), zero.Interface()) {
			field.Set(reflect.Zero(field.Type()))
		}
	}
	return p
}

// PayloadHashVersion is the version of the payload hash scheme the panel
// issues.
const PayloadHashVersion = 2

// PayloadHash computes the plan hash of the scheme the panel issues,
// PayloadHashVersion.
func PayloadHash(action ActionType, version int, payload Payload) ([]byte, error) {
	return PayloadHashOfScheme(PayloadHashVersion, action, version, payload)
}

// PayloadHashSchemes lists the scheme versions the agent recognises, the
// one the panel issues first.
var PayloadHashSchemes = []int{PayloadHashVersion, 1}

// PayloadHashOfScheme computes the plan hash of one scheme version. Version 1
// hashes "<type>\n<version>\n<encoding/json text>".
func PayloadHashOfScheme(scheme int, action ActionType, version int, payload Payload) ([]byte, error) {
	switch scheme {
	case 1:
		encoded, err := json.Marshal(payload.withoutEmpty())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(fmt.Appendf(nil, "%s\n%d\n%s", action, version, encoded))
		return sum[:], nil
	case 2:
		encoded, err := jcs.Canonical(payload.withoutEmpty())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(fmt.Appendf(nil, "flotestro-payload-hash/%d\n%s\n%d\n%s",
			scheme, action, version, encoded))
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unknown payload hash scheme %d", scheme)
	}
}
