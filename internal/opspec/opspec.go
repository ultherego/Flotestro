// Package opspec defines the typed operations shared by the control plane,
// the agent and the helper. Outside the standard library it reaches only for
// the module packages, and only for their validation: thanks to that an order
// rejected on the host is rejected already when it is placed, by the same code
// and with the same reason. The plan hash is computed by one implementation on
// both sides.
package opspec

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	backupmodule "github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/dns"
	"github.com/ultherego/flotestro/internal/modules/docker"
	filesmodule "github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/modules/kernel"
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
	ActionReadJournal ActionType = "journal.read"
	// Reading a log file is limited by the host administrator's allowlist.
	ActionReadLogFile ActionType = "logfile.read"
	// A live view of the journal. The stream is short-lived and bounded from
	// above: by time, by rate and by the number of lines.
	ActionFollowJournal ActionType = "journal.follow"

	// Process diagnostics. A snapshot is taken on request and has an upper
	// bound; a continuous stream of metrics belongs to Prometheus, not to the
	// panel.
	ActionProcessList   ActionType = "process.list"
	ActionProcessSignal ActionType = "process.signal"

	// Scheduled jobs. A managed entry describes the target state, not a
	// command to run once.
	ActionNetworkPlan         ActionType = "network.plan"
	ActionNetworkProfileApply ActionType = "network.profile.apply"
	ActionNetworkRouteEnsure  ActionType = "network.route.ensure"
	ActionNetworkMTUSet       ActionType = "network.mtu.set"
	ActionNetworkRollback     ActionType = "network.rollback"

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

	ActionSSHConfigPlan    ActionType = "ssh.config.plan"
	ActionSSHConfigApply   ActionType = "ssh.config.apply"
	ActionSSHHostKeyRotate ActionType = "ssh.hostkey.rotate"

	// Security. A scan collects facts from the host; the compliance verdict
	// is formed in the panel, because that is where the checks are
	// versioned. Remediation is not a separate host operation - each one maps
	// onto a typed operation of the module responsible for that thing.
	ActionSecurityScan   ActionType = "security.scan"
	ActionSELinuxModeSet ActionType = "selinux.mode.set"
	// Reloading the audit rules is a separate operation, because a rule that
	// is written and not loaded records nothing, and the auditd unit on some
	// distributions refuses a manual restart.
	ActionAuditRulesReload ActionType = "security.audit.reload"

	// Certificates. The scan looks only at the files it is pointed at: a
	// panel that walks the whole filesystem finds the trust store instead of
	// service certificates. The private key does not travel in the order -
	// the payload carries a reference to the store, and the host reaches for
	// the value only at execution time.
	ActionCertificateScan ActionType = "certificate.scan"
	ActionCertificatePlan ActionType = "certificate.plan"
	// Rotating the authority is a sequence of states, not one change: the
	// host first trusts the old and the new authority at once, then gets a
	// new certificate, and the old authority disappears at the end - and only
	// where nothing is signed by it any more.
	ActionCertificateTrustPlan   ActionType = "certificate.trust.plan"
	ActionCertificateTrustEnsure ActionType = "certificate.trust.ensure"
	ActionCertificateTrustRemove ActionType = "certificate.trust.remove"
	ActionCertificateDeploy      ActionType = "certificate.deploy"
	// A renewal is a separate operation, because the host does it with its
	// own daemon: the panel asks certmonger for a new certificate instead of
	// handing it the content.
	ActionCertificateRenew ActionType = "certificate.renew"

	// Time and synchronisation. The test changes nothing on the host, but it
	// leaves it with a query to the time server - and it is the server that
	// answers whether the new source works at all, before the panel takes a
	// working one away from the host.
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

	// The full package list is fetched on request rather than in every
	// inventory cycle: it is a few hundred kilobytes per host and changes
	// rarely. The inventory carries the digest of the list itself, so the
	// panel knows when its copy stopped describing the host.
	ActionPackageList ActionType = "packages.list"

	ActionPackagePlan    ActionType = "packages.plan"
	ActionPackageUpgrade ActionType = "packages.upgrade"
	// A repair unblocks package operations on the host: it sets the
	// operator's answers to configuration questions and finishes configuring
	// the packages.
	ActionPackageRepair ActionType = "packages.repair"

	// The full package lifecycle. An install adds software, a removal takes
	// it away together with its dependencies, a hold freezes the version.
	ActionPackageInstall ActionType = "packages.install"
	ActionPackageRemove  ActionType = "packages.remove"
	ActionPackageHoldSet ActionType = "packages.hold.set"
	// Package sources. Adding a source installs nothing today, but it decides
	// whose packages the host will accept tomorrow - together with their
	// scripts, which run as root. Hence the critical risk and its own
	// permission.
	ActionRepositorySet ActionType = "packages.repository.set"
	// ActionAgentUpgrade replaces the agent itself. An ordinary package
	// upgrade deliberately skips flotestro-agent - otherwise the host would
	// cut itself off from management in the middle of a transaction it is
	// running. This operation does it knowingly and is settled differently:
	// success is the host coming back with the expected version, not the exit
	// code of the package manager.
	ActionAgentUpgrade ActionType = "agent.upgrade"

	// Backup. The data does not flow through the panel: the host talks to the
	// repository directly, and the panel sees metadata - when a copy
	// succeeded, how much room it takes and what it covers. A restore is a
	// separate operation of the highest risk, because it unpacks old state
	// onto a running system.
	// A probe answers the question central monitoring cannot ask: what does
	// this host see. Silencing an alert is not an operation on the host and
	// does not go this way - it changes what the alerting system thinks about
	// the host, not the host itself.
	ActionMonitoringProbe ActionType = "monitoring.probe.run"

	ActionBackupPlan    ActionType = "backup.plan"
	ActionBackupRun     ActionType = "backup.run"
	ActionBackupVerify  ActionType = "backup.verify"
	ActionBackupRestore ActionType = "backup.restore"

	ActionSystemReboot ActionType = "system.reboot"
	// Shutting a host down is an operation the panel cannot bring it back
	// from: powering it on needs out-of-band access. That is why it is a
	// separate operation with its own permission rather than a mode of
	// reboot.
	ActionSystemShutdown ActionType = "system.shutdown"
	ActionUnitStatus     ActionType = "unit.status"
	// Enabling and masking change what the host will do after a reboot, not
	// its state now. A unit that is enabled and a unit that is running are
	// two different things, so there are two operations.
	ActionUnitEnableSet ActionType = "unit.enable.set"
	ActionUnitMaskSet   ActionType = "unit.mask.set"

	ActionDomainEnroll    ActionType = "identity.host.enroll"
	ActionDomainPreflight ActionType = "identity.host.preflight"

	ActionLocalUserCreate ActionType = "localuser.create"
	ActionLocalUserLock   ActionType = "localuser.lock"
	ActionLocalUserUnlock ActionType = "localuser.unlock"
	ActionLocalSSHKeysSet ActionType = "localuser.sshkeys.set"

	// ActionInventoryRefresh orders the inventory to be read again.
	//
	// The panel sees the picture from the last cycle, and a decision taken
	// before a campaign or after a manual change on the host has to rest on
	// the state of this moment. The operation changes nothing and is
	// therefore cheap - but not free: the read starts subprocesses on the
	// host, so it has its own permission and its own time limit.
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
	// ActionDockerEvents reads the engine's event journal. A separate
	// operation, because it answers a different question from a state read:
	// not "how are things", but "what happened here".
	ActionDockerEvents ActionType = "docker.events"

	// The plan of a Compose project computes the difference between the
	// host's state and the manifest.
	ActionComposePlan ActionType = "docker.compose.plan"
	// Deploying a project is bound to one specific plan.
	ActionComposeDeploy ActionType = "docker.compose.deploy"
)

// ActionVersion is the version of the payload contract. Changing the meaning
// of a field requires raising the version, not a silent reinterpretation.
const ActionVersion = 1

// RiskLevel describes what an operation threatens. The level is not a label
// in the interface: it decides the freshness of authentication, the target
// confirmation and the default campaign policy.
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

// LockClass names the host resource an operation uses exclusively. Only one
// mutation in a given class can run at a time: two package transactions on
// the same database can damage it.
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
	// A backup repository is one resource: the tools hold their own lock on
	// it, and a second operation would wait under that lock anyway - only
	// without the panel knowing, and until its time limit runs out.
	LockBackup = "backup"
	// The trust store is one per host, and the tool that recomputes it
	// rewrites the whole bundle: two anchor changes at once give a bundle
	// neither of the plans saw.
	LockCertificates = "certificates"
)

// CampaignMode says whether and how an operation may run on many hosts at
// once.
//
// Every operation declares it explicitly, and the default value is none.
// Adding a new operation to the registry therefore does not open it to the
// whole fleet: missing metadata means a refusal, not "the same payload
// everywhere".
type CampaignMode string

const (
	// CampaignNone marks an operation that is not allowed in bulk. This is
	// not a missing feature but a deliberate refusal: removing a package,
	// wiping a disk or shutting a host down has one target, which the
	// operator types by hand.
	CampaignNone CampaignMode = "none"
	// CampaignSamePayload marks an operation whose intent carries over: the
	// same payload means the same thing on every host, and preflight and
	// verification happen separately anyway.
	CampaignSamePayload CampaignMode = "same_payload"
	// CampaignPerHostPlan marks a shared target state from which every host
	// computes its own plan. Two hosts picked by the same request almost
	// never have the same diff, so the approval has to cover a set of plans
	// rather than one payload.
	CampaignPerHostPlan CampaignMode = "per_host_plan"
	// CampaignSpecialized marks an operation with its own state machine: a
	// reboot is settled by the host coming back, enrollment has its own
	// stages.
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
	// RequiresPlan marks an operation that must not be ordered without a plan
	// approved by a human. The plan hash binds the approval to one specific
	// diff.
	RequiresPlan bool `json:"requires_plan"`
}

// Describe returns the full contract of an operation.
func (a ActionType) Describe() Spec {
	spec := actionSpecs[a]
	return Spec{
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
		RequiresPlan:   spec.requiresPlan,
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

// CampaignMode returns the bulk-operation mode. An unknown operation and an
// operation without a declaration both get a refusal: missing metadata must
// not mean consent.
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

// RequiresFreshAuth says whether the operator has to confirm their identity
// right before ordering. An operation that can cut off access to a host must
// not travel on an hour-old session.
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
	// A shutdown destroys no data, but it is irreversible remotely: nobody
	// will power this host back on through the panel. A list of hosts is
	// often long and full of similar names, so the target name is the same
	// decision here as for a destructive operation.
	if a == ActionSystemShutdown {
		return true
	}
	return a.Risk() == RiskDestructive
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
}

// The risk levels and lock classes follow chapters 6.1 and 8 of the
// specification. Risk is not a label: critical requires fresh
// authentication, destructive additionally requires typing the target name.
// The lock class says which operations must not run at once on the same host.
var actionSpecs = map[ActionType]actionSpec{
	ActionUnitStart: {mutating: true, capability: "systemd", permission: "unit.start",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockUnits},
	// Stopping a service interrupts it, so it ranks higher than starting.
	ActionUnitStop: {mutating: true, capability: "systemd", permission: "unit.stop",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockUnits},
	ActionUnitRestart: {mutating: true, capability: "systemd", permission: "unit.restart",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockUnits},
	ActionUnitReload: {mutating: true, capability: "systemd", permission: "unit.reload",
		timeoutSeconds: 60, risk: RiskMedium, lockClass: LockUnits},
	ActionReadJournal: {mutating: false, capability: "journald", permission: "journal.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Creating a scheduled entry means something will run without the
	// operator - including when nobody is watching.
	ActionScheduleEnsure: {mutating: true, capability: "schedules", permission: "schedule.write",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockUnits},
	// Disabling leaves the content on the host and is reversible.
	ActionScheduleDisable: {mutating: true, capability: "schedules", permission: "schedule.disable",
		timeoutSeconds: 60, risk: RiskMedium, lockClass: LockUnits},
	ActionScheduleRemove: {mutating: true, capability: "schedules", permission: "schedule.remove",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockUnits},
	// Running now executes the same command outside the schedule.
	ActionScheduleRunNow: {mutating: true, capability: "schedules", permission: "schedule.run",
		timeoutSeconds: 900, risk: RiskHigh, lockClass: LockUnits},

	// Reading NetworkManager profiles before a change. The plan does not
	// touch the host.
	ActionNetworkPlan: {mutating: false, capability: "network", permission: "network.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Changing the address profile means changing the branch the panel sits
	// on: a wrongly set address cuts the host off and no further order will
	// ever arrive.
	ActionNetworkProfileApply: {mutating: true, capability: "network.write", permission: "network.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork},
	// Routes are a separate permission: changing the default route redirects
	// all of the host's traffic, not just its address.
	ActionNetworkRouteEnsure: {mutating: true, capability: "network.write", permission: "network.route.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork},
	// MTU has its own permission, because it is a change of a different
	// weight from rewriting an address: a wrong MTU breaks large packets, a
	// wrong address cuts the host off.
	ActionNetworkMTUSet: {mutating: true, capability: "network.write", permission: "network.mtu.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockNetwork},
	// A rollback on request returns to the state from before the change, so
	// it is itself a network change - and just as risky as the one it undoes.
	ActionNetworkRollback: {mutating: true, capability: "network.write", permission: "network.rollback",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockNetwork},

	// The name resolution test asks from the host, because the panel's answer
	// says nothing about what the host will see. The query changes nothing.
	ActionDNSResolveTest: {mutating: false, capability: "dns", permission: "dns.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 64 << 10},
	// The resolver plan: the difference between the profile found and the one
	// requested. It does not touch the host, so it has no rollback and no
	// lock class.
	ActionDNSPlan: {mutating: false, capability: "dns", permission: "dns.plan",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 64 << 10},
	// A bad resolver cuts the host off from the directory and from Kerberos,
	// and therefore from logging in - the effect is wider than the one name
	// that will not resolve.
	ActionDNSHostApply: {mutating: true, capability: "dns.write", permission: "dns.host.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork},

	// Reading the ruleset before a change. The plan does not touch the host.
	ActionFirewallPlan: {mutating: false, capability: "firewall", permission: "firewall.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 512 << 10},
	// A bad rule cuts the panel off from the host and there is nothing left
	// to undo the change with, so every firewall change is an operation of
	// the highest risk.
	ActionFirewallRuleEnsure: {mutating: true, capability: "firewall.write", permission: "firewall.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork},
	ActionFirewallRuleRemove: {mutating: true, capability: "firewall.write", permission: "firewall.rule.remove",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork},
	// firewalld zones describe access differently from rules: the question is
	// "what is open", not "which rule matches first".
	ActionFirewallZonePort: {mutating: true, capability: "firewall.zones", permission: "firewall.zone.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork},
	ActionFirewallZoneService: {mutating: true, capability: "firewall.zones", permission: "firewall.service.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork},
	ActionFirewallRulesetRestore: {mutating: true, capability: "firewall.write", permission: "firewall.restore",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNetwork},

	// Reading the topology on request. The inventory carries it anyway, but
	// before a change the operator wants the state of this moment, not the
	// one from the last cycle.
	ActionStoragePlan: {mutating: false, capability: "storage", permission: "storage.read",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 512 << 10},
	// Mounting is reversible, but the fstab entry decides whether the host
	// comes back from a reboot the way it stands now.
	ActionMountEnsure: {mutating: true, capability: "storage", permission: "storage.mount.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockStorage},
	ActionMountRemove: {mutating: true, capability: "storage", permission: "storage.mount.remove",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockStorage},
	// A filesystem check takes long and requires that nobody is using it.
	ActionFilesystemCheck: {mutating: true, capability: "storage", permission: "storage.fsck",
		timeoutSeconds: 3600, risk: RiskHigh, lockClass: LockStorage},

	// Extending a volume and a filesystem is reversible only in theory:
	// shrinking requires getting the data below a boundary nobody planned
	// for. Hence the critical risk, even though nothing is deleted.
	ActionLVMExtend: {mutating: true, capability: "storage.lvm", permission: "storage.lvm.write",
		timeoutSeconds: 900, risk: RiskCritical, lockClass: LockStorage},
	ActionFilesystemResize: {mutating: true, capability: "storage", permission: "storage.filesystem.write",
		timeoutSeconds: 1800, risk: RiskCritical, lockClass: LockStorage},
	// Formatting and wiping destroy data irreversibly: they require fresh
	// authentication, typing the target name and the consent of two people.
	ActionFilesystemCreate: {mutating: true, capability: "storage", permission: "storage.destructive",
		timeoutSeconds: 1800, risk: RiskDestructive, lockClass: LockStorage},
	ActionDiskWipe: {mutating: true, capability: "storage", permission: "storage.wipe",
		timeoutSeconds: 1800, risk: RiskDestructive, lockClass: LockStorage},

	// Reading the sshd configuration before a change. The plan does not touch
	// the host.
	ActionSSHConfigPlan: {mutating: false, capability: "sshd", permission: "ssh.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 128 << 10},
	// A bad sshd configuration cuts off administration of the host and there
	// is nothing to fix it with remotely - exactly like a bad firewall rule.
	ActionSSHConfigApply: {mutating: true, capability: "sshd", permission: "ssh.config.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockUnits},
	// Replacing the host key changes the identity every client sees: everyone
	// gets a known_hosts warning, and automation based on the fingerprint
	// stops working.
	ActionSSHHostKeyRotate: {mutating: true, capability: "sshd", permission: "ssh.hostkey.rotate",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockUnits},

	// The scan does not change the host, but it collects reconnaissance
	// material: a list of what the host exposes to the outside, together with
	// the owners of the sockets. Hence higher than an ordinary read and with
	// its own permission.
	ActionSecurityScan: {mutating: false, capability: "security", permission: "security.scan",
		timeoutSeconds: 120, risk: RiskMedium, maxOutputBytes: 512 << 10},
	// Switching to permissive takes protection off the whole host and does it
	// immediately. The change is reversible, but in the meantime it protects
	// nothing.
	ActionSELinuxModeSet: {mutating: true, capability: "security.mac", permission: "security.mac.write",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockNone},
	// Reloading the audit rules changes what the host records. It is
	// reversible and local, but it is not a read.
	ActionAuditRulesReload: {mutating: true, capability: "security.audit", permission: "security.audit.reload",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockUnits},

	// The scan looks at the files it is pointed at and does not change the
	// host. The result carries dates and names that the certificate shows to
	// anyone connecting to the service anyway - and it does not touch the
	// private key.
	ActionCertificateScan: {mutating: false, capability: "certificates", permission: "certificate.read",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 256 << 10},
	// A deployment replaces the identity a service shows to the world and
	// ends with reloading that service. Bad material stops the service, and
	// bad key permissions hand it to everyone on the host - hence the
	// critical risk.
	// The deployment plan: the difference between the certificate found and
	// the one ordered. It does not touch the host and does not reach for the
	// private key.
	ActionCertificatePlan: {mutating: false, capability: "certificates", permission: "certificate.plan",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 256 << 10},
	ActionCertificateTrustPlan: {mutating: false, capability: "certificates", permission: "certificate.trust.plan",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 512 << 10},
	// Trusting an authority is a decision wider than one file: from that
	// moment the host accepts every certificate this authority signs.
	ActionCertificateTrustEnsure: {mutating: true, capability: "certificates", permission: "certificate.trust.write",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockCertificates},
	// Withdrawing trust breaks connections nobody changed, if the authority
	// still signs anything. The host checks that at its own end.
	ActionCertificateTrustRemove: {mutating: true, capability: "certificates", permission: "certificate.trust.remove",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockCertificates},
	ActionCertificateDeploy: {mutating: true, capability: "certificates", permission: "certificate.deploy",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockUnits},
	// A renewal ends the same way a deployment does: with a new file and a
	// service that reads it. The host's daemon does it, but the effect is the
	// same.
	ActionCertificateRenew: {mutating: true, capability: "certificates.renew", permission: "certificate.renew",
		timeoutSeconds: 600, risk: RiskCritical, lockClass: LockUnits},

	// The synchronisation test does not change the host, but it sends packets
	// from it to the named servers: that is the only way to say anything
	// about a server the host is not using yet.
	ActionTimeSyncTest: {mutating: false, capability: "time", permission: "time.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 128 << 10},
	// The time-source plan: the difference between the panel's file and the
	// order, together with whether the daemon will be restarted. It does not
	// touch the host.
	ActionTimePlan: {mutating: false, capability: "time", permission: "time.plan",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Changing the time sources can step the clock, and then databases,
	// tokens and certificates see time that went backwards. The unit lock is
	// needed here because the change ends with restarting the daemon.
	ActionTimeConfigApply: {mutating: true, capability: "time", permission: "time.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockUnits},
	// The timezone changes what the host shows to people and writes to the
	// journal; it does not change the moment the host lives in.
	ActionTimezoneSet: {mutating: true, capability: "time", permission: "time.timezone.write",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockNone},

	// Reading kernel settings. The profile plus the keys named in the order;
	// the whole of /proc/sys has a few thousand entries and enumerating it
	// answers no question at all.
	ActionSysctlPlan: {mutating: false, capability: "kernel", permission: "kernel.read",
		timeoutSeconds: 120, risk: RiskLow, maxOutputBytes: 256 << 10},
	// A kernel setting changes the behaviour of the whole host, but it can be
	// undone the same way it was set.
	ActionSysctlEnsure: {mutating: true, capability: "kernel", permission: "kernel.sysctl.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockNone},
	ActionKernelModuleLoad: {mutating: true, capability: "kernel", permission: "kernel.module.write",
		timeoutSeconds: 300, risk: RiskHigh, lockClass: LockNone},
	// The module blacklist plan: the difference between the blacklist found
	// and the one requested. It does not touch the host.
	ActionKernelModulePlan: {mutating: false, capability: "kernel", permission: "kernel.module.plan",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Blacklisting a module takes effect only after a reboot, and for modules
	// from the initramfs also after it is rebuilt: the effect shows up when
	// the host comes back.
	ActionKernelModuleBlacklist: {mutating: true, capability: "kernel", permission: "kernel.module.blacklist",
		timeoutSeconds: 300, risk: RiskCritical, lockClass: LockNone},

	// Reading a configuration file reaches for content that is often
	// sensitive even when the file itself is not a secret: addresses, account
	// names, topology.
	ActionFileRead: {mutating: false, capability: "files.managed", permission: "file.read",
		timeoutSeconds: 60, risk: RiskHigh, maxOutputBytes: 1 << 20},
	ActionFilePlan: {mutating: false, capability: "files.managed", permission: "file.plan",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},
	// Writing a configuration file changes the behaviour of a service once it
	// is reloaded - including when nobody planned for that.
	ActionFileEnsure: {mutating: true, capability: "files.managed", permission: "file.write",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockNone},
	ActionFileRemove: {mutating: true, capability: "files.managed", permission: "file.remove",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockNone},
	// Going back to an earlier version is a write of content that was once on
	// the host - but it is still a write.
	ActionFileRollback: {mutating: true, capability: "files.managed", permission: "file.rollback",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockNone},

	ActionProcessList: {mutating: false, capability: "", permission: "process.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 1 << 20},
	// Sending a signal stops somebody's work: a signal has no before and
	// after state that could be undone.
	ActionProcessSignal: {mutating: true, capability: "", permission: "process.signal",
		timeoutSeconds: 30, risk: RiskHigh},
	// A live view keeps a process on the host for the whole time it lasts, so
	// it ranks higher than a one-off read and has its own permission.
	ActionFollowJournal: {mutating: false, capability: "journald", permission: "journal.follow",
		timeoutSeconds: 300, risk: RiskMedium, maxOutputBytes: 1 << 20},
	// Reading a file reaches beyond the system journal, so it carries a
	// higher risk and its own permission: the allowlist is sometimes wide,
	// and an application log sometimes holds data the journal does not.
	ActionReadLogFile: {mutating: false, capability: "", permission: "logfile.read",
		timeoutSeconds: 60, risk: RiskMedium, maxOutputBytes: 1 << 20},

	// Planning does not change the state of the system, but refreshing the
	// metadata does, so the plan has its own permission too.
	// Reading the list does not change the host and does not need root: the
	// dpkg database and the RPM database are readable by everyone. The output
	// limit is high, because a list of a thousand packages is its natural
	// size.
	ActionPackageList: {mutating: false, capability: "packages", permission: "packages.read",
		timeoutSeconds: 300, risk: RiskLow, maxOutputBytes: 8 << 20},

	ActionPackagePlan: {mutating: false, capability: "packages", permission: "packages.plan",
		timeoutSeconds: 300, risk: RiskLow, lockClass: LockPackages},
	// A package transaction is the riskiest operation in the system.
	ActionPackageUpgrade: {mutating: true, capability: "packages", permission: "packages.upgrade",
		timeoutSeconds: 1800, risk: RiskHigh, lockClass: LockPackages, requiresPlan: true},
	ActionAgentUpgrade: {mutating: true, capability: "packages", permission: "agent.upgrade",
		timeoutSeconds: 1800, risk: RiskHigh, lockClass: LockPackages},

	// A repair changes the state of the host and can touch packages of great
	// importance, the bootloader included, so it has its own permission and
	// its own timeout.
	//
	// The requirement is narrower than the mere presence of a package
	// manager: a repair answers debconf questions and exists only for apt. A
	// host that does not have it has to say so when the operation is ordered,
	// not after the task has been delivered.
	ActionPackageRepair: {mutating: true, capability: "packages.repair", permission: "packages.repair",
		timeoutSeconds: 1800, risk: RiskCritical, lockClass: LockPackages},
	// An install adds software to the host that will start running right
	// away.
	ActionPackageInstall: {mutating: true, capability: "packages", permission: "packages.install",
		timeoutSeconds: 1800, risk: RiskHigh, lockClass: LockPackages, requiresPlan: true},
	// A removal takes the package away together with everything that depends
	// on it, and it cannot be undone by restoring state: what disappeared has
	// to be downloaded again.
	ActionPackageRemove: {mutating: true, capability: "packages", permission: "packages.remove",
		timeoutSeconds: 1800, risk: RiskDestructive, lockClass: LockPackages, requiresPlan: true},
	// A hold freezes the package version. It is reversible and local, but a
	// held package will not get security fixes either.
	ActionPackageHoldSet: {mutating: true, capability: "packages", permission: "packages.hold.write",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockPackages},
	// A reboot is a separate, approved campaign phase, not a side effect of
	// an upgrade. Cutting the host off for the duration of the reboot makes
	// it critical.
	// A probe does not change the host, but it leaves it with a connection to
	// the named service - and that is its whole value: it says what this host
	// sees, not what monitoring sees from another place in the network.
	ActionMonitoringProbe: {mutating: false, capability: "monitoring", permission: "monitoring.probe",
		timeoutSeconds: 120, risk: RiskMedium, maxOutputBytes: 64 << 10},

	// The plan reads the backup repository: the list of copies and their
	// size. It changes neither the host nor the repository, but it needs
	// credentials - a backup repository is encrypted and answers nobody
	// without a password.
	ActionBackupPlan: {mutating: false, capability: "backup", permission: "backup.read",
		timeoutSeconds: 600, risk: RiskLow, lockClass: LockBackup, maxOutputBytes: 512 << 10},
	// A copy reads the whole named range of the host and sends it to the
	// repository. It does not change the host, but it costs its disk, its CPU
	// and its link - and it takes time.
	ActionBackupRun: {mutating: true, capability: "backup", permission: "backup.run",
		timeoutSeconds: 7200, risk: RiskHigh, lockClass: LockBackup, maxOutputBytes: 512 << 10},
	// Verification reads the repository and does not change the host; with
	// the data read it costs as much as restoring part of a copy.
	ActionBackupVerify: {mutating: true, capability: "backup", permission: "backup.verify",
		timeoutSeconds: 3600, risk: RiskMedium, lockClass: LockBackup, maxOutputBytes: 512 << 10},
	// A restore unpacks old state onto a running system. It requires naming
	// the target and an overwrite plan, and the panel does not allow aiming
	// at system directories: what comes back from a restored directory to its
	// place is a separate decision and a separate operation.
	ActionBackupRestore: {mutating: true, capability: "backup", permission: "backup.restore",
		timeoutSeconds: 7200, risk: RiskCritical, lockClass: LockBackup, maxOutputBytes: 512 << 10},

	// A package source is a decision about trust, not about a version: from
	// that moment the host takes software from there as well. The package
	// lock is necessary here, because the write ends with refreshing the
	// metadata.
	ActionRepositorySet: {mutating: true, capability: "packages", permission: "packages.repository.write",
		timeoutSeconds: 600, risk: RiskCritical, lockClass: LockPackages},

	ActionSystemReboot: {mutating: true, capability: "systemd", permission: "system.reboot",
		timeoutSeconds: 120, risk: RiskCritical},
	// Shutting a host down ends in a state the panel cannot undo: nobody will
	// power this machine on remotely. The unit lock is needed here so that no
	// other operation starts at the moment the host is going down.
	ActionSystemShutdown: {mutating: true, capability: "systemd", permission: "system.shutdown",
		timeoutSeconds: 120, risk: RiskCritical, lockClass: LockUnits},
	// Reading unit state is non-mutating and serves campaign health checks.
	ActionUnitStatus: {mutating: false, capability: "systemd", permission: "unit.status",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 1 << 20},
	// Enabling a unit changes the behaviour of the host after every following
	// reboot, so it ranks higher than starting it now.
	ActionUnitEnableSet: {mutating: true, capability: "systemd", permission: "unit.enable.write",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockUnits},
	// Masking takes away a unit's ability to start even manually and survives
	// a reboot of the host - the furthest-reaching change in this module.
	ActionUnitMaskSet: {mutating: true, capability: "systemd", permission: "unit.mask.write",
		timeoutSeconds: 60, risk: RiskCritical, lockClass: LockUnits},

	// Joining a domain changes authentication for the whole host.
	ActionDomainEnroll: {mutating: true, capability: "systemd", permission: "identity.host.enroll",
		timeoutSeconds: 900, risk: RiskCritical, lockClass: LockIdentity},
	// Preflight changes nothing, so it needs no approval.
	ActionDomainPreflight: {mutating: false, capability: "systemd", permission: "identity.read",
		timeoutSeconds: 120, risk: RiskLow, lockClass: LockIdentity},

	// Local accounts depend neither on systemd nor on a directory: the module
	// works also where the customer stays with plain SSH authorisation.
	// Locking and unlocking have separate permissions: in response to an
	// incident, cutting an account off is sometimes allowed where restoring
	// access is not.
	ActionLocalUserCreate: {mutating: true, capability: "", permission: "localuser.create",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockAccounts},
	ActionLocalUserLock: {mutating: true, capability: "", permission: "localuser.lock",
		timeoutSeconds: 60, risk: RiskMedium, lockClass: LockAccounts},
	// Restoring access is always more serious than taking it away.
	ActionLocalUserUnlock: {mutating: true, capability: "", permission: "localuser.unlock",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockAccounts},
	ActionLocalSSHKeysSet: {mutating: true, capability: "", permission: "localuser.sshkeys.write",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockAccounts},

	// Reading containers changes nothing, but it can be heavy: the full list
	// of images on a build host is megabytes, so it has its own resource
	// class and its own output limit.
	// Refreshing the inventory does not change the host and takes no lock: a
	// read may run alongside an operation that is under way - at worst it
	// will see state halfway through a change, and that is the truth about
	// this moment.
	ActionInventoryRefresh: {mutating: false, permission: "inventory.refresh",
		timeoutSeconds: 300, risk: RiskLow, lockClass: LockNone, maxOutputBytes: 1 << 20},

	ActionDockerRead: {mutating: false, capability: "docker", permission: "docker.read",
		timeoutSeconds: 120, risk: RiskLow, lockClass: LockContainers, maxOutputBytes: 4 << 20},

	// Starting a container restores a service; stopping interrupts one, so
	// stop and restart rank higher than start.
	ActionDockerStart: {mutating: true, capability: "docker", permission: "docker.container.start",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockContainers},
	ActionDockerStop: {mutating: true, capability: "docker", permission: "docker.container.stop",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockContainers},
	ActionDockerRestart: {mutating: true, capability: "docker", permission: "docker.container.restart",
		timeoutSeconds: 180, risk: RiskHigh, lockClass: LockContainers},
	// Removing a container is irreversible: data outside volumes dies with
	// it, so the operator types the target name before the operation starts.
	ActionDockerRemove: {mutating: true, capability: "docker", permission: "docker.container.remove",
		timeoutSeconds: 120, risk: RiskDestructive, lockClass: LockContainers},
	// Pulling an image changes what will come up at the next start, but by
	// itself it does not touch running containers.
	ActionDockerPull: {mutating: true, capability: "docker", permission: "docker.image.pull",
		timeoutSeconds: 1800, risk: RiskMedium, lockClass: LockContainers},
	// Pruning removes data for good and by default does not run in bulk.
	ActionDockerPrune: {mutating: true, capability: "docker", permission: "docker.prune",
		timeoutSeconds: 900, risk: RiskDestructive, lockClass: LockContainers},
	// The event journal changes nothing and takes no container lock: a read
	// lasting the follow window must not hold back the restart the operator
	// is asking for - and that restart is exactly what they want to see in
	// it. The time limit covers the longest allowed window with a margin.
	ActionDockerEvents: {mutating: false, capability: "docker", permission: "docker.events",
		timeoutSeconds: 180, risk: RiskLow, lockClass: LockNone, maxOutputBytes: 1 << 20},

	// The plan changes nothing, but it runs compose on the host and fetches
	// image metadata, so it has its own permission.
	ActionComposePlan: {mutating: false, capability: "docker.compose",
		permission: "docker.compose.plan", timeoutSeconds: 300,
		risk: RiskLow, lockClass: LockContainers, maxOutputBytes: 1 << 20},
	// Deploying a manifest starts the images the operator named on the host.
	// It is the furthest-reaching operation of this module and must not be
	// ordered without a plan approved by a human.
	ActionComposeDeploy: {mutating: true, capability: "docker.compose",
		permission: "docker.compose.deploy", timeoutSeconds: 1800,
		risk: RiskCritical, lockClass: LockContainers, requiresPlan: true,
		maxOutputBytes: 1 << 20},
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

// maxFollowSeconds bounds a single live view. A stream without an upper bound
// would keep a process on the host even long after the operator closed the
// browser tab.
const maxFollowSeconds = 900

// validateJournalPayload checks the filters shared by a read and a live view.
func validateJournalPayload(payload *JournalPayload) error {
	if priority := payload.MaxPriority; priority != nil && *priority > 7 {
		return fmt.Errorf("the syslog priority has to be in the range 0-7")
	}
	if payload.Unit != "" {
		if err := validateUnitName(payload.Unit); err != nil {
			return err
		}
	}
	// The "since" value goes into a journalctl argument. It does not pass
	// through a shell, but narrower validation is still cheaper than trust.
	if payload.Since != "" && !periodPattern.MatchString(payload.Since) {
		return fmt.Errorf("invalid time range %q", payload.Since)
	}
	return nil
}

// periodPattern allows the formats journalctl accepts: a timestamp, a
// relative expression and keywords.
var periodPattern = regexp.MustCompile(
	`^(-?\d+ ?(s|sec|second|seconds|m|min|minute|minutes|h|hour|hours|d|day|days|w|week|weeks)( ago)?` +
		`|yesterday|today|now` +
		`|\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?)$`)

// scheduleIdentifier repeats the pattern from the schedules module. The name
// becomes the name of a file in /etc/cron.d, and cron skips files with a dot
// and other special characters - an entry with a bad name would silently
// never run.
var scheduleIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// interfaceName allows the names the kernel accepts at all. The length limit
// is IFNAMSIZ minus the terminator.
var interfaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)

// checkFilePath rejects paths the panel will not write - before the task even
// comes into being.
//
// The host decides conclusively with its own allowlist; here we sieve out
// what is an error in the order regardless of the host.
func checkFilePath(path string) error {
	// Paths the panel never touches are rejected already at ordering time:
	// the host would refuse anyway, and a queued task with such a target
	// would look like a change about to happen.
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

// firstPort returns the single port of a zone operation. The operation
// concerns exactly one port, so a list longer than one element is an error -
// and the zone validator reports it.
func firstPort(ports []string) string {
	if len(ports) != 1 {
		return ""
	}
	return ports[0]
}

// checkNetworkChange rejects a configuration the host will not accept or one
// that would cut it off from the panel. The panel refuses early, the host
// conclusively.
func checkNetworkChange(action ActionType, change *NetworkPayload) error {
	switch action {
	case ActionNetworkMTUSet:
		if change.MTU == "" {
			return fmt.Errorf("an MTU change requires a value")
		}
		return network.ValidateMTU(change.MTU)

	case ActionNetworkRouteEnsure:
		// An empty list is a valid target state here: it means "a profile
		// without routes of its own". So that it does not become one by
		// accident, the order has to give it explicitly as a list rather than
		// omit the field.
		if change.Routes == nil {
			return fmt.Errorf("a route operation requires a list of routes; an empty list clears the profile's routes")
		}
		for _, route := range change.Routes {
			if err := network.ValidateRoute(route); err != nil {
				return err
			}
		}
		return nil

	case ActionNetworkProfileApply:
		switch change.Method {
		case "auto", "manual":
		default:
			return fmt.Errorf("unsupported method %q; the panel sets auto or manual", change.Method)
		}
		// The manual method without an address would leave the interface
		// without one, and so cut the host off. That is not a configuration,
		// it is a mistake.
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

// scheduleShellCharacters are forbidden in command arguments. Cron runs the
// command through a shell, so an argument with a metacharacter stops being an
// argument and becomes a second command.
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
	}
	return nil
}

// protectedPackages repeats the list from the packages module. The duplicate
// is deliberate: opspec is the contract of the operations and does not reach
// for packages that start processes or read host state - and the packages
// module does both. The plan hash has to be computed by the same
// implementation on both sides, so the list lives here in full. The panel
// refuses early, and the host - conclusively.
//
// The cron grammar we already use directly from the schedules module: it is a
// pure parser without side effects, and repeating it here would drift from
// what the host really understands.
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
		// dependants. Repeating it in the message would suggest two problems
		// instead of one.
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

// validateLogPath rejects paths the host will not accept anyway. The
// allowlist on the host decides; the panel sieves out what is not even an
// absolute path, so that a hopeless task is not queued.
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

// unitPattern repeats the pattern from the systemd module. The duplicate is
// deliberate: the opspec package has no dependencies outside the standard
// library, because the plan hash has to be computed by the same
// implementation on both sides. The panel refuses early, and the host -
// conclusively.
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

// maxComposeManifest bounds the size of a manifest. A file larger than this
// is no longer a project configuration, but something the operator will not
// read before approving it.
const maxComposeManifest = 256 << 10

// containerIdentifier allows only the engine's hexadecimal identifier. The
// identifier goes into the path of an Engine API request, so it must not
// carry anything that changes that path.
var containerIdentifier = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

func validContainerIdentifier(id string) bool {
	return containerIdentifier.MatchString(id)
}

// imageReference allows a repository name with an optional registry, tag or
// digest. The reference goes to the engine as a request parameter rather than
// to a shell, but narrower validation is still cheaper than trust.
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

// checkEventsRead guards the window boundaries. An order outside them is an
// error in the order, not something the host should silently trim: an
// operator who asked for a day of following has to learn that no such
// operation exists.
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
	// FollowSeconds bounds the live view. Zero means the default limit; a
	// stream without an upper bound would keep a process on the host
	// forever, including when nobody is watching any more.
	FollowSeconds uint32 `json:"follow_seconds,omitempty"`
}

// PackageChangePayload describes an install, a removal or a hold.
type PackageChangePayload struct {
	Packages []string `json:"packages"`
	// ExpectedRemovals is the set the operator approved for a removal. The
	// host computes it again right before the operation: a difference means a
	// different set would be removed from the one that was reviewed.
	ExpectedRemovals []string `json:"expected_removals,omitempty"`
	// Hold concerns holds only: true freezes, false releases.
	Hold bool `json:"hold,omitempty"`
	// PlanHash binds the install to the plan computed on this host: the host
	// computes the plan once more and refuses when the repository metadata
	// changed since the approval.
	PlanHash string `json:"plan_hash,omitempty"`
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
}

// AgentUpgradePayload describes replacing the agent with a named version.
type AgentUpgradePayload struct {
	// TargetVersion is the version that has to report in after the restart.
	// It is what settles success: the exit code of the package manager says
	// only that the transaction went through, not that the host came back.
	TargetVersion string `json:"target_version"`
	// PackageSHA256 is the checksum of the package from the release. The
	// manager checks the repository signature, and this is a second,
	// independent check - and the only one the panel can perform on its own
	// side.
	PackageSHA256 string `json:"package_sha256,omitempty"`
	// RollbackVersion says what to return to when the host does not come back
	// with the new version. Empty means no prepared return.
	RollbackVersion string `json:"rollback_version,omitempty"`
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

// UnitStatusPayload describes a read of unit state.
//
// An empty list means the full list of the host's units. That is a separate
// query and a different cost from reading a few units known by name, so it
// has to be ordered explicitly rather than result from a mistake in the call.
type UnitStatusPayload struct {
	Units []string `json:"units"`
	// All orders the full list. Without it an empty list of units is an
	// error.
	All bool `json:"all,omitempty"`
}

// UnitToggle turns a property of a unit on or off.
type UnitToggle struct {
	Unit string `json:"unit"`
	// Enabled for unit.enable.set, Masked for unit.mask.set. The field is a
	// target value rather than a toggle: the operation describes the state to
	// be reached, so repeating it does not undo the change.
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
	LocalUser       *LocalUserPayload       `json:"local_user,omitempty"`
	PackageRepair   *PackageRepairPayload   `json:"package_repair,omitempty"`
	DockerRead      *DockerReadPayload      `json:"docker_read,omitempty"`
	DockerContainer *DockerContainerPayload `json:"docker_container,omitempty"`
	DockerImage     *DockerImagePayload     `json:"docker_image,omitempty"`
	DockerPrune     *DockerPrunePayload     `json:"docker_prune,omitempty"`
	DockerEvents    *DockerEventsPayload    `json:"docker_events,omitempty"`
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
}

// maxRefreshModules bounds the length of the scope. An order with a list
// longer than the set of modules is not a partial order, it is a wrong one.
const maxRefreshModules = 32

// InventoryModules lists the modules the panel can refresh on request.
//
// The list is here rather than in the agent, because it is part of the
// operation contract: the panel refuses an order with an unknown name before
// the task goes out into the world.
var InventoryModules = []string{
	"system", "packages", "services", "identity", "accounts", "network",
	"dns", "firewall", "storage", "ssh", "kernel", "time", "power",
	"security", "certificates", "backups", "files", "containers", "schedules",
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
	// Modules narrows the read. Empty means the whole inventory - and that is
	// the default way, because an operator usually asks "how are things now",
	// not "how are things now on one tab".
	Modules []string `json:"modules,omitempty"`
}

// SecurityPayload describes an operation of the security module.
type SecurityPayload struct {
	// Mode is the mode of mandatory access control.
	Mode string `json:"mode,omitempty"`
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

// BackupPayload describes a backup operation.
//
// The credentials are references to the store: the repository password and
// the tool's environment variables. The values are in neither the order, nor
// the audit trail, nor the inventory - the host reaches for them at execution
// time and hands them to the tool through the environment rather than as an
// argument visible in /proc.
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
	// Plan names the kind of planned operation: run or verify. Empty means a
	// read of the repository state - the same order serves both things, so
	// the kind of plan has to be named rather than guessed from the scope.
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
//
// The source key travels in the order, because it is public material and the
// plan is meant to show what the host will trust. The password does not
// travel: it is a reference to the store, which the host reaches for only at
// write time.
type RepositoryPayload struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	URL           string   `json:"url,omitempty"`
	Suites        []string `json:"suites,omitempty"`
	Components    []string `json:"components,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Enabled       bool     `json:"enabled,omitempty"`
	Priority      int      `json:"priority,omitempty"`
	// GPGKey is the public key of the source in an ASCII frame. The host
	// computes its fingerprint and sends it back in the result: only a human
	// can compare that fingerprint with the one the supplier gave.
	GPGKey string `json:"gpg_key,omitempty"`
	// AllowUnsigned is the consent to a source whose signatures the host does
	// not check. Without it a source without a key does not pass: an unsigned
	// repository is a remote root shell, not a default setting.
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
//
// The key path and the service name come from the panel's configuration
// rather than from a guess by the host: the link "this file is read by this
// service" is typed in by a human, because only a human knows it.
type CertificateTarget struct {
	Path    string `json:"path"`
	KeyPath string `json:"key_path,omitempty"`
	Service string `json:"service,omitempty"`
}

// CertificatePayload describes an operation of the certificates module.
type CertificatePayload struct {
	// Targets sets the scope of the scan. An empty list means scanning what
	// the host knows about itself - that is, certmonger's requests - and not
	// scanning the whole disk.
	Targets []CertificateTarget `json:"targets,omitempty"`

	// Path and KeyPath are the target of a deployment.
	Path    string `json:"path,omitempty"`
	KeyPath string `json:"key_path,omitempty"`
	// Certificate is content in the clear: the certificate together with its
	// chain. It travels in the order, because it is public and the plan is
	// meant to show what will reach the host.
	Certificate string `json:"certificate,omitempty"`
	// KeySecret points at the private key in the store. The value is in
	// neither the order, nor the audit trail, nor the inventory - the host
	// fetches it right before the swap, on a single-use lease.
	KeySecret *SecretRef `json:"key_secret,omitempty"`
	Owner     string     `json:"owner,omitempty"`
	Group     string     `json:"group,omitempty"`
	Mode      string     `json:"mode,omitempty"`
	KeyMode   string     `json:"key_mode,omitempty"`
	// ReloadUnit is the service that has to read the new file. Without it a
	// deployment ends with a file on disk and the old identity in the
	// process's memory - and that looks like a change nobody can see.
	ReloadUnit string `json:"reload_unit,omitempty"`
	// ProbeTarget is the address at which the host will check the result of
	// the deployment. The probe compares the fingerprint rather than trust:
	// it asks whether the service serves the certificate just written.
	ProbeTarget string `json:"probe_target,omitempty"`
	// Request points at the certmonger request during a renewal.
	Request string `json:"request,omitempty"`
	// AnchorID names the panel's anchor in the host's trust store. The file
	// on the host is named after it, so that is how the panel recognises its
	// own anchor.
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
	// Servers are the target time servers. An empty list in a configuration
	// change is an error rather than a request to clear the sources: a host
	// without a time source drifts silently.
	Servers []string `json:"servers,omitempty"`
	// Probe names the servers to check without changing the configuration.
	Probe    []string `json:"probe,omitempty"`
	Timezone string   `json:"timezone,omitempty"`
	// AllowStep is the consent to step the clock. Without it the host
	// rejects a change that would move time by more than the threshold.
	AllowStep bool `json:"allow_step,omitempty"`
	// EnableDropIn is the consent to add the panel's source directory to the
	// daemon's main file. Without it a host that includes none stays
	// read-only - the panel does not add itself to somebody else's
	// configuration silently.
	EnableDropIn bool `json:"enable_dropin,omitempty"`
	// PlanHash binds the change to the plan computed on this host; the host
	// computes the plan once more before writing.
	PlanHash string `json:"plan_hash,omitempty"`
}

// SecretRef points at a secret in the panel's store.
//
// The task payload carries only the reference. The value passes through
// neither the task, nor the audit trail, nor the inventory: the host reaches
// for it only at execution time, on a short lease issued for that one task.
// Thanks to that the plan hash also describes the reference rather than the
// content - and it can be shown.
type SecretRef struct {
	Name string `json:"name"`
	// Version equal to zero means the version current at the moment the task
	// is delivered.
	Version int `json:"version,omitempty"`
}

// secretName repeats the store's rule, so that an order with a name the store
// would not accept anyway falls out already at ordering time. The store
// remains the deciding authority - it checks the name again when it issues
// the lease.
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

// String describes the reference as "name#version". The name and the version
// only: the value of the secret is not in this module and must not appear in
// a plan or in a log.
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
	// It excludes the Content field: either the content is in the clear and
	// visible in the plan, or it comes from the store and exists nowhere
	// outside it.
	ContentSecret *SecretRef `json:"content_secret,omitempty"`
}

// Secrets lists the references the host will have to reach for.
//
// The scheduler issues a lease for exactly what the payload points at -
// neither less nor more.
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
//
// An empty field means "do not change": the panel does not rewrite the
// server's whole configuration, only the settings the operator asked about.
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
	// authentication method is left. It requires an explicit decision by the
	// operator.
	AllowLockout bool   `json:"allow_lockout,omitempty"`
	KeyType      string `json:"key_type,omitempty"`
	// PlanHash binds the change to the plan computed on this host; the host
	// computes the plan once more before writing.
	PlanHash string `json:"plan_hash,omitempty"`
}

// DescribesChange says whether the payload carries settings to plan. A
// payload without settings is a question about the state of the server, not
// about a difference.
func (p SSHPayload) DescribesChange() bool {
	return p.Port != "" || p.PermitRootLogin != "" || p.PasswordAuthentication != "" ||
		p.PubkeyAuthentication != "" || p.KbdInteractive != "" || p.MaxAuthTries != "" ||
		len(p.AllowUsers) > 0 || len(p.AllowGroups) > 0 || len(p.DenyUsers) > 0
}

// StoragePayload describes an operation on storage.
//
// The source is named by a persistent identifier or by a path in /dev: the
// name /dev/sdX depends on the order of discovery and after a reboot can
// point at a different disk.
type StoragePayload struct {
	Source  string `json:"source,omitempty"`
	Target  string `json:"target,omitempty"`
	FSType  string `json:"fs_type,omitempty"`
	Options string `json:"options,omitempty"`
	// Persist writes an entry in fstab. Without it the mount disappears after
	// a reboot - and the operator is to know that before the outage, not
	// after.
	Persist bool   `json:"persist,omitempty"`
	Device  string `json:"device,omitempty"`
	// ExpectedSerial and ExpectedSizeBytes bind the operation to the device
	// the operator reviewed. A /dev/sdX path points at something else after a
	// reboot.
	ExpectedSerial    string `json:"expected_serial,omitempty"`
	ExpectedSizeBytes uint64 `json:"expected_size_bytes,omitempty"`
	// Size is the increment of the volume, e.g. "+10G".
	Size  string `json:"size,omitempty"`
	Label string `json:"label,omitempty"`
	// ExpectedUUID binds the operation to one specific filesystem.
	ExpectedUUID string `json:"expected_uuid,omitempty"`
	Repair       bool   `json:"repair,omitempty"`
	// Plan names the kind of operation storage.plan is planning on the
	// device: check, resize or lvm_extend. A mount is recognised by its
	// target, so it needs no name.
	Plan string `json:"plan,omitempty"`
	// PlanHash binds the change to the plan computed on this host; the host
	// computes the plan once more before the operation.
	PlanHash string `json:"plan_hash,omitempty"`
}

// FirewallPayload describes an operation on the host's firewall.
//
// The panel does not accept raw nft text: a rule written as text is a
// language, and accepting a language would mean the host executes everything
// that can be written in it. The wizard builds the rule out of fields the
// panel understands.
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
	// BreakGlass overrides the protection of the management channel. It
	// requires an explicit decision by the operator, because the result is
	// sometimes a host somebody has to drive to.
	BreakGlass      bool   `json:"break_glass,omitempty"`
	RollbackSeconds uint32 `json:"rollback_seconds,omitempty"`
	RollbackID      string `json:"rollback_id,omitempty"`
	// ExpectedHash binds the change to the ruleset the operator reviewed.
	ExpectedHash string `json:"expected_hash,omitempty"`
}

// DNSPayload describes an operation on the host's resolver.
type DNSPayload struct {
	// Interface names the connection profile the change goes through. The
	// host's resolver belongs to the interface rather than to the file: the
	// file is only what the service computed out of it.
	Interface     string   `json:"interface,omitempty"`
	Servers       []string `json:"servers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
	// IgnoreAutoDNS rejects the servers from DHCP. Without it the panel's
	// servers and the provider's servers land in one list, and the operator
	// does not know which one answered.
	IgnoreAutoDNS   bool     `json:"ignore_auto_dns,omitempty"`
	RollbackSeconds uint32   `json:"rollback_seconds,omitempty"`
	Names           []string `json:"names,omitempty"`
	// PlanHash binds the change to the plan computed on this host; the host
	// computes the plan once more before the change.
	PlanHash string `json:"plan_hash,omitempty"`
}

// NetworkPayload describes a change to the network configuration.
//
// The payload describes the target state of the interface, not commands to
// run. The panel names the interface, because that is what the operator sees;
// the NetworkManager profile the host finds by itself.
type NetworkPayload struct {
	Interface string `json:"interface"`
	// MTU is text, because "auto" is an equally valid value here: zero would
	// mean a link with an MTU of zero.
	MTU string `json:"mtu,omitempty"`
	// Routes is the profile's complete list of routes, not an addition: the
	// operator saw one specific set in the plan and that is what is to stay
	// on the host.
	Routes    []string `json:"routes,omitempty"`
	Method    string   `json:"method,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	// RollbackSeconds is the window in which the agent has to confirm
	// connectivity. Zero means the host's default value, not the absence of a
	// rollback.
	RollbackSeconds uint32 `json:"rollback_seconds,omitempty"`
	// RollbackID points at the rollback plan in a network.rollback operation.
	RollbackID string `json:"rollback_id,omitempty"`
	// PlanHash binds the change to the plan computed on this host. The host
	// computes the plan once more before the change: a different digest means
	// the profile changed since planning and the change would enter a state
	// other than the one reviewed.
	PlanHash string `json:"plan_hash,omitempty"`
}

// DescribesChange says whether the payload carries a change to plan: an MTU,
// a list of routes or an address profile. A payload with an interface alone
// is a question about state, not about a difference.
func (p NetworkPayload) DescribesChange() bool {
	return p.Interface != "" && (p.MTU != "" || p.Routes != nil || p.Method != "")
}

// SchedulePayload describes a scheduled job.
//
// The entry describes the target state, not a command to run once: repeating
// the operation with the same payload duplicates nothing.
type SchedulePayload struct {
	// ID is the stable identifier of a managed entry. An entry found on the
	// host has no such identifier and cannot be named here.
	ID string `json:"id"`
	// Expression is the cron expression. Checked on both sides: an entry the
	// host will not understand would never run.
	Expression string `json:"expression,omitempty"`
	// Command is an array of arguments, never a shell line.
	Command []string `json:"command,omitempty"`
	User    string   `json:"user,omitempty"`
	Comment string   `json:"comment,omitempty"`
	// Enabled concerns schedule.disable only: true enables, false disables.
	// Disabling does not delete the content of the entry.
	Enabled bool `json:"enabled,omitempty"`
	// Adopt allows taking over an entry found on the host. Without it the
	// panel does not overwrite work nobody entered into the panel.
	Adopt bool `json:"adopt,omitempty"`
}

// ProcessListPayload describes a snapshot of processes.
type ProcessListPayload struct {
	// SortBy decides which processes land in the result when there are more
	// of them than the limit: rss, cpu, pid or started.
	SortBy string `json:"sort_by,omitempty"`
	Limit  uint32 `json:"limit,omitempty"`
}

// ProcessSignalPayload describes a signal to a process.
//
// A PID alone does not identify a process: the kernel reuses numbers, so a
// signal sent a moment after the list was reviewed could hit something else.
// The start time binds the task to one specific process.
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
//
// The manifest is part of the payload rather than a reference to a file on
// the host: the operator approves the content they reviewed, and the payload
// hash binds the approval to exactly that.
type ComposePayload struct {
	Project  string `json:"project"`
	Manifest string `json:"manifest"`
	// PlanDigest binds the deployment to a plan. An empty one is allowed only
	// while planning; a deployment without it has no basis.
	PlanDigest string `json:"plan_digest,omitempty"`
}

// DockerContainerPayload names the container of an operation.
//
// The target is an identifier, not a name. A container name is a label: it
// can be assigned to a different container between the plan and the
// execution, and the operator approved one specific object.
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

// DockerPrunePayload lists the objects to remove.
//
// Pruning by filter removes what matches at execution time - including an
// object created after the operator reviewed the preview. That is why the
// operation takes an explicit list of objects: it removes exactly what was
// shown, or nothing.
type DockerPrunePayload struct {
	ImageIDs   []string `json:"image_ids,omitempty"`
	VolumeName []string `json:"volume_names,omitempty"`
	NetworkIDs []string `json:"network_ids,omitempty"`
}

// The boundaries of an event journal read. The panel refuses an order outside
// them before the task goes out into the world; the host closes them a second
// time, because it is the one paying for the read.
const (
	maxEventWindow = 24 * 60 * 60
	maxEventFollow = 60
	maxEvents      = 1000
)

// DockerEventsPayload describes a closed window of an event journal read.
//
// Every field has a boundary, because a task without boundaries stays on the
// host forever. Zero means the module's default value, not the absence of a
// limit.
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

// DockerReadPayload describes a read of the container engine's state. The
// payload is empty by design: the scope of the read follows from the
// operation rather than from a parameter - otherwise "read the containers"
// and "read everything" would be the same operation at a different price for
// the host.
type DockerReadPayload struct{}

// PackageRepairPayload carries the operator's answers to package
// configuration questions that block package operations.
//
// The payload may be empty: finishing the configuration is enough when the
// previous transaction was interrupted and nothing is waiting for a decision.
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
//
// The payload contains no password: the one-time credential is fetched from
// the directory at send time and injected into the envelope. Storing it in
// the database would mean a secret lying on disk for the whole life of the
// task.
type DomainEnrollPayload struct {
	Domain   string `json:"domain"`
	Realm    string `json:"realm"`
	Server   string `json:"server,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// LocalUserPayload describes a change to a local account.
//
// The payload contains neither a password nor a hash. An account created by
// the panel is reachable by SSH key only, so there is no secret the panel
// would have to store or carry.
type LocalUserPayload struct {
	Name   string   `json:"name"`
	Gecos  string   `json:"gecos,omitempty"`
	Shell  string   `json:"shell,omitempty"`
	Groups []string `json:"groups,omitempty"`
	// SSHKeys is the complete, intended list of keys. An empty list in a
	// key-setting operation takes access away and is a deliberate change, not
	// missing data.
	SSHKeys    []string `json:"ssh_keys,omitempty"`
	CreateHome bool     `json:"create_home,omitempty"`
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

	case ActionLocalUserCreate, ActionLocalUserLock, ActionLocalUserUnlock, ActionLocalSSHKeysSet:
		if payload.LocalUser == nil {
			return fmt.Errorf("the operation %s requires a local_user payload", action)
		}
		if !localUserNamePattern.MatchString(payload.LocalUser.Name) {
			return fmt.Errorf("invalid account name %q", payload.LocalUser.Name)
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
			// An unknown module name must not pass as "nothing to do": a typo
			// would end in a refresh that refreshes nothing and looks like a
			// success.
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

	case ActionDockerPrune:
		if payload.DockerPrune == nil {
			return fmt.Errorf("the operation %s requires a docker_prune payload", action)
		}
		return checkPruneList(payload.DockerPrune)

	case ActionDockerEvents:
		return checkEventsRead(payload.DockerEvents)

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
		// We check the expression here rather than only on the host: an entry
		// cron will not understand would never run, and the operator would
		// learn about it from an execution error instead of a refusal at
		// ordering time.
		if _, err := schedules.ParseExpression(payload.Schedule.Expression); err != nil {
			return fmt.Errorf("schedule expression: %w", err)
		}
		if len(payload.Schedule.Command) == 0 {
			return fmt.Errorf("a schedule requires a command")
		}
		return checkScheduleCommand(payload.Schedule.Command)

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
		// Clear content and content from the store exclude each other:
		// otherwise it is unknown what really lands in the file, and the plan
		// would show something else.
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
		// The panel knows the manager from the host's inventory, but the
		// order has to be checkable without it: the shared fields we check
		// always, and those that depend on the system family - for the
		// manager that matches the description of the source.
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
		// A source we trust has to have something to show for itself. We
		// check the key here with the same code the host will use - so that
		// material without a key falls out at ordering time rather than after
		// approval.
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
		// The plan accepts the same thing a deployment does and names by
		// itself what the host will not accept: a refusal is the content of
		// the plan, not an error in the order.
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
		// We check the material here with the same code the host will use: an
		// order with a broken chain falls out at ordering time rather than
		// after approval and delivery to the host.
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
		// The request is named by an identifier or by a file path. The path is
		// needed here not for convenience: a certmonger request identifier is
		// different on every host, so a campaign renewing the same
		// certificate across the fleet has nothing to name it with.
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
		// The plan accepts the same thing a change does and names by itself
		// what the host will not accept: a refusal is the content of the
		// plan, not an error in the order.
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
		// The plan accepts the same thing a change does and names by itself
		// what the host will not accept: a refusal is the content of the
		// plan, not an error in the order.
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
		return nil

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
		// A destructive operation has to know what it aims at: the path alone
		// is not enough, because /dev/sdX points at a different disk after a
		// reboot.
		if payload.Storage.ExpectedSerial == "" && payload.Storage.ExpectedSizeBytes == 0 &&
			payload.Storage.ExpectedUUID == "" {
			return fmt.Errorf("formatting requires the identity of the device (serial, UUID or size)")
		}
		_, err := storage.FormatArguments(payload.Storage.Device,
			payload.Storage.FSType, payload.Storage.Label)
		return err

	case ActionDiskWipe:
		if payload.Storage == nil {
			return fmt.Errorf("the operation %s requires a storage payload", action)
		}
		if payload.Storage.ExpectedSerial == "" && payload.Storage.ExpectedSizeBytes == 0 &&
			payload.Storage.ExpectedUUID == "" {
			return fmt.Errorf("wiping requires the identity of the device (serial, UUID or size)")
		}
		_, err := storage.WipeArguments(payload.Storage.Device)
		return err

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
		// The plan accepts the same thing a change does and names by itself
		// what the host will not accept: a refusal is the content of the
		// plan, not an error in the order.
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
		return nil

	case ActionNetworkRollback:
		if payload.Network == nil || payload.Network.RollbackID == "" {
			return fmt.Errorf("a rollback requires the identifier of a plan")
		}
		return nil

	case ActionNetworkMTUSet, ActionNetworkRouteEnsure, ActionNetworkProfileApply:
		if payload.Network == nil {
			return fmt.Errorf("the operation %s requires a network payload", action)
		}
		if !interfaceName.MatchString(payload.Network.Interface) {
			return fmt.Errorf("invalid interface name %q", payload.Network.Interface)
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
		if version := payload.AgentUpgrade.RollbackVersion; version != "" &&
			!validAgentVersion(version) {
			return fmt.Errorf("the rollback version %q is not a package version", version)
		}
		if sum := payload.AgentUpgrade.PackageSHA256; sum != "" && !validChecksum(sum) {
			return fmt.Errorf("the package checksum is not a hexadecimal SHA-256")
		}
		return nil

	case ActionFollowJournal:
		if payload.Journal == nil {
			return fmt.Errorf("the operation %s requires a journal payload", action)
		}
		if payload.Journal.FollowSeconds > maxFollowSeconds {
			return fmt.Errorf("a live view must not last longer than %d s", maxFollowSeconds)
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

// packageNamePattern matches Debian and RPM package names. A name never
// reaches a shell, but validation is a second line of defence and rejects
// shapes that cannot be a package name.
// localUserNamePattern matches the range of names useradd accepts. Validation
// on the panel's side does not replace validation in the helper; both exist,
// because an envelope can reach the agent by a way other than through the
// panel.
var localUserNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)

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
//
// A payload with an empty sub-payload describes exactly the same operation as
// a payload without one, but it serialises differently - and a hash computed
// on both sides has to come out the same. On a read the panel sends an empty
// payload, the envelope has nothing to carry, and the agent reconstructs a
// zero structure from it: without this step the task ended with the refusal
// "the content does not match the plan", although the content was the same.
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

// PayloadHash computes the plan hash in canonical form. The agent computes it
// the same way and compares it with the envelope, so swapping the payload
// after approval is detectable.
//
// The canonical form is: "<type>\n<version>\n<payload JSON>". The JSON comes
// from encoding/json, which serialises struct fields in declaration order, so
// the result is deterministic.
func PayloadHash(action ActionType, version int, payload Payload) ([]byte, error) {
	encoded, err := json.Marshal(payload.withoutEmpty())
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\n%d\n%s", action, version, encoded))
	return sum[:], nil
}
