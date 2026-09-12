// Package authz holds the authorisation model: permissions, roles and
// scopes. A permission is always a pair of operation + scope, never an
// operation alone.
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Permission is a single permission. Host operations have their own
// permissions coming from opspec, so that restarting a service is not the
// same level of trust as reading the inventory.
type Permission string

const (
	PermHostRead      Permission = "host.read"
	PermInventoryRead Permission = "inventory.read"
	// PermInventoryRefresh allows ordering the inventory to be read again.
	// Separate from reading: looking at the stored picture is free, telling
	// the host to collect it anew is not - those are subprocesses on a
	// machine that is doing work.
	PermInventoryRefresh Permission = "inventory.refresh"
	PermAuditRead        Permission = "audit.read"
	PermJobRead          Permission = "job.read"
	PermJobCreate        Permission = "job.create"
	PermJobApprove       Permission = "job.approve"
	PermJobCancel        Permission = "job.cancel"
	// Enrollment requests: who may invite a machine into the fleet, who sees
	// the pending installations and who may revoke them.
	PermHostEnrollCreate Permission = "host.enroll.create"
	PermHostEnrollRead   Permission = "host.enroll.read"
	PermHostEnrollRevoke Permission = "host.enroll.revoke"
	// PermHostIdentityReplace allows restoring the identity of an existing
	// host. That is a right separate from inviting new machines: replacing an
	// identity means taking over a host that is already in the fleet.
	PermHostIdentityReplace Permission = "host.identity.replace"
	// The host lifecycle. Quarantine, lifting it and decommissioning are
	// three different decisions and have three different rights: cutting a
	// host off during an incident has to be fast, restoring and
	// decommissioning - deliberate.
	PermHostQuarantine        Permission = "host.quarantine"
	PermHostQuarantineRelease Permission = "host.quarantine.release"
	PermHostDecommission      Permission = "host.decommission"
	PermPrincipalManage       Permission = "principal.manage"

	PermUnitStart   Permission = "unit.start"
	PermUnitStop    Permission = "unit.stop"
	PermUnitRestart Permission = "unit.restart"
	PermUnitReload  Permission = "unit.reload"
	PermJournalRead Permission = "journal.read"

	PermPackagesPlan    Permission = "packages.plan"
	PermPackagesUpgrade Permission = "packages.upgrade"
	// PermAgentUpgrade is a right separate from upgrading packages: replacing
	// the agent cuts the host off from management for the restart and is
	// settled differently - only the host's return is a success.
	PermAgentUpgrade Permission = "agent.upgrade"
	// A repair touches packages that can decide whether the host starts, so
	// it is a separate permission rather than part of an upgrade.
	PermPackagesRepair Permission = "packages.repair"
	PermSystemReboot   Permission = "system.reboot"
	PermUnitStatus     Permission = "unit.status"
	// Enabling a unit changes the host's behaviour after every reboot, and
	// masking takes away the ability to start it even manually.
	PermUnitEnableWrite Permission = "unit.enable.write"
	PermUnitMaskWrite   Permission = "unit.mask.write"
	// Reading a log file reaches beyond the system journal.
	PermLogFileRead Permission = "logfile.read"
	// A live view keeps a process on the host for its whole duration, so it
	// is separated from a one-off journal read.
	PermJournalFollow Permission = "journal.follow"
	// Reading processes is diagnostics; sending a signal stops somebody's
	// work and cannot be undone.
	PermProcessRead   Permission = "process.read"
	PermProcessSignal Permission = "process.signal"
	// The full package lifecycle. Installing and removing are separated from
	// upgrading: those are three different decisions about the same host.
	// The full package list is an inventory read, but a separate one: the
	// vulnerability assessment comes from it, so it has its own permission
	// and its own trail.
	PermPackagesRead    Permission = "packages.read"
	PermPackagesInstall Permission = "packages.install"
	PermPackagesRemove  Permission = "packages.remove"
	PermPackagesHold    Permission = "packages.hold.write"
	// A package source is a decision about trust rather than about a version:
	// once it is added the host takes software from there as well, together
	// with package scripts that run as root. Hence a permission separate from
	// installing.
	PermPackagesRepository Permission = "packages.repository.write"
	// Scheduled jobs run without the operator, including when nobody is
	// watching - creating an entry is a decision separate from disabling or
	// removing it.
	PermScheduleWrite   Permission = "schedule.write"
	PermScheduleDisable Permission = "schedule.disable"
	PermScheduleRemove  Permission = "schedule.remove"
	PermScheduleRun     Permission = "schedule.run"
	// The network. Reading the profiles is preparation for a change, so it is
	// cheap; changing an address or a route can cut the host off from the
	// panel, and then no further order will arrive. Routes have their own
	// permission, because changing the default route redirects all of the
	// host's traffic, not just its address.
	PermNetworkRead       Permission = "network.read"
	PermNetworkWrite      Permission = "network.write"
	PermNetworkRouteWrite Permission = "network.route.write"
	// MTU and rollback are separated from rewriting an address: a wrong MTU
	// breaks large packets, a wrong address cuts the host off, and a rollback
	// returns to a state the operator may no longer remember.
	PermNetworkMTUWrite Permission = "network.mtu.write"
	PermNetworkRollback Permission = "network.rollback"
	// The host's DNS is separated from the records in the directory: an entry
	// in a zone is seen by every client of the domain, and the host's
	// resolver - only by that host.
	PermDNSRead Permission = "dns.read"
	// The resolver plan is a read: it computes a difference and changes nothing.
	PermDNSPlan      Permission = "dns.plan"
	PermDNSHostWrite Permission = "dns.host.write"
	// Directory DNS is a different scope from the host's resolver: there the
	// panel tells one host whom to ask, and here - what the directory answers
	// the whole network. A bad record breaks not one host but everyone who
	// asks about it, so the permission is separate and global.
	PermDNSDirectoryWrite Permission = "dns.directory.write"
	// The firewall. Reading the ruleset is preparation for a change; a bad
	// rule cuts the panel off from the host and there is nothing left to undo
	// the change with. Removing a rule, changing a zone and restoring the
	// state have their own permissions, because those are three different
	// decisions about the same host.
	PermFirewallRead         Permission = "firewall.read"
	PermFirewallWrite        Permission = "firewall.write"
	PermFirewallRuleRemove   Permission = "firewall.rule.remove"
	PermFirewallZoneWrite    Permission = "firewall.zone.write"
	PermFirewallServiceWrite Permission = "firewall.service.write"
	PermFirewallRestore      Permission = "firewall.restore"
	// Storage. Reading the topology is diagnostics; mounting decides whether
	// the host comes back from a reboot the way it stands now, and checking a
	// filesystem requires that nobody is using it.
	PermStorageRead        Permission = "storage.read"
	PermStorageMountWrite  Permission = "storage.mount.write"
	PermStorageMountRemove Permission = "storage.mount.remove"
	PermStorageFsck        Permission = "storage.fsck"
	// Extending and formatting are two different decisions: the first adds
	// space, the second deletes everything that was on it.
	PermStorageLVMWrite        Permission = "storage.lvm.write"
	PermStorageFilesystemWrite Permission = "storage.filesystem.write"
	PermStorageDestructive     Permission = "storage.destructive"
	PermStorageWipe            Permission = "storage.wipe"
	// The sshd server. A bad configuration cuts off administration of the
	// host, and replacing the key changes the identity every client sees.
	PermSSHRead          Permission = "ssh.read"
	PermSSHConfigWrite   Permission = "ssh.config.write"
	PermSSHHostKeyRotate Permission = "ssh.hostkey.rotate"
	// Security. A scan collects reconnaissance material about the host, so it
	// has its own permission separate from reading the findings. Remediation
	// has no host operation of its own: it is carried out by the module
	// responsible for the given thing, so the remediation permission does not
	// replace those modules' permissions.
	PermSecurityRead      Permission = "security.read"
	PermSecurityScan      Permission = "security.scan"
	PermSecurityRemediate Permission = "security.remediate"
	PermSecurityMACWrite  Permission = "security.mac.write"
	// Reloading the audit rules changes what the host records.
	PermSecurityAuditReload Permission = "security.audit.reload"
	// Backup. Reading the state of the repository is part of being on call -
	// a backup nobody knows is broken is worse than none. A restore has its
	// own permission and the highest risk: it unpacks old state onto a
	// running system.
	PermBackupRead    Permission = "backup.read"
	PermBackupRun     Permission = "backup.run"
	PermBackupVerify  Permission = "backup.verify"
	PermBackupRestore Permission = "backup.restore"

	// Vulnerabilities. The assessment is formed in the panel out of the
	// distribution vendor's findings; reading it is a separate permission,
	// because the fleet's list of vulnerabilities is reconnaissance material
	// about the fleet itself.
	PermVulnerabilityRead Permission = "vulnerability.read"

	// Monitoring. The panel has neither metrics nor alerting rules of its
	// own: it reads somebody else's. Silencing an alert does have its own
	// permission, because it switches a sensor off - and a probe leaves the
	// host with a connection, so it is not an ordinary inventory read.
	PermMonitoringRead    Permission = "monitoring.read"
	PermMonitoringProbe   Permission = "monitoring.probe"
	PermMonitoringSilence Permission = "monitoring.silence.write"

	// A maintenance window belongs to running operations rather than to
	// changing a host: it is declared by whoever watches the campaigns and
	// the on-call duty.
	PermHostMaintenanceWrite Permission = "host.maintenance.write"
	// Shutting a host down has its own permission, separate from rebooting:
	// after a reboot the host comes back by itself, after a shutdown somebody
	// has to go to it.
	PermSystemShutdown Permission = "system.shutdown"
	// Time. Reading and testing the sources are part of diagnosis - a drifted
	// clock looks from the outside like broken Kerberos or broken mTLS.
	// Changing the sources can step the clock, so it has its own
	// permission.
	PermTimeRead Permission = "time.read"
	// The time-source plan is a read: it computes a difference and changes nothing.
	PermTimePlan  Permission = "time.plan"
	PermTimeWrite Permission = "time.write"
	// The timezone has its own permission, because it is a different decision
	// from the time sources: it changes what the host shows to people and
	// writes to the journal, but it does not touch the moment the host lives
	// in.
	PermTimezoneWrite Permission = "time.timezone.write"
	// The kernel. A sysctl setting can be undone the same way it was set;
	// blacklisting a module shows its effect only when the host starts, so it
	// has a separate permission.
	PermKernelRead Permission = "kernel.read"
	// The module blacklist plan is a read: it computes a difference and changes nothing.
	PermKernelModulePlan      Permission = "kernel.module.plan"
	PermKernelSysctlWrite     Permission = "kernel.sysctl.write"
	PermKernelModuleWrite     Permission = "kernel.module.write"
	PermKernelModuleBlacklist Permission = "kernel.module.blacklist"
	// Configuration files. Reading the content is separated from the plan,
	// because the content is sometimes sensitive even when the file is not a
	// secret.
	PermFileRead     Permission = "file.read"
	PermFilePlan     Permission = "file.plan"
	PermFileWrite    Permission = "file.write"
	PermFileRemove   Permission = "file.remove"
	PermFileRollback Permission = "file.rollback"
	// PermDockerRead allows reading the state of the container engine.
	// Reading is separated from changes: looking at containers is part of the
	// work of anyone diagnosing a host, stopping them is not.
	PermDockerRead Permission = "docker.read"
	// PermDockerEvents allows reading the engine's event journal. Separate
	// from reading state: state says how things are, and the journal - what
	// happened here, including what the state no longer remembers.
	PermDockerEvents Permission = "docker.events"
	// Container operations have separate permissions: starting a service and
	// removing it are two different decisions, including as to who may take
	// them.
	PermDockerStart   Permission = "docker.container.start"
	PermDockerStop    Permission = "docker.container.stop"
	PermDockerRestart Permission = "docker.container.restart"
	PermDockerRemove  Permission = "docker.container.remove"
	PermDockerPull    Permission = "docker.image.pull"
	PermDockerPrune   Permission = "docker.prune"
	// Deploying a project starts the images the operator named on the host,
	// so it is separated from the rest of the container operations.
	PermComposePlan   Permission = "docker.compose.plan"
	PermComposeDeploy Permission = "docker.compose.deploy"

	PermCampaignRead    Permission = "campaign.read"
	PermCampaignCreate  Permission = "campaign.create"
	PermCampaignApprove Permission = "campaign.approve"
	PermCampaignControl Permission = "campaign.control"

	// Budgets say how many changes at once the fleet and the site can carry.
	// Reading them is part of the view into campaigns: without it a host
	// waiting on a budget looks like a forgotten host. Changing the capacity
	// is a separate permission, because raised silently it takes the meaning
	// out of every limit below.
	PermBudgetRead  Permission = "budget.read"
	PermBudgetWrite Permission = "budget.write"

	// Permissions of the identity layer. Managing sudo and HBAC is separated
	// from the rest, because a mistake in those rules opens access to the
	// whole fleet.
	PermIdentityRead Permission = "identity.read"
	// HBAC and sudo rules describe who may get access and raise their
	// privileges. That is reconnaissance material, so reading them is a
	// separate permission rather than part of an ordinary view into the
	// directory.
	PermIdentityPolicyRead  Permission = "identity.policy.read"
	PermIdentityUserWrite   Permission = "identity.user.write"
	PermIdentityGroupWrite  Permission = "identity.group.write"
	PermIdentityPolicyWrite Permission = "identity.policy.write"
	PermIdentityHostEnroll  Permission = "identity.host.enroll"

	// Local accounts are a separate path of access to the host, independent
	// of the directory. Creating an account and changing SSH keys means
	// granting access to the system, so they have their own permissions;
	// reading the list of accounts fits within the inventory.
	PermLocalUserRead    Permission = "localuser.read"
	PermLocalUserCreate  Permission = "localuser.create"
	PermLocalUserLock    Permission = "localuser.lock"
	PermLocalUserUnlock  Permission = "localuser.unlock"
	PermLocalSSHKeyWrite Permission = "localuser.sshkeys.write"

	// The metrics describe the fleet: the number of hosts, the states of
	// tasks and the validity of the CA. That is reconnaissance material, so
	// it has its own permission rather than being available to everyone who
	// knows the panel's address.
	PermMetricsRead Permission = "metrics.read"

	// The secret store. Reading concerns metadata - the value cannot be read
	// through the API at all. Destroying a version is irreversible, so it has
	// its own permission, separate from creating and rotating.
	PermSecretRead    Permission = "secret.read"
	PermSecretWrite   Permission = "secret.write"
	PermSecretDestroy Permission = "secret.destroy"

	// Certificates on hosts. Reading the dates and names is part of being on
	// call - an expired certificate looks like a service outage. A deployment
	// and a renewal replace the identity a service shows to the world, so
	// they have their own permissions. Pointing the panel at a file to watch
	// does not change the host and is a separate, lighter decision.
	// The deployment plan is a read: it computes a difference and changes
	// nothing.
	PermCertificatePlan   Permission = "certificate.plan"
	PermCertificateRead   Permission = "certificate.read"
	PermCertificateWatch  Permission = "certificate.watch"
	PermCertificateDeploy Permission = "certificate.deploy"
	// Trusting an authority is wider than one file: from that moment the host
	// accepts every certificate this authority signs. Withdrawing it has a
	// separate permission, because it breaks connections nobody changed.
	// The plan of a rotation step is a read: it reads the trust store and
	// computes a difference, changing nothing.
	PermCertificateTrustPlan   Permission = "certificate.trust.plan"
	PermCertificateTrustWrite  Permission = "certificate.trust.write"
	PermCertificateTrustRemove Permission = "certificate.trust.remove"
	PermCertificateRenew       Permission = "certificate.renew"

	// The fleet's CA is the root of trust for every host. Replacing it has
	// its own permission, separate from the rest of administration: a mistake
	// here cuts off the whole fleet.
	PermPKIRead   Permission = "pki.read"
	PermPKIRotate Permission = "pki.rotate"
)

// Role groups permissions. The split matches the roles from the document:
// platform admin, operator, auditor and approver.
type Role string

const (
	RoleViewer        Role = "viewer"
	RoleAuditor       Role = "auditor"
	RoleOperator      Role = "operator"
	RoleApprover      Role = "approver"
	RoleIdentityAdmin Role = "identity_admin"
	RolePlatformAdmin Role = "platform_admin"
)

// rolePermissions describes what each role may do. Separating the operator
// from the approver is deliberate: whoever orders a change should not be the
// one to approve it.
var rolePermissions = map[Role][]Permission{
	RoleViewer: {
		PermHostRead, PermInventoryRead, PermJobRead, PermCampaignRead, PermUnitStatus,
		PermIdentityRead, PermLocalUserRead, PermDockerRead, PermDockerEvents, PermProcessRead,
		PermNetworkRead, PermDNSRead, PermDNSPlan, PermFirewallRead, PermStorageRead, PermSSHRead, PermKernelRead, PermKernelModulePlan,
		PermTimeRead, PermTimePlan, PermSecurityRead, PermFilePlan, PermCertificateRead, PermCertificatePlan, PermCertificateTrustPlan,
		PermBackupRead, PermMonitoringRead, PermPackagesRead, PermVulnerabilityRead,
	},
	RoleAuditor: {
		PermHostRead, PermInventoryRead, PermJobRead, PermAuditRead, PermCampaignRead,
		PermIdentityRead, PermIdentityPolicyRead, PermLocalUserRead, PermDockerRead, PermDockerEvents,
		// An auditor looks at the state of the system, so the metrics and a
		// review of the CA are part of their work; replacing the CA is not.
		PermMetricsRead, PermPKIRead,
		// An auditor looks at the host's protective state and at the results
		// of the checks - that is the material of their work; they do not
		// have to fix it.
		PermSecurityRead, PermSecurityScan,
		// Certificate dates are audit material just as the protective state
		// is: an expiring certificate is a finding, not an outage.
		PermCertificateRead, PermCertificatePlan, PermCertificateTrustPlan,
		// A backup nobody verified is an audit finding, not an on-call
		// outage.
		PermBackupRead,
		// Alerts and silences are audit material: a silence set for a
		// quarter is a finding, not an on-call detail.
		PermMonitoringRead,
		// The package list is the basis of the vulnerability assessment, so
		// an auditor has to be able to see it - together with the assessment
		// itself.
		PermPackagesRead, PermVulnerabilityRead,
		// Secret metadata is part of the picture of the installation: what
		// exists, who created it, when it was rotated. Nobody sees the
		// values.
		PermSecretRead,
	},
	RoleOperator: {
		PermHostRead, PermInventoryRead, PermJobRead,
		// Refreshing the inventory is the first move in every outage: before
		// somebody starts changing a host, they want to know how things are
		// now.
		PermInventoryRefresh,
		PermJobCreate, PermJobCancel,
		PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload, PermJournalRead,
		// The operator runs containers but does not delete them: removing and
		// pruning are irreversible and belong to the administrator.
		PermDockerRead, PermDockerEvents,
		PermDockerStart, PermDockerStop, PermDockerRestart, PermDockerPull,
		// The operator plans project deployments but does not carry them out.
		PermComposePlan,
		// The operator plans upgrades but does not carry them out: a package
		// transaction is an operation of the highest risk and requires a
		// separate right.
		PermPackagesPlan, PermPackagesRead,
		// The operator plans and runs campaigns but does not approve them.
		PermCampaignRead, PermCampaignCreate, PermCampaignControl,
		// A maintenance window is a tool for running operations: it is the
		// operator who knows that this host is being repaired right now.
		PermHostMaintenanceWrite,
		// The operator sees local accounts but does not create them: granting
		// access to a host is an administrative decision rather than part of
		// handling an outage.
		PermLocalUserRead,
		// The operator reads the network configuration but does not change
		// it: a bad change cuts the host off and cannot be fixed remotely.
		PermNetworkRead, PermDNSRead, PermDNSPlan, PermFirewallRead, PermStorageRead, PermSSHRead, PermKernelRead, PermKernelModulePlan,
		// A drifted clock looks like a directory or certificate outage, so
		// testing the time sources belongs to the first diagnosis.
		PermTimeRead, PermTimePlan, PermSecurityRead, PermSecurityScan, PermFilePlan,
		PermVulnerabilityRead,
		// The operator looks at certificates and tells the panel which files
		// to watch; deploying a new one is already an administrator's
		// decision.
		PermCertificateRead, PermCertificatePlan, PermCertificateTrustPlan, PermCertificateWatch,
		// The operator makes and verifies copies; a restore is a separate
		// decision, because it unpacks old state onto a running system.
		PermBackupRead, PermBackupRun, PermBackupVerify,
		// On-call reads alerts, probes from the host and silences during a repair.
		PermMonitoringRead, PermMonitoringProbe, PermMonitoringSilence,
	},
	RoleApprover: {
		PermHostRead, PermInventoryRead, PermJobRead, PermAuditRead,
		PermJobApprove, PermCampaignRead, PermCampaignApprove,
		PermIdentityRead, PermIdentityPolicyRead, PermLocalUserRead,
	},
	// identity_admin manages the directory but does not run operations on hosts.
	RoleIdentityAdmin: {
		PermHostRead, PermInventoryRead, PermJobRead, PermCampaignRead,
		PermIdentityRead, PermIdentityPolicyRead, PermIdentityUserWrite,
		PermIdentityGroupWrite, PermIdentityPolicyWrite, PermIdentityHostEnroll,
		PermDNSDirectoryWrite,
		PermUnitStatus,
		// Local accounts are an alternative to the directory, so they belong
		// to the same role: it is the one responsible for who has access to
		// the hosts.
		PermLocalUserRead, PermLocalUserCreate, PermLocalUserLock,
		PermLocalUserUnlock, PermLocalSSHKeyWrite,
	},
	RolePlatformAdmin: {
		PermHostRead, PermInventoryRead, PermInventoryRefresh, PermJobRead, PermAuditRead,
		PermJobCreate, PermJobApprove, PermJobCancel,
		PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload, PermJournalRead,
		// The administrator also has the irreversible container operations.
		PermDockerRead, PermDockerEvents,
		PermDockerStart, PermDockerStop, PermDockerRestart,
		PermDockerPull, PermDockerRemove, PermDockerPrune,
		PermComposePlan, PermComposeDeploy,
		PermUnitStatus, PermUnitEnableWrite, PermUnitMaskWrite,
		PermJournalFollow, PermLogFileRead, PermProcessRead, PermProcessSignal,
		PermPackagesInstall, PermPackagesRemove, PermPackagesHold,
		PermPackagesRepository,
		PermScheduleWrite, PermScheduleDisable, PermScheduleRemove, PermScheduleRun,
		PermNetworkRead, PermNetworkWrite, PermNetworkRouteWrite,
		PermNetworkMTUWrite, PermNetworkRollback,
		PermDNSRead, PermDNSPlan, PermDNSHostWrite,
		PermFirewallRead, PermFirewallWrite, PermFirewallRuleRemove,
		PermFirewallZoneWrite, PermFirewallServiceWrite, PermFirewallRestore,
		PermStorageRead, PermStorageMountWrite, PermStorageMountRemove, PermStorageFsck,
		PermStorageLVMWrite, PermStorageFilesystemWrite,
		PermStorageDestructive, PermStorageWipe,
		PermSSHRead, PermSSHConfigWrite, PermSSHHostKeyRotate,
		PermKernelRead, PermKernelModulePlan, PermKernelSysctlWrite,
		PermKernelModuleWrite, PermKernelModuleBlacklist,
		PermTimeRead, PermTimePlan, PermTimeWrite, PermTimezoneWrite,
		PermSecurityRead, PermSecurityScan, PermSecurityRemediate,
		PermSecurityMACWrite, PermSecurityAuditReload,
		PermFileRead, PermFilePlan, PermFileWrite, PermFileRemove, PermFileRollback,
		PermPackagesPlan, PermPackagesRead, PermPackagesUpgrade, PermPackagesRepair,
		PermAgentUpgrade,
		PermSystemReboot, PermSystemShutdown, PermHostMaintenanceWrite,
		PermCampaignRead, PermCampaignCreate, PermCampaignApprove, PermCampaignControl,
		PermBudgetRead, PermBudgetWrite,
		PermIdentityRead, PermIdentityPolicyRead, PermIdentityUserWrite,
		PermIdentityGroupWrite, PermIdentityPolicyWrite, PermIdentityHostEnroll,
		PermDNSDirectoryWrite,
		PermHostEnrollCreate, PermHostEnrollRead, PermHostEnrollRevoke,
		PermHostIdentityReplace, PermHostQuarantine, PermHostQuarantineRelease,
		PermHostDecommission, PermPrincipalManage,
		PermLocalUserRead, PermLocalUserCreate, PermLocalUserLock,
		PermLocalUserUnlock, PermLocalSSHKeyWrite, PermMetricsRead,
		PermPKIRead, PermPKIRotate,
		PermSecretRead, PermSecretWrite, PermSecretDestroy,
		PermCertificateRead, PermCertificatePlan, PermCertificateTrustPlan, PermCertificateWatch,
		PermCertificateDeploy, PermCertificateRenew,
		PermCertificateTrustWrite, PermCertificateTrustRemove,
		PermBackupRead, PermBackupRun, PermBackupVerify, PermBackupRestore,
		PermMonitoringRead, PermMonitoringProbe, PermMonitoringSilence,
		PermVulnerabilityRead,
	},
}

// KnownRole checks whether the role exists.
func KnownRole(role Role) bool {
	_, ok := rolePermissions[role]
	return ok
}

// Permissions returns the sorted list of the role's permissions.
func (r Role) Permissions() []Permission {
	permissions := append([]Permission(nil), rolePermissions[r]...)
	sort.Slice(permissions, func(i, j int) bool { return permissions[i] < permissions[j] })
	return permissions
}

// Has checks whether the role has the permission.
func (r Role) Has(permission Permission) bool {
	for _, granted := range rolePermissions[r] {
		if granted == permission {
			return true
		}
	}
	return false
}

// AllRoles returns the sorted list of roles.
func AllRoles() []Role {
	roles := make([]Role, 0, len(rolePermissions))
	for role := range rolePermissions {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return roles
}

// Scope limits a permission to part of the fleet. An asterisk means any value.
type Scope struct {
	Site        string `json:"site"`
	Environment string `json:"environment"`
}

// Wildcard is the value meaning any scope.
const Wildcard = "*"

// Matches checks whether the permission's scope covers the target's scope.
// An asterisk on the permission's side matches everything. An empty target
// scope is not matched by a narrow permission: not knowing the target must
// not widen permissions.
func (s Scope) Matches(target Scope) bool {
	return matchesValue(s.Site, target.Site) && matchesValue(s.Environment, target.Environment)
}

func matchesValue(granted, target string) bool {
	if granted == Wildcard {
		return true
	}
	return granted != "" && granted == target
}

// String returns a readable description of the scope.
func (s Scope) String() string {
	return fmt.Sprintf("site=%s env=%s", orWildcard(s.Site), orWildcard(s.Environment))
}

func orWildcard(value string) string {
	if strings.TrimSpace(value) == "" {
		return Wildcard
	}
	return value
}

// Binding is a role assigned within a scope.
type Binding struct {
	Role  Role  `json:"role"`
	Scope Scope `json:"scope"`
}

// Principal is an authenticated identity together with its roles.
type Principal struct {
	ID          string    `json:"id"`
	Subject     string    `json:"subject"`
	DisplayName string    `json:"display_name,omitempty"`
	Kind        string    `json:"kind"`
	Bindings    []Binding `json:"bindings"`
}

// Can checks whether the identity has the permission within the target's scope.
func (p Principal) Can(permission Permission, target Scope) bool {
	for _, binding := range p.Bindings {
		if binding.Role.Has(permission) && binding.Scope.Matches(target) {
			return true
		}
	}
	return false
}

// CanAnywhere checks whether the identity has the permission in any scope at
// all.
//
// It serves collections: a list of hosts or campaigns has no single scope, so
// the question "may you see this globally" is wrongly put for it. The
// operator of one environment is to see their part of the fleet, not a
// refusal.
func (p Principal) CanAnywhere(permission Permission) bool {
	for _, binding := range p.Bindings {
		if binding.Role.Has(permission) {
			return true
		}
	}
	return false
}

// Permissions returns the sorted list of permissions the identity has in any
// scope at all.
//
// The interface uses it to hide the sections that must not be opened anyway.
// The source is the server rather than guesswork over role names in the
// browser: the policy can change without rebuilding the panel.
func (p Principal) Permissions() []string {
	unique := map[string]bool{}
	for _, binding := range p.Bindings {
		for _, permission := range binding.Role.Permissions() {
			unique[string(permission)] = true
		}
	}
	list := make([]string, 0, len(unique))
	for permission := range unique {
		list = append(list, permission)
	}
	sort.Strings(list)
	return list
}

// ScopesFor returns the scopes in which the identity has the given
// permission. An empty result means no permission anywhere.
func (p Principal) ScopesFor(permission Permission) []Scope {
	var scopes []Scope
	for _, binding := range p.Bindings {
		if binding.Role.Has(permission) {
			scopes = append(scopes, binding.Scope)
		}
	}
	return scopes
}

// Roles returns the names of the assigned roles, for audit and diagnostics.
func (p Principal) Roles() []string {
	seen := map[Role]bool{}
	var roles []string
	for _, binding := range p.Bindings {
		if !seen[binding.Role] {
			seen[binding.Role] = true
			roles = append(roles, string(binding.Role))
		}
	}
	sort.Strings(roles)
	return roles
}

// ScopeSQL builds an SQL condition narrowing the rows to the given scopes.
//
// The semantics are the same as in Matches, and that is the reason this
// function exists: narrowing lists once drifted apart from authorisation,
// because it was written separately. An asterisk means any scope and lifts
// the condition. An empty value matches nothing - not knowing the scope must
// not widen visibility.
//
// An empty list of scopes gives a false condition: an identity without any
// scope sees nothing. Returning an empty condition would mean access to
// everything, that is, an error in the worst possible direction.
//
// offset is the number of parameters already used in the query; the function
// numbers its own from the next one.
func ScopeSQL(scopes []Scope, siteColumn, envColumn string, offset int) (string, []any) {
	if len(scopes) == 0 {
		return "false", nil
	}

	var conditions []string
	var args []any
	for _, scope := range scopes {
		if scope.Site == Wildcard && scope.Environment == Wildcard {
			// A global scope covers everything, so further conditions no
			// longer matter.
			return "", nil
		}
		parts := make([]string, 0, 2)
		for _, dimension := range []struct {
			column string
			value  string
		}{{siteColumn, scope.Site}, {envColumn, scope.Environment}} {
			switch dimension.value {
			case Wildcard:
				// Any value in this dimension.
			case "":
				parts = append(parts, "false")
			default:
				args = append(args, dimension.value)
				parts = append(parts, fmt.Sprintf("%s = $%d", dimension.column, offset+len(args)))
			}
		}
		if len(parts) == 0 {
			return "", nil
		}
		conditions = append(conditions, "("+strings.Join(parts, " and ")+")")
	}
	return "(" + strings.Join(conditions, " or ") + ")", args
}
