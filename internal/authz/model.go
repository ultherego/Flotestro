// Package authz holds the authorisation model: permissions, roles and scopes.
package authz

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Permission is a single permission.
type Permission string

const (
	PermHostRead      Permission = "host.read"
	PermInventoryRead Permission = "inventory.read"
	// PermInventoryRefresh allows ordering the inventory to be read again.
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
	// PermHostEnrollBatch is the right to issue one token good for many machines.
	PermHostEnrollBatch Permission = "host.enroll.batch"
	// PermRelayEnrollCreate is separate from inviting hosts: a relay carries
	// the traffic of a whole site, so the right to add one is its own role.
	PermRelayEnrollCreate Permission = "relay.enroll.create"
	// PermRelayManage covers the life of a relay after its registration: revoking
	// one cuts a whole site off from the panel, so it is a right separate from
	// adding one.
	PermRelayManage Permission = "relay.manage"
	// PermHostIdentityReplace allows restoring the identity of an existing host.
	PermHostIdentityReplace Permission = "host.identity.replace"
	// The host lifecycle.
	PermHostQuarantine        Permission = "host.quarantine"
	PermHostQuarantineRelease Permission = "host.quarantine.release"
	PermHostDecommission      Permission = "host.decommission"
	PermPrincipalManage       Permission = "principal.manage"
	// Teams draw the boundary of what somebody may touch, so the two rights that
	// move that boundary are their own, and both are global: moving a host into a
	// team changes who may act on it, and binding a role to a team hands that.
	PermHostScopeWrite   Permission = "host.scope.write"
	PermTeamBindingWrite Permission = "team.binding.write"

	PermUnitStart   Permission = "unit.start"
	PermUnitStop    Permission = "unit.stop"
	PermUnitRestart Permission = "unit.restart"
	PermUnitReload  Permission = "unit.reload"
	PermJournalRead Permission = "journal.read"

	PermPackagesPlan    Permission = "packages.plan"
	PermPackagesUpgrade Permission = "packages.upgrade"
	// PermAgentUpgrade is a right separate from upgrading packages: replacing the
	// agent cuts the host off from management for the restart and is settled
	// differently - only the host's return is a success.
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
	// Clearing the failed state of a unit touches no process; it belongs
	// with restarting, which is the verb it usually follows.
	PermUnitResetFailed Permission = "unit.reset_failed"
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
	PermPackagesRead    Permission = "packages.read"
	PermPackagesInstall Permission = "packages.install"
	PermPackagesRemove  Permission = "packages.remove"
	PermPackagesHold    Permission = "packages.hold.write"
	// A package source is a decision about trust rather than about a version:
	// once it is added the host takes software from there as well, together with
	// package scripts that run as root.
	PermPackagesRepository Permission = "packages.repository.write"
	// Scheduled jobs run without the operator, including when nobody is watching
	// - creating an entry is a decision separate from disabling or removing it.
	PermScheduleWrite   Permission = "schedule.write"
	PermScheduleDisable Permission = "schedule.disable"
	PermScheduleRemove  Permission = "schedule.remove"
	PermScheduleRun     Permission = "schedule.run"
	// A preview of the next runs of an expression computes dates on the
	// host and writes nothing.
	PermSchedulePreview Permission = "schedule.preview"
	// An entry for root is a level of trust above writing schedules: the
	// grant is separate and travels in the capability under this name.
	PermScheduleRootExec Permission = "schedule.root.exec"
	// A write whose validator the host lacks may go on only with this
	// grant and an order that says so; without it the host refuses.
	PermFileWriteUnvalidated Permission = "file.write.unvalidated"
	// The network.
	PermNetworkRead       Permission = "network.read"
	PermNetworkWrite      Permission = "network.write"
	PermNetworkRouteWrite Permission = "network.route.write"
	// MTU and rollback are separated from rewriting an address: a wrong MTU
	// breaks large packets, a wrong address cuts the host off, and a rollback
	// returns to a state the operator may no longer remember.
	PermNetworkMTUWrite Permission = "network.mtu.write"
	PermNetworkRollback Permission = "network.rollback"
	// Building a layer moves the addressing of every member onto the layer above,
	// and removing one gives it back: two decisions of their own, separate from
	// rewriting an address on a single interface.
	PermNetworkLinkWrite  Permission = "network.link.write"
	PermNetworkLinkRemove Permission = "network.link.remove"
	// The host's DNS is separated from the records in the directory: an entry in
	// a zone is seen by every client of the domain, and the host's resolver -
	// only by that host.
	PermDNSRead Permission = "dns.read"
	// The resolver plan is a read: it computes a difference and changes nothing.
	PermDNSPlan      Permission = "dns.plan"
	PermDNSHostWrite Permission = "dns.host.write"
	// Directory DNS is a different scope from the host's resolver: there the
	// panel tells one host whom to ask, and here - what the directory answers the
	// whole network.
	PermDNSDirectoryWrite Permission = "dns.directory.write"
	// The firewall.
	PermFirewallRead         Permission = "firewall.read"
	PermFirewallWrite        Permission = "firewall.write"
	PermFirewallRuleRemove   Permission = "firewall.rule.remove"
	PermFirewallZoneWrite    Permission = "firewall.zone.write"
	PermFirewallServiceWrite Permission = "firewall.service.write"
	PermFirewallRestore      Permission = "firewall.restore"
	// Storage.
	PermStorageRead        Permission = "storage.read"
	PermStorageMountWrite  Permission = "storage.mount.write"
	PermStorageMountRemove Permission = "storage.mount.remove"
	PermStorageFsck        Permission = "storage.fsck"
	// The SMART read is diagnostics like the topology read: the device's
	// own health log, changing nothing.
	PermStorageSmartRead Permission = "storage.smart.read"
	// Extending and formatting are two different decisions: the first adds
	// space, the second deletes everything that was on it.
	PermStorageLVMWrite        Permission = "storage.lvm.write"
	PermStorageFilesystemWrite Permission = "storage.filesystem.write"
	PermStorageDestructive     Permission = "storage.destructive"
	PermStorageWipe            Permission = "storage.wipe"
	// The layers above a bare disk.
	PermStorageRAIDFail          Permission = "storage.raid.fail"
	PermStorageRAIDRemove        Permission = "storage.raid.remove"
	PermStorageRAIDAdd           Permission = "storage.raid.add"
	PermStorageLVMVolumeCreate   Permission = "storage.lvm.volume.create"
	PermStorageLVMVolumeRemove   Permission = "storage.lvm.volume.remove"
	PermStorageLVMGroupExtend    Permission = "storage.lvm.group.extend"
	PermStorageLVMSnapshotCreate Permission = "storage.lvm.snapshot.create"
	PermStorageLVMSnapshotRemove Permission = "storage.lvm.snapshot.remove"
	// The sshd server. A bad configuration cuts off administration of the
	// host, and replacing the key changes the identity every client sees.
	PermSSHRead          Permission = "ssh.read"
	PermSSHConfigWrite   Permission = "ssh.config.write"
	PermSSHHostKeyRotate Permission = "ssh.hostkey.rotate"
	// Security. A scan collects reconnaissance material about the host, so it has
	// its own permission separate from reading the findings.
	PermSecurityRead      Permission = "security.read"
	PermSecurityScan      Permission = "security.scan"
	PermSecurityRemediate Permission = "security.remediate"
	PermSecurityMACWrite  Permission = "security.mac.write"
	// Reloading the audit rules changes what the host records.
	PermSecurityAuditReload Permission = "security.audit.reload"
	// Backup. Reading the state of the repository is part of being on call - a
	// backup nobody knows is broken is worse than none.
	PermBackupRead    Permission = "backup.read"
	PermBackupRun     Permission = "backup.run"
	PermBackupVerify  Permission = "backup.verify"
	PermBackupRestore Permission = "backup.restore"

	// Vulnerabilities.
	PermVulnerabilityRead Permission = "vulnerability.read"

	// Monitoring. The panel keeps the resource samples of the hosts and evaluates
	// its own alert rules over them.
	PermMonitoringRead       Permission = "monitoring.read"
	PermMonitoringProbe      Permission = "monitoring.probe"
	PermMonitoringSilence    Permission = "monitoring.silence.write"
	PermMonitoringRulesWrite Permission = "monitoring.rules.write"
	// Notifications.
	PermNotificationRead   Permission = "notification.read"
	PermNotificationManage Permission = "notification.manage"

	// A maintenance window belongs to running operations rather than to changing
	// a host: it is declared by whoever watches the campaigns and the on-call
	// duty.
	PermHostMaintenanceWrite Permission = "host.maintenance.write"
	// Tags and groups describe the fleet in the panel and change nothing on a
	// host, but they decide which hosts a campaign reaches: a wrong tag puts a
	// machine into somebody else's rollout.
	PermHostTagWrite   Permission = "host.tag.write"
	PermHostGroupWrite Permission = "host.group.write"
	// Shutting a host down has its own permission, separate from rebooting: after
	// a reboot the host comes back by itself, after a shutdown somebody has to go
	// to it.
	PermSystemShutdown Permission = "system.shutdown"
	// Renaming a host changes its identity towards everything that knows it
	// by name; it belongs to the administrator alone.
	PermSystemHostnameWrite Permission = "system.hostname.write"
	// Time. Reading and testing the sources are part of diagnosis - a drifted
	// clock looks from the outside like broken Kerberos or broken mTLS.
	PermTimeRead Permission = "time.read"
	// The time-source plan is a read: it computes a difference and changes nothing.
	PermTimePlan  Permission = "time.plan"
	PermTimeWrite Permission = "time.write"
	// The timezone has its own permission, because it is a different decision
	// from the time sources: it changes what the host shows to people and writes
	// to the journal, but it does not touch the moment the host lives in.
	PermTimezoneWrite Permission = "time.timezone.write"
	// The kernel.
	PermKernelRead Permission = "kernel.read"
	// The module blacklist plan is a read: it computes a difference and changes nothing.
	PermKernelModulePlan      Permission = "kernel.module.plan"
	PermKernelSysctlWrite     Permission = "kernel.sysctl.write"
	PermKernelModuleWrite     Permission = "kernel.module.write"
	PermKernelModuleBlacklist Permission = "kernel.module.blacklist"
	// Configuration files.
	PermFileRead     Permission = "file.read"
	PermFilePlan     Permission = "file.plan"
	PermFileWrite    Permission = "file.write"
	PermFileRemove   Permission = "file.remove"
	PermFileRollback Permission = "file.rollback"
	// PermDockerRead allows reading the state of the container engine.
	PermDockerRead Permission = "docker.read"
	// PermDockerEvents allows reading the engine's event journal.
	PermDockerEvents Permission = "docker.events"
	// PermDockerLogs allows reading what a container wrote.
	PermDockerLogs Permission = "docker.container.logs"
	// Container operations have separate permissions: starting a service and
	// removing it are two different decisions, including as to who may take them.
	PermDockerStart   Permission = "docker.container.start"
	PermDockerStop    Permission = "docker.container.stop"
	PermDockerRestart Permission = "docker.container.restart"
	PermDockerRemove  Permission = "docker.container.remove"
	PermDockerPull    Permission = "docker.image.pull"
	PermDockerPrune   Permission = "docker.prune"
	// A declared object is its own decision, separate from starting a container
	// or pruning what nobody uses: a declaration replaces what stands on the host
	// when it differs, and the plan that says what differs is read with the plan.
	PermDockerPlan            Permission = "docker.plan"
	PermDockerContainerEnsure Permission = "docker.container.ensure"
	PermDockerNetworkEnsure   Permission = "docker.network.ensure"
	PermDockerNetworkRemove   Permission = "docker.network.remove"
	PermDockerVolumeEnsure    Permission = "docker.volume.ensure"
	PermDockerVolumeRemove    Permission = "docker.volume.remove"
	// Deploying a project starts the images the operator named on the host,
	// so it is separated from the rest of the container operations.
	PermComposePlan   Permission = "docker.compose.plan"
	PermComposeDeploy Permission = "docker.compose.deploy"

	PermCampaignRead    Permission = "campaign.read"
	PermCampaignCreate  Permission = "campaign.create"
	PermCampaignApprove Permission = "campaign.approve"
	PermCampaignControl Permission = "campaign.control"

	// Budgets say how many changes at once the fleet and the site can carry.
	PermBudgetRead  Permission = "budget.read"
	PermBudgetWrite Permission = "budget.write"

	// Desired-state policies.
	PermPolicyRead          Permission = "policy.read"
	PermPolicyWrite         Permission = "policy.write"
	PermPolicyPublish       Permission = "policy.publish"
	PermPolicyRemediateAuto Permission = "policy.remediate.auto"

	// Permissions of the identity layer. Managing sudo and HBAC is separated from
	// the rest, because a mistake in those rules opens access to the whole fleet.
	PermIdentityRead Permission = "identity.read"
	// HBAC and sudo rules describe who may get access and raise their privileges.
	PermIdentityPolicyRead  Permission = "identity.policy.read"
	PermIdentityUserWrite   Permission = "identity.user.write"
	PermIdentityGroupWrite  Permission = "identity.group.write"
	PermIdentityPolicyWrite Permission = "identity.policy.write"
	PermIdentityHostEnroll  Permission = "identity.host.enroll"
	// Taking a host out of the domain is a separate right: it cuts every
	// directory account off the host, and bringing hosts in does not imply the
	// right to do that.
	PermIdentityHostLeave Permission = "identity.host.leave"
	// Rotating a service keytab is a right of its own, as the architecture
	// document asks: the directory retires the credential a service authenticates
	// with, and the host fetches a new one.
	PermIdentityKeytabRotate Permission = "identity.keytab.rotate"

	// Local accounts are a separate path of access to the host, independent of
	// the directory.
	PermLocalUserRead    Permission = "localuser.read"
	PermLocalUserCreate  Permission = "localuser.create"
	PermLocalUserLock    Permission = "localuser.lock"
	PermLocalUserUnlock  Permission = "localuser.unlock"
	PermLocalSSHKeyWrite Permission = "localuser.sshkeys.write"
	// The keys edited one at a time: appending a key and taking a named one away
	// are ordinary changes of access, while writing the whole list anew is the
	// operation that has cut accounts off by accident and keeps a permission of.
	PermLocalSSHKeyAdd     Permission = "localuser.sshkeys.add"
	PermLocalSSHKeyRemove  Permission = "localuser.sshkeys.remove"
	PermLocalSSHKeyReplace Permission = "localuser.sshkeys.replace"
	// PermAccountsPrivilegedGroups is asked for on top of the permission of the
	// change whenever an account lands in a group that is root by another name:
	// sudo, wheel, docker, lxd.
	PermAccountsPrivilegedGroups Permission = "accounts.privileged_groups"
	// The groups and the expiry of an account are changes of access with a scope
	// of their own: a group can be root by another name, an expiry is a lock with
	// a date.
	PermLocalUserGroupsWrite Permission = "localuser.groups.write"
	PermLocalUserExpiryWrite Permission = "localuser.expiry.write"
	PermLocalUserDelete      Permission = "localuser.delete"

	// The metrics describe the fleet: the number of hosts, the states of tasks
	// and the validity of the CA.
	PermMetricsRead Permission = "metrics.read"

	// The secret store. Reading concerns metadata - the value cannot be read
	// through the API at all.
	PermSecretRead    Permission = "secret.read"
	PermSecretWrite   Permission = "secret.write"
	PermSecretDestroy Permission = "secret.destroy"

	// Certificates on hosts. Reading the dates and names is part of being on call
	// - an expired certificate looks like a service outage.
	PermCertificatePlan   Permission = "certificate.plan"
	PermCertificateRead   Permission = "certificate.read"
	PermCertificateWatch  Permission = "certificate.watch"
	PermCertificateDeploy Permission = "certificate.deploy"
	// Trusting an authority is wider than one file: from that moment the host
	// accepts every certificate this authority signs.
	PermCertificateTrustPlan   Permission = "certificate.trust.plan"
	PermCertificateTrustWrite  Permission = "certificate.trust.write"
	PermCertificateTrustRemove Permission = "certificate.trust.remove"
	PermCertificateRenew       Permission = "certificate.renew"

	// The fleet's CA is the root of trust for every host.
	PermPKIRead   Permission = "pki.read"
	PermPKIRotate Permission = "pki.rotate"

	// The effective configuration of the installation: which provider signs
	// people in, which directory the panel reads, what the step-up policy is.
	PermSettingsRead Permission = "settings.read"
	// PermSettingsAdvertiseWrite is naming the address the whole fleet dials. It
	// is separate from reading the settings and from every other right because
	// what it changes is the rendezvous point of the installation: the panel's
	// own certificate is issued again for the new name, every agent configuration
	// handed out afterwards carries it, and the name goes on being refused to a
	// relay. No existing permission covers that - rotating the fleet CA is of the
	// same gravity but a different subject, and managing relays or inviting hosts
	// are narrower - so borrowing one would have granted an unrelated power.
	PermSettingsAdvertiseWrite Permission = "settings.advertise.write"
	// The support bundle of the panel. Asking for one reads everything the panel
	// knows about itself, so it is a right of its own.
	PermSupportBundleCreate Permission = "support.bundle.create"
	PermSupportBundleRead   Permission = "support.bundle.read"
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

// rolePermissions describes what each role may do.
var rolePermissions = map[Role][]Permission{
	RoleViewer: {
		PermHostRead, PermInventoryRead, PermJobRead, PermCampaignRead, PermUnitStatus,
		PermIdentityRead, PermLocalUserRead, PermDockerRead, PermDockerEvents, PermProcessRead,
		PermNetworkRead, PermDNSRead, PermDNSPlan, PermFirewallRead, PermStorageRead, PermStorageSmartRead, PermSSHRead, PermKernelRead, PermKernelModulePlan,
		PermTimeRead, PermTimePlan, PermSecurityRead, PermFilePlan, PermCertificateRead, PermCertificatePlan, PermCertificateTrustPlan,
		PermBackupRead, PermMonitoringRead, PermPackagesRead, PermVulnerabilityRead,
		PermPolicyRead,
	},
	RoleAuditor: {
		PermHostRead, PermInventoryRead, PermJobRead, PermAuditRead, PermCampaignRead,
		PermIdentityRead, PermIdentityPolicyRead, PermLocalUserRead, PermDockerRead, PermDockerEvents,
		// An auditor looks at the state of the system, so the metrics and a
		// review of the CA are part of their work; replacing the CA is not.
		PermMetricsRead, PermPKIRead,
		// An auditor looks at the host's protective state and at the results of the
		// checks - that is the material of their work; they do not have to fix it.
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
		// The package list is the basis of the vulnerability assessment, so an
		// auditor has to be able to see it - together with the assessment itself.
		PermPackagesRead, PermVulnerabilityRead,
		// Secret metadata is part of the picture of the installation: what exists,
		// who created it, when it was rotated.
		PermSecretRead,
		// Compliance with the declared state is audit material of the
		// first order: the verdicts, not the fixes.
		PermPolicyRead,
	},
	RoleOperator: {
		PermHostRead, PermInventoryRead, PermJobRead,
		// Refreshing the inventory is the first move in every outage: before
		// somebody starts changing a host, they want to know how things are now.
		PermInventoryRefresh,
		PermJobCreate, PermJobCancel,
		PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload, PermUnitResetFailed,
		PermJournalRead,
		// The operator runs containers but does not delete them: removing and
		// pruning are irreversible and belong to the administrator.
		PermDockerRead, PermDockerEvents, PermDockerLogs,
		PermDockerStart, PermDockerStop, PermDockerRestart, PermDockerPull,
		// The operator plans project deployments and declarations but does
		// not carry them out: a plan is a read of the difference.
		PermComposePlan, PermDockerPlan,
		// The operator plans upgrades but does not carry them out: a package
		// transaction is an operation of the highest risk and requires a separate
		// right.
		PermPackagesPlan, PermPackagesRead,
		// The operator plans and runs campaigns but does not approve them.
		PermCampaignRead, PermCampaignCreate, PermCampaignControl,
		// The operator writes the desired state as a draft; publishing it
		// is the approval, and that stays with the approver.
		PermPolicyRead, PermPolicyWrite,
		// A maintenance window is a tool for running operations: it is the
		// operator who knows that this host is being repaired right now.
		PermHostMaintenanceWrite,
		// Tags and groups are how the operator names the targets of a
		// campaign, so they go with the right to order one.
		PermHostTagWrite, PermHostGroupWrite,
		// The operator invites a machine into their own site, one token per host,
		// sees the pending installations and closes a token that leaked.
		PermHostEnrollCreate, PermHostEnrollRead, PermHostEnrollRevoke,
		// The operator sees local accounts but does not create them: granting access
		// to a host is an administrative decision rather than part of handling an
		// outage.
		PermLocalUserRead, PermLocalUserGroupsWrite, PermLocalUserExpiryWrite,
		// The operator reads the network configuration but does not change
		// it: a bad change cuts the host off and cannot be fixed remotely.
		PermNetworkRead, PermDNSRead, PermDNSPlan, PermFirewallRead, PermStorageRead, PermStorageSmartRead, PermSSHRead, PermKernelRead, PermKernelModulePlan,
		// A drifted clock looks like a directory or certificate outage, so
		// testing the time sources belongs to the first diagnosis.
		PermTimeRead, PermTimePlan, PermSecurityRead, PermSecurityScan, PermFilePlan,
		PermVulnerabilityRead,
		// The operator looks at certificates and tells the panel which files to
		// watch; deploying a new one is already an administrator's decision.
		PermCertificateRead, PermCertificatePlan, PermCertificateTrustPlan, PermCertificateWatch,
		// The operator makes and verifies copies; a restore is a separate
		// decision, because it unpacks old state onto a running system.
		PermBackupRead, PermBackupRun, PermBackupVerify,
		// On-call reads alerts, probes from the host and silences during a repair.
		PermMonitoringRead, PermMonitoringProbe, PermMonitoringSilence, PermNotificationRead,
	},
	RoleApprover: {
		PermHostRead, PermInventoryRead, PermJobRead, PermAuditRead,
		PermJobApprove, PermCampaignRead, PermCampaignApprove,
		PermIdentityRead, PermIdentityPolicyRead, PermLocalUserRead,
		PermPolicyRead, PermPolicyPublish,
	},
	// identity_admin manages the directory but does not run operations on hosts.
	RoleIdentityAdmin: {
		PermHostRead, PermInventoryRead, PermJobRead, PermCampaignRead,
		PermIdentityRead, PermIdentityPolicyRead, PermIdentityUserWrite,
		PermIdentityGroupWrite, PermIdentityPolicyWrite, PermIdentityHostEnroll,
		PermIdentityHostLeave, PermIdentityKeytabRotate,
		PermDNSDirectoryWrite,
		PermUnitStatus,
		// Local accounts are an alternative to the directory, so they belong to the
		// same role: it is the one responsible for who has access to the hosts.
		PermLocalUserRead, PermLocalUserCreate, PermLocalUserLock,
		PermLocalUserUnlock, PermLocalSSHKeyWrite,
		PermLocalSSHKeyAdd, PermLocalSSHKeyRemove, PermLocalSSHKeyReplace,
		// Not accounts.privileged_groups: this role opens ordinary accounts, and an
		// account that is root by another name is opened by whoever may grant root.
		PermNotificationRead,
		PermScheduleRootExec,
	},
	RolePlatformAdmin: {
		PermHostRead, PermInventoryRead, PermInventoryRefresh, PermJobRead, PermAuditRead,
		PermJobCreate, PermJobApprove, PermJobCancel,
		PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload, PermUnitResetFailed,
		PermJournalRead,
		// The administrator also has the irreversible container operations.
		PermDockerRead, PermDockerEvents, PermDockerLogs,
		PermDockerStart, PermDockerStop, PermDockerRestart,
		PermDockerPull, PermDockerRemove, PermDockerPrune,
		PermDockerPlan, PermDockerContainerEnsure,
		PermDockerNetworkEnsure, PermDockerNetworkRemove,
		PermDockerVolumeEnsure, PermDockerVolumeRemove,
		PermComposePlan, PermComposeDeploy,
		PermUnitStatus, PermUnitEnableWrite, PermUnitMaskWrite,
		PermJournalFollow, PermLogFileRead, PermProcessRead, PermProcessSignal,
		PermPackagesInstall, PermPackagesRemove, PermPackagesHold,
		PermPackagesRepository,
		PermScheduleWrite, PermScheduleDisable, PermScheduleRemove, PermScheduleRun,
		PermSchedulePreview, PermScheduleRootExec, PermFileWriteUnvalidated,
		PermNetworkRead, PermNetworkWrite, PermNetworkRouteWrite,
		PermNetworkMTUWrite, PermNetworkRollback,
		PermNetworkLinkWrite, PermNetworkLinkRemove,
		PermDNSRead, PermDNSPlan, PermDNSHostWrite,
		PermFirewallRead, PermFirewallWrite, PermFirewallRuleRemove,
		PermFirewallZoneWrite, PermFirewallServiceWrite, PermFirewallRestore,
		PermStorageRead, PermStorageSmartRead, PermStorageMountWrite, PermStorageMountRemove, PermStorageFsck,
		PermStorageLVMWrite, PermStorageFilesystemWrite,
		PermStorageDestructive, PermStorageWipe,
		PermStorageRAIDFail, PermStorageRAIDRemove, PermStorageRAIDAdd,
		PermStorageLVMVolumeCreate, PermStorageLVMVolumeRemove, PermStorageLVMGroupExtend,
		PermStorageLVMSnapshotCreate, PermStorageLVMSnapshotRemove,
		PermSSHRead, PermSSHConfigWrite, PermSSHHostKeyRotate,
		PermKernelRead, PermKernelModulePlan, PermKernelSysctlWrite,
		PermKernelModuleWrite, PermKernelModuleBlacklist,
		PermTimeRead, PermTimePlan, PermTimeWrite, PermTimezoneWrite,
		PermSecurityRead, PermSecurityScan, PermSecurityRemediate,
		PermSecurityMACWrite, PermSecurityAuditReload,
		PermFileRead, PermFilePlan, PermFileWrite, PermFileRemove, PermFileRollback,
		PermPackagesPlan, PermPackagesRead, PermPackagesUpgrade, PermPackagesRepair,
		PermAgentUpgrade,
		PermSystemReboot, PermSystemShutdown, PermSystemHostnameWrite, PermHostMaintenanceWrite,
		PermHostTagWrite, PermHostGroupWrite,
		PermCampaignRead, PermCampaignCreate, PermCampaignApprove, PermCampaignControl,
		PermBudgetRead, PermBudgetWrite,
		PermPolicyRead, PermPolicyWrite, PermPolicyPublish, PermPolicyRemediateAuto,
		PermIdentityRead, PermIdentityPolicyRead, PermIdentityUserWrite,
		PermIdentityGroupWrite, PermIdentityPolicyWrite, PermIdentityHostEnroll,
		PermIdentityHostLeave, PermIdentityKeytabRotate,
		PermDNSDirectoryWrite,
		PermHostEnrollCreate, PermHostEnrollRead, PermHostEnrollRevoke, PermHostEnrollBatch,
		PermRelayEnrollCreate, PermRelayManage,
		PermHostIdentityReplace, PermHostQuarantine, PermHostQuarantineRelease,
		PermHostDecommission, PermPrincipalManage,
		PermHostScopeWrite, PermTeamBindingWrite,
		PermLocalUserRead, PermLocalUserCreate, PermLocalUserLock,
		PermLocalUserUnlock, PermLocalSSHKeyWrite, PermLocalUserGroupsWrite,
		PermLocalSSHKeyAdd, PermLocalSSHKeyRemove, PermLocalSSHKeyReplace,
		PermAccountsPrivilegedGroups,
		PermLocalUserExpiryWrite, PermLocalUserDelete, PermMetricsRead,
		PermPKIRead, PermPKIRotate,
		PermSecretRead, PermSecretWrite, PermSecretDestroy,
		PermCertificateRead, PermCertificatePlan, PermCertificateTrustPlan, PermCertificateWatch,
		PermCertificateDeploy, PermCertificateRenew,
		PermCertificateTrustWrite, PermCertificateTrustRemove,
		PermBackupRead, PermBackupRun, PermBackupVerify, PermBackupRestore,
		PermMonitoringRead, PermMonitoringProbe, PermMonitoringSilence, PermMonitoringRulesWrite,
		PermNotificationRead, PermNotificationManage,
		PermVulnerabilityRead,
		PermSettingsRead, PermSettingsAdvertiseWrite,
		// A bundle is a reading of the whole panel; it belongs to whoever
		// administers the panel and to nobody else.
		PermSupportBundleCreate, PermSupportBundleRead,
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
	// Team is the group of hosts a target belongs to. TeamAny says the binding
	// is not narrowed by team at all; the two are exclusive, which the database
	// holds to with a check constraint. A binding never leaves both unset: an
	// omitted field must fail rather than widen what somebody may reach.
	Team    string `json:"team,omitempty"`
	TeamAny bool   `json:"team_any,omitempty"`
	// Owners and Tags narrow the binding further. Within a list the values are
	// alternatives; across the categories every one has to be satisfied.
	Owners []string `json:"owners,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// Wildcard is the value meaning any scope.
const Wildcard = "*"

// Placement is the scope of a binding that narrows by site and environment and
// by nothing else. It says so in every category rather than leaving three of
// them empty: an empty category matches nothing, so a binding built field by
// field and missing one grants nothing at all - which is the safe way round,
// and this is how a caller says it meant "any".
func Placement(site, environment string) Scope {
	return Scope{
		Site: site, Environment: environment, TeamAny: true,
		Owners: []string{Wildcard}, Tags: []string{Wildcard},
	}
}

// OfTeam is the scope of a binding that narrows to one team, and to nothing
// else within it.
func OfTeam(team string) Scope {
	return Scope{
		Site: Wildcard, Environment: Wildcard, Team: team,
		Owners: []string{Wildcard}, Tags: []string{Wildcard},
	}
}

// TargetOf is the other side: what a thing is, for a binding to be held
// against. The facts, not a permission.
func TargetOf(site, environment, team, owner string, tags []string) Scope {
	target := Scope{Site: site, Environment: environment, Team: team, Tags: tags}
	if owner != "" {
		target.Owners = []string{owner}
	}
	return target
}

// Matches checks whether the permission's scope covers the target's scope.
//
// Every category has to be satisfied - site and environment and team and owner
// and tag - and within a category the values are alternatives. An asterisk is
// how a binding says it does not care about a category; an empty value is not,
// because a field nobody filled in must not widen what a role reaches.
func (s Scope) Matches(target Scope) bool {
	return matchesValue(s.Site, target.Site) &&
		matchesValue(s.Environment, target.Environment) &&
		s.matchesTeam(target.Team) &&
		matchesAny(s.Owners, target.Owners) &&
		matchesAny(s.Tags, target.Tags)
}

// Covers says the binding narrows by nothing at all: every category is an
// asterisk and the team is any. Such a binding needs no condition in SQL.
func (s Scope) Covers() bool {
	return s.Site == Wildcard && s.Environment == Wildcard && s.TeamAny &&
		hasWildcard(s.Owners) && hasWildcard(s.Tags)
}

func hasWildcard(values []string) bool {
	for _, value := range values {
		if value == Wildcard {
			return true
		}
	}
	return false
}

// Contains says whether the scope is at least as wide as another one, category
// by category. It is the question a grant asks - nobody hands out access they do
// not hold - and it compares the effective scope rather than equal columns: a
// binding that says "any team" must not pass for one that names a team.
func (s Scope) Contains(other Scope) bool {
	return containsValue(s.Site, other.Site) &&
		containsValue(s.Environment, other.Environment) &&
		s.containsTeam(other) &&
		containsAll(s.Owners, other.Owners) &&
		containsAll(s.Tags, other.Tags)
}

// containsTeam: only a binding that covers any team can hand out any team.
func (s Scope) containsTeam(other Scope) bool {
	if s.TeamAny {
		return true
	}
	return !other.TeamAny && s.Team != "" && s.Team == other.Team
}

// containsValue is one single-valued category. An empty value on the narrow side
// reaches nothing, so anything contains it.
func containsValue(granted, other string) bool {
	if granted == Wildcard || other == "" {
		return true
	}
	return granted == other
}

// containsAll is one category of alternatives: every value the narrow side lists
// has to be one the wide side lists, and only a wildcard contains a wildcard.
func containsAll(granted, other []string) bool {
	if hasWildcard(granted) {
		return true
	}
	for _, value := range other {
		if value == Wildcard || !contains(granted, value) {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// matchesTeam holds a binding to one team unless it says it covers any. The
// team is a foreign key and has no value that means "all", which is why the
// binding carries a separate word for it rather than an empty column.
func (s Scope) matchesTeam(team string) bool {
	if s.TeamAny {
		return true
	}
	return s.Team != "" && s.Team == team
}

// matchesAny is one category of alternatives: the binding lists what it allows,
// the target carries what it is. An asterisk in the list covers every value,
// including a target that carries none - an unowned host is still a host.
func matchesAny(granted, target []string) bool {
	if len(granted) == 0 {
		return false
	}
	for _, allowed := range granted {
		if allowed == Wildcard {
			return true
		}
		for _, value := range target {
			if allowed == value {
				return true
			}
		}
	}
	return false
}

func matchesValue(granted, target string) bool {
	if granted == Wildcard {
		return true
	}
	return granted != "" && granted == target
}

// String returns a readable description of the scope, and names every category:
// what is not written down is what somebody later mistakes for "all".
func (s Scope) String() string {
	team := Wildcard
	if !s.TeamAny {
		team = s.Team
	}
	return fmt.Sprintf("site=%s env=%s team=%s owner=%s tag=%s",
		orWildcard(s.Site), orWildcard(s.Environment), orWildcard(team),
		listOrWildcard(s.Owners), listOrWildcard(s.Tags))
}

func listOrWildcard(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, "|")
}

func orWildcard(value string) string {
	if strings.TrimSpace(value) == "" {
		return Wildcard
	}
	return value
}

// MarshalJSON writes every category, always. A scope that answered with three
// fields and left two out would be read as "the rest is any", which is the one
// reading this design refuses; the team comes out as a word for the same reason.
func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Site        string         `json:"site"`
		Environment string         `json:"environment"`
		TeamScope   map[string]any `json:"team_scope"`
		Owners      []string       `json:"owners"`
		Tags        []string       `json:"tags"`
	}{
		Site: s.Site, Environment: s.Environment, TeamScope: s.TeamScope(),
		Owners: orEmpty(s.Owners), Tags: orEmpty(s.Tags),
	})
}

func orEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// TeamScope is how a scope answers about its team: a word, never the presence
// or absence of a field. A reader that has to infer "any" from a missing value
// is a reader that will one day infer it wrongly.
func (s Scope) TeamScope() map[string]any {
	if s.TeamAny {
		return map[string]any{"mode": "any"}
	}
	return map[string]any{"mode": "exact", "team_id": s.Team}
}

// Binding is a role assigned within a scope.
type Binding struct {
	Role  Role  `json:"role"`
	Scope Scope `json:"scope"`
	// ValidUntil is the moment the binding stops granting anything. Nil means
	// until somebody revokes it.
	ValidUntil *time.Time `json:"valid_until,omitempty"`
}

// Active says whether the binding still grants its role at the given moment.
func (b Binding) Active(now time.Time) bool {
	return b.ValidUntil == nil || now.Before(*b.ValidUntil)
}

// Principal is an authenticated identity together with its roles.
type Principal struct {
	ID          string    `json:"id"`
	Subject     string    `json:"subject"`
	DisplayName string    `json:"display_name,omitempty"`
	Kind        string    `json:"kind"`
	Bindings    []Binding `json:"bindings"`
}

// live returns the bindings that grant something now.
func (p Principal) live() []Binding {
	now := time.Now()
	live := p.Bindings[:0:0]
	for _, binding := range p.Bindings {
		if binding.Active(now) {
			live = append(live, binding)
		}
	}
	return live
}

// Can checks whether the identity has the permission within the target's scope.
func (p Principal) Can(permission Permission, target Scope) bool {
	for _, binding := range p.live() {
		if binding.Role.Has(permission) && binding.Scope.Matches(target) {
			return true
		}
	}
	return false
}

// CanAnywhere checks whether the identity has the permission in any scope at
// all.
func (p Principal) CanAnywhere(permission Permission) bool {
	for _, binding := range p.live() {
		if binding.Role.Has(permission) {
			return true
		}
	}
	return false
}

// Permissions returns the sorted list of permissions the identity has in any
// scope at all.
func (p Principal) Permissions() []string {
	unique := map[string]bool{}
	for _, binding := range p.live() {
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
	for _, binding := range p.live() {
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
	for _, binding := range p.live() {
		if !seen[binding.Role] {
			seen[binding.Role] = true
			roles = append(roles, string(binding.Role))
		}
	}
	sort.Strings(roles)
	return roles
}

// Columns names the columns a query compares a scope against. An empty name
// means the query cannot express that category at all, so a binding narrowing by
// it matches no row: a category nothing can check is not a category that is
// satisfied, and answering "everything" there is how a narrow binding becomes
// the whole fleet.
type Columns struct {
	Site        string
	Environment string
	Team        string
	Owner       string
	Tags        string
}

// HostColumns names the five columns of a hosts row under the given alias, for
// the many queries that join the fleet to answer about it.
func HostColumns(alias string) Columns {
	if alias != "" {
		alias += "."
	}
	return Columns{
		Site: alias + "site", Environment: alias + "environment", Team: alias + "team_id",
		Owner: alias + "owner", Tags: alias + "tags",
	}
}

// Placements names a table carrying a site and an environment and nothing else,
// such as the enrollment orders: there is no host yet, so there is no team, no
// owner and no tags, and a binding narrowed by one of those reaches no order.
func Placements(siteColumn, envColumn string) Columns {
	return Columns{Site: siteColumn, Environment: envColumn}
}

// ScopeSQL builds an SQL condition narrowing the rows to the given scopes.
// Within one scope every category has to hold; between the scopes any one of
// them is enough. No scope at all is no row.
func ScopeSQL(scopes []Scope, columns Columns, offset int) (string, []any) {
	if len(scopes) == 0 {
		return "false", nil
	}
	var (
		conditions []string
		args       []any
	)
	for _, scope := range scopes {
		if scope.Covers() {
			// A scope that narrows by nothing covers everything, so no further
			// condition can narrow the answer.
			return "", nil
		}
		parts := make([]string, 0, 5)
		for _, dimension := range []struct {
			column string
			value  string
		}{{columns.Site, scope.Site}, {columns.Environment, scope.Environment}} {
			switch {
			case dimension.value == Wildcard:
				// Any value in this dimension.
			case dimension.value == "", dimension.column == "":
				// Not knowing the scope, or having no column to read it from, must
				// not widen what is shown.
				parts = append(parts, "false")
			default:
				args = append(args, dimension.value)
				parts = append(parts, fmt.Sprintf("%s = $%d", dimension.column, offset+len(args)))
			}
		}
		// Then the categories added later, in the order the rule is written: site
		// and environment and team and owner and tag. The team is a foreign key
		// with no value meaning "all", so the binding carries a separate word.
		if !scope.TeamAny {
			switch {
			case scope.Team == "", columns.Team == "":
				parts = append(parts, "false")
			default:
				args = append(args, scope.Team)
				parts = append(parts, fmt.Sprintf("%s = $%d::uuid", columns.Team, offset+len(args)))
			}
		}
		for _, list := range []struct {
			column string
			values []string
			array  bool
		}{{columns.Owner, scope.Owners, false}, {columns.Tags, scope.Tags, true}} {
			condition, used := listSQL(list.column, list.values, list.array, offset+len(args))
			if condition == "" {
				continue
			}
			args = append(args, used...)
			parts = append(parts, condition)
		}
		if len(parts) == 0 {
			return "", nil
		}
		// One part needs no brackets: this SQL is read in a slow query log.
		if len(parts) == 1 {
			conditions = append(conditions, parts[0])
		} else {
			conditions = append(conditions, "("+strings.Join(parts, " and ")+")")
		}
	}
	return "(" + strings.Join(conditions, " or ") + ")", args
}

// listSQL is one category of alternatives. An asterisk anywhere in the list
// covers every value, so the category adds no condition; an empty list reaches
// nothing, and so does a list with no column to compare it against.
func listSQL(column string, values []string, array bool, offset int) (string, []any) {
	// The wildcard is read first and needs no column: a category that narrows
	// nothing asks nothing of the query.
	for _, value := range values {
		if value == Wildcard {
			return "", nil
		}
	}
	if len(values) == 0 || column == "" {
		return "false", nil
	}
	if array {
		return fmt.Sprintf("coalesce(%s, '{}') && $%d::text[]", column, offset+1), []any{values}
	}
	return fmt.Sprintf("coalesce(%s, '') = any($%d::text[])", column, offset+1), []any{values}
}
