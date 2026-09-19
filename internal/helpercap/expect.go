package helpercap

import (
	"fmt"
	"slices"
	"strings"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Expectation is what a helper request has to be authorized as.
type Expectation struct {
	// Kind names the request for the log.
	Kind string
	// Mutating says the request changes the host.
	Mutating bool
	// Actions are the action types a capability may name for the request.
	Actions []opspec.ActionType
}

// Allows says whether a capability of the given action type authorizes the
// request.
func (e Expectation) Allows(action string) bool {
	return slices.Contains(e.Actions, opspec.ActionType(action))
}

func mutating(kind string, actions ...opspec.ActionType) Expectation {
	return Expectation{Kind: kind, Mutating: true, Actions: actions}
}

func read(kind string) Expectation {
	return Expectation{Kind: kind, Mutating: false}
}

// Expect maps a request to the operations that may have produced it.
func Expect(request *helperv1.HelperRequest) Expectation {
	switch action := request.GetAction().(type) {
	case *helperv1.HelperRequest_UnitAction:
		switch action.UnitAction.GetOperation() {
		case helperv1.UnitActionRequest_OPERATION_START:
			return mutating("unit.start", opspec.ActionUnitStart)
		case helperv1.UnitActionRequest_OPERATION_STOP:
			return mutating("unit.stop", opspec.ActionUnitStop)
		case helperv1.UnitActionRequest_OPERATION_RESTART:
			return mutating("unit.restart", opspec.ActionUnitRestart)
		case helperv1.UnitActionRequest_OPERATION_RELOAD:
			return mutating("unit.reload", opspec.ActionUnitReload)
		case helperv1.UnitActionRequest_OPERATION_ENABLE, helperv1.UnitActionRequest_OPERATION_DISABLE:
			return mutating("unit.enable", opspec.ActionUnitEnableSet)
		case helperv1.UnitActionRequest_OPERATION_MASK, helperv1.UnitActionRequest_OPERATION_UNMASK:
			return mutating("unit.mask", opspec.ActionUnitMaskSet)
		case helperv1.UnitActionRequest_OPERATION_RESET_FAILED:
			return mutating("unit.reset_failed", opspec.ActionUnitResetFailed)
		}
		return mutating("unit.unknown")

	case *helperv1.HelperRequest_PackageAction:
		switch action.PackageAction.GetOperation() {
		case helperv1.PackageActionRequest_OPERATION_REFRESH:
			// A refresh rewrites the manager's metadata cache and nothing the operator
			// owns; it is the first step of a plan as much as of a transaction.
			return read("packages.refresh")
		case helperv1.PackageActionRequest_OPERATION_UPGRADE:
			return mutating("packages.upgrade", opspec.ActionPackageUpgrade)
		case helperv1.PackageActionRequest_OPERATION_INSTALL:
			return mutating("packages.install", opspec.ActionPackageInstall, opspec.ActionAgentUpgrade)
		case helperv1.PackageActionRequest_OPERATION_REMOVE:
			return mutating("packages.remove", opspec.ActionPackageRemove)
		case helperv1.PackageActionRequest_OPERATION_HOLD:
			return mutating("packages.hold", opspec.ActionPackageHoldSet)
		}
		return mutating("packages.unknown")
	case *helperv1.HelperRequest_PackageRepair:
		return mutating("packages.repair", opspec.ActionPackageRepair)
	case *helperv1.HelperRequest_Repository:
		return mutating("packages.repository", opspec.ActionRepositorySet)

	case *helperv1.HelperRequest_Reboot:
		return mutating("system.reboot", opspec.ActionSystemReboot)
	case *helperv1.HelperRequest_Shutdown:
		return mutating("system.shutdown", opspec.ActionSystemShutdown)
	case *helperv1.HelperRequest_Hostname:
		return mutating("system.hostname", opspec.ActionSystemHostnameSet)
	case *helperv1.HelperRequest_FinalWipe:
		// The final wipe is the end of the decommission handshake, a typed message
		// rather than a task, so no capability exists for it.
		return read("final_wipe")

	case *helperv1.HelperRequest_IdentityProbe:
		return read("identity.probe")
	case *helperv1.HelperRequest_LocalAccounts:
		return read("accounts.read")
	case *helperv1.HelperRequest_System:
		return read("system.read")
	case *helperv1.HelperRequest_DockerRead:
		return read("docker.read")
	case *helperv1.HelperRequest_DockerEvents:
		return read("docker.events")
	case *helperv1.HelperRequest_DockerLogs:
		return read("docker.logs")
	case *helperv1.HelperRequest_LogFile:
		return read("logfile.read")

	case *helperv1.HelperRequest_DomainEnroll:
		if action.DomainEnroll.GetPreflightOnly() {
			return read("identity.preflight")
		}
		return mutating("identity.enroll", opspec.ActionDomainEnroll)
	case *helperv1.HelperRequest_DomainLeave:
		return mutating("identity.leave", opspec.ActionDomainLeave)
	case *helperv1.HelperRequest_KeytabRenew:
		return mutating("identity.keytab", opspec.ActionIdentityKeytabRenew)

	case *helperv1.HelperRequest_LocalUserAction:
		switch action.LocalUserAction.GetOperation() {
		case helperv1.LocalUserActionRequest_OPERATION_CREATE:
			return mutating("localuser.create", opspec.ActionLocalUserCreate)
		case helperv1.LocalUserActionRequest_OPERATION_LOCK:
			return mutating("localuser.lock", opspec.ActionLocalUserLock)
		case helperv1.LocalUserActionRequest_OPERATION_UNLOCK:
			return mutating("localuser.unlock", opspec.ActionLocalUserUnlock)
		case helperv1.LocalUserActionRequest_OPERATION_SET_SSH_KEYS:
			return mutating("localuser.sshkeys", opspec.ActionLocalSSHKeysSet)
		case helperv1.LocalUserActionRequest_OPERATION_ADD_SSH_KEYS:
			return mutating("localuser.sshkeys.add", opspec.ActionLocalSSHKeysAdd)
		case helperv1.LocalUserActionRequest_OPERATION_REMOVE_SSH_KEYS:
			return mutating("localuser.sshkeys.remove", opspec.ActionLocalSSHKeysRemove)
		case helperv1.LocalUserActionRequest_OPERATION_REPLACE_SSH_KEYS:
			return mutating("localuser.sshkeys.replace", opspec.ActionLocalSSHKeysReplaceAll)
		case helperv1.LocalUserActionRequest_OPERATION_SET_GROUPS:
			return mutating("localuser.groups", opspec.ActionLocalUserGroupsSet)
		case helperv1.LocalUserActionRequest_OPERATION_SET_EXPIRY:
			return mutating("localuser.expiry", opspec.ActionLocalUserExpirySet)
		case helperv1.LocalUserActionRequest_OPERATION_DELETE:
			return mutating("localuser.delete", opspec.ActionLocalUserDelete)
		}
		return mutating("localuser.unknown")

	case *helperv1.HelperRequest_DockerAction:
		switch action.DockerAction.GetOperation() {
		case helperv1.DockerActionRequest_OPERATION_START:
			return mutating("docker.start", opspec.ActionDockerStart)
		case helperv1.DockerActionRequest_OPERATION_STOP:
			return mutating("docker.stop", opspec.ActionDockerStop)
		case helperv1.DockerActionRequest_OPERATION_RESTART:
			return mutating("docker.restart", opspec.ActionDockerRestart)
		case helperv1.DockerActionRequest_OPERATION_REMOVE:
			return mutating("docker.remove", opspec.ActionDockerRemove)
		case helperv1.DockerActionRequest_OPERATION_PULL_IMAGE:
			return mutating("docker.pull", opspec.ActionDockerPull)
		case helperv1.DockerActionRequest_OPERATION_PRUNE:
			return mutating("docker.prune", opspec.ActionDockerPrune)
		}
		return mutating("docker.unknown")
	case *helperv1.HelperRequest_DockerEnsure:
		switch action.DockerEnsure.GetOperation() {
		case helperv1.DockerEnsureRequest_OPERATION_PLAN:
			// The plan of a declared object reads the engine and asks the
			// registry what the image tag means today; it writes nothing.
			return read("docker.declare.plan")
		case helperv1.DockerEnsureRequest_OPERATION_CONTAINER_ENSURE:
			return mutating("docker.container.ensure", opspec.ActionDockerContainerEnsure)
		case helperv1.DockerEnsureRequest_OPERATION_NETWORK_ENSURE:
			return mutating("docker.network.ensure", opspec.ActionDockerNetworkEnsure)
		case helperv1.DockerEnsureRequest_OPERATION_NETWORK_REMOVE:
			return mutating("docker.network.remove", opspec.ActionDockerNetworkRemove)
		case helperv1.DockerEnsureRequest_OPERATION_VOLUME_ENSURE:
			return mutating("docker.volume.ensure", opspec.ActionDockerVolumeEnsure)
		case helperv1.DockerEnsureRequest_OPERATION_VOLUME_REMOVE:
			return mutating("docker.volume.remove", opspec.ActionDockerVolumeRemove)
		}
		return mutating("docker.declare.unknown")
	case *helperv1.HelperRequest_Compose:
		if action.Compose.GetOperation() == helperv1.ComposeRequest_OPERATION_PLAN {
			return read("compose.plan")
		}
		return mutating("compose.deploy", opspec.ActionComposeDeploy)

	case *helperv1.HelperRequest_ProcessSignal:
		return mutating("process.signal", opspec.ActionProcessSignal)

	case *helperv1.HelperRequest_Schedule:
		switch action.Schedule.GetOperation() {
		case helperv1.ScheduleRequest_OPERATION_READ:
			return read("schedule.read")
		case helperv1.ScheduleRequest_OPERATION_ENSURE:
			return mutating("schedule.ensure", opspec.ActionScheduleEnsure)
		case helperv1.ScheduleRequest_OPERATION_DISABLE:
			return mutating("schedule.disable", opspec.ActionScheduleDisable)
		case helperv1.ScheduleRequest_OPERATION_REMOVE:
			return mutating("schedule.remove", opspec.ActionScheduleRemove)
		case helperv1.ScheduleRequest_OPERATION_RUN_NOW:
			return mutating("schedule.run_now", opspec.ActionScheduleRunNow)
		}
		return mutating("schedule.unknown")

	case *helperv1.HelperRequest_Network:
		switch action.Network.GetOperation() {
		case helperv1.NetworkRequest_OPERATION_READ, helperv1.NetworkRequest_OPERATION_PLAN:
			return read("network.read")
		case helperv1.NetworkRequest_OPERATION_CONFIRM:
			// The confirmation disarms the rollback of a change already verified under
			// its own capability.
			return read("network.confirm")
		case helperv1.NetworkRequest_OPERATION_SET_MTU:
			return mutating("network.mtu", opspec.ActionNetworkMTUSet)
		case helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES:
			return mutating("network.routes", opspec.ActionNetworkRouteEnsure)
		case helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
			return mutating("network.profile", opspec.ActionNetworkProfileApply)
		case helperv1.NetworkRequest_OPERATION_ROLLBACK:
			return mutating("network.rollback", opspec.ActionNetworkRollback)
		case helperv1.NetworkRequest_OPERATION_APPLY_LINK:
			return mutating("network.link", opspec.ActionNetworkLinkApply)
		case helperv1.NetworkRequest_OPERATION_REMOVE_LINK:
			return mutating("network.link.remove", opspec.ActionNetworkLinkRemove)
		}
		return mutating("network.unknown")
	case *helperv1.HelperRequest_Dns:
		if action.Dns.GetOperation() == helperv1.DnsRequest_OPERATION_PLAN {
			return read("dns.plan")
		}
		return mutating("dns.apply", opspec.ActionDNSHostApply)
	case *helperv1.HelperRequest_Firewall:
		switch action.Firewall.GetOperation() {
		case helperv1.FirewallRequest_OPERATION_READ, helperv1.FirewallRequest_OPERATION_PLAN,
			helperv1.FirewallRequest_OPERATION_CONFIRM:
			return read("firewall.read")
		case helperv1.FirewallRequest_OPERATION_RULE_ENSURE:
			return mutating("firewall.rule.ensure", opspec.ActionFirewallRuleEnsure)
		case helperv1.FirewallRequest_OPERATION_RULE_REMOVE:
			return mutating("firewall.rule.remove", opspec.ActionFirewallRuleRemove)
		case helperv1.FirewallRequest_OPERATION_ZONE_PORT:
			return mutating("firewall.zone.port", opspec.ActionFirewallZonePort)
		case helperv1.FirewallRequest_OPERATION_ZONE_SERVICE:
			return mutating("firewall.zone.service", opspec.ActionFirewallZoneService)
		case helperv1.FirewallRequest_OPERATION_RESTORE:
			return mutating("firewall.restore", opspec.ActionFirewallRulesetRestore)
		}
		return mutating("firewall.unknown")

	case *helperv1.HelperRequest_Storage:
		switch action.Storage.GetOperation() {
		case helperv1.StorageRequest_OPERATION_READ_LVM, helperv1.StorageRequest_OPERATION_MOUNT_PLAN,
			helperv1.StorageRequest_OPERATION_DEVICE_PLAN, helperv1.StorageRequest_OPERATION_SMART_READ,
			helperv1.StorageRequest_OPERATION_READ_RAID:
			return read("storage.read")
		case helperv1.StorageRequest_OPERATION_MOUNT_ENSURE:
			return mutating("mount.ensure", opspec.ActionMountEnsure)
		case helperv1.StorageRequest_OPERATION_MOUNT_REMOVE:
			return mutating("mount.remove", opspec.ActionMountRemove)
		case helperv1.StorageRequest_OPERATION_FS_CHECK:
			return mutating("filesystem.check", opspec.ActionFilesystemCheck)
		case helperv1.StorageRequest_OPERATION_LVM_EXTEND:
			return mutating("lvm.extend", opspec.ActionLVMExtend)
		case helperv1.StorageRequest_OPERATION_FS_RESIZE:
			return mutating("filesystem.resize", opspec.ActionFilesystemResize)
		case helperv1.StorageRequest_OPERATION_FS_CREATE:
			return mutating("filesystem.create", opspec.ActionFilesystemCreate)
		case helperv1.StorageRequest_OPERATION_DISK_WIPE:
			return mutating("disk.wipe", opspec.ActionDiskWipe)
		case helperv1.StorageRequest_OPERATION_RAID_MEMBER_FAIL:
			return mutating("raid.member.fail", opspec.ActionRAIDMemberFail)
		case helperv1.StorageRequest_OPERATION_RAID_MEMBER_REMOVE:
			return mutating("raid.member.remove", opspec.ActionRAIDMemberRemove)
		case helperv1.StorageRequest_OPERATION_RAID_MEMBER_ADD:
			return mutating("raid.member.add", opspec.ActionRAIDMemberAdd)
		case helperv1.StorageRequest_OPERATION_LVM_LV_CREATE:
			return mutating("lvm.volume.create", opspec.ActionLVMVolumeCreate)
		case helperv1.StorageRequest_OPERATION_LVM_LV_REMOVE:
			return mutating("lvm.volume.remove", opspec.ActionLVMVolumeRemove)
		case helperv1.StorageRequest_OPERATION_LVM_VG_EXTEND:
			return mutating("lvm.group.extend", opspec.ActionLVMGroupExtend)
		case helperv1.StorageRequest_OPERATION_LVM_SNAPSHOT_CREATE:
			return mutating("lvm.snapshot.create", opspec.ActionLVMSnapshotCreate)
		case helperv1.StorageRequest_OPERATION_LVM_SNAPSHOT_REMOVE:
			return mutating("lvm.snapshot.remove", opspec.ActionLVMSnapshotRemove)
		}
		return mutating("storage.unknown")
	case *helperv1.HelperRequest_Ssh:
		switch action.Ssh.GetOperation() {
		case helperv1.SshRequest_OPERATION_READ, helperv1.SshRequest_OPERATION_PLAN:
			return read("ssh.read")
		case helperv1.SshRequest_OPERATION_APPLY:
			return mutating("ssh.apply", opspec.ActionSSHConfigApply)
		case helperv1.SshRequest_OPERATION_ROTATE_HOSTKEY:
			return mutating("ssh.hostkey", opspec.ActionSSHHostKeyRotate)
		}
		return mutating("ssh.unknown")
	case *helperv1.HelperRequest_Kernel:
		switch action.Kernel.GetOperation() {
		case helperv1.KernelRequest_OPERATION_READ, helperv1.KernelRequest_OPERATION_MODULE_PLAN:
			return read("kernel.read")
		case helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE:
			return mutating("sysctl.ensure", opspec.ActionSysctlEnsure)
		case helperv1.KernelRequest_OPERATION_MODULE_LOAD:
			return mutating("kernel.module.load", opspec.ActionKernelModuleLoad)
		case helperv1.KernelRequest_OPERATION_MODULE_BLACKLIST:
			return mutating("kernel.module.blacklist", opspec.ActionKernelModuleBlacklist)
		}
		return mutating("kernel.unknown")
	case *helperv1.HelperRequest_File:
		switch action.File.GetOperation() {
		case helperv1.FileRequest_OPERATION_READ, helperv1.FileRequest_OPERATION_LIST,
			helperv1.FileRequest_OPERATION_PLAN:
			return read("file.read")
		case helperv1.FileRequest_OPERATION_ENSURE:
			return mutating("file.ensure", opspec.ActionFileEnsure, opspec.ActionFileRollback)
		case helperv1.FileRequest_OPERATION_REMOVE:
			return mutating("file.remove", opspec.ActionFileRemove)
		}
		return mutating("file.unknown")
	case *helperv1.HelperRequest_Time:
		switch action.Time.GetOperation() {
		case helperv1.TimeRequest_OPERATION_PLAN:
			return read("time.plan")
		case helperv1.TimeRequest_OPERATION_CONFIG_APPLY:
			return mutating("time.config", opspec.ActionTimeConfigApply)
		case helperv1.TimeRequest_OPERATION_TIMEZONE_SET:
			return mutating("time.timezone", opspec.ActionTimezoneSet)
		}
		return mutating("time.unknown")
	case *helperv1.HelperRequest_Security:
		switch action.Security.GetOperation() {
		case helperv1.SecurityRequest_OPERATION_FACTS:
			return read("security.facts")
		case helperv1.SecurityRequest_OPERATION_SELINUX_MODE:
			return mutating("selinux.mode", opspec.ActionSELinuxModeSet, opspec.ActionSecurityRemediate)
		case helperv1.SecurityRequest_OPERATION_AUDIT_RELOAD:
			return mutating("audit.reload", opspec.ActionAuditRulesReload, opspec.ActionSecurityRemediate)
		}
		return mutating("security.unknown")
	case *helperv1.HelperRequest_Certificate:
		switch action.Certificate.GetOperation() {
		case helperv1.CertificateRequest_OPERATION_FACTS, helperv1.CertificateRequest_OPERATION_PLAN,
			helperv1.CertificateRequest_OPERATION_TRUST_PLAN:
			return read("certificate.read")
		case helperv1.CertificateRequest_OPERATION_DEPLOY:
			return mutating("certificate.deploy", opspec.ActionCertificateDeploy)
		case helperv1.CertificateRequest_OPERATION_RENEW:
			return mutating("certificate.renew", opspec.ActionCertificateRenew)
		case helperv1.CertificateRequest_OPERATION_TRUST_ENSURE:
			return mutating("certificate.trust.ensure", opspec.ActionCertificateTrustEnsure)
		case helperv1.CertificateRequest_OPERATION_TRUST_REMOVE:
			return mutating("certificate.trust.remove", opspec.ActionCertificateTrustRemove)
		}
		return mutating("certificate.unknown")
	case *helperv1.HelperRequest_Backup:
		switch action.Backup.GetOperation() {
		case helperv1.BackupRequest_OPERATION_PLAN:
			return read("backup.plan")
		case helperv1.BackupRequest_OPERATION_RUN:
			return mutating("backup.run", opspec.ActionBackupRun)
		case helperv1.BackupRequest_OPERATION_VERIFY:
			return mutating("backup.verify", opspec.ActionBackupVerify)
		case helperv1.BackupRequest_OPERATION_RESTORE:
			return mutating("backup.restore", opspec.ActionBackupRestore)
		}
		return mutating("backup.unknown")

	case *helperv1.HelperRequest_TrustUpdate:
		// The keyring update proves itself with the bundle's own signature
		// and is never authorized by a capability.
		return read("trust.update")
	case nil:
		// A request without an action runs nothing: the helper refuses it as
		// unknown.
		return read("none")
	}
	return mutating("unknown")
}

// CheckBinding compares what the request names with what the bound payload
// names, for the operations whose payload carries the target: the unit, the
// packages, the schedule entry with its user and command, the file path, the
func CheckBinding(request *helperv1.HelperRequest, bound *BoundPayload) error {
	payload := bound.Payload
	switch action := request.GetAction().(type) {
	case *helperv1.HelperRequest_UnitAction:
		want := ""
		switch {
		case payload.Unit != nil:
			want = payload.Unit.Unit
		case payload.UnitToggle != nil:
			want = payload.UnitToggle.Unit
		}
		return same("unit", action.UnitAction.GetUnit(), want)

	case *helperv1.HelperRequest_PackageAction:
		switch action.PackageAction.GetOperation() {
		case helperv1.PackageActionRequest_OPERATION_UPGRADE:
			if payload.PackageUpgrade == nil {
				return binding("the bound payload describes no package upgrade")
			}
			return sameList("packages", action.PackageAction.GetPackages(), payload.PackageUpgrade.Packages)
		case helperv1.PackageActionRequest_OPERATION_INSTALL,
			helperv1.PackageActionRequest_OPERATION_REMOVE,
			helperv1.PackageActionRequest_OPERATION_HOLD:
			if bound.Action == opspec.ActionAgentUpgrade {
				// The agent upgrade installs its own package at the version
				// the payload names; nothing else may ride on that order.
				return agentPackagesOnly(action.PackageAction, payload.AgentUpgrade)
			}
			if payload.PackageChange == nil {
				return binding("the bound payload describes no package change")
			}
			if err := sameList("packages", action.PackageAction.GetPackages(), payload.PackageChange.Packages); err != nil {
				return err
			}
			if action.PackageAction.GetOperation() == helperv1.PackageActionRequest_OPERATION_HOLD &&
				action.PackageAction.GetHold() != payload.PackageChange.Hold {
				return binding("the request holds or releases the packages the other way than the bound payload")
			}
		}
		return nil

	case *helperv1.HelperRequest_Schedule:
		if payload.Schedule == nil {
			return binding("the bound payload describes no schedule entry")
		}
		if err := same("schedule id", action.Schedule.GetId(), payload.Schedule.ID); err != nil {
			return err
		}
		if err := same("schedule user", action.Schedule.GetUser(), payload.Schedule.User); err != nil {
			return err
		}
		switch action.Schedule.GetOperation() {
		case helperv1.ScheduleRequest_OPERATION_ENSURE, helperv1.ScheduleRequest_OPERATION_RUN_NOW:
			if err := sameList("schedule command", action.Schedule.GetCommand(), payload.Schedule.Command); err != nil {
				return err
			}
		}
		return nil

	case *helperv1.HelperRequest_File:
		if payload.File == nil {
			return binding("the bound payload describes no file")
		}
		return same("file path", action.File.GetPath(), payload.File.Path)

	case *helperv1.HelperRequest_LocalUserAction:
		if payload.LocalUser == nil {
			return binding("the bound payload describes no account")
		}
		return same("account name", action.LocalUserAction.GetName(), payload.LocalUser.Name)

	case *helperv1.HelperRequest_Storage:
		// A destructive storage request is bound to the device and to its
		// stable identity: a capability for one disk must not format another.
		if payload.Storage == nil {
			return nil
		}
		switch action.Storage.GetOperation() {
		case helperv1.StorageRequest_OPERATION_FS_CREATE, helperv1.StorageRequest_OPERATION_DISK_WIPE:
			if err := same("device", action.Storage.GetDevice(), payload.Storage.Device); err != nil {
				return err
			}
			if err := same("device by-id link", action.Storage.GetExpectedById(), payload.Storage.ExpectedByID); err != nil {
				return err
			}
			return same("device WWN", action.Storage.GetExpectedWwn(), payload.Storage.ExpectedWWN)
		}
		return nil
	}
	return nil
}

func agentPackagesOnly(action *helperv1.PackageActionRequest, upgrade *opspec.AgentUpgradePayload) error {
	if upgrade == nil {
		return binding("the bound payload describes no agent upgrade")
	}
	for _, name := range action.GetPackages() {
		if !strings.HasPrefix(name, "flotestro-agent") {
			return binding(fmt.Sprintf("an agent upgrade does not install %s", name))
		}
	}
	// The digest the helper checks the artefact against and the version it keeps
	// a way back to are part of what the operator approved: an agent must not ask
	// the helper to verify another file or to prepare a return to a version
	if err := same("package digest", action.GetPackageSha256(), upgrade.PackageSHA256); err != nil {
		return err
	}
	return same("rollback version", action.GetRollbackVersion(), upgrade.RollbackVersion)
}

func same(what, got, want string) error {
	if got != want {
		return binding(fmt.Sprintf("the request names the %s %q, the bound payload %q", what, got, want))
	}
	return nil
}

func sameList(what string, got, want []string) error {
	left := slices.Clone(got)
	right := slices.Clone(want)
	slices.Sort(left)
	slices.Sort(right)
	if !slices.Equal(left, right) {
		return binding(fmt.Sprintf("the request names other %s than the bound payload", what))
	}
	return nil
}

func binding(message string) error { return refusal(ErrorPayloadBinding, message) }
