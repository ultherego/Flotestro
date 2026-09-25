package helpercap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/network"
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
// packages, the schedule entry with its user and command, the file path, the.
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
			// When the entry runs is as much of the order as what it runs.
			if err := same("schedule expression", action.Schedule.GetExpression(), payload.Schedule.Expression); err != nil {
				return err
			}
		}
		return nil

	case *helperv1.HelperRequest_File:
		if payload.File == nil {
			return binding("the bound payload describes no file")
		}
		return sameFile(action.File, payload.File)

	case *helperv1.HelperRequest_LocalUserAction:
		if payload.LocalUser == nil {
			return binding("the bound payload describes no account")
		}
		return sameAccount(action.LocalUserAction, payload.LocalUser)

	case *helperv1.HelperRequest_ProcessSignal:
		if payload.ProcessSignal == nil {
			return binding("the bound payload describes no process")
		}
		// One capability used to signal any process with any signal: the
		// request's own numbers decided, and nothing compared them.
		if request := action.ProcessSignal; request.GetPid() != payload.ProcessSignal.PID ||
			request.GetSignal() != payload.ProcessSignal.Signal ||
			request.GetExpectedStartTicks() != payload.ProcessSignal.ExpectedStart {
			return binding(fmt.Sprintf(
				"the request signals the process %d with %s, the bound payload %d with %s",
				request.GetPid(), request.GetSignal(),
				payload.ProcessSignal.PID, payload.ProcessSignal.Signal))
		}
		return nil

	case *helperv1.HelperRequest_Hostname:
		if payload.Hostname == nil {
			return binding("the bound payload describes no hostname")
		}
		if err := same("hostname", action.Hostname.GetHostname(), payload.Hostname.Hostname); err != nil {
			return err
		}
		return same("pretty hostname", action.Hostname.GetPretty(), payload.Hostname.Pretty)

	case *helperv1.HelperRequest_DockerEnsure:
		if payload.DockerEnsure == nil {
			return binding("the bound payload describes no declared object")
		}
		// The panel describes an object it creates and names one it removes, so
		// the kind and the name come from whichever of the two the payload has.
		if err := same("object kind", action.DockerEnsure.GetKind(),
			payload.DockerEnsure.ObjectKind()); err != nil {
			return err
		}
		if err := same("object name", action.DockerEnsure.GetName(),
			payload.DockerEnsure.ObjectName()); err != nil {
			return err
		}
		return same("plan digest", action.DockerEnsure.GetPlanDigest(), payload.DockerEnsure.PlanDigest)

	case *helperv1.HelperRequest_Repository:
		if payload.Repository == nil {
			return binding("the bound payload describes no repository")
		}
		if err := same("repository", action.Repository.GetId(), payload.Repository.ID); err != nil {
			return err
		}
		return same("repository address", action.Repository.GetUrl(), payload.Repository.URL)

	case *helperv1.HelperRequest_Backup:
		if payload.Backup == nil {
			return binding("the bound payload describes no backup definition")
		}
		return same("backup definition", action.Backup.GetId(), payload.Backup.ID)

	case *helperv1.HelperRequest_Certificate:
		if action.Certificate.GetOperation() != helperv1.CertificateRequest_OPERATION_DEPLOY {
			// A renewal and a trust change name an anchor rather than a path;
			// they have no rule yet and are listed as such.
			return nil
		}
		if payload.Certificate == nil {
			return binding("the bound payload describes no certificate")
		}
		if err := same("certificate path", action.Certificate.GetPath(), payload.Certificate.Path); err != nil {
			return err
		}
		return same("plan digest", action.Certificate.GetPlanHash(), payload.Certificate.PlanHash)

	case *helperv1.HelperRequest_DockerAction:
		container := action.DockerAction
		switch container.GetOperation() {
		case helperv1.DockerActionRequest_OPERATION_START,
			helperv1.DockerActionRequest_OPERATION_STOP,
			helperv1.DockerActionRequest_OPERATION_RESTART,
			helperv1.DockerActionRequest_OPERATION_REMOVE:
			if payload.DockerContainer == nil {
				return binding("the bound payload describes no container")
			}
			if err := same("container", container.GetContainerId(),
				payload.DockerContainer.ContainerID); err != nil {
				return err
			}
			// Taking the volumes with the container destroys the data it kept,
			// and the order decides that, not the request.
			if container.GetRemoveVolumes() != payload.DockerContainer.RemoveVolumes {
				return binding("the request removes the volumes of the container against the bound payload")
			}
			if container.GetTimeoutSeconds() != payload.DockerContainer.TimeoutSeconds {
				return binding(fmt.Sprintf(
					"the request gives the container %ds to shut down, the bound payload %ds",
					container.GetTimeoutSeconds(), payload.DockerContainer.TimeoutSeconds))
			}
			return nil
		case helperv1.DockerActionRequest_OPERATION_PULL_IMAGE:
			if payload.DockerImage == nil {
				return binding("the bound payload describes no image")
			}
			return same("image", container.GetImageReference(), payload.DockerImage.Reference)
		case helperv1.DockerActionRequest_OPERATION_PRUNE:
			if payload.DockerPrune == nil {
				return binding("the bound payload describes no cleanup")
			}
			if err := sameList("images", container.GetImageIds(), payload.DockerPrune.ImageIDs); err != nil {
				return err
			}
			if err := sameList("volumes", container.GetVolumeNames(), payload.DockerPrune.VolumeName); err != nil {
				return err
			}
			return sameList("networks", container.GetNetworkIds(), payload.DockerPrune.NetworkIDs)
		}
		return nil

	case *helperv1.HelperRequest_Compose:
		if payload.Compose == nil {
			return binding("the bound payload describes no project")
		}
		if err := same("project", action.Compose.GetProject(), payload.Compose.Project); err != nil {
			return err
		}
		// The manifest is what will run; the digest names it without carrying it
		// into a refusal message.
		if err := same("manifest", contentDigest([]byte(action.Compose.GetManifest())),
			contentDigest([]byte(payload.Compose.Manifest))); err != nil {
			return err
		}
		if err := same("plan digest", action.Compose.GetPlanDigest(), payload.Compose.PlanDigest); err != nil {
			return err
		}
		return sameList("image digests", serviceDigests(action.Compose.GetImageDigests()),
			serviceDigests(payload.Compose.ImageDigests))

	case *helperv1.HelperRequest_DomainEnroll:
		if payload.DomainEnroll == nil {
			return binding("the bound payload describes no domain")
		}
		if err := same("domain", action.DomainEnroll.GetDomain(), payload.DomainEnroll.Domain); err != nil {
			return err
		}
		if err := same("realm", action.DomainEnroll.GetRealm(), payload.DomainEnroll.Realm); err != nil {
			return err
		}
		if err := same("directory server", action.DomainEnroll.GetServer(), payload.DomainEnroll.Server); err != nil {
			return err
		}
		// The one-time password is not in the payload: the panel puts it into the
		// envelope at delivery, after the capability is signed.
		return same("hostname", action.DomainEnroll.GetHostname(), payload.DomainEnroll.Hostname)

	case *helperv1.HelperRequest_DomainLeave:
		if payload.DomainLeave == nil {
			return binding("the bound payload describes no domain")
		}
		if err := same("domain", action.DomainLeave.GetDomain(), payload.DomainLeave.Domain); err != nil {
			return err
		}
		return same("realm", action.DomainLeave.GetRealm(), payload.DomainLeave.Realm)

	case *helperv1.HelperRequest_KeytabRenew:
		if payload.Keytab == nil {
			return binding("the bound payload describes no principal")
		}
		return same("principal", action.KeytabRenew.GetPrincipal(), payload.Keytab.Principal)

	case *helperv1.HelperRequest_PackageRepair:
		// An order that answers nothing leaves no payload behind at all, so an
		// empty request under an empty payload is the honest case.
		var answers []opspec.DebconfAnswer
		if payload.PackageRepair != nil {
			answers = payload.PackageRepair.Answers
		}
		return sameList("configuration answers", selectedAnswers(action.PackageRepair.GetAnswers()),
			approvedAnswers(answers))

	case *helperv1.HelperRequest_Reboot:
		// A restart of every default leaves no payload behind, and the agent
		// fills an unset delay with its own; the reason always travels.
		reason, delay, inhibitors := "", uint32(0), false
		if payload.Reboot != nil {
			reason = payload.Reboot.Reason
			delay = payload.Reboot.DelaySeconds
			inhibitors = payload.Reboot.IgnoreInhibitors
		}
		if err := same("reboot reason", action.Reboot.GetReason(), reason); err != nil {
			return err
		}
		if delay != 0 && action.Reboot.GetDelaySeconds() != delay {
			return binding(fmt.Sprintf("the request restarts in %ds, the bound payload in %ds",
				action.Reboot.GetDelaySeconds(), delay))
		}
		if action.Reboot.GetIgnoreInhibitors() != inhibitors {
			return binding("the request steps over the inhibitors against the bound payload")
		}
		return nil

	case *helperv1.HelperRequest_Shutdown:
		if payload.Power == nil {
			return binding("the bound payload describes no power operation")
		}
		if err := same("shutdown reason", action.Shutdown.GetReason(), payload.Power.Reason); err != nil {
			return err
		}
		// The agent fills an unnamed mode and an unset delay with its own
		// defaults, so only a value the payload named is compared.
		if payload.Power.Mode != "" {
			if err := same("shutdown mode", action.Shutdown.GetMode(), payload.Power.Mode); err != nil {
				return err
			}
		}
		if payload.Power.DelaySeconds != 0 &&
			action.Shutdown.GetDelaySeconds() != payload.Power.DelaySeconds {
			return binding(fmt.Sprintf("the request powers off in %ds, the bound payload in %ds",
				action.Shutdown.GetDelaySeconds(), payload.Power.DelaySeconds))
		}
		if action.Shutdown.GetIgnoreInhibitors() != payload.Power.IgnoreInhibitors {
			return binding("the request steps over the inhibitors against the bound payload")
		}
		return nil

	case *helperv1.HelperRequest_Network:
		if payload.Network == nil {
			return binding("the bound payload describes no network change")
		}
		// The management address is the host's own knowledge of the way home;
		// every other field of a mutating request comes from the payload.
		change := action.Network
		if err := same("interface", change.GetInterface(), payload.Network.Interface); err != nil {
			return err
		}
		if err := same("plan digest", change.GetPlanHash(), payload.Network.PlanHash); err != nil {
			return err
		}
		if err := same("rollback plan", change.GetRollbackId(), payload.Network.RollbackID); err != nil {
			return err
		}
		switch change.GetOperation() {
		case helperv1.NetworkRequest_OPERATION_SET_MTU:
			return same("mtu", change.GetMtu(), payload.Network.MTU)
		case helperv1.NetworkRequest_OPERATION_ENSURE_ROUTES:
			return sameList("routes", change.GetRoutes(), payload.Network.Routes)
		case helperv1.NetworkRequest_OPERATION_APPLY_PROFILE:
			return sameProfile(change, payload.Network)
		case helperv1.NetworkRequest_OPERATION_APPLY_LINK:
			return sameLink(change.GetLink(), payload.Network.Link)
		}
		// A removal and a rollback name the interface and the plan, and carry
		// nothing else of their own.
		return nil

	case *helperv1.HelperRequest_Dns:
		if payload.DNS == nil {
			return binding("the bound payload describes no resolver change")
		}
		// A capability for one resolver must not point the host at another.
		resolver := action.Dns
		if err := same("interface", resolver.GetInterface(), payload.DNS.Interface); err != nil {
			return err
		}
		if err := sameList("resolvers", resolver.GetServers(), payload.DNS.Servers); err != nil {
			return err
		}
		if err := sameList("search domains", resolver.GetSearchDomains(), payload.DNS.SearchDomains); err != nil {
			return err
		}
		if resolver.GetIgnoreAutoDns() != payload.DNS.IgnoreAutoDNS {
			return binding("the request and the bound payload disagree about rejecting the servers from DHCP")
		}
		return same("plan digest", resolver.GetPlanHash(), payload.DNS.PlanHash)

	case *helperv1.HelperRequest_Firewall:
		if payload.Firewall == nil {
			return binding("the bound payload describes no firewall change")
		}
		// The management address and port are the agent's own knowledge of the
		// channel it answers on; the rest of the request is the payload.
		rules := action.Firewall
		if err := same("rule", rules.GetRuleId(), payload.Firewall.RuleID); err != nil {
			return err
		}
		if err := same("zone", rules.GetZone(), payload.Firewall.Zone); err != nil {
			return err
		}
		if err := same("ruleset digest", rules.GetExpectedHash(), payload.Firewall.ExpectedHash); err != nil {
			return err
		}
		if rules.GetBreakGlass() != payload.Firewall.BreakGlass {
			return binding("the request and the bound payload disagree about overriding the protection of the management channel")
		}
		switch rules.GetOperation() {
		case helperv1.FirewallRequest_OPERATION_RULE_ENSURE:
			return sameRule(rules, payload.Firewall)
		case helperv1.FirewallRequest_OPERATION_ZONE_PORT:
			if err := sameList("ports", rules.GetPorts(), payload.Firewall.Ports); err != nil {
				return err
			}
			if err := same("protocol", rules.GetProtocol(), payload.Firewall.Protocol); err != nil {
				return err
			}
			return sameSwitch(rules.GetEnable(), payload.Firewall.Enable)
		case helperv1.FirewallRequest_OPERATION_ZONE_SERVICE:
			if err := same("service", rules.GetService(), payload.Firewall.Service); err != nil {
				return err
			}
			return sameSwitch(rules.GetEnable(), payload.Firewall.Enable)
		case helperv1.FirewallRequest_OPERATION_RESTORE:
			return same("rollback plan", rules.GetRollbackId(), payload.Firewall.RollbackID)
		}
		// A removal names the rule and nothing of the rule's content.
		return nil

	case *helperv1.HelperRequest_Ssh:
		if payload.SSH == nil {
			return binding("the bound payload describes no sshd change")
		}
		return sameSSH(action.Ssh, payload.SSH)

	case *helperv1.HelperRequest_Kernel:
		if payload.Kernel == nil {
			return binding("the bound payload describes no kernel change")
		}
		switch action.Kernel.GetOperation() {
		case helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE:
			// Only the keys: an unverified change is rolled back with the host's
			// previous values under this very capability.
			return boundSysctlKeys(action.Kernel.GetSettings(), payload.Kernel.Settings)
		case helperv1.KernelRequest_OPERATION_MODULE_LOAD:
			return same("module", action.Kernel.GetModule(), payload.Kernel.Module)
		case helperv1.KernelRequest_OPERATION_MODULE_BLACKLIST:
			if err := same("module", action.Kernel.GetModule(), payload.Kernel.Module); err != nil {
				return err
			}
			if action.Kernel.GetBlacklist() != payload.Kernel.Blacklist {
				return binding("the request blocks or unblocks the module the other way than the bound payload")
			}
			return same("plan digest", action.Kernel.GetPlanHash(), payload.Kernel.PlanHash)
		}
		return nil

	case *helperv1.HelperRequest_Time:
		if payload.Time == nil {
			return binding("the bound payload describes no time change")
		}
		switch action.Time.GetOperation() {
		case helperv1.TimeRequest_OPERATION_TIMEZONE_SET:
			return same("timezone", action.Time.GetTimezone(), payload.Time.Timezone)
		case helperv1.TimeRequest_OPERATION_CONFIG_APPLY:
			return sameTimeSources(action.Time, payload.Time)
		}
		return nil

	case *helperv1.HelperRequest_Security:
		if action.Security.GetOperation() != helperv1.SecurityRequest_OPERATION_SELINUX_MODE {
			// A rules reload names nothing, and the check that orders it carries
			// no payload at all.
			return nil
		}
		if payload.Security == nil {
			return binding("the bound payload describes no protection mode")
		}
		return same("protection mode", action.Security.GetMode(), payload.Security.Mode)

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
	// The default is a refusal. A request nothing compares with the payload is a
	// capability for one change authorising every other change of its kind, which
	// is what every rule above exists to end; a kind added without a rule is
	// refused here and named by the test that walks the whole union.
	return refusal(ErrorPayloadUnchecked,
		fmt.Sprintf("the helper holds no rule comparing a request of %T with the bound payload",
			request.GetAction()))
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
	// the helper to verify another file or to prepare a return to a version.
	if err := same("package digest", action.GetPackageSha256(), upgrade.PackageSHA256); err != nil {
		return err
	}
	return same("rollback version", action.GetRollbackVersion(), upgrade.RollbackVersion)
}

// sameFile binds what will be written, and not only where. A capability for
// one path used to authorise any content, mode and owner at that path.
func sameFile(request *helperv1.FileRequest, payload *opspec.FilePayload) error {
	if err := same("file path", request.GetPath(), payload.Path); err != nil {
		return err
	}
	if err := same("file mode", request.GetMode(), payload.Mode); err != nil {
		return err
	}
	if err := same("file owner", request.GetOwner(), payload.Owner); err != nil {
		return err
	}
	if err := same("file group", request.GetGroup(), payload.Group); err != nil {
		return err
	}
	if err := same("file validator", request.GetValidator(), payload.Validator); err != nil {
		return err
	}
	return sameContent(request, payload)
}

// sameContent binds the bytes. The panel does not hold them in two cases: a
// value fetched from the secret store on the host, and a return to a version
// only the host kept - each is bound by the name it travels under instead.
func sameContent(request *helperv1.FileRequest, payload *opspec.FilePayload) error {
	if request.GetFromSecret() != !payload.ContentSecret.Empty() {
		return binding("the request and the bound payload disagree about filling the file from a secret")
	}
	if request.GetFromSecret() {
		return nil
	}
	if err := same("file version", request.GetVersionSha256(), payload.VersionSHA256); err != nil {
		return err
	}
	if request.GetVersionSha256() != "" {
		return nil
	}
	return same("file content", contentDigest(request.GetContent()), contentDigest([]byte(payload.Content)))
}

// contentDigest names the bytes without carrying them into a refusal message.
func contentDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// sameAccount binds who the access is handed to, and not only whose account it
// is: a capability for one account used to authorise any key list on it.
func sameAccount(request *helperv1.LocalUserActionRequest, payload *opspec.LocalUserPayload) error {
	if err := same("account name", request.GetName(), payload.Name); err != nil {
		return err
	}
	if err := sameList("ssh keys", request.GetSshKeys(), payload.SSHKeys); err != nil {
		return err
	}
	if err := sameList("keys", publicKeys(request.GetKeys()), payloadKeys(payload.Keys)); err != nil {
		return err
	}
	if err := sameList("fingerprints", request.GetFingerprints(), payload.Fingerprints); err != nil {
		return err
	}
	if err := sameList("groups", request.GetGroups(), payload.Groups); err != nil {
		return err
	}
	if err := same("shell", request.GetShell(), payload.Shell); err != nil {
		return err
	}
	return same("expiry", request.GetExpiresAt(), payload.ExpiresAt)
}

func publicKeys(keys []*helperv1.LocalSSHKeyInput) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key.GetPublicKey())
	}
	return out
}

func payloadKeys(keys []opspec.SSHKeyInput) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key.PublicKey)
	}
	return out
}

// sameProfile binds what the interface will carry: a capability for one
// address profile must not write another.
func sameProfile(request *helperv1.NetworkRequest, payload *opspec.NetworkPayload) error {
	if err := same("method", request.GetMethod(), payload.Method); err != nil {
		return err
	}
	if err := sameList("addresses", request.GetAddresses(), payload.Addresses); err != nil {
		return err
	}
	if err := same("gateway", request.GetGateway(), payload.Gateway); err != nil {
		return err
	}
	if err := sameList("resolvers", request.GetDns(), payload.DNS); err != nil {
		return err
	}
	if err := sameList("routes", request.GetRoutes(), payload.Routes); err != nil {
		return err
	}
	if err := same("mtu", request.GetMtu(), payload.MTU); err != nil {
		return err
	}
	if err := same("method6", request.GetMethod6(), payload.Method6); err != nil {
		return err
	}
	if err := sameList("addresses6", request.GetAddresses6(), payload.Addresses6); err != nil {
		return err
	}
	if err := same("gateway6", request.GetGateway6(), payload.Gateway6); err != nil {
		return err
	}
	if err := same("router advertisements", request.GetAcceptRa(), payload.AcceptRA); err != nil {
		return err
	}
	return same("privacy", request.GetPrivacy(), payload.Privacy)
}

// sameLink binds the layer itself: a capability for one bond must not enslave
// other interfaces or tag another VLAN.
func sameLink(request *helperv1.NetworkLink, payload *network.LinkSpec) error {
	if request == nil || payload == nil {
		if request == nil && payload == nil {
			return nil
		}
		return binding("the request and the bound payload disagree about ordering a layer")
	}
	if err := same("layer", request.GetName(), payload.Name); err != nil {
		return err
	}
	if err := same("layer kind", request.GetKind(), payload.Kind); err != nil {
		return err
	}
	if err := sameList("layer members", request.GetMembers(), payload.Members); err != nil {
		return err
	}
	if err := same("bond mode", request.GetMode(), payload.Mode); err != nil {
		return err
	}
	if err := same("bond primary", request.GetPrimary(), payload.Primary); err != nil {
		return err
	}
	if err := same("lacp rate", request.GetLacpRate(), payload.LACPRate); err != nil {
		return err
	}
	if err := same("link monitoring", fmt.Sprint(request.GetMiimonMs()), fmt.Sprint(uint32(payload.MIIMonMS))); err != nil {
		return err
	}
	if request.GetStp() != payload.STP || request.GetVlanFiltering() != payload.VLANFiltering {
		return binding("the request switches the bridge settings the other way than the bound payload")
	}
	if err := same("vlan parent", request.GetParent(), payload.Parent); err != nil {
		return err
	}
	if err := same("vlan tag", fmt.Sprint(request.GetVlanId()), fmt.Sprint(uint32(payload.VLANID))); err != nil {
		return err
	}
	if err := same("vlan protocol", request.GetProtocol(), payload.Protocol); err != nil {
		return err
	}
	return same("layer mtu", request.GetMtu(), payload.MTU)
}

// sameRule binds the content of the rule and not only its name: a capability
// for one rule used to authorise any ports and sources under that name.
func sameRule(request *helperv1.FirewallRequest, payload *opspec.FirewallPayload) error {
	if err := same("chain", request.GetChain(), payload.Chain); err != nil {
		return err
	}
	if err := same("verdict", request.GetAction(), payload.Action); err != nil {
		return err
	}
	if err := same("protocol", request.GetProtocol(), payload.Protocol); err != nil {
		return err
	}
	if err := sameList("ports", request.GetPorts(), payload.Ports); err != nil {
		return err
	}
	if err := sameList("sources", request.GetSources(), payload.Sources); err != nil {
		return err
	}
	return same("interface", request.GetInterface(), payload.Interface)
}

// sameSwitch binds the direction of a zone change: a capability must not open
// what the operator ordered closed.
func sameSwitch(got, want bool) error {
	if got != want {
		return binding("the request opens or closes the zone the other way than the bound payload")
	}
	return nil
}

// sameSSH binds what the change would set, and not only that it is an sshd
// change: the consent to leave no login method is part of the order.
func sameSSH(request *helperv1.SshRequest, payload *opspec.SSHPayload) error {
	if request.GetOperation() == helperv1.SshRequest_OPERATION_ROTATE_HOSTKEY {
		// A rotation names a key type; no setting plays a part in it.
		return same("host key type", request.GetKeyType(), payload.KeyType)
	}
	if err := same("sshd port", request.GetPort(), payload.Port); err != nil {
		return err
	}
	if err := same("root login", request.GetPermitRootLogin(), payload.PermitRootLogin); err != nil {
		return err
	}
	if err := same("password authentication", request.GetPasswordAuthentication(),
		payload.PasswordAuthentication); err != nil {
		return err
	}
	if err := same("public key authentication", request.GetPubkeyAuthentication(),
		payload.PubkeyAuthentication); err != nil {
		return err
	}
	if err := same("keyboard-interactive authentication", request.GetKbdInteractiveAuthentication(),
		payload.KbdInteractive); err != nil {
		return err
	}
	if err := same("authentication attempts", request.GetMaxAuthTries(), payload.MaxAuthTries); err != nil {
		return err
	}
	if err := sameList("allowed users", request.GetAllowUsers(), payload.AllowUsers); err != nil {
		return err
	}
	if err := sameList("allowed groups", request.GetAllowGroups(), payload.AllowGroups); err != nil {
		return err
	}
	if err := sameList("denied users", request.GetDenyUsers(), payload.DenyUsers); err != nil {
		return err
	}
	if request.GetAllowLockout() != payload.AllowLockout {
		return binding("the request and the bound payload disagree about consent to leave no login method")
	}
	return same("plan digest", request.GetPlanHash(), payload.PlanHash)
}

// sameTimeSources binds the servers and the two consents; the helper checks
// the plan only when the request carries it, so the digest is bound as well.
func sameTimeSources(request *helperv1.TimeRequest, payload *opspec.TimePayload) error {
	if err := sameList("time servers", request.GetServers(), payload.Servers); err != nil {
		return err
	}
	if request.GetAllowStep() != payload.AllowStep {
		return binding("the request and the bound payload disagree about consent to step the clock")
	}
	if request.GetEnableDropin() != payload.EnableDropIn {
		return binding("the request and the bound payload disagree about writing the source directory into the daemon's file")
	}
	return same("plan digest", request.GetPlanHash(), payload.PlanHash)
}

// boundSysctlKeys binds the keys and not their values: an unverified change is
// rolled back with the host's previous readings under the same capability, and
// the baseline drops the keys the agent could not read.
func boundSysctlKeys(got, want map[string]string) error {
	if len(got) == 0 {
		return binding("the request names no kernel setting")
	}
	keys := make([]string, 0, len(got))
	for key := range got {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if _, named := want[key]; !named {
			return binding(fmt.Sprintf("the request sets the kernel setting %q, which the bound payload does not name", key))
		}
	}
	return nil
}

// serviceDigests flattens the per-service image digests into a comparable list.
func serviceDigests(digests map[string]string) []string {
	out := make([]string, 0, len(digests))
	for service, digest := range digests {
		out = append(out, service+"="+digest)
	}
	return out
}

// selectedAnswers names each answer by all four of its parts: the value is
// what configures the package, not only the question it answers.
func selectedAnswers(answers []*helperv1.DebconfSelection) []string {
	out := make([]string, 0, len(answers))
	for _, answer := range answers {
		out = append(out, strings.Join([]string{answer.GetPackage(), answer.GetQuestion(),
			answer.GetType(), answer.GetValue()}, "\x00"))
	}
	return out
}

func approvedAnswers(answers []opspec.DebconfAnswer) []string {
	out := make([]string, 0, len(answers))
	for _, answer := range answers {
		out = append(out, strings.Join([]string{answer.Package, answer.Question,
			answer.Type, answer.Value}, "\x00"))
	}
	return out
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
