package opspec

import (
	"fmt"
	"sort"
	"strings"
)

// The verifier of an operation: how the host confirms, after the change,
// that the state the operator asked for is the state the host is in.
//
// An exit code says that a tool ran; it does not say that the unit is
// active, that the file has the digest of the plan or that the mount is
// there. The verifier is a read of the host after the apply, compared with
// what the payload or the plan promised, and only it may turn a change
// into a success: an apply whose verifier fails settles as
// applied_unverified - the change was made, the state was not observed -
// and, where the contract says so, the host puts the previous state back
// first. The contract declares one verifier per mutating family and
// declares none only where the result of the operation is the observation
// itself: a read, a plan, a signal delivered, a one-shot run.

// Verifier names the read that confirms an operation.
type Verifier string

const (
	// VerifierNone: the result is the observation. Reads, plans, a signal,
	// a one-shot run of somebody else's command, a prune whose result is
	// what it freed.
	VerifierNone Verifier = "none"
	// VerifierUnitState: the unit is in the state the verb asked for -
	// active after a start, inactive after a stop, enabled or masked as
	// the toggle says, no failed state after a reset.
	VerifierUnitState Verifier = "unit_state"
	// VerifierScheduleEntry: the managed entry is on the host, enabled or
	// disabled as ordered, or gone after a removal.
	VerifierScheduleEntry Verifier = "schedule_entry"
	// VerifierPackageVersions: every package of the plan is installed at
	// the candidate version, or absent after a removal, read from the
	// package database and not from the transaction's output.
	VerifierPackageVersions Verifier = "package_versions"
	// VerifierPackageHold: the hold list of the manager names the package,
	// or no longer does.
	VerifierPackageHold Verifier = "package_hold"
	// VerifierPackageDatabase: the package database needs no attention
	// after a repair.
	VerifierPackageDatabase Verifier = "package_database"
	// VerifierRepository: the source list of the host names the repository
	// as ordered.
	VerifierRepository Verifier = "repository"
	// VerifierFileContent: the file has the digest of the content written,
	// with the mode and the owner ordered, or is absent after a removal.
	VerifierFileContent Verifier = "file_content"
	// VerifierMountState: the mount point is mounted from the source with
	// the filesystem ordered, and in fstab when the order persists it; or
	// unmounted and out of fstab after a removal.
	VerifierMountState Verifier = "mount_state"
	// VerifierStorageLayout: the volume or the filesystem has at least the
	// size ordered, the device carries the filesystem ordered, or carries
	// no signature after a wipe.
	VerifierStorageLayout Verifier = "storage_layout"
	// VerifierHostname: the kernel's host name is the one ordered.
	VerifierHostname Verifier = "hostname"
	// VerifierSysctl: every key of the order reads the value ordered from
	// /proc/sys.
	VerifierSysctl Verifier = "sysctl"
	// VerifierKernelModule: the module is loaded, or blacklisted in the
	// managed configuration.
	VerifierKernelModule Verifier = "kernel_module"
	// VerifierSSHDConfig: the effective sshd configuration carries every
	// setting of the order.
	VerifierSSHDConfig Verifier = "sshd_config"
	// VerifierSSHHostKey: the host key of the type ordered is a new one.
	VerifierSSHHostKey Verifier = "ssh_host_key"
	// VerifierResolver: the resolver of the host names the servers and the
	// search domains ordered.
	VerifierResolver Verifier = "resolver"
	// VerifierTimeSource: the configured time servers are the ones ordered.
	VerifierTimeSource Verifier = "time_source"
	// VerifierTimezone: the host's zone is the one ordered.
	VerifierTimezone Verifier = "timezone"
	// VerifierNetworkState: the interface carries the MTU or the addresses
	// ordered and the routes ordered are in the table.
	VerifierNetworkState Verifier = "network_state"
	// VerifierFirewallRuleset: the rule or the zone entry is in the live
	// ruleset, or gone after a removal; a restore reads the ruleset
	// digest of the plan restored.
	VerifierFirewallRuleset Verifier = "firewall_ruleset"
	// VerifierMACMode: the mandatory access control reports the mode
	// ordered.
	VerifierMACMode Verifier = "mac_mode"
	// VerifierAuditRules: the audit subsystem reports loaded rules after
	// the reload.
	VerifierAuditRules Verifier = "audit_rules"
	// VerifierTrustAnchor: the trust store lists the anchor, or no longer
	// does.
	VerifierTrustAnchor Verifier = "trust_anchor"
	// VerifierCertificate: the certificate at the path has the fingerprint
	// deployed, or a later expiry than before a renewal.
	VerifierCertificate Verifier = "certificate"
	// VerifierLocalAccount: the account exists with the shell, the groups,
	// the expiry, the lock state or the keys ordered, or is gone after a
	// deletion.
	VerifierLocalAccount Verifier = "local_account"
	// VerifierContainerState: the container is running, stopped or gone as
	// the verb asked.
	VerifierContainerState Verifier = "container_state"
	// VerifierImagePresent: the engine lists the image pulled.
	VerifierImagePresent Verifier = "image_present"
	// VerifierComposeServices: every service of the project runs from the
	// image digest the plan bound.
	VerifierComposeServices Verifier = "compose_services"
	// VerifierBackupRun: the repository lists the snapshot the run reported.
	VerifierBackupRun Verifier = "backup_run"
	// VerifierRestoreTarget: the restore target holds files after the
	// restore.
	VerifierRestoreTarget Verifier = "restore_target"
	// VerifierDomainMembership: the host is joined to, or has left, the
	// domain, by the host's own configuration and keytab.
	VerifierDomainMembership Verifier = "domain_membership"
	// VerifierKeytab: the key version number of the principal went up.
	VerifierKeytab Verifier = "keytab"
	// VerifierReboot: the host comes back with a boot identifier other than
	// the one it had when the reboot was ordered. The agent cannot observe
	// it - the process that would is gone with the host - so the panel
	// settles it on the next Hello, and a host that does not come back
	// within the wait ends reboot_not_observed.
	VerifierReboot Verifier = "reboot"
	// VerifierAgentVersion: the agent comes back with the version ordered.
	// Settled by the panel on the next Hello, like a reboot.
	VerifierAgentVersion Verifier = "agent_version"
)

// UnverifiedPolicy says what the host does with a change whose verifier
// failed.
type UnverifiedPolicy string

const (
	// UnverifiedReport: the change stays; the result says the state was
	// not observed and what was found instead.
	UnverifiedReport UnverifiedPolicy = "report"
	// UnverifiedRollback: the host puts the state from before the change
	// back - the previous content of the file, the previous value of the
	// key - and the result says both that the change did not verify and
	// that it was undone. A rollback that itself fails is reported.
	UnverifiedRollback UnverifiedPolicy = "rollback"
)

// PanelSettled says whether the verifier is run by the panel on the host's
// return rather than by the agent after the apply: the observation is the
// host coming back, and no process on the host survives to make it.
func (v Verifier) PanelSettled() bool {
	return v == VerifierReboot || v == VerifierAgentVersion
}

// KnownVerifier checks that the verifier is one of the registry's.
func KnownVerifier(verifier Verifier) bool {
	switch verifier {
	case VerifierNone, VerifierUnitState, VerifierScheduleEntry, VerifierPackageVersions,
		VerifierPackageHold, VerifierPackageDatabase, VerifierRepository, VerifierFileContent,
		VerifierMountState, VerifierStorageLayout, VerifierHostname, VerifierSysctl,
		VerifierKernelModule, VerifierSSHDConfig, VerifierSSHHostKey, VerifierResolver,
		VerifierTimeSource, VerifierTimezone, VerifierNetworkState, VerifierFirewallRuleset,
		VerifierMACMode, VerifierAuditRules, VerifierTrustAnchor, VerifierCertificate,
		VerifierLocalAccount, VerifierContainerState, VerifierImagePresent, VerifierComposeServices,
		VerifierBackupRun, VerifierRestoreTarget, VerifierDomainMembership, VerifierKeytab,
		VerifierReboot, VerifierAgentVersion:
		return true
	}
	return false
}

// Verifier returns the verifier of an operation. A read has none: its
// result is the observation. An unknown operation has none either, and
// ValidateVerifiers keeps a mutating operation without one from ever
// reaching a running control plane.
func (a ActionType) Verifier() Verifier {
	spec, ok := actionSpecs[a]
	if !ok || !spec.mutating || spec.verifier == "" {
		return VerifierNone
	}
	return spec.verifier
}

// OnUnverified returns what the host does with a change of this operation
// whose verifier failed. Report is the default: a rollback is declared
// only where the host keeps what it takes to put the previous state back.
func (a ActionType) OnUnverified() UnverifiedPolicy {
	if actionSpecs[a].onUnverified == UnverifiedRollback {
		return UnverifiedRollback
	}
	return UnverifiedReport
}

// ErrorAppliedUnverified is the code of a change that was made and whose
// verifier did not observe the state the operator asked for. It is a
// failure of the job - the operator has to look at the host - and never a
// success with a footnote.
const ErrorAppliedUnverified = "applied_unverified"

// ErrorRebootNotObserved is the code of a reboot the host never came back
// from within the wait: the reboot was ordered and accepted, and no session
// with a new boot identifier followed.
const ErrorRebootNotObserved = "reboot_not_observed"

// ValidateVerifiers checks that every mutating operation declares a known
// verifier and that a rollback policy sits only on an operation with a
// way back. Like ValidateContracts it is called before the control plane
// listens: an operation that could end succeeded on an exit code alone is
// a reason not to start.
func ValidateVerifiers() error {
	var problems []string
	for _, action := range AllActions() {
		spec := actionSpecs[action]
		if !spec.mutating {
			if spec.verifier != "" && spec.verifier != VerifierNone {
				problems = append(problems, fmt.Sprintf("%s: a verifier on a read; a read is its own observation", action))
			}
			continue
		}
		if spec.verifier == "" {
			problems = append(problems, fmt.Sprintf("%s: no verifier declared", action))
			continue
		}
		if !KnownVerifier(spec.verifier) {
			problems = append(problems, fmt.Sprintf("%s: verifier %q is not declared", action, spec.verifier))
		}
		if spec.onUnverified == UnverifiedRollback && spec.verifier == VerifierNone {
			problems = append(problems, fmt.Sprintf("%s: a rollback on unverified with no verifier", action))
		}
		if spec.onUnverified == UnverifiedRollback && action.Contract().Rollback == RollbackNone {
			problems = append(problems, fmt.Sprintf("%s: a rollback on unverified with rollback class none", action))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%w: %s", ErrContractMissing, strings.Join(problems, "; "))
}
