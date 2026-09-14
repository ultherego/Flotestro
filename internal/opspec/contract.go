package opspec

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The second half of the operation contract: what happens to an operation
// that is already under way.
//
// The first half - permission, risk, capability, campaign mode, offline
// policy - decides whether an order is placed at all. This half decides what
// the panel may promise once the order is on the host: whether a running
// operation can be stopped, whether repeating it is safe, whether there is a
// way back, what the campaign checks afterwards and which host resources the
// operation takes. Every mutating operation declares all of it explicitly.
// Missing metadata does not become the most convenient answer: the control
// plane refuses to start, because a cancel button drawn on a guess would
// promise the operator something the host cannot do.

// CancelMode says what a cancel request does to an operation that is under
// way. A queued operation is always cancellable: it has not touched the host.
type CancelMode string

const (
	// CancelSafe: the context cancel interrupts the operation and leaves a
	// consistent state - a read, a probe, a stream.
	CancelSafe CancelMode = "safe"
	// CancelCheckpointOnly: the cancel is checked only between atomic steps.
	// The step under way finishes; the next one does not start.
	CancelCheckpointOnly CancelMode = "checkpoint_only"
	// CancelImpossibleAfterStart: once the host reported a start, the cancel
	// is only information. A package transaction or a filesystem resize runs
	// to its end.
	CancelImpossibleAfterStart CancelMode = "impossible_after_start"
	// CancelLocalWatchdogOwned: the host's own safety mechanism decides. The
	// control plane may ask, but it never stops a rollback timer that guards
	// the management channel.
	CancelLocalWatchdogOwned CancelMode = "local_watchdog_owned"
)

// RollbackClass says what way back exists after the change landed.
type RollbackClass string

const (
	// RollbackAutomaticLocal: the host reverts itself without the control
	// plane - the connectivity watchdog of the network and firewall modules.
	RollbackAutomaticLocal RollbackClass = "automatic_local"
	// RollbackExactRestore: a previous version is kept and can be put back
	// as it was - a managed file, a schedule, a Compose manifest.
	RollbackExactRestore RollbackClass = "exact_restore"
	// RollbackCompensating: a new plan neutralises the effect, but the
	// history stays - a downgrade after an upgrade, a start after a stop.
	RollbackCompensating RollbackClass = "compensating"
	// RollbackBestEffort: an attempt to limit the damage with no guarantee
	// of the initial state.
	RollbackBestEffort RollbackClass = "best_effort"
	// RollbackNone: irreversible - a wipe, a shutdown, a signal.
	RollbackNone RollbackClass = "none"
)

// Verification says what a campaign checks on the host after the change.
type Verification string

const (
	// VerifyNone: nothing to check, or nothing that can be checked from the
	// panel.
	VerifyNone Verification = "none"
	// VerifyUnitHealth: the unit the change concerns is in the expected
	// state and healthy.
	VerifyUnitHealth Verification = "unit_health"
	// VerifyConnectivity: the host still answers on the management channel.
	VerifyConnectivity Verification = "connectivity"
	// VerifyPlanRecheck: the plan computed again shows no difference.
	VerifyPlanRecheck Verification = "plan_recheck"
	// VerifyCustom: the module has its own check - a probe, a boot ID, a
	// version reported back.
	VerifyCustom Verification = "custom"
)

// ClaimMode says whether a claim on a host resource tolerates neighbours.
type ClaimMode string

const (
	// ClaimShared coexists with other shared claims on the same class; its
	// weight is what it costs the host.
	ClaimShared ClaimMode = "shared"
	// ClaimExclusive keeps everything else off the class.
	ClaimExclusive ClaimMode = "exclusive"
)

// Claim classes that are not lock classes: they name resources the host
// agent takes next to the registry's lock class.
const (
	// ClaimHost is the whole host: a reboot or a shutdown collides with every
	// other mutation.
	ClaimHost = "host"
	// ClaimKernel covers sysctl and modules; such a change takes the network
	// as well, because it changes the network stack.
	ClaimKernel = "kernel"
	// ClaimSecurity covers the MAC mode and the audit rules.
	ClaimSecurity = "security"
	// ClaimFile is one managed file. The registry declares the class; the
	// agent binds it to the path from the payload at dispatch, so changes of
	// different files do not wait for each other.
	ClaimFile = "file"
	// ClaimLogsRead is a shared class for reading the journal and log
	// files: bytes per second and file descriptors.
	ClaimLogsRead = "logs-read"
	// ClaimInventoryHeavy is a shared class for reads that start
	// subprocesses and walk the host: process, container and storage scans.
	ClaimInventoryHeavy = "inventory-heavy"
)

// ResourceClaim is one claim an operation takes on a host resource.
type ResourceClaim struct {
	Class  string    `json:"class"`
	Mode   ClaimMode `json:"mode"`
	Weight int       `json:"weight"`
}

// Contract is the part of the operation contract that concerns an operation
// under way and after it.
type Contract struct {
	CancelMode CancelMode `json:"cancel_mode"`
	// RetryClass reuses the retry policy of the error guide: it is the answer
	// to "may this be repeated" when the outcome is a failure or unknown.
	RetryClass     RetryPolicy     `json:"retry_class"`
	Rollback       RollbackClass   `json:"rollback"`
	Verification   Verification    `json:"verification"`
	ResourceClaims []ResourceClaim `json:"resource_claims"`
}

// ErrContractMissing means a mutating operation without a full declaration.
var ErrContractMissing = errors.New("operation contract missing")

// Contract returns the declaration of an operation.
//
// A read derives it: it can be cancelled any time, repeating it is free,
// there is nothing to roll back and nothing to verify, and it takes shared
// claims with the weight of one. A mutating operation has to be in the
// table; an undeclared one gets the strictest reading - not cancellable
// once started, never repeated blind, nothing to roll back - and
// ValidateContracts keeps such an operation from ever reaching a running
// control plane.
func (a ActionType) Contract() Contract {
	if declared, ok := contracts[a]; ok {
		return declared.withClaims(a)
	}
	if a.Known() && !a.Mutating() {
		return Contract{
			CancelMode:     CancelSafe,
			RetryClass:     RetryAutomatic,
			Rollback:       RollbackNone,
			Verification:   VerifyNone,
			ResourceClaims: readClaims(a),
		}
	}
	return Contract{
		CancelMode:     CancelImpossibleAfterStart,
		RetryClass:     RetryReadState,
		Rollback:       RollbackNone,
		Verification:   VerifyNone,
		ResourceClaims: []ResourceClaim{},
	}
}

// contract is one row of the table. The claims list only what the agent
// takes next to the lock class of the registry; the lock class itself is
// added by withClaims, so the two registries cannot drift apart.
type contract struct {
	cancel   CancelMode
	retry    RetryPolicy
	rollback RollbackClass
	verify   Verification
	// weight is the cost of the exclusive claim on the lock class; zero
	// means one.
	weight int
	extra  []ResourceClaim
}

func (c contract) withClaims(action ActionType) Contract {
	claims := make([]ResourceClaim, 0, len(c.extra)+1)
	if class := action.LockClass(); class != LockNone {
		weight := c.weight
		if weight == 0 {
			weight = 1
		}
		claims = append(claims, ResourceClaim{Class: class, Mode: ClaimExclusive, Weight: weight})
	}
	claims = append(claims, c.extra...)
	sort.Slice(claims, func(i, j int) bool { return claims[i].Class < claims[j].Class })
	return Contract{
		CancelMode:     c.cancel,
		RetryClass:     c.retry,
		Rollback:       c.rollback,
		Verification:   c.verify,
		ResourceClaims: claims,
	}
}

// readClaims derives the claims of a read: the lock class it names, shared,
// and one of the two shared classes of the document for the reads that
// cost the host something even though they change nothing.
func readClaims(action ActionType) []ResourceClaim {
	claims := []ResourceClaim{}
	if class := action.LockClass(); class != LockNone {
		claims = append(claims, ResourceClaim{Class: class, Mode: ClaimShared, Weight: 1})
	}
	switch action {
	case ActionReadJournal, ActionFollowJournal, ActionReadLogFile, ActionDockerEvents:
		claims = append(claims, ResourceClaim{Class: ClaimLogsRead, Mode: ClaimShared, Weight: 1})
	case ActionProcessList, ActionDockerRead, ActionInventoryRefresh, ActionSecurityScan,
		ActionCertificateScan, ActionStoragePlan, ActionPackageList:
		claims = append(claims, ResourceClaim{Class: ClaimInventoryHeavy, Mode: ClaimShared, Weight: 1})
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].Class < claims[j].Class })
	return claims
}

func exclusive(class string) ResourceClaim {
	return ResourceClaim{Class: class, Mode: ClaimExclusive, Weight: 1}
}

// contracts is the table of declarations for mutating operations.
//
// The cancel modes follow the cancellation contract of chapter 15 of the
// multitasking document, the rollback classes chapter 19. The retry class
// follows the cancel mode: an operation that runs to its end once started
// is never repeated blind, a change bound to a per-host plan is repeated
// only after a new plan.
var contracts = map[ActionType]contract{
	// systemd units. One systemctl call is one step: it either happened or
	// it did not, and the panel reads the unit before deciding anything.
	// Start and stop undo each other; a restart or a reload has no reverse.
	ActionUnitStart:     {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyUnitHealth},
	ActionUnitStop:      {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyUnitHealth},
	ActionUnitRestart:   {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyUnitHealth},
	ActionUnitReload:    {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyUnitHealth},
	ActionUnitEnableSet: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyUnitHealth},
	ActionUnitMaskSet:   {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyUnitHealth},
	// Clearing the failed state changes a record, not a process: it can be
	// cancelled at any point, repeated freely, and there is nothing to put
	// back - the failure it clears has already happened.
	ActionUnitResetFailed: {cancel: CancelSafe, retry: RetryAutomatic, rollback: RollbackNone, verify: VerifyUnitHealth},

	// Scheduled jobs. A managed entry keeps its previous version; writing
	// it is a sequence of steps (the unit files, the reload, the enable) and
	// the cancel is honoured between them. The entry is a declaration, so
	// repeating it is free. Running an entry now is a run of somebody
	// else's command: it ends when it ends.
	ActionScheduleEnsure:  {cancel: CancelCheckpointOnly, retry: RetryAutomatic, rollback: RollbackExactRestore, verify: VerifyUnitHealth},
	ActionScheduleDisable: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackExactRestore, verify: VerifyUnitHealth},
	ActionScheduleRemove:  {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackExactRestore, verify: VerifyUnitHealth},
	ActionScheduleRunNow:  {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyCustom},

	// The network and the resolver. The host arms a rollback timer before
	// the change and reverts itself when the commit does not come; the
	// control plane only asks. After a commit the way back is a new plan.
	ActionNetworkProfileApply: {cancel: CancelLocalWatchdogOwned, retry: RetryAfterReplan, rollback: RollbackAutomaticLocal, verify: VerifyConnectivity},
	ActionNetworkRouteEnsure:  {cancel: CancelLocalWatchdogOwned, retry: RetryAfterReplan, rollback: RollbackAutomaticLocal, verify: VerifyConnectivity},
	ActionNetworkMTUSet:       {cancel: CancelLocalWatchdogOwned, retry: RetryAfterReplan, rollback: RollbackAutomaticLocal, verify: VerifyConnectivity},
	ActionNetworkRollback:     {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyConnectivity},
	ActionDNSHostApply:        {cancel: CancelLocalWatchdogOwned, retry: RetryAfterReplan, rollback: RollbackAutomaticLocal, verify: VerifyConnectivity},

	// The firewall, the same way: the ruleset is replaced atomically under a
	// watchdog, and restoring a ruleset is the rollback itself.
	ActionFirewallRuleEnsure:     {cancel: CancelLocalWatchdogOwned, retry: RetryAfterReplan, rollback: RollbackAutomaticLocal, verify: VerifyConnectivity},
	ActionFirewallRuleRemove:     {cancel: CancelLocalWatchdogOwned, retry: RetryAfterReplan, rollback: RollbackAutomaticLocal, verify: VerifyConnectivity},
	ActionFirewallZonePort:       {cancel: CancelLocalWatchdogOwned, retry: RetryAfterReplan, rollback: RollbackAutomaticLocal, verify: VerifyConnectivity},
	ActionFirewallZoneService:    {cancel: CancelLocalWatchdogOwned, retry: RetryAfterReplan, rollback: RollbackAutomaticLocal, verify: VerifyConnectivity},
	ActionFirewallRulesetRestore: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyConnectivity},

	// Storage. A mount is fstab plus the mount itself, with a checkpoint
	// between; a removal reverses it. A check, an extension or a resize
	// runs on the device until it is done, and there is no safe shrink.
	// Creating a filesystem and wiping a disk have neither a way back nor a
	// repeat.
	ActionMountEnsure:      {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackCompensating, verify: VerifyPlanRecheck, weight: 2},
	ActionMountRemove:      {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackCompensating, verify: VerifyPlanRecheck, weight: 2},
	ActionFilesystemCheck:  {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyCustom, weight: 3},
	ActionLVMExtend:        {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyPlanRecheck, weight: 3},
	ActionFilesystemResize: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyPlanRecheck, weight: 3},
	ActionFilesystemCreate: {cancel: CancelImpossibleAfterStart, retry: RetryNever, rollback: RollbackNone, verify: VerifyCustom, weight: 3},
	ActionDiskWipe:         {cancel: CancelImpossibleAfterStart, retry: RetryNever, rollback: RollbackNone, verify: VerifyNone, weight: 3},

	// sshd. The configuration goes in as a staged drop-in under a watchdog
	// that keeps the login path; a host key rotation is a change of
	// identity with no way back but a new plan.
	ActionSSHConfigApply:   {cancel: CancelLocalWatchdogOwned, retry: RetryAfterReplan, rollback: RollbackAutomaticLocal, verify: VerifyConnectivity},
	ActionSSHHostKeyRotate: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyCustom},

	// Security. The MAC mode is set back by setting it again; loaded audit
	// rules are not unloaded by the panel.
	ActionSELinuxModeSet:   {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom, extra: []ResourceClaim{exclusive(ClaimSecurity)}},
	ActionAuditRulesReload: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyCustom, extra: []ResourceClaim{exclusive(ClaimSecurity)}},
	// A fleet remediation is a plan of steps: a cancel is honoured between
	// them, the step under way finishes. It is repeated only after the
	// findings are assessed again, the way back depends on the steps and
	// part of them has no compensation, and the verification is the same
	// checks computed anew. The claims are the steps' own.
	ActionSecurityRemediate: {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackBestEffort, verify: VerifyCustom},

	// Certificates. Trust changes are steps with a recomputed bundle at
	// the end; the reverse of adding an anchor is removing it. A deployment
	// keeps the previous certificate next to the new one; a renewal is
	// ordered from the host's own daemon and settled by the probe.
	ActionCertificateTrustEnsure: {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackCompensating, verify: VerifyPlanRecheck},
	ActionCertificateTrustRemove: {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackCompensating, verify: VerifyPlanRecheck},
	ActionCertificateDeploy:      {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackExactRestore, verify: VerifyCustom},
	ActionCertificateRenew:       {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyCustom},

	// Time. The sources go in through the panel's own file and the daemon
	// reload, with a checkpoint between; the previous sources come back as
	// a new plan. A timezone is one call, set back by setting it again.
	ActionTimeConfigApply: {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackCompensating, verify: VerifyPlanRecheck},
	ActionTimezoneSet:     {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},

	// The kernel. A sysctl value and a module take the network as well: they
	// change the stack an address change relies on. A blacklist entry is
	// removed by a new change and may need another reboot to take effect.
	ActionSysctlEnsure:          {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom, extra: []ResourceClaim{exclusive(ClaimKernel), exclusive(LockNetwork)}},
	ActionKernelModuleLoad:      {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom, extra: []ResourceClaim{exclusive(ClaimKernel), exclusive(LockNetwork)}},
	ActionKernelModuleBlacklist: {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackCompensating, verify: VerifyPlanRecheck, extra: []ResourceClaim{exclusive(ClaimKernel), exclusive(LockNetwork)}},

	// Managed files. The write is bound to the digest the plan saw, goes
	// through validation before the atomic replace, and the previous
	// version stays in the store - including the one a rollback replaces.
	ActionFileEnsure:   {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackExactRestore, verify: VerifyPlanRecheck, extra: []ResourceClaim{exclusive(ClaimFile)}},
	ActionFileRemove:   {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackExactRestore, verify: VerifyPlanRecheck, extra: []ResourceClaim{exclusive(ClaimFile)}},
	ActionFileRollback: {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackExactRestore, verify: VerifyPlanRecheck, extra: []ResourceClaim{exclusive(ClaimFile)}},

	// A signal is delivered or it is not; nothing takes it back and nothing
	// on the host is held for it.
	ActionProcessSignal: {cancel: CancelImpossibleAfterStart, retry: RetryNever, rollback: RollbackNone, verify: VerifyNone},

	// Packages. A transaction of the package manager runs to its end. The
	// way back from an upgrade or an install is a downgrade as a new plan,
	// checked by the plan computed again showing nothing left to do; a
	// reinstall after a removal brings the files back but not the state
	// the package had. The changes without a planner - a hold, a source, a
	// repair - are checked by the module itself. The agent's own upgrade
	// is settled by the host coming back with the version.
	ActionPackageUpgrade: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyPlanRecheck, weight: 4},
	ActionPackageInstall: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyPlanRecheck, weight: 4},
	ActionPackageRemove:  {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackBestEffort, verify: VerifyCustom, weight: 4},
	ActionPackageRepair:  {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyCustom, weight: 4},
	ActionPackageHoldSet: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},
	ActionRepositorySet:  {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom, weight: 2},
	ActionAgentUpgrade:   {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackBestEffort, verify: VerifyCustom, weight: 4},

	// Backup. A copy and a verification go chunk by chunk and stop between
	// chunks; neither changes the host. A restore unpacks old state onto a
	// running system and has no way back.
	ActionBackupRun:     {cancel: CancelCheckpointOnly, retry: RetryAfterChange, rollback: RollbackNone, verify: VerifyCustom, weight: 4},
	ActionBackupVerify:  {cancel: CancelCheckpointOnly, retry: RetryAutomatic, rollback: RollbackNone, verify: VerifyCustom, weight: 2},
	ActionBackupRestore: {cancel: CancelCheckpointOnly, retry: RetryReadState, rollback: RollbackNone, verify: VerifyCustom, weight: 4},

	// Power. A reboot is settled by a new boot ID and the units after it; a
	// shutdown is not brought back through the panel.
	ActionSystemReboot:   {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyCustom, extra: []ResourceClaim{exclusive(ClaimHost)}},
	ActionSystemShutdown: {cancel: CancelImpossibleAfterStart, retry: RetryNever, rollback: RollbackNone, verify: VerifyNone, extra: []ResourceClaim{exclusive(ClaimHost)}},
	// A rename is one hostnamectl call and is undone by renaming back; the
	// host lock is the registry's lock class, so the claim comes with it.
	// The verification is the host's own: the next inventory reports the
	// new name.
	ActionSystemHostnameSet: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},

	// Identity. Enrollment is a saga with checkpoints; leaving the domain
	// is a separate decision, not an automatic reverse.
	ActionDomainEnroll: {cancel: CancelCheckpointOnly, retry: RetryAfterChange, rollback: RollbackCompensating, verify: VerifyCustom, weight: 2},
	// Leaving is one uninstall that runs to its end once started; the way
	// back is a new join with a new credential, and the host's own
	// verification - configuration and keytab gone - settles the result.
	ActionDomainLeave: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom, weight: 2},

	// Local accounts. Each change is one call on the account database and
	// has a compensating change: lock after create, unlock after lock, the
	// previous key set after a new one.
	ActionLocalUserCreate: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},
	ActionLocalUserLock:   {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},
	ActionLocalUserUnlock: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},
	ActionLocalSSHKeysSet: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},
	// The previous group list and the previous expiry date are read back
	// from the account before the change, so each has a compensating
	// change. A deleted account has none: the UID's ownership of what it
	// left behind does not come back with a new account of the same name.
	ActionLocalUserGroupsSet: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},
	ActionLocalUserExpirySet: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},
	ActionLocalUserDelete:    {cancel: CancelImpossibleAfterStart, retry: RetryNever, rollback: RollbackNone, verify: VerifyCustom},

	// Containers. Start and stop undo each other; a restart has no
	// reverse; a removal and a prune free what is gone. A pull can be
	// dropped at any moment - the engine keeps only complete layers - and
	// repeating it is free. A deployment keeps the previous manifest and
	// digests, so the project can be put back as it was where the images
	// are still there.
	ActionDockerStart:   {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},
	ActionDockerStop:    {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackCompensating, verify: VerifyCustom},
	ActionDockerRestart: {cancel: CancelImpossibleAfterStart, retry: RetryReadState, rollback: RollbackNone, verify: VerifyCustom},
	ActionDockerRemove:  {cancel: CancelImpossibleAfterStart, retry: RetryNever, rollback: RollbackNone, verify: VerifyNone},
	ActionDockerPull:    {cancel: CancelSafe, retry: RetryAutomatic, rollback: RollbackBestEffort, verify: VerifyCustom, weight: 3},
	ActionDockerPrune:   {cancel: CancelImpossibleAfterStart, retry: RetryNever, rollback: RollbackNone, verify: VerifyNone, weight: 2},
	ActionComposeDeploy: {cancel: CancelCheckpointOnly, retry: RetryAfterReplan, rollback: RollbackExactRestore, verify: VerifyCustom, weight: 3},
}

// KnownCancelMode checks that the mode is one of the registry's.
func KnownCancelMode(mode CancelMode) bool {
	switch mode {
	case CancelSafe, CancelCheckpointOnly, CancelImpossibleAfterStart, CancelLocalWatchdogOwned:
		return true
	}
	return false
}

// KnownRetryPolicy checks that the policy is one of the error guide's.
func KnownRetryPolicy(policy RetryPolicy) bool {
	switch policy {
	case RetryNever, RetryAutomatic, RetryAfterChange, RetryAfterReplan, RetryReadState:
		return true
	}
	return false
}

// KnownRollbackClass checks that the class is one of the registry's.
func KnownRollbackClass(class RollbackClass) bool {
	switch class {
	case RollbackAutomaticLocal, RollbackExactRestore, RollbackCompensating, RollbackBestEffort, RollbackNone:
		return true
	}
	return false
}

// KnownVerification checks that the verification is one of the registry's.
func KnownVerification(verification Verification) bool {
	switch verification {
	case VerifyNone, VerifyUnitHealth, VerifyConnectivity, VerifyPlanRecheck, VerifyCustom:
		return true
	}
	return false
}

// CancellableIn says whether a cancel request stops an operation in the
// given stage. Before the start every operation is cancellable: nothing has
// touched the host. Once started, only an operation that reads or streams
// stops on request; the rest finishes, the step or the whole of it.
func (c Contract) CancellableIn(started bool) bool {
	if !started {
		return true
	}
	return c.CancelMode == CancelSafe
}

// ValidateContracts checks that every mutating operation declares its whole
// contract and that the declarations agree with the rest of the registry.
//
// The control plane calls it before it listens on anything: an operation
// without an explicit decision is not an operation with a default, it is a
// reason not to start. The error lists every offending operation at once,
// so one restart fixes them all.
func ValidateContracts() error {
	var problems []string
	for _, action := range AllActions() {
		if !action.Mutating() {
			continue
		}
		declared, ok := contracts[action]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: no contract declared", action))
			continue
		}
		for _, problem := range contractProblems(action, declared.withClaims(action)) {
			problems = append(problems, fmt.Sprintf("%s: %s", action, problem))
		}
	}
	for action := range contracts {
		if !action.Known() {
			problems = append(problems, fmt.Sprintf("%s: a contract for an operation the registry does not know", action))
		} else if !action.Mutating() {
			problems = append(problems, fmt.Sprintf("%s: a contract table row for a read; reads derive theirs", action))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%w: %s", ErrContractMissing, strings.Join(problems, "; "))
}

// contractProblems names what is missing or contradictory in one
// declaration. The rules are the ones the interface relies on: a cancel
// button, a rollback link and a retry hint are drawn from these fields,
// and a contradiction between them would draw a promise the host cannot
// keep.
func contractProblems(action ActionType, c Contract) []string {
	var problems []string
	if !KnownCancelMode(c.CancelMode) {
		problems = append(problems, fmt.Sprintf("cancel_mode %q is not declared", c.CancelMode))
	}
	if !KnownRetryPolicy(c.RetryClass) {
		problems = append(problems, fmt.Sprintf("retry_class %q is not declared", c.RetryClass))
	}
	if !KnownRollbackClass(c.Rollback) {
		problems = append(problems, fmt.Sprintf("rollback %q is not declared", c.Rollback))
	}
	if !KnownVerification(c.Verification) {
		problems = append(problems, fmt.Sprintf("verification %q is not declared", c.Verification))
	}
	if c.ResourceClaims == nil {
		problems = append(problems, "resource_claims is not declared")
	}

	// An operation that runs to its end once started is never repeated
	// blind: the outcome of the first run has to be read first, or the
	// operation is not repeated at all.
	if c.CancelMode == CancelImpossibleAfterStart &&
		c.RetryClass != RetryReadState && c.RetryClass != RetryNever {
		problems = append(problems, fmt.Sprintf(
			"impossible_after_start with retry_class %s; only read_state or never fit", c.RetryClass))
	}
	// A host that reverts itself does so under a watchdog the control plane
	// does not own, and vice versa.
	if (c.Rollback == RollbackAutomaticLocal) != (c.CancelMode == CancelLocalWatchdogOwned) {
		problems = append(problems, fmt.Sprintf(
			"rollback %s with cancel_mode %s; automatic_local and local_watchdog_owned go together", c.Rollback, c.CancelMode))
	}
	// An exact restore needs a kept version: only a planned change, a file,
	// a schedule or a Compose project has one.
	if c.Rollback == RollbackExactRestore && PlanningAction(action) == "" && !versionedFamily(action) {
		problems = append(problems, "rollback exact_restore on an operation that keeps no previous version")
	}
	// A destructive operation promises no exact way back and is not
	// repeated blind.
	if action.Risk() == RiskDestructive {
		if c.Rollback == RollbackExactRestore || c.Rollback == RollbackAutomaticLocal {
			problems = append(problems, fmt.Sprintf("rollback %s on a destructive operation", c.Rollback))
		}
		if c.RetryClass == RetryAutomatic {
			problems = append(problems, "retry_class automatic on a destructive operation")
		}
	}
	// A plan recheck needs a planner to compute the plan again.
	if c.Verification == VerifyPlanRecheck && PlanningAction(action) == "" {
		problems = append(problems, "verification plan_recheck on an operation without a planner")
	}
	// A safe cancel with a retry that waits for a change of the host
	// contradicts itself: what stops cleanly can be repeated cleanly.
	if c.CancelMode == CancelSafe && c.RetryClass == RetryReadState {
		problems = append(problems, "cancel_mode safe with retry_class read_state")
	}

	seen := map[string]bool{}
	lockClaimed := action.LockClass() == LockNone
	for _, claim := range c.ResourceClaims {
		if claim.Class == "" {
			problems = append(problems, "a resource claim without a class")
			continue
		}
		if claim.Mode != ClaimShared && claim.Mode != ClaimExclusive {
			problems = append(problems, fmt.Sprintf("claim %s has the mode %q", claim.Class, claim.Mode))
		}
		if claim.Weight < 1 {
			problems = append(problems, fmt.Sprintf("claim %s has the weight %d", claim.Class, claim.Weight))
		}
		if seen[claim.Class] {
			problems = append(problems, fmt.Sprintf("claim %s is declared twice", claim.Class))
		}
		seen[claim.Class] = true
		if claim.Class == action.LockClass() && claim.Mode == ClaimExclusive {
			lockClaimed = true
		}
		// A mutation takes its resources exclusively: a shared claim on a
		// mutation is a lock that stops nothing.
		if claim.Mode == ClaimShared {
			problems = append(problems, fmt.Sprintf("claim %s is shared on a mutating operation", claim.Class))
		}
	}
	if !lockClaimed {
		problems = append(problems, fmt.Sprintf("no exclusive claim on the lock class %s", action.LockClass()))
	}
	return problems
}

// versionedFamily names the operations that keep a previous version
// without a planner: schedules and Compose projects.
func versionedFamily(action ActionType) bool {
	switch action {
	case ActionScheduleEnsure, ActionScheduleDisable, ActionScheduleRemove, ActionComposeDeploy:
		return true
	}
	return strings.HasPrefix(string(action), "file.")
}
