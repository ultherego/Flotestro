package opspec

// campaignModes is the registry of bulk-operation modes.
//
// The registry is an explicit list, not a property derived from risk: an
// operation being safe on one host does not mean its intent carries over to a
// hundred. An operation outside this map does not run in bulk - a missing
// declaration is a refusal, not consent by omission.
//
// The split comes from the matrix in the multitasking document: same_payload
// for operations whose payload means the same thing everywhere; per_host_plan
// for changes that compute a different diff on every host; specialized for
// operations with their own state machine. The rest stay on a single host.
var campaignModes = map[ActionType]CampaignMode{
	// systemd units: the unit name means the same on every host, and the
	// state before and after is checked separately.
	ActionUnitStart:     CampaignSamePayload,
	ActionUnitStop:      CampaignSamePayload,
	ActionUnitRestart:   CampaignSamePayload,
	ActionUnitReload:    CampaignSamePayload,
	ActionUnitEnableSet: CampaignSamePayload,
	ActionUnitMaskSet:   CampaignSamePayload,

	// Scheduled jobs: an entry is a declaration, not a diff of state.
	ActionScheduleEnsure:  CampaignSamePayload,
	ActionScheduleDisable: CampaignSamePayload,
	ActionScheduleRemove:  CampaignSamePayload,
	ActionScheduleRunNow:  CampaignSamePayload,

	// Local accounts: the account name and the key carry over, and the host
	// checks whether the account exists anyway.
	ActionLocalUserCreate: CampaignSamePayload,
	ActionLocalUserLock:   CampaignSamePayload,
	ActionLocalUserUnlock: CampaignSamePayload,
	ActionLocalSSHKeysSet: CampaignSamePayload,

	// A package version hold is a declaration about a name, not about a diff.
	ActionPackageHoldSet: CampaignSamePayload,

	// Containers: the container identifier is local, but the operation goes
	// through preflight on every host separately.
	ActionDockerStart:   CampaignSamePayload,
	ActionDockerStop:    CampaignSamePayload,
	ActionDockerRestart: CampaignSamePayload,
	ActionDockerPull:    CampaignSamePayload,

	// Kernel and time: the value is a declaration, not a diff.
	ActionKernelModuleLoad: CampaignSamePayload,
	ActionSysctlEnsure:     CampaignSamePayload,
	ActionSELinuxModeSet:   CampaignSamePayload,
	ActionTimezoneSet:      CampaignSamePayload,

	// Changes that compute a different diff on every host. The approval has
	// to cover a set of plans rather than one payload - until the panel can
	// do that, the campaign planner refuses with its own code.
	ActionPackageInstall:    CampaignPerHostPlan,
	ActionPackageUpgrade:    CampaignPerHostPlan,
	ActionFileEnsure:        CampaignPerHostPlan,
	ActionFileRemove:        CampaignPerHostPlan,
	ActionFileRollback:      CampaignPerHostPlan,
	ActionBackupRun:         CampaignPerHostPlan,
	ActionBackupVerify:      CampaignPerHostPlan,
	ActionCertificateDeploy: CampaignPerHostPlan,
	ActionCertificateRenew:  CampaignPerHostPlan,
	// Rotating the authority is a sequence of steps, but every step is its
	// own change with its own per-host plan: the host trusts both
	// authorities at once, gets a new certificate, and only then does the
	// old authority disappear.
	ActionCertificateTrustEnsure: CampaignPerHostPlan,
	ActionCertificateTrustRemove: CampaignPerHostPlan,
	ActionMountEnsure:            CampaignPerHostPlan,
	ActionMountRemove:            CampaignPerHostPlan,
	ActionFilesystemCheck:        CampaignPerHostPlan,
	ActionFilesystemResize:       CampaignPerHostPlan,
	ActionLVMExtend:              CampaignPerHostPlan,
	ActionNetworkProfileApply:    CampaignPerHostPlan,
	ActionNetworkRouteEnsure:     CampaignPerHostPlan,
	ActionNetworkMTUSet:          CampaignPerHostPlan,
	ActionDNSHostApply:           CampaignPerHostPlan,
	ActionFirewallRuleEnsure:     CampaignPerHostPlan,
	ActionFirewallRuleRemove:     CampaignPerHostPlan,
	ActionFirewallZonePort:       CampaignPerHostPlan,
	ActionFirewallZoneService:    CampaignPerHostPlan,
	ActionSSHConfigApply:         CampaignPerHostPlan,
	ActionTimeConfigApply:        CampaignPerHostPlan,
	ActionComposeDeploy:          CampaignPerHostPlan,
	ActionKernelModuleBlacklist:  CampaignPerHostPlan,

	// Operations with their own state machine. A reboot is settled by the
	// host coming back with a new boot ID, not by the command being sent.
	ActionSystemReboot:           CampaignSpecialized,
	ActionDomainEnroll:           CampaignSpecialized,
	ActionPackageRepair:          CampaignSpecialized,
	ActionNetworkRollback:        CampaignSpecialized,
	ActionFirewallRulesetRestore: CampaignSpecialized,
}

// PlanningAction says which operation computes the plan for a mutating one.
//
// A plan is a read and has its own operation type: it is the one that walks
// the host, computes the diff and returns its digest. A campaign in
// per_host_plan mode runs it on every host first, and only then does the set
// of those plans go for approval.
//
// An empty value means the panel cannot plan this change in bulk.
func PlanningAction(action ActionType) ActionType {
	switch action {
	// A package transaction: the plan computes the diff and returns its own
	// digest, which comes back to the host together with the change.
	case ActionPackageUpgrade, ActionPackageInstall:
		return ActionPackagePlan

	// A file: the plan computes the difference between the content found and
	// the content wanted, and returns the digest of the content the host had
	// at that moment. The write comes back with that digest, so a file
	// changed after planning stops the change instead of overwriting
	// somebody else's work.
	case ActionFileEnsure, ActionFileRemove, ActionFileRollback:
		return ActionFilePlan

	// The firewall: the plan computes the difference against the panel's rule
	// registry and returns the digest of the whole set the host has now. The
	// change comes back with that digest, so a set changed after planning
	// stops it instead of landing between somebody else's rules. A firewalld
	// zone is a set of entries, so its plan says whether an entry is in it -
	// and is bound by the same set digest, because firewalld rewrites
	// nftables on every zone change.
	case ActionFirewallRuleEnsure, ActionFirewallRuleRemove,
		ActionFirewallZonePort, ActionFirewallZoneService:
		return ActionFirewallPlan

	// Mounting: the plan resolves the source to the UUID of the filesystem
	// this host has, and that UUID travels in the change. A /dev/sdX path
	// points at something else after a reboot; a UUID points at the same
	// filesystem or at none.
	case ActionMountEnsure, ActionMountRemove:
		return ActionStoragePlan

	// Checks and extensions: the plan says whether the host sees the device,
	// whether the filesystem is mounted, how much room the group has. The
	// kind of plan is named by the planner payload (StoragePayload.Plan),
	// because the path alone does not say what the operator intends.
	case ActionFilesystemCheck, ActionFilesystemResize, ActionLVMExtend:
		return ActionStoragePlan

	// The network: the plan computes the difference between the
	// NetworkManager profile the host has and the one requested - and
	// returns the digest of that difference. The change comes back with the
	// digest, and the host computes the plan once more: a profile changed
	// after planning stops the change. The resolver goes the same way
	// through its own dns.plan operation.
	case ActionNetworkProfileApply, ActionNetworkRouteEnsure, ActionNetworkMTUSet:
		return ActionNetworkPlan
	case ActionDNSHostApply:
		return ActionDNSPlan

	// sshd: the plan computes the difference between what the server applies
	// and what was ordered, together with the panel's own file that the write
	// replaces in full. Cutting off every login method is a refusal in the
	// plan, not in the execution.
	case ActionSSHConfigApply:
		return ActionSSHConfigPlan

	// Blacklisting a module: the plan says whether the entry is already
	// there, whether the module is loaded and who holds it - because then
	// the entry takes effect only after a reboot. A protected module is a
	// refusal in the plan.
	case ActionKernelModuleBlacklist:
		return ActionKernelModulePlan

	// Time sources: the plan says which daemon the host has, whether it will
	// reload the sources or restart itself, and whether the panel will add
	// its own directory to somebody else's file. A host without a daemon and
	// without consent for the directory is a refusal in the plan.
	case ActionTimeConfigApply:
		return ActionTimePlan

	// Compose: the plan computes a digest from the manifest and from the
	// image digests, and the deployment carries it back. A deployment with
	// somebody else's digest would reach a host that never saw that plan.
	// A certificate: the plan shows the fingerprint found and the one
	// wanted, the expiry date, the service to reload and the probe. The
	// private key travels to the host separately, right before the swap, and
	// is in neither the plan nor the approval.
	// A renewal: the plan says whether the host has anyone to order it from
	// and what watches that file now. There is no material here - the host's
	// own daemon goes to its authority for the new certificate.
	case ActionCertificateDeploy, ActionCertificateRenew:
		return ActionCertificatePlan

	// An anchor: the plan says whether the host already trusts this
	// authority, and on removal - whether the authority still signs anything
	// the host shows to clients.
	case ActionCertificateTrustEnsure, ActionCertificateTrustRemove:
		return ActionCertificateTrustPlan

	// A copy: the plan says what will travel from this host and what it
	// costs - which directories the host really has, how much lies in them,
	// whether the repository answers and what remains after retention.
	case ActionBackupRun, ActionBackupVerify:
		return ActionBackupPlan

	case ActionComposeDeploy:
		return ActionComposePlan
	}
	// A family without a planner refuses and names the reason: a campaign
	// without a per-host plan would approve a change whose diff nobody
	// computed. A planner is separate work (proto, helper, agent release),
	// not a mapping of names - that is how every family above got one.
	return ""
}

// CampaignExclusionReason names the operations that must not run in bulk, and
// says why.
//
// This is a different refusal from a missing planner: there the panel cannot
// do it yet, here it must not. An empty value means the operation is not
// excluded here.
func CampaignExclusionReason(action ActionType) string {
	switch action {
	case ActionBackupRestore:
		return "a restore unpacks old state onto a running system and needs an " +
			"operator present at every host; a campaign does not queue it"
	}
	return ""
}

// FullCoverageReason names the operations that must not be carried out on
// part of the fleet, and says why.
//
// An ordinary campaign may skip a host that is offline: it will come back and
// get its change. There are changes, though, that are only correct together.
// Withdrawing an authority is one of them: a host that has not yet received
// the new trust stops being recognised by the rest of the fleet once the old
// one is removed - and nobody finds out until a connection breaks.
//
// An empty value means an operation that may be run partially.
func FullCoverageReason(action ActionType) string {
	switch action {
	case ActionCertificateTrustRemove:
		return "withdrawing an authority applies to the whole fleet at once: as long " +
			"as even one host has not confirmed the new trust, the old authority stays"
	}
	return ""
}

// ExecutableMode says whether the campaign engine can really carry out the
// mode an operation declares.
//
// The list is narrower than the registry of modes, and that is deliberate:
// the declaration says what the operation is, and this list says what the
// panel can safely do today. A campaign in per_host_plan mode without a set
// of plans would approve a change nobody saw.
func ExecutableMode(action ActionType) bool {
	switch action.CampaignMode() {
	case CampaignSamePayload:
		return true
	case CampaignPerHostPlan:
		// A per-host plan needs something to come from. Without a planning
		// operation the campaign would approve a change whose diff nobody
		// computed.
		return PlanningAction(action) != ""
	case CampaignSpecialized:
		// A reboot has its own phase in the engine: a new boot ID and a check
		// of the units after the host comes back. The other specialised
		// operations do not have one yet.
		return action == ActionSystemReboot
	}
	return false
}

// PendingPlanDigest is a marker standing in for a digest that does not exist
// yet.
//
// It travels to no host: it serves only to validate a campaign request, and
// the orchestrator replaces it with the digest of the plan computed on that
// host.
const PendingPlanDigest = "pending-per-host-plan"

// ValidateCampaignRequest checks the payload of a campaign request.
//
// It differs from Validate in one thing: an operation computed per host
// cannot have a plan digest at request time, because the plan will only come
// into being on the hosts. The rest of the requirements stay unchanged, and
// the digest itself is enforced twice: the orchestrator puts this host's plan
// digest into the task, and the host refuses when the digest does not match
// the state it has now.
func ValidateCampaignRequest(action ActionType, payload Payload) error {
	if PlanningAction(action) != "" {
		payload = withPlanPlaceholder(payload)
	}
	return Validate(action, payload)
}

// withPlanPlaceholder puts the marker where validation requires a digest.
func withPlanPlaceholder(payload Payload) Payload {
	if payload.Compose != nil && payload.Compose.PlanDigest == "" {
		copied := *payload.Compose
		copied.PlanDigest = PendingPlanDigest
		payload.Compose = &copied
	}
	return payload
}
