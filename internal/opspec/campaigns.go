package opspec

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ultherego/flotestro/internal/modules/hostname"
)

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
	// Clearing the failed state of the same unit everywhere after a fleet
	// wide fix is the very case of the same payload meaning the same thing.
	ActionUnitResetFailed: CampaignSamePayload,

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
	// A group list and an expiry date are declarations about a name; a
	// deletion has one target the operator types by hand.
	ActionLocalUserGroupsSet: CampaignSamePayload,
	ActionLocalUserExpirySet: CampaignSamePayload,

	// A package version hold is a declaration about a name, not about a diff.
	ActionPackageHoldSet: CampaignSamePayload,
	// A package source is the same declaration on every host: the address,
	// the key and the consent to trust it. The host refreshes its metadata
	// and reports the key's fingerprint on its own; there is no diff to plan,
	// so the same payload means the same thing everywhere.
	ActionRepositorySet: CampaignSamePayload,

	// An agent replacement: the target version means the same on every host,
	// and the verification is the host's own - the job is settled by the
	// host coming back with the version asked for, not by the exit code of
	// the package manager. A fleet is upgraded in waves this way.
	ActionAgentUpgrade: CampaignSamePayload,

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
	// A rename is a per-host plan of the other kind: the diff is not read
	// from the host but comes with the order, as a mapping of host to new
	// name, and the panel splits it host by host (HostnameMapping,
	// PanelPlanned). The same payload would give every host the same name,
	// which is the one thing a rename must never do. The target name a
	// single rename requires typed by hand is the mapping here: every host
	// is named in it, one by one, and a host it does not name gets nothing.
	ActionSystemHostnameSet: CampaignPerHostPlan,

	// Operations with their own state machine. A reboot is settled by the
	// host coming back with a new boot ID, not by the command being sent.
	ActionSystemReboot:           CampaignSpecialized,
	ActionDomainEnroll:           CampaignSpecialized,
	ActionPackageRepair:          CampaignSpecialized,
	ActionNetworkRollback:        CampaignSpecialized,
	ActionFirewallRulesetRestore: CampaignSpecialized,
	// A fleet remediation: every host gets its own plan of typed steps,
	// computed in the panel from its findings, and the engine drives the
	// plan through the remediation runner instead of creating one task.
	ActionSecurityRemediate: CampaignSpecialized,
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

// PanelPlanned says whether the per-host plan of an operation is computed in
// the panel from the order itself rather than read from the host.
//
// A rename is the case: no read on the host can say which name the operator
// intends for it, so the order carries a mapping and the plan of a host is
// its own entry. Such a plan still goes through the plan set and the
// approval fingerprint - the consent covers the split, not the mapping as a
// blob - but no planning task ever reaches a host.
func PanelPlanned(action ActionType) bool {
	return action == ActionSystemHostnameSet
}

// CampaignPlans says whether a campaign of this operation has a planning
// phase at all: a read on every host, or a split of the order in the panel.
func CampaignPlans(action ActionType) bool {
	return PlanningAction(action) != "" || PanelPlanned(action)
}

// HostnameMapping is the per-host part of a rename ordered in bulk: the new
// name of every host, by host identifier.
type HostnameMapping map[string]string

// ReasonNoHostnameForHost is the ineligibility code of a target the mapping
// does not name. A host without an entry gets no name at all rather than a
// shared one: silence in the mapping is not consent to a default.
const ReasonNoHostnameForHost = "no_hostname_for_host"

// ParseHostnameMapping reads the mapping out of a campaign payload.
//
// The mapping travels under the hostname key next to the shared fields
// ({"hostname": {"pretty": ..., "mapping": {"<host_id>": "<fqdn>"}}}), and
// the typed payload does not carry it: HostnamePayload describes one host,
// and a single-host order must not be able to smuggle a mapping in. An
// order without a mapping, or with a name the host would refuse, or with
// the same name for two hosts, is refused here - before any host is
// resolved, because the mapping is the whole intent of the campaign.
func ParseHostnameMapping(raw json.RawMessage) (HostnameMapping, error) {
	var order struct {
		Hostname struct {
			Mapping map[string]string `json:"mapping"`
		} `json:"hostname"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &order); err != nil {
			return nil, fmt.Errorf("the payload is not valid JSON")
		}
	}
	mapping := HostnameMapping(order.Hostname.Mapping)
	if len(mapping) == 0 {
		return nil, fmt.Errorf("a rename in bulk names every host's new name in hostname.mapping; " +
			"there is no shared name")
	}
	seen := map[string]string{}
	for hostID, name := range mapping {
		if strings.TrimSpace(hostID) == "" {
			return nil, fmt.Errorf("the mapping names an empty host identifier")
		}
		if err := hostname.Validate(name); err != nil {
			return nil, fmt.Errorf("the name for the host %s: %w", hostID, err)
		}
		// The same name on two hosts is not a typo the hosts sort out
		// between themselves: DNS, Kerberos and the other hosts would see
		// two machines claiming one identity.
		key := strings.ToLower(name)
		if other, taken := seen[key]; taken {
			return nil, fmt.Errorf("the name %s is given to both %s and %s", name, other, hostID)
		}
		seen[key] = hostID
	}
	return mapping, nil
}

// ValidateCampaignMapping checks the per-host part of a campaign order for
// the operations that carry one. An operation without a panel-side plan
// has nothing to check here.
func ValidateCampaignMapping(action ActionType, raw json.RawMessage) error {
	if !PanelPlanned(action) {
		return nil
	}
	_, err := ParseHostnameMapping(raw)
	return err
}

// PayloadFor materialises the payload of one host from the shared fields of
// the order and the host's own entry.
//
// The second value is the ineligibility code when the mapping has no entry
// for the host; an empty code means a payload the host may run.
func (m HostnameMapping) PayloadFor(hostID string, shared Payload) (Payload, string) {
	name, ok := m[hostID]
	if !ok || name == "" {
		return Payload{}, ReasonNoHostnameForHost
	}
	own := HostnamePayload{Hostname: name}
	if shared.Hostname != nil {
		own.Pretty = shared.Hostname.Pretty
	}
	shared.Hostname = &own
	return shared, ""
}

// HostIDs lists the hosts the mapping names, in a fixed order.
func (m HostnameMapping) HostIDs() []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// CampaignPace gives the wave size and the concurrency a campaign of the
// operation starts with when the order names neither.
//
// The numbers follow the module chapters of the multitasking document: a
// package source on fifty hosts a wave, a rename on ten with two at a time.
// An operation without a row of its own gets the general default, and the
// order may always narrow both; the API ceilings still bound them.
func CampaignPace(action ActionType) (waveSize, maxConcurrent int) {
	switch action {
	case ActionRepositorySet:
		return 50, 5
	case ActionSystemHostnameSet:
		return 10, 2
	}
	return 10, 5
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
	case ActionSecurityRemediate:
		// The generic order has no findings to plan from. The composite is
		// ordered from the security view, which computes the plan of every
		// host and hands the campaign the whole set for one approval.
		return "a fleet remediation is ordered from the security view, where the " +
			"per-host plans are computed from the findings; a generic campaign order " +
			"has nothing to plan them from"
	}
	return ""
}

// ValidateRemediationOrder checks the payload of a fleet remediation as the
// security view orders it.
//
// Validate refuses the composite outright, because it must not become a
// task on one host. The campaign that carries it needs the list of checks
// and nothing else: the steps live in the per-host plans, not in the
// payload.
func ValidateRemediationOrder(payload Payload) error {
	if payload.Security == nil || len(payload.Security.CheckIDs) == 0 {
		return fmt.Errorf("a fleet remediation names the checks to fix; there is no fix-all")
	}
	if payload.Security.Mode != "" {
		return fmt.Errorf("a fleet remediation carries the checks alone; the MAC mode is a step, not the order")
	}
	seen := map[string]bool{}
	for _, id := range payload.Security.CheckIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("a check identifier is empty")
		}
		if seen[id] {
			return fmt.Errorf("the check %s is named twice", id)
		}
		seen[id] = true
	}
	return nil
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
		// A per-host plan needs something to come from: a planning operation
		// on the host, or an order the panel splits host by host. Without
		// either the campaign would approve a change whose diff nobody
		// computed.
		return CampaignPlans(action)
	case CampaignSpecialized:
		// A reboot has its own phase in the engine: a new boot ID and a check
		// of the units after the host comes back. A fleet remediation has
		// one too: the engine starts the host's plan of steps and settles the
		// host when the plan settles. The other specialised operations do
		// not have one yet.
		return action == ActionSystemReboot || action == ActionSecurityRemediate
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
	if PanelPlanned(action) {
		payload = withNamePlaceholder(payload)
	}
	return Validate(action, payload)
}

// PendingHostname is a marker standing in for the name a host gets from the
// mapping. It travels to no host: the shared part of a rename order carries
// no name, and the validation of that part still needs one to pass. The
// mapping itself is checked by ValidateCampaignMapping.
const PendingHostname = "pending-per-host-name"

// withNamePlaceholder puts the marker where validation requires a name.
func withNamePlaceholder(payload Payload) Payload {
	var copied HostnamePayload
	if payload.Hostname != nil {
		copied = *payload.Hostname
	}
	if copied.Hostname == "" {
		copied.Hostname = PendingHostname
	}
	payload.Hostname = &copied
	return payload
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
