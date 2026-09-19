package opspec

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ultherego/flotestro/internal/modules/hostname"
)

// campaignModes is the registry of bulk-operation modes.
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
	// A package source is the same declaration on every host: the address, the
	// key and the consent to trust it.
	ActionRepositorySet: CampaignSamePayload,

	// An agent replacement: the target version means the same on every host, and
	// the verification is the host's own - the job is settled by the host coming
	// back with the version asked for, not by the exit code of the package
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

	// Changes that compute a different diff on every host.
	ActionPackageInstall:    CampaignPerHostPlan,
	ActionPackageUpgrade:    CampaignPerHostPlan,
	ActionFileEnsure:        CampaignPerHostPlan,
	ActionFileRemove:        CampaignPerHostPlan,
	ActionFileRollback:      CampaignPerHostPlan,
	ActionBackupRun:         CampaignPerHostPlan,
	ActionBackupVerify:      CampaignPerHostPlan,
	ActionCertificateDeploy: CampaignPerHostPlan,
	ActionCertificateRenew:  CampaignPerHostPlan,
	// Rotating the authority is a sequence of steps, but every step is its own
	// change with its own per-host plan: the host trusts both authorities at
	// once, gets a new certificate, and only then does the old authority
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
	// A layered change is planned per host for the same reason an address change
	// is, and for one more: the refusals are about relations on that particular
	// host - which interface another bond already owns, which one the panel talks
	ActionNetworkLinkApply:      CampaignPerHostPlan,
	ActionNetworkLinkRemove:     CampaignPerHostPlan,
	ActionDNSHostApply:          CampaignPerHostPlan,
	ActionFirewallRuleEnsure:    CampaignPerHostPlan,
	ActionFirewallRuleRemove:    CampaignPerHostPlan,
	ActionFirewallZonePort:      CampaignPerHostPlan,
	ActionFirewallZoneService:   CampaignPerHostPlan,
	ActionSSHConfigApply:        CampaignPerHostPlan,
	ActionTimeConfigApply:       CampaignPerHostPlan,
	ActionComposeDeploy:         CampaignPerHostPlan,
	ActionKernelModuleBlacklist: CampaignPerHostPlan,
	// Declared containers, networks and volumes.
	ActionDockerContainerEnsure: CampaignPerHostPlan,
	ActionDockerNetworkEnsure:   CampaignPerHostPlan,
	ActionDockerVolumeEnsure:    CampaignPerHostPlan,
	// A rename is a per-host plan of the other kind: the diff is not read from
	// the host but comes with the order, as a mapping of host to new name, and
	// the panel splits it host by host (HostnameMapping, PanelPlanned).
	ActionSystemHostnameSet: CampaignPerHostPlan,

	// Operations with their own state machine. A reboot is settled by the
	// host coming back with a new boot ID, not by the command being sent.
	ActionSystemReboot:  CampaignSpecialized,
	ActionDomainEnroll:  CampaignSpecialized,
	ActionPackageRepair: CampaignSpecialized,
	// The rollback of a network profile and the restore of a firewall rule set
	// name a plan the host kept under an identifier it minted from its own clock
	// at the time of the change - a different one on every host, and gone from
	ActionNetworkRollback:        CampaignSpecialized,
	ActionFirewallRulesetRestore: CampaignSpecialized,
	// A fleet remediation: every host gets its own plan of typed steps, computed
	// in the panel from its findings, and the engine drives the plan through the
	// remediation runner instead of creating one task.
	ActionSecurityRemediate: CampaignSpecialized,
}

// PlanningAction says which operation computes the plan for a mutating one.
func PlanningAction(action ActionType) ActionType {
	switch action {
	// A package transaction: the plan computes the diff and returns its own
	// digest, which comes back to the host together with the change.
	case ActionPackageUpgrade, ActionPackageInstall:
		return ActionPackagePlan

	// A file: the plan computes the difference between the content found and the
	// content wanted, and returns the digest of the content the host had at that
	// moment.
	case ActionFileEnsure, ActionFileRemove, ActionFileRollback:
		return ActionFilePlan

	// The firewall: the plan computes the difference against the panel's rule
	// registry and returns the digest of the whole set the host has now.
	case ActionFirewallRuleEnsure, ActionFirewallRuleRemove,
		ActionFirewallZonePort, ActionFirewallZoneService:
		return ActionFirewallPlan

	// Mounting: the plan resolves the source to the UUID of the filesystem this
	// host has, and that UUID travels in the change.
	case ActionMountEnsure, ActionMountRemove:
		return ActionStoragePlan

	// Checks and extensions: the plan says whether the host sees the device,
	// whether the filesystem is mounted, how much room the group has.
	case ActionFilesystemCheck, ActionFilesystemResize, ActionLVMExtend:
		return ActionStoragePlan

	// The network: the plan computes the difference between the NetworkManager
	// profile the host has and the one requested - and returns the digest of that
	// difference.
	case ActionNetworkProfileApply, ActionNetworkRouteEnsure, ActionNetworkMTUSet,
		ActionNetworkLinkApply, ActionNetworkLinkRemove:
		return ActionNetworkPlan
	case ActionDNSHostApply:
		return ActionDNSPlan

	// sshd: the plan computes the difference between what the server applies and
	// what was ordered, together with the panel's own file that the write
	// replaces in full.
	case ActionSSHConfigApply:
		return ActionSSHConfigPlan

	// Blacklisting a module: the plan says whether the entry is already there,
	// whether the module is loaded and who holds it - because then the entry
	// takes effect only after a reboot.
	case ActionKernelModuleBlacklist:
		return ActionKernelModulePlan

	// Time sources: the plan says which daemon the host has, whether it will
	// reload the sources or restart itself, and whether the panel will add its
	// own directory to somebody else's file.
	case ActionTimeConfigApply:
		return ActionTimePlan

	// Compose: the plan computes a digest from the manifest and from the image
	// digests, and the deployment carries it back.
	case ActionCertificateDeploy, ActionCertificateRenew:
		return ActionCertificatePlan

	// An anchor: the plan says whether the host already trusts this authority,
	// and on removal - whether the authority still signs anything the host shows
	// to clients.
	case ActionCertificateTrustEnsure, ActionCertificateTrustRemove:
		return ActionCertificateTrustPlan

	// A copy: the plan says what will travel from this host and what it costs -
	// which directories the host really has, how much lies in them, whether the
	// repository answers and what remains after retention.
	case ActionBackupRun, ActionBackupVerify:
		return ActionBackupPlan

	case ActionComposeDeploy:
		return ActionComposePlan

	// A declared object: the plan compares the description with what stands on
	// the host, binds the image tag to a digest and says whether the container
	// would be replaced.
	case ActionDockerContainerEnsure, ActionDockerNetworkEnsure, ActionDockerVolumeEnsure,
		ActionDockerNetworkRemove, ActionDockerVolumeRemove:
		return ActionDockerPlan
	}
	// A family without a planner refuses and names the reason: a campaign without
	// a per-host plan would approve a change whose diff nobody computed.
	return ""
}

// PanelPlanned says whether the per-host plan of an operation is computed in
// the panel from the order itself rather than read from the host.
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
// does not name.
const ReasonNoHostnameForHost = "no_hostname_for_host"

// ParseHostnameMapping reads the mapping out of a campaign payload.
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
		// The same name on two hosts is not a typo the hosts sort out between
		// themselves: DNS, Kerberos and the other hosts would see two machines
		// claiming one identity.
		key := strings.ToLower(name)
		if other, taken := seen[key]; taken {
			return nil, fmt.Errorf("the name %s is given to both %s and %s", name, other, hostID)
		}
		seen[key] = hostID
	}
	return mapping, nil
}

// ValidateCampaignMapping checks the per-host part of a campaign order for the
// operations that carry one.
func ValidateCampaignMapping(action ActionType, raw json.RawMessage) error {
	if !PanelPlanned(action) {
		return nil
	}
	_, err := ParseHostnameMapping(raw)
	return err
}

// PayloadFor materialises the payload of one host from the shared fields of
// the order and the host's own entry.
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
func CampaignExclusionReason(action ActionType) string {
	switch action {
	case ActionBackupRestore:
		return "a restore unpacks old state onto a running system and needs an " +
			"operator present at every host; a campaign does not queue it"
	case ActionSecurityRemediate:
		// The generic order has no findings to plan from.
		return "a fleet remediation is ordered from the security view, where the " +
			"per-host plans are computed from the findings; a generic campaign order " +
			"has nothing to plan them from"

	// The layers above a bare disk.
	case ActionRAIDMemberFail, ActionRAIDMemberRemove, ActionRAIDMemberAdd:
		return "an array member is one disk in one machine: the order binds to the " +
			"UUID of that array and to the by-id link of that disk, and neither means " +
			"anything on the next host. A fleet-wide version would have to name a " +
			"different array and a different disk per host, which is a list, not a campaign"
	case ActionLVMVolumeCreate, ActionLVMSnapshotCreate, ActionLVMSnapshotRemove:
		return "a volume operation binds to the UUID of the group and of the volume on " +
			"that host; a campaign would need the per-host plan to carry each host's own " +
			"UUID into its order, and the planner does not do that yet. Until it does, the " +
			"panel does not ask for consent it cannot bind"
	case ActionLVMVolumeRemove, ActionLVMGroupExtend:
		return "deleting a volume and taking a disk into a group destroy what is on them; " +
			"like formatting and wiping, they are ordered on one host, with the target " +
			"typed out and two people behind it"
	}
	return ""
}

// ValidateRemediationOrder checks the payload of a fleet remediation as the
// security view orders it.
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

// FullCoverageReason names the operations that must not be carried out on part
// of the fleet, and says why.
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
func ExecutableMode(action ActionType) bool {
	switch action.CampaignMode() {
	case CampaignSamePayload:
		return true
	case CampaignPerHostPlan:
		// A per-host plan needs something to come from: a planning operation on the
		// host, or an order the panel splits host by host.
		return CampaignPlans(action)
	case CampaignSpecialized:
		// A reboot has its own phase in the engine: a new boot ID and a check of the
		// units after the host comes back.
		return action == ActionSystemReboot || action == ActionSecurityRemediate
	}
	return false
}

// PendingPlanDigest is a marker standing in for a digest that does not exist
// yet.
const PendingPlanDigest = "pending-per-host-plan"

// ValidateCampaignRequest checks the payload of a campaign request.
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
// mapping.
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
	if payload.DockerEnsure != nil && payload.DockerEnsure.PlanDigest == "" {
		copied := *payload.DockerEnsure
		copied.PlanDigest = PendingPlanDigest
		payload.DockerEnsure = &copied
	}
	return payload
}
