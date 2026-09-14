package opspec

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAMissingDeclarationMeansRefusal guards the rule that protects the fleet
// from the panel's own registry: adding an operation must not by itself open
// it to every host.
func TestAMissingDeclarationMeansRefusal(t *testing.T) {
	if mode := ActionType("no.such.thing").CampaignMode(); mode != CampaignNone {
		t.Fatalf("an unknown operation got the mode %q", mode)
	}
	// A real operation without a declaration is a refusal too.
	if mode := ActionDiskWipe.CampaignMode(); mode != CampaignNone {
		t.Fatalf("wiping a disk got the mode %q", mode)
	}
	if ExecutableMode(ActionDiskWipe) {
		t.Fatal("wiping a disk allowed in bulk")
	}
}

// TestIrreversibleOperationsDoNotRunInBulk guards that a boundary drawn on a
// single host holds for the fleet as well: an operation that requires typing
// the target name has no single target to type in a campaign.
func TestIrreversibleOperationsDoNotRunInBulk(t *testing.T) {
	for _, action := range AllActions() {
		if !action.RequiresTargetConfirmation() {
			continue
		}
		if action.CampaignMode() != CampaignNone {
			t.Errorf("%s requires a target name and has the bulk mode %q", action, action.CampaignMode())
		}
	}
}

// TestAnOperationWithAPlanIsNotOnePayload guards the most dangerous campaign
// mistake: an operation that computes its diff on every host separately must
// not travel as one approved payload.
func TestAnOperationWithAPlanIsNotOnePayload(t *testing.T) {
	for _, action := range AllActions() {
		if !action.RequiresPlan() {
			continue
		}
		if action.CampaignMode() == CampaignSamePayload {
			t.Errorf("%s requires a plan and is declared as same_payload", action)
		}
		// A campaign may run such an operation only when it has something to
		// compute the plan with on every host separately.
		if ExecutableMode(action) && PlanningAction(action) == "" {
			t.Errorf("%s requires a plan and the campaign has nothing to compute it with", action)
		}
	}
}

// TestReadsAreNotACampaign guards that a campaign is a mechanism for change.
// A read on a hundred hosts is something else and has its own way.
func TestReadsAreNotACampaign(t *testing.T) {
	for _, action := range AllActions() {
		if action.Mutating() {
			continue
		}
		if action.CampaignMode() != CampaignNone {
			t.Errorf("the read %s has the bulk mode %q", action, action.CampaignMode())
		}
	}
}

// TestExecutableModesAreSamePayloadAndReboot guards the boundary between what
// an operation is and what the panel can carry out today.
func TestExecutableModesAreSamePayloadAndReboot(t *testing.T) {
	if !ExecutableMode(ActionUnitRestart) {
		t.Error("restarting a unit is not executable in bulk")
	}
	if !ExecutableMode(ActionSystemReboot) {
		t.Error("rebooting a host is not executable in bulk, although it has its own phase")
	}
	// A package upgrade computes a different plan on every host, so the
	// campaign runs it through a planning phase - and only for that reason is
	// it allowed.
	if ActionPackageUpgrade.CampaignMode() != CampaignPerHostPlan {
		t.Errorf("a package upgrade has the mode %q", ActionPackageUpgrade.CampaignMode())
	}
	if PlanningAction(ActionPackageUpgrade) != ActionPackagePlan {
		t.Errorf("a package upgrade is planned by the operation %q",
			PlanningAction(ActionPackageUpgrade))
	}
	if !ExecutableMode(ActionPackageUpgrade) {
		t.Error("a package upgrade is not run despite the planning phase")
	}
	// A Compose deployment computes its plan on every host just like
	// packages do: the digest comes from the manifest and from the digests of
	// the images this host really sees, and comes back to it with the change.
	for change, planner := range map[ActionType]ActionType{
		ActionComposeDeploy:          ActionComposePlan,
		ActionFileEnsure:             ActionFilePlan,
		ActionFileRemove:             ActionFilePlan,
		ActionFileRollback:           ActionFilePlan,
		ActionFirewallRuleEnsure:     ActionFirewallPlan,
		ActionFirewallRuleRemove:     ActionFirewallPlan,
		ActionFirewallZonePort:       ActionFirewallPlan,
		ActionFirewallZoneService:    ActionFirewallPlan,
		ActionMountEnsure:            ActionStoragePlan,
		ActionMountRemove:            ActionStoragePlan,
		ActionNetworkMTUSet:          ActionNetworkPlan,
		ActionNetworkRouteEnsure:     ActionNetworkPlan,
		ActionNetworkProfileApply:    ActionNetworkPlan,
		ActionDNSHostApply:           ActionDNSPlan,
		ActionSSHConfigApply:         ActionSSHConfigPlan,
		ActionKernelModuleBlacklist:  ActionKernelModulePlan,
		ActionTimeConfigApply:        ActionTimePlan,
		ActionFilesystemCheck:        ActionStoragePlan,
		ActionFilesystemResize:       ActionStoragePlan,
		ActionLVMExtend:              ActionStoragePlan,
		ActionPackageInstall:         ActionPackagePlan,
		ActionCertificateDeploy:      ActionCertificatePlan,
		ActionCertificateRenew:       ActionCertificatePlan,
		ActionCertificateTrustEnsure: ActionCertificateTrustPlan,
		ActionCertificateTrustRemove: ActionCertificateTrustPlan,
		ActionBackupRun:              ActionBackupPlan,
		ActionBackupVerify:           ActionBackupPlan,
	} {
		if PlanningAction(change) != planner {
			t.Errorf("%s is planned by the operation %q, expected %q",
				change, PlanningAction(change), planner)
		}
		if !ExecutableMode(change) {
			t.Errorf("%s refused although a planner exists", change)
		}
	}

	// Every family declared as a per-host plan has a planner: a missing one
	// would mean a campaign that declares planning and cannot do it. A new
	// family without a planner has to fall out here, not in production.
	for _, action := range AllActions() {
		if action.CampaignMode() != CampaignPerHostPlan {
			continue
		}
		if PlanningAction(action) == "" {
			t.Errorf("%s declares a per-host plan and has no planner", action)
		}
		if !ExecutableMode(action) {
			t.Errorf("%s refused although it has a planner", action)
		}
	}
	// The gate still exists: a specialised operation without its own phase in
	// the engine is refused with a reason instead of being faked.
	for _, change := range []ActionType{ActionDomainEnroll, ActionPackageRepair} {
		if ExecutableMode(change) {
			t.Errorf("%s allowed without its own phase in the engine", change)
		}
	}
}

// TestARestoreDoesNotRunInBulk guards a boundary that is not a missing
// feature: a restore unpacks old state onto a running system and is meant to
// require an operator present at every host.
func TestARestoreDoesNotRunInBulk(t *testing.T) {
	if CampaignExclusionReason(ActionBackupRestore) == "" {
		t.Error("a restore is not excluded from campaigns")
	}
	if CampaignExclusionReason(ActionBackupRun) != "" {
		t.Error("a copy excluded from campaigns together with a restore")
	}
}

// TestWithdrawingAnAuthorityNeedsTheWholeFleet guards a boundary invisible on
// a single host: withdrawing an authority is only correct once it covers
// every target. A host left out keeps a trust the rest of the fleet no longer
// has.
func TestWithdrawingAnAuthorityNeedsTheWholeFleet(t *testing.T) {
	if FullCoverageReason(ActionCertificateTrustRemove) == "" {
		t.Error("withdrawing an authority may be run on part of the fleet")
	}
	// Handing out trust is safe partially: a host that gets it later trusts
	// until then what it trusted before.
	if FullCoverageReason(ActionCertificateTrustEnsure) != "" {
		t.Error("handing out trust requires the whole fleet")
	}
	if FullCoverageReason(ActionPackageUpgrade) != "" {
		t.Error("a package upgrade requires the whole fleet")
	}
}

// TestAPackageSourceIsTheSameDeclarationEverywhere guards the row of the
// packages chapter: a source is an address, a key and a consent, and those
// mean the same on every host - there is no diff to plan, so the campaign
// runs it as one payload, fifty hosts a wave.
func TestAPackageSourceIsTheSameDeclarationEverywhere(t *testing.T) {
	if mode := ActionRepositorySet.CampaignMode(); mode != CampaignSamePayload {
		t.Fatalf("a package source has the mode %q", mode)
	}
	if !ExecutableMode(ActionRepositorySet) {
		t.Error("a package source is not executable in bulk")
	}
	if wave, _ := CampaignPace(ActionRepositorySet); wave != 50 {
		t.Errorf("a package source starts with a wave of %d, the document says 50", wave)
	}
	// A source without its key must not pass as a template: the placeholder
	// is refused the way placeholder certificate material is.
	if !TemplateNeedsMaterial(ActionRepositorySet) {
		t.Error("the template of a package source passes without the signing key")
	}
	if wave, concurrent := CampaignPace(ActionUnitRestart); wave != 10 || concurrent != 5 {
		t.Errorf("an operation without a row of its own paces at %d/%d, expected the general 10/5", wave, concurrent)
	}
}

// TestAnInventoryRefreshFansOutAndIsNotACampaign guards the row of the
// overview chapter: a refresh changes nothing and needs no approval, so it
// goes the way of the reads - up to the document's wave of two hundred
// hosts - and never the way of a campaign.
func TestAnInventoryRefreshFansOutAndIsNotACampaign(t *testing.T) {
	if limit := ActionInventoryRefresh.FanOutLimit(); limit != 200 {
		t.Fatalf("a refresh fans out to %d hosts, the document says 200", limit)
	}
	if reason := FanOutRefusal(ActionInventoryRefresh); reason != "" {
		t.Errorf("a refresh is refused as a fan-out: %s", reason)
	}
	if mode := ActionInventoryRefresh.CampaignMode(); mode != CampaignNone {
		t.Errorf("a refresh has the bulk mode %q; a read is not a campaign", mode)
	}
}

// TestARenameSplitsTheMappingPerHost guards the mechanism of the system
// chapter: a rename in bulk carries a map of host to new name, every host
// gets its own name and nothing else, and a host the map does not name is
// ineligible with a reason rather than renamed to a default.
func TestARenameSplitsTheMappingPerHost(t *testing.T) {
	if !PanelPlanned(ActionSystemHostnameSet) {
		t.Fatal("a rename is not planned from the order")
	}
	if PanelPlanned(ActionUnitRestart) {
		t.Fatal("restarting a unit is planned from the order")
	}
	// A plan split from the order has no host planner, and the engine opens
	// its planning phase on a host planner alone: the rename stays refused
	// in bulk until the engine and the campaign API learn the split, rather
	// than jumping to execution with no name per host.
	if PlanningAction(ActionSystemHostnameSet) != "" {
		t.Errorf("a rename names a host planner %q", PlanningAction(ActionSystemHostnameSet))
	}
	if ExecutableMode(ActionSystemHostnameSet) {
		t.Error("a rename allowed in bulk although the engine has no panel-side planning phase")
	}
	if !CampaignPlans(ActionSystemHostnameSet) || CampaignPlans(ActionUnitRestart) {
		t.Error("CampaignPlans does not follow the panel-side plan")
	}
	order := json.RawMessage(`{"hostname": {"pretty": "Web node", "mapping": {
		"host-a": "web-a.example.test", "host-b": "web-b.example.test"}}}`)
	mapping, err := ParseHostnameMapping(order)
	if err != nil {
		t.Fatalf("a valid mapping is refused: %v", err)
	}
	if got := mapping.HostIDs(); strings.Join(got, ",") != "host-a,host-b" {
		t.Errorf("the mapping names %v", got)
	}
	// The shared part of the order carries no name; the campaign validation
	// still passes it, because the names live in the mapping.
	var shared Payload
	if err := json.Unmarshal(order, &shared); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCampaignRequest(ActionSystemHostnameSet, shared); err != nil {
		t.Errorf("the shared part of a rename order is refused: %v", err)
	}
	if err := ValidateCampaignMapping(ActionSystemHostnameSet, order); err != nil {
		t.Errorf("the mapping of a rename order is refused: %v", err)
	}
	if err := Validate(ActionSystemHostnameSet, shared); err == nil {
		t.Error("a single-host order without a name passes")
	}

	own, reason := mapping.PayloadFor("host-a", shared)
	if reason != "" {
		t.Fatalf("host-a is ineligible: %s", reason)
	}
	if own.Hostname == nil || own.Hostname.Hostname != "web-a.example.test" || own.Hostname.Pretty != "Web node" {
		t.Errorf("host-a gets the payload %+v", own.Hostname)
	}
	if err := Validate(ActionSystemHostnameSet, own); err != nil {
		t.Errorf("the payload split for host-a does not validate: %v", err)
	}
	other, _ := mapping.PayloadFor("host-b", shared)
	if other.Hostname.Hostname != "web-b.example.test" {
		t.Errorf("host-b gets the name %q", other.Hostname.Hostname)
	}
	if _, reason := mapping.PayloadFor("host-c", shared); reason != ReasonNoHostnameForHost {
		t.Errorf("a host outside the mapping gets the reason %q", reason)
	}

	// Refusals: no mapping at all, an invalid name, and one name on two
	// hosts - each named before any host is resolved.
	for name, raw := range map[string]string{
		"no mapping":     `{"hostname": {"hostname": "shared.example.test"}}`,
		"empty mapping":  `{"hostname": {"mapping": {}}}`,
		"invalid name":   `{"hostname": {"mapping": {"host-a": "not a name!"}}}`,
		"duplicate name": `{"hostname": {"mapping": {"host-a": "web.example.test", "host-b": "web.example.test"}}}`,
		"empty host id":  `{"hostname": {"mapping": {" ": "web.example.test"}}}`,
	} {
		if _, err := ParseHostnameMapping(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: the mapping passes", name)
		}
	}
	// An operation without a panel-side plan has no mapping to check.
	if err := ValidateCampaignMapping(ActionUnitRestart, json.RawMessage(`{"unit": {"unit": "a.service"}}`)); err != nil {
		t.Errorf("a unit restart is checked for a mapping: %v", err)
	}
	if wave, concurrent := CampaignPace(ActionSystemHostnameSet); wave != 10 || concurrent != 2 {
		t.Errorf("a rename paces at %d/%d, the document says 10 a wave and 2 at a time", wave, concurrent)
	}
}
