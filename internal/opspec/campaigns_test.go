package opspec

import "testing"

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
