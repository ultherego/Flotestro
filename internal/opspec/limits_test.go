package opspec

import (
	"errors"
	"testing"

	"github.com/ultherego/flotestro/internal/buildinfo"
)

// TestResourceLimitsFollowTheFamily: the heavy families carry a scope, the
// rest none, and the properties render only what is set.
func TestResourceLimitsFollowTheFamily(t *testing.T) {
	for _, action := range []ActionType{ActionPackageUpgrade, ActionPackageInstall, ActionPackageRemove,
		ActionPackageRepair, ActionAgentUpgrade} {
		if action.ResourceFamily() != FamilyPackages {
			t.Errorf("%s is not in the packages family", action)
		}
	}
	for _, action := range []ActionType{ActionBackupRun, ActionBackupVerify, ActionBackupRestore} {
		if action.ResourceFamily() != FamilyBackups {
			t.Errorf("%s is not in the backups family", action)
		}
	}
	if ActionUnitRestart.ResourceFamily() != FamilyNone || !ActionUnitRestart.ResourceLimits().Empty() {
		t.Error("a unit restart has a resource family or limits")
	}
	if !ActionComposeDeploy.ResourceLimits().Empty() || ActionComposeDeploy.ResourceFamily() != FamilyCompose {
		t.Error("a Compose deployment has limits by default, or no family")
	}

	properties := (ResourceLimits{CPUWeight: 50, MemoryHighBytes: 1 << 20}).Properties()
	if len(properties) != 2 || properties[0] != "CPUWeight=50" || properties[1] != "MemoryHigh=1048576" {
		t.Errorf("properties = %v", properties)
	}
	if len((ResourceLimits{}).Properties()) != 0 {
		t.Error("empty limits render properties")
	}
}

// TestAgentUpgradeChecksTheProtocol: the panel's own release is always a
// valid target, and a refusal on the protocol carries its own code.
func TestAgentUpgradeChecksTheProtocol(t *testing.T) {
	if err := Validate(ActionAgentUpgrade, Payload{
		AgentUpgrade: &AgentUpgradePayload{TargetVersion: buildinfo.Version},
	}); err != nil {
		t.Fatalf("the panel's own version was refused: %v", err)
	}
	// A release older than any known protocol has no protocol to speak of,
	// and is refused like a malformed order.
	err := Validate(ActionAgentUpgrade, Payload{AgentUpgrade: &AgentUpgradePayload{TargetVersion: "0.0.1"}})
	if err == nil {
		t.Fatal("a release from before the first protocol was accepted")
	}
	if RefusalCode(err) != RefusalProtocolIncompatible {
		t.Fatalf("the refusal code is %q, expected %s", RefusalCode(err), RefusalProtocolIncompatible)
	}
	if RefusalCode(errors.New("plain")) != "invalid_payload" {
		t.Fatal("a plain validation error is not invalid_payload")
	}
}

// TestAgentUpgradeIsCampaignReady: the fleet is upgraded in waves as a
// campaign with the same payload everywhere.
func TestAgentUpgradeIsCampaignReady(t *testing.T) {
	if ActionAgentUpgrade.CampaignMode() != CampaignSamePayload {
		t.Fatalf("agent.upgrade has campaign mode %s", ActionAgentUpgrade.CampaignMode())
	}
	if !ExecutableMode(ActionAgentUpgrade) || CampaignExclusionReason(ActionAgentUpgrade) != "" {
		t.Fatal("agent.upgrade is not campaign-ready")
	}
	if ActionAgentUpgrade.Contract().Verification != VerifyCustom {
		t.Fatalf("agent.upgrade is verified by %s, expected the host coming back",
			ActionAgentUpgrade.Contract().Verification)
	}
	payload, ok := PayloadTemplate(ActionAgentUpgrade)
	if !ok || payload.AgentUpgrade == nil || payload.AgentUpgrade.TargetVersion == "" {
		t.Fatal("agent.upgrade has no template")
	}
}
