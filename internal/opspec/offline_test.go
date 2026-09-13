package opspec

import (
	"errors"
	"testing"
)

// TestEveryOperationDeclaresAnOfflinePolicy guards that no operation is
// left without an answer for a disconnected host: an unknown answer would
// silently become "wait forever", which is the behaviour the policy
// replaces.
func TestEveryOperationDeclaresAnOfflinePolicy(t *testing.T) {
	for _, action := range AllActions() {
		policy := action.OfflinePolicy()
		if !KnownOfflinePolicy(policy) {
			t.Errorf("%s has the offline policy %q", action, policy)
		}
		if !action.Mutating() && policy != OfflineSkip {
			t.Errorf("%s is a read and has the offline policy %q", action, policy)
		}
		if policy == OfflineReplan && PlanningAction(action) == "" {
			t.Errorf("%s is planned again after a reconnect and has no planner", action)
		}
	}
	// An operation nobody described requires the host online.
	if policy := ActionType("no.such.thing").OfflinePolicy(); policy != OfflineRequireOnline {
		t.Errorf("an unknown operation got the offline policy %q", policy)
	}
}

// TestACampaignMayOnlyTightenTheOfflinePolicy guards the boundary the
// registry draws: a campaign may skip a host the operation would have
// waited for, but never wait for a host the operation requires online.
func TestACampaignMayOnlyTightenTheOfflinePolicy(t *testing.T) {
	if _, err := ResolveOfflinePolicy(ActionSystemReboot, OfflineWait); !errors.Is(err, ErrOfflinePolicyLoosened) {
		t.Errorf("a reboot waiting for an offline host was accepted: %v", err)
	}
	if _, err := ResolveOfflinePolicy(ActionUnitRestart, OfflineReplan); !errors.Is(err, ErrNothingToReplan) {
		t.Errorf("a replan on an operation without a planner was accepted: %v", err)
	}
	if _, err := ResolveOfflinePolicy(ActionUnitRestart, "sometimes"); !errors.Is(err, ErrUnknownOfflinePolicy) {
		t.Errorf("an unknown policy was accepted: %v", err)
	}
	for _, tightened := range []OfflinePolicy{OfflineWait, OfflineSkip, OfflineRequireOnline} {
		policy, err := ResolveOfflinePolicy(ActionUnitRestart, tightened)
		if err != nil || policy != tightened {
			t.Errorf("tightening a restart to %s: %v (%s)", tightened, err, policy)
		}
	}
	policy, err := ResolveOfflinePolicy(ActionPackageUpgrade, "")
	if err != nil || policy != OfflineReplan {
		t.Errorf("an upgrade without a request got %s (%v)", policy, err)
	}
}
