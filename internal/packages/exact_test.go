package packages

import (
	"testing"

	"github.com/ultherego/flotestro/internal/plan"
)

// A state that could not be read is not a state in which everything happened.
// The removal of a package whose database cannot be listed afterwards used to
// report every expected absence as achieved, and so a clean success.
func TestAnUnreadableStateSettlesNothing(t *testing.T) {
	// A removal of two packages: the plan expects both to be gone afterwards.
	approved := Plan{Manager: "apt", Mode: ModeRemove, Changes: []Change{
		{Name: "nginx", Action: ActionRemove},
		{Name: "nginx-common", Action: ActionRemove},
	}}
	var apply Apply
	err := settleEffects(&apply, approved, nil)
	if err == nil {
		t.Fatal("an unreadable state was settled as if it were read")
	}
	if code, ok := plan.CodeOf(err); !ok || code != plan.ErrorStateUnreadable {
		t.Errorf("the refusal came back as %q (%v)", code, err)
	}
	if len(apply.EffectsAchieved) != 0 {
		t.Errorf("%d effects were called achieved against a state nobody read", len(apply.EffectsAchieved))
	}
	if len(apply.EffectsMissed) != 2 {
		t.Errorf("%d effects were left unsettled, expected both", len(apply.EffectsMissed))
	}

	// The same state read successfully settles what it says.
	apply = Apply{}
	if err := settleEffects(&apply, approved, map[string]string{"nginx-common": "1.24"}); err == nil {
		t.Error("a package still installed was accepted as removed")
	}
	if len(apply.EffectsAchieved) != 1 || apply.EffectsAchieved[0].Effect.Subject != "nginx" {
		t.Errorf("the effects achieved = %+v", apply.EffectsAchieved)
	}
}

// Neither reading is an empty host: a diff against a map nobody could read
// would report the whole host as changed.
func TestTheVersionDiffRefusesAnUnreadState(t *testing.T) {
	if changes := diffVersions(nil, map[string]string{"nginx": "1.24"}); len(changes) != 0 {
		t.Errorf("with no state before, the diff reports %+v", changes)
	}
	if changes := diffVersions(map[string]string{"nginx": "1.24"}, nil); len(changes) != 0 {
		t.Errorf("with no state after, the diff reports %+v", changes)
	}
	changes := diffVersions(map[string]string{"nginx": "1.24"}, map[string]string{"nginx": "1.26"})
	if len(changes) != 1 || changes[0].CurrentVersion != "1.24" || changes[0].CandidateVersion != "1.26" {
		t.Errorf("a read state reports %+v", changes)
	}
}
