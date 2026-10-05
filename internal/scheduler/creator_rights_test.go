package scheduler

import (
	"testing"

	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/opspec"
)

// AUTHZ-02, the dispatch half. The permissions of the creator were read before
// a task went out and used only to widen the grants; the permission of the
// action itself was added whatever they said. So an order queued for a host
// that was offline still left with the right to do it after its creator had
// lost that right.
func TestTheGrantOfTheActionIsOneTheCreatorHolds(t *testing.T) {
	action := opspec.ActionUnitRestart
	permission := action.Permission()
	if permission == "" {
		t.Fatal("the action carries no permission; this test reads nothing")
	}

	held := helpercap.GrantsFor(action, opspec.Payload{}, []string{permission, "unit.read"}, false)
	if !holdsGrant(held, permission) {
		t.Errorf("a creator who holds %s did not get it: %v", permission, held)
	}

	// Read, and gone: the grant goes with it.
	lost := helpercap.GrantsFor(action, opspec.Payload{}, []string{"unit.read"}, false)
	if holdsGrant(lost, permission) {
		t.Errorf("a creator who lost %s still got it: %v", permission, lost)
	}

	// An approval is somebody who holds the right saying so.
	approved := helpercap.GrantsFor(action, opspec.Payload{}, []string{"unit.read"}, true)
	if !holdsGrant(approved, permission) {
		t.Errorf("an approved job lost %s: %v", permission, approved)
	}

	// A creator the store does not know - a system task, a subject removed
	// since - keeps the permission of the action alone, which is the narrow
	// side and what the caller relies on.
	unknown := helpercap.GrantsFor(action, opspec.Payload{}, nil, false)
	if !holdsGrant(unknown, permission) {
		t.Errorf("a task with no creator lost %s: %v", permission, unknown)
	}
}

func holdsGrant(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
