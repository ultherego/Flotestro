package identity

import (
	"bytes"
	"testing"
)

func TestAPartialSuccessHasItsOwnState(t *testing.T) {
	// The document forbids presenting a partial success as a success: the
	// operator would have to discover for themselves that some of the changes
	// were applied.
	phases := []Phase{
		{Name: "creating the account", Status: "succeeded"},
		{Name: "adding to the group", Status: "failed"},
	}
	if got := StateFor(phases); got != StatePartiallyApplied {
		t.Fatalf("state = %s, expected partially_applied", got)
	}
}

func TestTheFinalStateFollowsTheResultsOfThePhases(t *testing.T) {
	cases := map[string]struct {
		phases []Phase
		want   State
	}{
		"all succeeded": {
			[]Phase{{Status: "succeeded"}, {Status: "succeeded"}}, StateSucceeded},
		"all failed": {
			[]Phase{{Status: "failed"}, {Status: "failed"}}, StateFailed},
		"the first phase failed": {
			[]Phase{{Status: "failed"}}, StateFailed},
		"no phases": {
			nil, StateFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := StateFor(tc.phases); got != tc.want {
				t.Fatalf("state = %s, expected %s", got, tc.want)
			}
		})
	}
}

func TestAPlanWithAConflictBlocksExecution(t *testing.T) {
	blocked := Plan{Conflicts: []string{"the account already exists"}}
	if !blocked.Blocked() {
		t.Fatal("a plan with a conflict does not block execution")
	}
	// A warning describes a consequence that is easy to miss but does not
	// stop the change; a conflict means the execution makes no sense.
	warned := Plan{Warnings: []string{"the account loses 3 sudo rules"}}
	if warned.Blocked() {
		t.Fatal("a warning alone blocked the execution")
	}
}

func TestValidationRequiresAPayloadMatchingTheType(t *testing.T) {
	cases := map[string]struct {
		action  ActionType
		payload Payload
		wantErr bool
	}{
		"creation without a payload": {ActionUserCreate, Payload{}, true},
		"creation without a surname": {ActionUserCreate, Payload{User: &UserPayload{UID: "jane"}}, true},
		"valid creation":             {ActionUserCreate, Payload{User: &UserPayload{UID: "jane", LastName: "Smith"}}, false},
		"locking without an account": {ActionUserDisable, Payload{}, true},
		"valid locking":              {ActionUserDisable, Payload{Reference: &ReferencePayload{UID: "jane"}}, false},
		"empty membership change":    {ActionGroupMembers, Payload{Group: &GroupPayload{Group: "group"}}, true},
		"membership change":          {ActionGroupMembers, Payload{Group: &GroupPayload{Group: "group", Add: []string{"jane"}}}, false},
		"unknown type":               {"identity.user.delete", Payload{}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := Validate(tc.action, tc.payload)
			if tc.wantErr && err == nil {
				t.Fatal("an invalid change passed validation")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("a valid change was rejected: %v", err)
			}
		})
	}
}

func TestThePayloadHashDetectsASwap(t *testing.T) {
	original := Payload{User: &UserPayload{UID: "jane", LastName: "Smith",
		Groups: []string{"flotestro-viewers"}}}
	approved, err := PayloadHash(ActionUserCreate, original)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Swapping the group after the approval is a privilege escalation, so it
	// has to change the plan hash.
	tampered := Payload{User: &UserPayload{UID: "jane", LastName: "Smith",
		Groups: []string{"flotestro-platform-admins"}}}
	changed, err := PayloadHash(ActionUserCreate, tampered)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if bytes.Equal(approved, changed) {
		t.Fatal("swapping the group did not change the plan hash")
	}

	// The same plan has to give the same hash.
	again, _ := PayloadHash(ActionUserCreate, original)
	if !bytes.Equal(approved, again) {
		t.Fatal("the same plan gave different hashes")
	}
}

func TestPermissionsAreSeparatedPerTypeOfChange(t *testing.T) {
	if ActionGroupMembers.Permission() == ActionUserCreate.Permission() {
		t.Error("a membership change has the same permission as creating an account")
	}
	for _, action := range []ActionType{ActionUserCreate, ActionUserDisable, ActionSSHKeys} {
		if action.Permission() != "identity.user.write" {
			t.Errorf("%s has the permission %s", action, action.Permission())
		}
	}
}

func TestTheFinalStateIsRecognised(t *testing.T) {
	for _, state := range []State{StateSucceeded, StatePartiallyApplied, StateFailed, StateCanceled} {
		if !state.Terminal() {
			t.Errorf("%s should be a final state", state)
		}
	}
	for _, state := range []State{StatePlanned, StateAwaitingApproval, StateRunning} {
		if state.Terminal() {
			t.Errorf("%s is not a final state", state)
		}
	}
}
