package scheduler

import (
	"context"
	"errors"
	"testing"
)

// A creator the panel has never heard of is a system task. A creator that
// exists and may do nothing is not, and used to look the same: the store
// refuses a disabled or denied identity with the same error as a missing one,
// the resolver turned both into "no permissions", and the dispatcher read that
// as the system-task case and signed a capability carrying the action's own
// permission. The counter-test of the review got exactly that capability.
type answeringPermissions struct {
	permissions []string
	err         error
	askedHost   string
}

func (a *answeringPermissions) PermissionsOfSubject(_ context.Context, _, hostID string) ([]string, error) {
	a.askedHost = hostID
	return a.permissions, a.err
}

func TestABlockedCreatorIsNotASystemTask(t *testing.T) {
	var _ PrincipalPermissions = &answeringPermissions{}

	// The three answers, told apart.
	blocked := &answeringPermissions{err: ErrSubjectBlocked}
	if _, err := blocked.PermissionsOfSubject(context.Background(), "alice", "host-1"); !errors.Is(err, ErrSubjectBlocked) {
		t.Fatal("the blocked answer does not carry its own error")
	}
	// And the dispatcher's own rule over it: a blocked creator is a right that
	// was read and is gone, not a question nobody could answer.
	if errors.Is(ErrSubjectBlocked, errCreatorRightsUnconfirmed) {
		t.Error("a blocked creator reads as an unanswered question")
	}

	// The question is asked about the host the task is for, because a
	// permission is held in a scope and "any scope at all" is not this one.
	asked := &answeringPermissions{permissions: []string{"unit.restart"}}
	if _, err := asked.PermissionsOfSubject(context.Background(), "alice", "host-9"); err != nil {
		t.Fatal(err)
	}
	if asked.askedHost != "host-9" {
		t.Fatalf("the resolver was asked about %q, not about the host of the task", asked.askedHost)
	}
}
