package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
)

// fakeSessions stands in for the session store: a fixed list of principals
// and a count of live sessions per principal.
type fakeSessions struct {
	principals []authz.Principal
	live       map[string]int64
	revoked    map[string]string
	listErr    error
}

func (f *fakeSessions) ListPrincipals(context.Context) ([]authz.Principal, error) {
	return f.principals, f.listErr
}

func (f *fakeSessions) RevokeSessionsOf(_ context.Context, principalID, reason string) (int64, error) {
	if f.revoked == nil {
		f.revoked = map[string]string{}
	}
	f.revoked[principalID] = reason
	return f.live[principalID], nil
}

func TestADirectoryUserMatchesThePrincipalsTheLoginNamedAfterIt(t *testing.T) {
	// The login names a principal after preferred_username, or after
	// "uid@issuer-host" when that name was taken. Both are the same person
	// in the directory; a name that merely starts alike is not.
	cases := []struct {
		subject, uid string
		matches      bool
	}{
		{"alice", "alice", true},
		{"alice@ipa.example.test", "alice", true},
		{"alice2", "alice", false},
		{"alice.smith", "alice", false},
		{"bob", "alice", false},
		{"bootstrap-admin", "alice", false},
		{"alice", "", false},
		{"", "alice", false},
	}
	for _, tc := range cases {
		if got := MatchesDirectoryUser(tc.subject, tc.uid); got != tc.matches {
			t.Errorf("MatchesDirectoryUser(%q, %q) = %v, expected %v", tc.subject, tc.uid, got, tc.matches)
		}
	}
}

func TestAMembershipChangeEndsTheSessionsOfTheMovedUsers(t *testing.T) {
	sessions := &fakeSessions{
		principals: []authz.Principal{
			{ID: "p-alice", Subject: "alice"},
			{ID: "p-alice-idp", Subject: "alice@ipa.example.test"},
			{ID: "p-bob", Subject: "bob"},
		},
		live: map[string]int64{"p-alice": 2, "p-alice-idp": 1, "p-bob": 3},
	}
	executor := &Executor{sessions: sessions}

	phase, result := executor.revokeChangedMembers(context.Background(),
		[]string{"alice", "carol"}, "the group membership changed: admins")

	if phase.Status != "succeeded" {
		t.Fatalf("phase = %s (%s), expected succeeded", phase.Status, phase.Message)
	}
	if result.Sessions != 3 {
		t.Fatalf("sessions revoked = %d, expected 3 (both principals of alice, none of bob)", result.Sessions)
	}
	// A user who never logged into the panel has nothing to end. That is
	// said in the result rather than reported as a failure.
	if len(result.WithoutPrincipal) != 1 || result.WithoutPrincipal[0] != "carol" {
		t.Fatalf("without principal = %v, expected [carol]", result.WithoutPrincipal)
	}
	if !strings.Contains(phase.Message, "sessions revoked: 3") ||
		!strings.Contains(phase.Message, "no panel identity for carol") {
		t.Fatalf("message = %q", phase.Message)
	}
	if _, ok := sessions.revoked["p-bob"]; ok {
		t.Fatal("bob was not moved and must keep the session")
	}
	if reason := sessions.revoked["p-alice"]; reason != "the group membership changed: admins" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestNothingToRevokeIsNotAFailure(t *testing.T) {
	executor := &Executor{sessions: &fakeSessions{}}
	phase, result := executor.revokeChangedMembers(context.Background(), []string{"dave"}, "moved")
	if phase.Status != "succeeded" {
		t.Fatalf("phase = %s (%s), expected succeeded", phase.Status, phase.Message)
	}
	if result.Sessions != 0 || len(result.WithoutPrincipal) != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func TestAFailedListingFailsTheRevocationPhase(t *testing.T) {
	// The directory change itself succeeded; a phase that fails here makes
	// the change partially applied, which is the truth: the membership moved
	// and the old sessions may still be alive.
	executor := &Executor{sessions: &fakeSessions{listErr: errors.New("database gone")}}
	phase, _ := executor.revokeChangedMembers(context.Background(), []string{"alice"}, "moved")
	if phase.Status != "failed" {
		t.Fatalf("phase = %s, expected failed", phase.Status)
	}
}

// fakeLogoutProvider stands in for the identity provider's admin logout: it
// remembers whom it was asked to log out and answers what the test set.
type fakeLogoutProvider struct {
	loggedOut []string
	err       error
}

func (f *fakeLogoutProvider) LogoutSubject(_ context.Context, subject string) error {
	f.loggedOut = append(f.loggedOut, subject)
	return f.err
}

func TestADisableEndsTheProviderSessionsAndNeverFailsOnThem(t *testing.T) {
	// The provider answers: the phase says so, and the result carries
	// provider_sessions_ended for the auditor.
	provider := &fakeLogoutProvider{}
	executor := &Executor{provider: provider}
	phase, ended := executor.endProviderSessions(context.Background(), "alice")
	if phase.Status != "succeeded" || !ended.Ended || ended.Reason != "" {
		t.Fatalf("phase = %s (%s), outcome = %+v", phase.Status, phase.Message, ended)
	}
	if len(provider.loggedOut) != 1 || provider.loggedOut[0] != "alice" {
		t.Fatalf("the provider was asked to log out %v", provider.loggedOut)
	}

	// The provider refuses or is unreachable: the disable holds on the
	// local marker, so the phase is skipped with the reason rather than
	// failed - a failed phase would call the whole disable partially
	// applied, and it is not.
	refusing := &Executor{provider: &fakeLogoutProvider{err: errors.New("the admin API answered 403 Forbidden")}}
	phase, ended = refusing.endProviderSessions(context.Background(), "alice")
	if phase.Status != "skipped" || ended.Ended || !strings.Contains(ended.Reason, "403") {
		t.Fatalf("phase = %s (%s), outcome = %+v", phase.Status, phase.Message, ended)
	}
	if state := StateFor([]Phase{{Status: "succeeded"}, phase}); state != StateSucceeded {
		t.Fatalf("a skipped provider logout made the change %s", state)
	}

	// No provider configured at all: the same skip, with that reason.
	phase, ended = (&Executor{}).endProviderSessions(context.Background(), "alice")
	if phase.Status != "skipped" || ended.Ended || ended.Reason == "" {
		t.Fatalf("phase = %s (%s), outcome = %+v", phase.Status, phase.Message, ended)
	}
}
