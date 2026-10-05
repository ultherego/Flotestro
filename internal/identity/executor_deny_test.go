package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
)

// Preserving an account the panel knows nobody by ended the whole change as
// partially_applied, over a step that had nothing to do: the lock path made
// the distinction and the preserve path did not. One function makes it now, and
// this holds both ends of it.
func TestAnAccountWithNoPanelIdentityIsNotAFailedDenial(t *testing.T) {
	phase := deniedLocally(startPhase("the local denial marker"), 0,
		errors.New("the panel holds no identity under that name: "+ErrNoPrincipal.Error()),
		"identities marked", "nothing to deny locally")
	// A plain error of that text is still a failure: the distinction is made on
	// the sentinel, not on the words.
	if phase.Status != "failed" {
		t.Fatalf("an unrecognised error became %q", phase.Status)
	}

	phase = deniedLocally(startPhase("the local denial marker"), 0, ErrNoPrincipal,
		"identities marked", "nothing to deny locally")
	if phase.Status != "skipped" {
		t.Fatalf("an account with no panel identity became %q", phase.Status)
	}
	if !strings.Contains(phase.Message, "nothing to deny locally") {
		t.Errorf("the phase does not say what it skipped: %q", phase.Message)
	}

	phase = deniedLocally(startPhase("the local denial marker"), 2, nil,
		"identities marked", "nothing to deny locally")
	if phase.Status != "succeeded" || !strings.Contains(phase.Message, "2") {
		t.Fatalf("a denial that marked two identities became %q (%s)", phase.Status, phase.Message)
	}
}

// The denial marker and the session revocation ask the same question: is this
// panel identity that directory account. The marker asked it by the account
// name alone, so a login named "uid@issuer" lost its sessions and kept its
// tokens, over a phase that said there was nothing to deny.
func TestTheDenialCoversTheRealmQualifiedIdentityTheSessionsCover(t *testing.T) {
	sessions := &fakeSessions{principals: []authz.Principal{
		{ID: "p-alice-idp", Subject: "alice@ipa.example.test"},
		{ID: "p-alice2", Subject: "alice2"},
		{ID: "p-bob", Subject: "bob"},
	}}
	var denied []string
	executor := &Executor{sessions: sessions,
		localDeny: func(_ context.Context, subject, _ string, _ bool) (int64, error) {
			denied = append(denied, subject)
			return 1, nil
		}}

	count, err := executor.denyDirectoryUser(context.Background(), "alice", "locked", true)
	if err != nil {
		t.Fatalf("denying alice: %v", err)
	}
	if count != 1 || len(denied) != 1 || denied[0] != "alice@ipa.example.test" {
		t.Fatalf("marked %d identities: %v", count, denied)
	}

	// An account no panel identity answers to is still the skipped phase it was.
	if _, err := executor.denyDirectoryUser(context.Background(), "carol", "locked", true); !errors.Is(err, ErrNoPrincipal) {
		t.Fatalf("an account with no panel identity ended as %v", err)
	}

	// Identities that could not be read are not identities that are not there:
	// the phase fails instead of saying there was nobody to deny.
	unreadable := &Executor{sessions: &fakeSessions{listErr: errors.New("database gone")}}
	_, err = unreadable.denyDirectoryUser(context.Background(), "alice", "locked", true)
	if err == nil || errors.Is(err, ErrNoPrincipal) {
		t.Fatalf("an unreadable list of identities ended as %v", err)
	}
}

// The link an operator writes down through PUT /principals/{id}/directory-account
// exists for an identity whose subject says nothing about the account. Neither
// the denial nor the revocation read it, so the field changed nothing and the
// one case it was added for was covered by neither.
func TestTheLinkAnOperatorWroteDownIsTheIdentityOfThatDirectoryAccount(t *testing.T) {
	sessions := &fakeSessions{
		principals: []authz.Principal{
			{ID: "p-linked", Subject: "a.smith@keycloak.example.test", DirectoryUID: "alice"},
			{ID: "p-other", Subject: "j.doe@keycloak.example.test", DirectoryUID: "bob"},
			{ID: "p-unlinked", Subject: "m.jones@keycloak.example.test"},
		},
		live: map[string]int64{"p-linked": 2, "p-other": 1, "p-unlinked": 4},
	}
	var denied []string
	executor := &Executor{sessions: sessions,
		localDeny: func(_ context.Context, subject, _ string, _ bool) (int64, error) {
			denied = append(denied, subject)
			return 1, nil
		}}

	count, err := executor.denyDirectoryUser(context.Background(), "alice", "locked", true)
	if err != nil {
		t.Fatalf("denying the account the link names: %v", err)
	}
	if count != 1 || len(denied) != 1 || denied[0] != "a.smith@keycloak.example.test" {
		t.Fatalf("marked %d identities: %v", count, denied)
	}

	// And the same identity loses its sessions, because both halves ask the
	// one function.
	result, err := executor.revokeSessions(context.Background(), "alice", "the account was locked")
	if err != nil {
		t.Fatalf("revoking the sessions of the account the link names: %v", err)
	}
	if result.Sessions != 2 || len(result.WithoutPrincipal) != 0 {
		t.Fatalf("the revocation came back as %+v", result)
	}
	if _, ended := sessions.revoked["p-other"]; ended {
		t.Error("an identity linked to another account lost its sessions")
	}
	if _, ended := sessions.revoked["p-unlinked"]; ended {
		t.Error("an identity with no link and an unrelated subject lost its sessions")
	}

	// A link to another account is not this account, and an identity with
	// neither a link nor the name is nobody's.
	for _, uid := range []string{"carol", "dave"} {
		if _, err := executor.denyDirectoryUser(context.Background(), uid, "locked", true); !errors.Is(err, ErrNoPrincipal) {
			t.Errorf("denying %q ended as %v", uid, err)
		}
	}
	// The name still carries where nobody wrote a link down.
	if !MatchesDirectoryPrincipal(authz.Principal{Subject: "alice@ipa.example.test"}, "alice") {
		t.Error("the qualified name stopped matching once the link was added")
	}
	// A link wins nothing it does not name: the subject rule still applies.
	if !MatchesDirectoryPrincipal(authz.Principal{Subject: "alice", DirectoryUID: "bob"}, "alice") {
		t.Error("a link to another account hid the identity's own name")
	}
}
