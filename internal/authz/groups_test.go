package authz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A group source that counts its calls and can be made to fail.
type countingSource struct {
	issuer string
	groups []string
	err    error
	calls  int
}

func (s *countingSource) Issuer() string { return s.issuer }

func (s *countingSource) GroupsOf(context.Context, string) ([]string, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.groups, nil
}

// A confirmation younger than the bound is served from the cache; one past it
// is not, and the directory is asked again. The age is the whole point of the
// cache: it bounds how long a revoked membership keeps working.
func TestAConfirmationIsServedWhileYoungAndAskedAgainWhenOld(t *testing.T) {
	source := &countingSource{issuer: "https://idp.example/realms/fleet", groups: []string{"operators"}}
	directory := NewGroupDirectory(2 * time.Minute)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	directory.SetClock(func() time.Time { return now })
	directory.AddIssuerSource(source)

	first, err := directory.ConfirmIssuer(context.Background(), source.issuer, "user-1")
	if err != nil {
		t.Fatalf("the first confirmation: %v", err)
	}
	if len(first.Groups) != 1 || first.Groups[0] != "operators" {
		t.Fatalf("the groups came back as %v", first.Groups)
	}
	if first.Issuer != source.issuer {
		t.Fatalf("the confirmation names the issuer %q", first.Issuer)
	}

	now = now.Add(time.Minute)
	if _, err := directory.ConfirmIssuer(context.Background(), source.issuer, "user-1"); err != nil {
		t.Fatalf("the cached confirmation: %v", err)
	}
	if source.calls != 1 {
		t.Fatalf("the directory was asked %d times inside the bound", source.calls)
	}

	now = now.Add(2 * time.Minute)
	if _, err := directory.ConfirmIssuer(context.Background(), source.issuer, "user-1"); err != nil {
		t.Fatalf("the refreshed confirmation: %v", err)
	}
	if source.calls != 2 {
		t.Fatalf("the directory was asked %d times past the bound", source.calls)
	}
}

// A directory that does not answer leaves no answer at all: the confirmation
// on hand is too old to serve, and the caller is told so rather than handed
// the old group set.
func TestAnUnreachableDirectoryLeavesNoConfirmation(t *testing.T) {
	source := &countingSource{issuer: "https://idp.example/realms/fleet", groups: []string{"operators"}}
	directory := NewGroupDirectory(time.Minute)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	directory.SetClock(func() time.Time { return now })
	directory.AddIssuerSource(source)

	if _, err := directory.ConfirmIssuer(context.Background(), source.issuer, "user-1"); err != nil {
		t.Fatalf("the first confirmation: %v", err)
	}
	now = now.Add(5 * time.Minute)
	source.err = errors.New("the admin API answered 503 Service Unavailable")

	confirmation, err := directory.ConfirmIssuer(context.Background(), source.issuer, "user-1")
	if !errors.Is(err, ErrGroupsUnavailable) {
		t.Fatalf("the failure came back as %v", err)
	}
	if len(confirmation.Groups) != 0 {
		t.Fatalf("a stale group set was served anyway: %v", confirmation.Groups)
	}
	if err != nil && !strings.Contains(err.Error(), "503") {
		t.Fatalf("the reason does not name what happened: %v", err)
	}
}

// The mapping of one issuer is never satisfied by another system's groups: a
// source answers for its own issuer, and an issuer without a source has no
// answer rather than somebody else's.
func TestASourceNeverAnswersForAnotherIssuer(t *testing.T) {
	keycloak := &countingSource{issuer: "https://idp.example/realms/fleet", groups: []string{"admins"}}
	ipa := &countingSource{issuer: "freeipa:EXAMPLE.TEST", groups: []string{"admins"}}
	directory := NewGroupDirectory(time.Minute)
	directory.AddIssuerSource(keycloak)

	confirmation, err := directory.ConfirmIssuer(context.Background(), keycloak.issuer, "user-1")
	if err != nil {
		t.Fatalf("the issuer with a source: %v", err)
	}
	if confirmation.Issuer != keycloak.issuer {
		t.Fatalf("the groups of %s were attributed to %s", keycloak.issuer, confirmation.Issuer)
	}
	// The same group name at the other system is a different group, so asking
	// about that issuer must not be answered out of this one.
	if _, err := directory.ConfirmIssuer(context.Background(), ipa.issuer, "user-1"); !errors.Is(err, ErrGroupsUnavailable) {
		t.Fatalf("an issuer without a source answered with %v", err)
	}
	if ipa.calls != 0 {
		t.Fatalf("the unregistered source was asked %d times", ipa.calls)
	}

	// A linked directory account resolves against the directory and comes back
	// named after it, never after the identity provider.
	directory.SetLinkedSource(ipa)
	linked, err := directory.ConfirmLinked(context.Background(), "jane")
	if err != nil {
		t.Fatalf("the linked account: %v", err)
	}
	if linked.Issuer != ipa.issuer {
		t.Fatalf("the directory's groups were attributed to %s", linked.Issuer)
	}
}

// An identity that names no account at a system cannot be asked about, and a
// guess is not an answer.
func TestAnIdentityWithoutAnAccountHasNoConfirmation(t *testing.T) {
	source := &countingSource{issuer: "https://idp.example/realms/fleet"}
	directory := NewGroupDirectory(time.Minute)
	directory.AddIssuerSource(source)

	if _, err := directory.ConfirmIssuer(context.Background(), source.issuer, ""); !errors.Is(err, ErrGroupsUnavailable) {
		t.Fatalf("an identity without an account answered with %v", err)
	}
	if _, err := directory.ConfirmLinked(context.Background(), "jane"); !errors.Is(err, ErrGroupsUnavailable) {
		t.Fatalf("a linked account without a directory answered with %v", err)
	}
}

// Forget sends the next question to the directory.
func TestForgettingAnAccountAsksTheDirectoryAgain(t *testing.T) {
	source := &countingSource{issuer: "https://idp.example/realms/fleet", groups: []string{"operators"}}
	directory := NewGroupDirectory(time.Hour)
	directory.AddIssuerSource(source)

	if _, err := directory.ConfirmIssuer(context.Background(), source.issuer, "user-1"); err != nil {
		t.Fatal(err)
	}
	directory.Forget(source.issuer, "user-1")
	if _, err := directory.ConfirmIssuer(context.Background(), source.issuer, "user-1"); err != nil {
		t.Fatal(err)
	}
	if source.calls != 2 {
		t.Fatalf("the directory was asked %d times", source.calls)
	}
}
