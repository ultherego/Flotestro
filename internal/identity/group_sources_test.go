package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// Each source answers for its own system. Keycloak and FreeIPA are asked
// separately, under separate issuer names, so a group mapping of one is never
// satisfied by a group of the other that happens to share a name.

type groupIssuer struct {
	issuer  string
	groups  []string
	err     error
	asked   string
	queries int
}

func (p *groupIssuer) Issuer() string { return p.issuer }

func (p *groupIssuer) GroupsOfSubject(_ context.Context, subjectID string) ([]string, error) {
	p.queries++
	p.asked = subjectID
	return p.groups, p.err
}

type groupAccounts struct {
	users map[string]*freeipa.User
	err   error
	asked string
}

func (a *groupAccounts) ShowUser(_ context.Context, uid string) (*freeipa.User, error) {
	a.asked = uid
	if a.err != nil {
		return nil, a.err
	}
	return a.users[uid], nil
}

func TestTheProviderIsAskedAboutItsOwnSubject(t *testing.T) {
	provider := &groupIssuer{issuer: "https://idp.example/realms/fleet",
		groups: []string{"flotestro-operators"}}
	source := NewProviderGroupSource(provider)
	if source.Issuer() != provider.issuer {
		t.Fatalf("the source speaks for %q", source.Issuer())
	}
	groups, err := source.GroupsOf(context.Background(), "9f1d-subject-id")
	if err != nil {
		t.Fatal(err)
	}
	if provider.asked != "9f1d-subject-id" {
		t.Fatalf("the provider was asked about %q", provider.asked)
	}
	if len(groups) != 1 || groups[0] != "flotestro-operators" {
		t.Fatalf("the groups came back as %v", groups)
	}

	provider.err = errors.New("the admin API answered 403 Forbidden")
	if _, err := source.GroupsOf(context.Background(), "9f1d-subject-id"); err == nil {
		t.Fatal("a refusal of the admin API passed for an empty group set")
	}
}

func TestTheDirectoryAnswersUnderItsOwnIssuer(t *testing.T) {
	accounts := &groupAccounts{users: map[string]*freeipa.User{
		"jane": {UID: "jane", Groups: []string{"flotestro-operators"}},
	}}
	source := NewDirectoryGroupSource("example.test", accounts)
	if source.Issuer() != "freeipa:EXAMPLE.TEST" {
		t.Fatalf("the directory speaks for %q", source.Issuer())
	}
	if source.Issuer() == "https://idp.example/realms/fleet" {
		t.Fatal("the directory took the identity provider's name")
	}
	groups, err := source.GroupsOf(context.Background(), "jane")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0] != "flotestro-operators" {
		t.Fatalf("the groups came back as %v", groups)
	}
	if accounts.asked != "jane" {
		t.Fatalf("the directory was asked about %q", accounts.asked)
	}
}

// A locked account is a member of nothing as far as rights go: the entry still
// lists its groups and the lock is the directory's answer.
func TestALockedDirectoryAccountGrantsNothing(t *testing.T) {
	accounts := &groupAccounts{users: map[string]*freeipa.User{
		"jane": {UID: "jane", Groups: []string{"flotestro-operators"}, Disabled: true},
	}}
	groups, err := NewDirectoryGroupSource("example.test", accounts).
		GroupsOf(context.Background(), "jane")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 0 {
		t.Fatalf("a locked account kept the groups %v", groups)
	}
}

// A directory that does not answer gives an error, not an empty group set: the
// difference is what makes the work pause instead of carrying on with fewer
// rights than the operator thinks.
func TestAnUnreachableDirectoryIsNotAnEmptyGroupSet(t *testing.T) {
	accounts := &groupAccounts{err: errors.New("the directory refused the session")}
	if _, err := NewDirectoryGroupSource("example.test", accounts).
		GroupsOf(context.Background(), "jane"); err == nil {
		t.Fatal("an unreachable directory passed for an account without groups")
	}
}

// Without a provider or a directory there is no source at all, and the store
// then has nothing to confirm with rather than a source that answers nothing.
func TestNoProviderMeansNoSource(t *testing.T) {
	if source := NewProviderGroupSource(nil); source != nil {
		t.Fatal("a source was built without a provider")
	}
	if source := NewDirectoryGroupSource("example.test", nil); source != nil {
		t.Fatal("a source was built without a directory")
	}
	if source := NewDirectoryGroupSource("  ", &groupAccounts{}); source != nil {
		t.Fatal("a source was built without a realm to name it")
	}
}
