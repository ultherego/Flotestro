package identity

import (
	"context"
	"strings"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/freeipa"
)

// The group membership that authorizes background work is read from the
// system that owns it, one source per issuer. Keycloak and FreeIPA are not
// each other's directory: their groups may share a name and mean different
// people, so each source answers for its own issuer and no other.

// IssuerGroups is the provider side: an issuer that can name the groups of one
// of its own accounts.
type IssuerGroups interface {
	Issuer() string
	GroupsOfSubject(ctx context.Context, subjectID string) ([]string, error)
}

// providerGroupSource reads the groups of an OIDC identity at its own issuer.
type providerGroupSource struct {
	provider IssuerGroups
}

// NewProviderGroupSource makes the identity provider answer about its own
// users' groups.
func NewProviderGroupSource(provider IssuerGroups) authz.GroupSource {
	if provider == nil {
		return nil
	}
	return providerGroupSource{provider: provider}
}

func (s providerGroupSource) Issuer() string { return s.provider.Issuer() }

func (s providerGroupSource) GroupsOf(ctx context.Context, account string) ([]string, error) {
	return s.provider.GroupsOfSubject(ctx, account)
}

// DirectoryAccounts is the part of the directory connector this source uses.
type DirectoryAccounts interface {
	ShowUser(ctx context.Context, uid string) (*freeipa.User, error)
}

// DirectoryIssuerPrefix names the directory as an issuer of groups. A FreeIPA
// group is mapped to a role under this name, which is a different issuer from
// any OIDC one: the two vocabularies stay apart.
const DirectoryIssuerPrefix = "freeipa:"

// DirectoryIssuer is the issuer name the groups of a realm are mapped under.
func DirectoryIssuer(realm string) string {
	return DirectoryIssuerPrefix + strings.ToUpper(strings.TrimSpace(realm))
}

// directoryGroupSource reads the groups of an explicitly linked directory
// account.
type directoryGroupSource struct {
	issuer   string
	accounts DirectoryAccounts
}

// NewDirectoryGroupSource makes the directory answer about the groups of the
// accounts identities are linked to.
func NewDirectoryGroupSource(realm string, accounts DirectoryAccounts) authz.GroupSource {
	if accounts == nil || strings.TrimSpace(realm) == "" {
		return nil
	}
	return directoryGroupSource{issuer: DirectoryIssuer(realm), accounts: accounts}
}

func (s directoryGroupSource) Issuer() string { return s.issuer }

func (s directoryGroupSource) GroupsOf(ctx context.Context, account string) ([]string, error) {
	user, err := s.accounts.ShowUser(ctx, account)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return []string{}, nil
	}
	// A locked account is a member of nothing as far as rights go: the entry
	// still lists its groups, and the lock is the directory saying no.
	if user.Disabled {
		return []string{}, nil
	}
	return user.Groups, nil
}
