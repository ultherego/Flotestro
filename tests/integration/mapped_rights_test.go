//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/authz"
)

// A group source that answers whatever the test last told it to.
type directoryAnswer struct {
	issuer string
	groups []string
	err    error
}

func (a *directoryAnswer) Issuer() string { return a.issuer }

func (a *directoryAnswer) GroupsOf(context.Context, string) ([]string, error) {
	return a.groups, a.err
}

// TestMappedRightsFollowTheDirectoryAndNotASession guards the person who signs
// in through the provider: away from a request their group-derived rights come
// from the directory, so a membership taken away stops the work and a logout
// does not bring back rights the directory no longer gives.
//
// The snapshot of a session is deliberately present and deliberately ignored:
// it is what this path used to read, and a revoked session's groups went on
// authorizing campaigns for as long as the row existed.
func TestMappedRightsFollowTheDirectoryAndNotASession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	store := authz.NewStore(pool)

	issuer := "https://issuer.integration.test/" + uuid.NewString()
	subject := "mapped-" + uuid.NewString()[:8]
	group := "fleet-admins"
	principalID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		insert into principals (id, subject, display_name, kind, issuer, subject_id)
		values ($1, $2, 'Mapped Person', 'user', $3, $4)`, principalID, subject, issuer, subject); err != nil {
		t.Fatalf("the principal: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `delete from web_sessions where principal_id = $1`, principalID)
		_, _ = pool.Exec(ctx, `delete from group_role_mappings where issuer = $1`, issuer)
		_, _ = pool.Exec(ctx, `delete from principals where id = $1`, principalID)
	})
	if _, err := pool.Exec(ctx, `
		insert into group_role_mappings (id, issuer, group_name, role, site, environment, created_by)
		values ($1, $2, $3, 'platform_admin', '*', '*', 'integration-test')`,
		uuid.NewString(), issuer, group); err != nil {
		t.Fatalf("the mapping: %v", err)
	}

	// A session that was revoked long ago, carrying the group. Nothing below
	// may follow from it.
	hash := sha256.Sum256([]byte("integration-cookie-" + uuid.NewString()))
	if _, err := pool.Exec(ctx, `
		insert into web_sessions (id, token_hash, principal_id, groups, absolute_expires_at, idle_expires_at, revoked_at)
		values ($1, $2, $3, $4, $5, $5, now())`,
		uuid.NewString(), hash[:], principalID, []string{group}, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("the session: %v", err)
	}

	// The issuer maps a group to a role and no directory can confirm who is in
	// it. That is not a reason to grant it and not a reason to deny it: the
	// answer is missing, and the caller is told so.
	if _, err := store.PrincipalBySubject(ctx, subject); !errors.Is(err, authz.ErrGroupsUnavailable) {
		t.Fatalf("without a directory the rights came back as %v", err)
	}

	answer := &directoryAnswer{issuer: issuer, groups: []string{group}}
	directory := authz.NewGroupDirectory(time.Minute)
	directory.AddIssuerSource(answer)
	store.SetGroupDirectory(directory)

	held, err := store.PrincipalBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("the principal with a confirmed membership: %v", err)
	}
	if !held.Can(authz.PermCampaignCreate, authz.Scope{Site: "lab", Environment: "test"}) {
		t.Fatalf("the mapped platform_admin does not hold campaign.create away from a request: %+v", held.Bindings)
	}
	if !held.Can(authz.PermHostRead, authz.Scope{Site: "elsewhere", Environment: "prod"}) {
		t.Fatal("the fleet-wide mapping does not reach every scope")
	}

	// The membership is taken away in the directory. The session row still
	// names the group; the rights are gone all the same.
	answer.groups = []string{"something-else"}
	directory.Forget(issuer, subject)
	revoked, err := store.PrincipalBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("the principal after the membership was taken away: %v", err)
	}
	if revoked.Can(authz.PermCampaignCreate, authz.Scope{Site: "lab", Environment: "test"}) {
		t.Fatalf("a revoked group still grants a role: %+v", revoked.Bindings)
	}

	// A binding granted by hand is not the directory's business and keeps
	// working next to the group that is gone.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.GrantRole(ctx, tx, principalID, authz.RoleOperator,
		authz.Placement("lab", "test"), nil, "integration-test"); err != nil {
		t.Fatalf("the direct binding: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	directory.Forget(issuer, subject)
	direct, err := store.PrincipalBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("the principal with a direct binding: %v", err)
	}
	if !direct.Can(authz.PermCampaignCreate, authz.Scope{Site: "lab", Environment: "test"}) {
		t.Fatalf("the direct binding stopped working: %+v", direct.Bindings)
	}
	if direct.Can(authz.PermPrincipalManage, authz.Scope{Site: "lab", Environment: "test"}) {
		t.Fatal("the direct operator binding grants what only the revoked group granted")
	}

	// The directory stops answering. The last confirmation is past its age, so
	// there is no answer again - not the previous one.
	answer.err = errors.New("the directory is unreachable")
	directory.Forget(issuer, subject)
	if _, err := store.PrincipalBySubject(ctx, subject); !errors.Is(err, authz.ErrGroupsUnavailable) {
		t.Fatalf("an unreachable directory came back as %v", err)
	}
}
