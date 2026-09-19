//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/authz"
)

// TestMappedRightsHoldAwayFromTheRequest guards the person who signs in
// through the identity provider: their rights come from the group mapping and
// not from bindings of their own, so a check made away from any request - the
func TestMappedRightsHoldAwayFromTheRequest(t *testing.T) {
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

	// Before any session the panel knows no groups: nothing is granted,
	// and nothing is invented.
	before, err := store.PrincipalBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("the principal before a session: %v", err)
	}
	if before.Can(authz.PermCampaignCreate, authz.Scope{Site: "lab", Environment: "test"}) {
		t.Fatal("a principal without a session holds a mapped right")
	}

	// A session, ended since, carries the snapshot of the groups: the
	// rights follow the groups, not the being signed in.
	hash := sha256.Sum256([]byte("integration-cookie-" + uuid.NewString()))
	if _, err := pool.Exec(ctx, `
		insert into web_sessions (id, token_hash, principal_id, groups, absolute_expires_at, idle_expires_at, revoked_at)
		values ($1, $2, $3, $4, $5, $5, now())`,
		uuid.NewString(), hash[:], principalID, []string{group}, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("the session: %v", err)
	}
	after, err := store.PrincipalBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("the principal after a session: %v", err)
	}
	if !after.Can(authz.PermCampaignCreate, authz.Scope{Site: "lab", Environment: "test"}) {
		t.Fatalf("the mapped platform_admin does not hold campaign.create away from a request: %+v", after.Bindings)
	}
	if !after.Can(authz.PermHostRead, authz.Scope{Site: "elsewhere", Environment: "prod"}) {
		t.Fatal("the fleet-wide mapping does not reach every scope")
	}
}
