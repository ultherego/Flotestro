//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/relays"
)

// Handing signing over to a new fleet CA cuts off everything whose trust set
// does not carry it. The guard before an activation counted hosts and stopped
// there - and a relay holds the bundle too, so a relay left behind darkens the
// whole site it terminates.
//
// The rule is the hosts' own: the bundle travels with the certificate, so what
// counts as evidence is the bundle that went out with the certificate the relay
// has been SEEN USING. This runs it against the real database, because the rule
// is two conditions in one SQL predicate and either of them alone would pass
// over a relay that never received anything.
func TestARelayCountsAsHoldingAnAuthorityOnlyOnceItHasUsedTheCertificateItCameWith(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	store := relays.NewStore(h.database(ctx))

	issuer := uuid.NewString()
	other := uuid.NewString()
	before, err := store.WithoutTrustGeneration(ctx, issuer)
	if err != nil {
		t.Fatalf("counting the relays without the authority: %v", err)
	}

	// A relay of this test's own, so the laboratory's own relay is left alone.
	id := uuid.NewString()
	fingerprint := make([]byte, 32)
	if _, err := rand.Read(fingerprint); err != nil {
		t.Fatal(err)
	}
	pool := h.database(ctx)
	if _, err := pool.Exec(ctx, `
		insert into relays (id, name, site, fingerprint_sha256, trust_issuer_ids)
		values ($1, $2, 'integration', $3, array[$4::uuid])`,
		id, "relay-trust-"+id[:8], fingerprint, issuer); err != nil {
		t.Fatalf("the synthetic relay: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "delete from relays where id = $1", id); err != nil {
			t.Logf("the synthetic relay %s was not cleaned up: %v", id, err)
		}
	})

	// The bundle names the authority and the relay has not been seen using the
	// certificate it came with. That is not evidence, and the count says so.
	after, err := store.WithoutTrustGeneration(ctx, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("a relay that was sent the authority and never shown to use it counts as %d of the missing, want one more than %d",
			after, before)
	}

	// Seen using another certificate: still nothing. This is the case that
	// matters, because a relay keeps the previous certificate until it expires.
	elsewhere := make([]byte, 32)
	if _, err := rand.Read(elsewhere); err != nil {
		t.Fatal(err)
	}
	store.MarkTrustPresented(ctx, id, elsewhere)
	if n, err := store.WithoutTrustGeneration(ctx, issuer); err != nil || n != before+1 {
		t.Fatalf("a heartbeat on another certificate counted as the bundle arriving (n=%d, err=%v)", n, err)
	}

	// Seen using the certificate the bundle came with: now it holds it.
	store.MarkTrustPresented(ctx, id, fingerprint)
	if n, err := store.WithoutTrustGeneration(ctx, issuer); err != nil || n != before {
		t.Fatalf("the relay used the certificate the bundle came with and still counts as missing (n=%d, err=%v)", n, err)
	}

	// And it holds that authority only - another one is still missing from it.
	missingOther, err := store.WithoutTrustGeneration(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if missingOther < 1 {
		t.Error("the relay counts as holding an authority its bundle never carried")
	}
}
