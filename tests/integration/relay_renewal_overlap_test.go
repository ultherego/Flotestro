//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/relays"
)

// The answer to a relay renewal can be lost. The relay commits its new
// identity only when the answer arrives, while the panel wrote the new
// fingerprint before sending it - so the relay was left holding a certificate
// the panel no longer knew, and the renewal that could have fixed that refuses
// an unknown certificate. The site stayed down until somebody enrolled it by
// hand.
func TestARelayIsStillRecognisedByTheCertificateItsRenewalReplaced(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	store := relays.NewStore(pool)

	id := uuid.NewString()
	first := []byte("fingerprint-first-" + id)
	second := []byte("fingerprint-second-" + id)
	if _, err := pool.Exec(ctx, `
		insert into relays (id, name, site, environment, enrolled_at)
		values ($1::uuid, $2, 'lab', 'test', now())`,
		id, "relay-overlap-"+id[:8]); err != nil {
		t.Fatalf("staging the relay: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `delete from relays where id = $1::uuid`, id)
	})

	save := func(fingerprint []byte) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("the transaction: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := store.SaveCertificate(ctx, tx, id, "serial-"+string(fingerprint),
			fingerprint, time.Now().Add(30*24*time.Hour),
			relays.Issuer{Subject: "CN=Flotestro Fleet CA", Serial: "01"}); err != nil {
			t.Fatalf("saving the certificate: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("committing: %v", err)
		}
	}

	save(first)
	save(second)

	// The renewal went out and its answer was lost: the relay still holds the
	// first certificate and has to be let back in with it.
	stale, err := store.LookupCertificate(ctx, first)
	if err != nil {
		t.Fatalf("the lookup of the replaced certificate: %v", err)
	}
	if !stale.Known || stale.ID != id {
		t.Fatalf("the certificate the renewal replaced is not recognised: %+v", stale)
	}
	if stale.Current {
		t.Error("the replaced certificate is reported as the current one")
	}

	current, err := store.LookupCertificate(ctx, second)
	if err != nil {
		t.Fatalf("the lookup of the new certificate: %v", err)
	}
	if !current.Known || !current.Current {
		t.Fatalf("the new certificate is not the current one: %+v", current)
	}

	// The overlap ends when the relay arrives with the new certificate.
	if err := store.ForgetPreviousCertificate(ctx, id); err != nil {
		t.Fatalf("forgetting the previous certificate: %v", err)
	}
	if gone, err := store.LookupCertificate(ctx, first); err != nil || gone.Known {
		t.Errorf("the spent certificate is still recognised: %+v (%v)", gone, err)
	}

	// Retiring an authority counts the relays resting on it, not only hosts.
	issuers, err := store.CertificateIssuers(ctx)
	if err != nil {
		t.Fatalf("counting the issuers: %v", err)
	}
	if issuers["CN=Flotestro Fleet CA"] == 0 {
		t.Errorf("the relay does not count towards its authority: %v", issuers)
	}
}
