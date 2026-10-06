//go:build integration

package integration

import (
	"context"
	"testing"
)

// The guard of a CA handover has to know that a host holds the authority that
// is about to take over. A presentation says only that the answer carrying a
// certificate arrived: a certificate issued from the bundle {A} before B was
// prepared, and first presented after the preparation, was counted as evidence
// of B and the activation then cut that host off. The evidence is the bundle
// that went out with the certificate, which the panel now writes down
// (audit of 6c38561, CR-04).
func TestTheRecordedTrustGenerationIsWhatTheHostWasHanded(t *testing.T) {
	h := newHarness(t)
	h.requireHealthy()
	ctx := context.Background()
	pool := h.database(ctx)

	// A recorded generation always carries the authority that signed the
	// certificate: the bundle a host is handed contains the issuer of its own
	// certificate, or the host could not verify anything the panel sends.
	var inconsistent int
	if err := pool.QueryRow(ctx, `
		select count(*) from agent_certificates
		 where trust_issuer_ids is not null and issuer_id is not null
		   and not (trust_issuer_ids @> array[issuer_id])`).Scan(&inconsistent); err != nil {
		t.Fatal(err)
	}
	if inconsistent > 0 {
		t.Errorf("%d certificates record a trust bundle that does not carry their own issuer", inconsistent)
	}

	// What the panel reports about a prepared authority is the count by that
	// rule and by no other. A host whose certificate was issued before the
	// preparation counts as missing however recently it connected.
	var authorities struct {
		Authorities []struct {
			State        string `json:"state"`
			IssuerID     string `json:"issuer_id"`
			HostsMissing int    `json:"hosts_missing"`
		} `json:"authorities"`
	}
	h.get("/api/v1/pki", &authorities)
	issuerID := ""
	reported := 0
	for _, authority := range authorities.Authorities {
		if authority.State == "pending" {
			issuerID, reported = authority.IssuerID, authority.HostsMissing
		}
	}
	if issuerID == "" {
		absent(t, "no CA is prepared, so there is nothing to count as missing")
	}

	var missing int
	if err := pool.QueryRow(ctx, `
		select count(*) from hosts h
		 where h.lifecycle_state <> 'retired'
		   and not exists (
		       select 1 from agent_certificates c
		        where c.host_id = h.id and c.revoked_at is null
		          and c.presented_at is not null
		          and c.trust_issuer_ids @> array[$1::uuid])`, issuerID).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if missing != reported {
		t.Errorf("the panel reports %d hosts without the prepared CA, the recorded bundles say %d",
			reported, missing)
	}
}
