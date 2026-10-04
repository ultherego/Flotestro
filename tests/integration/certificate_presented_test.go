//go:build integration

package integration

import (
	"context"
	"testing"
	"time"
)

// The guard of a CA handover asks whether the hosts have the new authority,
// because handing signing over to one a host does not trust cuts that host off.
// It used to answer from the moment the panel issued a certificate - which says
// the panel did its part, not that the answer carrying the certificate and the
// trust bundle arrived. The evidence is a session opened with that certificate,
// and this test asks whether the panel is collecting it (audit of 6c38561,
// CR-04).
func TestTheCertificateAHostConnectsWithIsRecordedAsPresented(t *testing.T) {
	h := newHarness(t)
	h.requireHealthy()
	ctx := context.Background()
	pool := h.database(ctx)

	var hosts []hostView
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		absent(t, "no host of the fleet is connected")
	}

	for _, host := range hosts {
		// A host that is connected opened its session with one of its
		// certificates, so one of them has to carry the moment.
		deadline := time.Now().Add(90 * time.Second)
		for {
			var presented int
			if err := pool.QueryRow(ctx, `
				select count(*) from agent_certificates
				 where host_id = $1::uuid and revoked_at is null and presented_at is not null`,
				host.ID).Scan(&presented); err != nil {
				t.Fatal(err)
			}
			if presented > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s is connected and no certificate of its own is recorded as presented",
					host.Hostname)
			}
			time.Sleep(3 * time.Second)
		}
		// The moment is never before the certificate existed. It can be well
		// after: a certificate issued at enrollment and first recorded as
		// presented by this release carries today's moment against an old
		// created_at, which is exactly what an upgrade looks like - asking for
		// the two to be close was asking the fleet to have been reissued.
		var impossible int
		if err := pool.QueryRow(ctx, `
			select count(*) from agent_certificates
			 where host_id = $1::uuid and presented_at < created_at`,
			host.ID).Scan(&impossible); err != nil {
			t.Fatal(err)
		}
		if impossible > 0 {
			t.Errorf("%s has %d certificates recorded as presented before they were issued",
				host.Hostname, impossible)
		}
	}
}
