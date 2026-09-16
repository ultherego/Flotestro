//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// The fault of chapter 23, "expired agent certificate": the gateway turns
// the host away and the panel has to say so, not show a host that looks
// switched off.
//
// The expired certificate itself is out of the test's reach: the key of the
// fleet CA lies on the panel machine and nothing here can sign with it, so
// the classification of an expired and a not-yet-valid certificate is
// covered by the unit test of the gateway with certificates minted there.
// What the fleet can show is the rest of the path, with a refusal the API
// can cause: the host is refused at the session layer, the refusal stands
// on the host with a code and a time, the list filters by it, and the next
// session that opens clears it.
func TestRefusedConnectionIsNamedOnTheHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host, identity := h.enrollSyntheticHostWithIdentity(t)

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{"reason": hardeningReason}, nil, http.StatusOK)
	t.Cleanup(func() {
		var state struct {
			LifecycleState string `json:"lifecycle_state"`
		}
		h.get("/api/v1/hosts/"+host.ID, &state)
		if state.LifecycleState == "quarantined" {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
				map[string]any{"reason": hardeningReason}, nil, http.StatusOK)
		}
	})

	// The certificate is live and the fleet's, so the handshake passes and
	// the session layer is the one that says no.
	if err := knock(ctx, identity); err == nil {
		t.Fatal("a quarantined host opened a session")
	}
	view := h.hostRefusal(host.ID)
	if view == nil || view.Code != "lifecycle_quarantined" {
		t.Fatalf("the refusal on the host = %+v, expected lifecycle_quarantined", view)
	}
	if time.Since(view.At) > 2*time.Minute {
		t.Errorf("the refusal is dated %s, expected a moment ago", view.At)
	}

	// The dashboard counter leads to a list, and the list answers the same
	// question the counter did.
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	h.get("/api/v1/hosts?connection_refusal=lifecycle_quarantined", &page)
	listed := false
	for _, item := range page.Items {
		listed = listed || item.ID == host.ID
	}
	if !listed {
		t.Errorf("the refused host is not on the list filtered by its refusal")
	}

	// Released, the host connects, and the reason it could not is gone
	// with the session that opened: an old refusal must not send the
	// operator after a fault the host no longer has.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
		map[string]any{"reason": hardeningReason}, nil, http.StatusOK)
	if err := knock(ctx, identity); err != nil {
		t.Fatalf("the released host did not open a session: %v", err)
	}
	if view := h.hostRefusal(host.ID); view != nil {
		t.Fatalf("the refusal outlived the session that opened: %+v", view)
	}
}

// hostRefusal reads the refusal the host page shows; nil when there is none.
func (h *harness) hostRefusal(hostID string) *struct {
	Code   string    `json:"code"`
	At     time.Time `json:"at"`
	Detail string    `json:"detail"`
} {
	h.t.Helper()
	var view struct {
		LastConnectionRefusal *struct {
			Code   string    `json:"code"`
			At     time.Time `json:"at"`
			Detail string    `json:"detail"`
		} `json:"last_connection_refusal"`
	}
	h.get("/api/v1/hosts/"+hostID, &view)
	return view.LastConnectionRefusal
}

// knock opens the agent stream at the test gateway with the identity,
// sends Hello and waits for the session configuration, then hangs up. Nil
// means a session opened; the error is the gateway's refusal otherwise.
func knock(ctx context.Context, identity tls.Certificate) error {
	return knockAs(ctx, envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway), identity, nil)
}

// enrollSyntheticHostWithIdentity brings a machine that does not exist into
// the fleet and keeps the key: the refusal tests need a client that can
// present the certificate, which the plain helper throws away.
func (h *harness) enrollSyntheticHostWithIdentity(t *testing.T) (hostView, tls.Certificate) {
	t.Helper()
	var order struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "synthetic test host", "site": "lab", "environment": "test",
	}, &order, http.StatusCreated)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine := uniqueSubject("test-machine")
	status, raw := h.enrollAttempt(t, order.Token, machine, relayCSR(t, key, machine, nil))
	if status != http.StatusOK {
		t.Fatalf("enrollment rejected: %d %s", status, raw)
	}
	var result struct {
		HostID         string `json:"hostId"`
		CertificatePem []byte `json:"certificatePem"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	// The synthetic machine disappears together with the test, straight in
	// the database, as the plain helper does it: the product has no such
	// operation and should not.
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := h.database(ctx).Exec(ctx,
			`delete from hosts where id = $1::uuid`, result.HostID); err != nil {
			t.Logf("the synthetic host %s was not cleaned up: %v", result.HostID, err)
		}
	})
	identity, leaf := tlsPair(t, key, result.CertificatePem)
	if leaf.NotAfter.Before(time.Now()) {
		t.Fatalf("the panel issued a certificate that is already expired: %s", leaf.NotAfter)
	}
	for _, host := range h.hosts() {
		if host.ID == result.HostID {
			return host, identity
		}
	}
	t.Fatalf("host %s did not appear on the fleet list", result.HostID)
	return hostView{}, tls.Certificate{}
}
