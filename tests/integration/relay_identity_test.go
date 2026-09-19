//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/net/http2"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/pki"
)

// The relay chapter of the security document: a relay is a buffer and a gate
// of its site, not a substitute for the identity of the host.

// defaultRelay points at the relay of the test fleet, on the Ubuntu host.
const defaultRelay = "https://192.168.56.60:8453"

// relayHeaders is what a relay says about the host it forwards.
type relayHeaders struct {
	HostID      string
	Fingerprint string
	Serial      string
}

// knockAs opens the agent stream at the given gateway with the given identity
// and headers, sends Hello and waits for the session configuration, then hangs
// up.
func knockAs(ctx context.Context, gateway string, identity tls.Certificate, headers *relayHeaders) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := agentv1connect.NewAgentServiceClient(&http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{identity},
				RootCAs:      testTrustPool(),
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, gateway, connect.WithGRPC())

	stream := client.Connect(ctx)
	if headers != nil {
		stream.RequestHeader().Set("Flotestro-Relay-Host", headers.HostID)
		if headers.Fingerprint != "" {
			stream.RequestHeader().Set("Flotestro-Relay-Host-Fingerprint", headers.Fingerprint)
		}
		if headers.Serial != "" {
			stream.RequestHeader().Set("Flotestro-Relay-Host-Serial", headers.Serial)
		}
	}
	defer func() {
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
	}()
	_ = stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
			AgentVersion: "test", BootId: uuid.NewString(),
		}},
	})
	first, err := stream.Receive()
	if err != nil {
		return err
	}
	if first.GetSessionConfig() == nil {
		return errors.New("the server answered Hello with something other than the session configuration")
	}
	return nil
}

// attestationOf is what a relay would say about the certificate.
func attestationOf(hostID string, leaf *x509.Certificate) *relayHeaders {
	return &relayHeaders{
		HostID: hostID, Fingerprint: hex.EncodeToString(pki.Fingerprint(leaf)),
		Serial: leaf.SerialNumber.String(),
	}
}

// relayIdentityOf reads how the host's newest session was identified.
func (h *harness) relayIdentityOf(hostID string) string {
	h.t.Helper()
	var view struct {
		RelayIdentity string `json:"relay_identity"`
	}
	h.get("/api/v1/hosts/"+hostID, &view)
	return view.RelayIdentity
}

// TestARelayedSessionIsCheckedAgainstTheCertificateRecord plays the relay with
// an identity enrolled for the test: the gateway lets a host through on a live
// certificate the relay names, refuses another host's certificate under the
func TestARelayedSessionIsCheckedAgainstTheCertificateRecord(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)
	relay := h.enrollRelay(t, []string{"identity-relay.flotestro.test"})
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	other, _ := h.enrollSyntheticHostWithIdentity(t)
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// A live certificate named by the relay: the session opens, and the
	// host says it was attested.
	if err := knockAs(ctx, gateway, relay.Cert, attestationOf(host.ID, leaf)); err != nil {
		t.Fatalf("the relayed session of a live host was refused: %v", err)
	}
	if strength := h.relayIdentityOf(host.ID); strength != "attested" {
		t.Fatalf("the host says its session was %q, expected attested", strength)
	}

	// The relay names the host alone: the packaged mode lets it in, and
	// the host carries the weakness where the operator looks.
	if err := knockAs(ctx, gateway, relay.Cert, &relayHeaders{HostID: host.ID}); err != nil {
		t.Fatalf("a relayed session without the certificate was refused under the packaged mode: %v", err)
	}
	if strength := h.relayIdentityOf(host.ID); strength != "weak" {
		t.Fatalf("the host says its session was %q, expected weak", strength)
	}

	// Another host's certificate under this host's name is an identity mismatch;
	// a serial that is not the fingerprint's is an attestation the gateway cannot
	// read.
	if err := knockAs(ctx, gateway, relay.Cert, attestationOf(other.ID, leaf)); err == nil {
		t.Fatal("the certificate of one host opened a session under the name of another")
	}
	if view := h.hostRefusal(other.ID); view == nil || view.Code != "identity_mismatch" {
		t.Fatalf("the refusal on the host = %+v, expected identity_mismatch", view)
	}
	wrongSerial := attestationOf(host.ID, leaf)
	wrongSerial.Serial = "1"
	if err := knockAs(ctx, gateway, relay.Cert, wrongSerial); err == nil {
		t.Fatal("a serial that does not belong to the fingerprint opened a session")
	}
	if view := h.hostRefusal(host.ID); view == nil || view.Code != "relay_identity_invalid" {
		t.Fatalf("the refusal on the host = %+v, expected relay_identity_invalid", view)
	}

	// The certificate is revoked through the panel - a recovery ordered for a
	// suspected copy cuts the old key off at once - and the relay can no longer
	// carry the host: the refusal is the one a direct connection gets, and stands
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery", map[string]any{
		"reason": "key replaced after a suspected copy", "revoke_old_immediately": true, "ttl_seconds": 300,
	}, nil, http.StatusCreated)
	if err := knockAs(ctx, gateway, relay.Cert, attestationOf(host.ID, leaf)); err == nil {
		t.Fatal("a revoked host opened a session through a live relay")
	}
	if view := h.hostRefusal(host.ID); view == nil || view.Code != "revoked_certificate" {
		t.Fatalf("the refusal on the host = %+v, expected revoked_certificate", view)
	}
	if err := knockAs(ctx, gateway, identity, nil); err == nil {
		t.Fatal("a revoked host opened a direct session")
	}
	if view := h.hostRefusal(host.ID); view == nil || view.Code != "revoked_certificate" {
		t.Fatalf("the refusal of the direct connection = %+v, expected revoked_certificate", view)
	}
}

// TestARevokedHostDoesNotConnectThroughTheLabRelay walks the whole path: a
// host of the lab connects through the relay on the Ubuntu machine, is revoked
// through the panel, and the relay - which knows nothing of the revocation and
func TestARevokedHostDoesNotConnectThroughTheLabRelay(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	relay := envOr("FLOTESTRO_TEST_RELAY", defaultRelay)
	address := strings.TrimPrefix(relay, "https://")
	if conn, err := net.DialTimeout("tcp", address, 3*time.Second); err != nil {
		t.Skipf("the lab relay at %s does not answer: %v", address, err)
	} else {
		_ = conn.Close()
	}
	host, identity := h.enrollSyntheticHostWithIdentity(t)

	if err := knockAs(ctx, relay, identity, nil); err != nil {
		t.Fatalf("the host did not open a session through the relay: %v", err)
	}
	strength := h.relayIdentityOf(host.ID)
	if strength != "attested" {
		t.Fatalf("the relay at %s named the host without its certificate (identity %q); it predates the attestation and needs the upgrade",
			address, strength)
	}

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery", map[string]any{
		"reason": "key replaced after a suspected copy", "revoke_old_immediately": true, "ttl_seconds": 300,
	}, nil, http.StatusCreated)
	if err := knockAs(ctx, relay, identity, nil); err == nil {
		t.Fatal("a revoked host opened a session through the lab relay")
	}
	if view := h.hostRefusal(host.ID); view == nil || view.Code != "revoked_certificate" {
		t.Fatalf("the refusal on the host = %+v, expected revoked_certificate", view)
	}
}
