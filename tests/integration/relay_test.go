//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// defaultGateway points at the agent gateway of the test fleet. A relay
// connects there just like an agent - only with a different kind of
// identity.
const defaultGateway = "https://192.168.56.10:8443"

// testRelay holds the identity of a relay enrolled for the test.
type testRelay struct {
	ID    string
	Key   *ecdsa.PrivateKey
	Cert  tls.Certificate
	Leaf  *x509.Certificate
	Names []string
}

// TestRelayRenewalKeepsTheNamesFromTheRegistry guards the property that
// makes relay renewal a separate RPC: the network names are the trust
// boundary towards the site's agents, so they come from the panel registry,
// not from the request.
//
// If the relay could pick them at renewal, a single renewal would be enough
// to appear to the agents under somebody else's name.
func TestRelayRenewalKeepsTheNamesFromTheRegistry(t *testing.T) {
	h := newHarness(t)
	relay := h.enrollRelay(t, []string{"test-relay.flotestro.test", "192.168.56.99"})

	// A relay certificate lives shorter than a host certificate: the relay
	// sees the traffic of the whole site, so the window of using a stolen
	// key is to be smaller.
	lifetime := relay.Leaf.NotAfter.Sub(relay.Leaf.NotBefore)
	if lifetime > 8*24*time.Hour {
		t.Fatalf("the relay certificate lives %s; the document speaks of about seven days", lifetime)
	}

	renewed := h.renewRelay(t, relay, []string{"impostor-relay.flotestro.test"})
	if len(renewed.DNSNames) != 1 || renewed.DNSNames[0] != "test-relay.flotestro.test" {
		t.Fatalf("DNS names after the renewal = %v; expected the ones from the registry", renewed.DNSNames)
	}
	if len(renewed.IPAddresses) != 1 || renewed.IPAddresses[0].String() != "192.168.56.99" {
		t.Fatalf("addresses after the renewal = %v", renewed.IPAddresses)
	}
	if renewed.NotAfter.Before(relay.Leaf.NotAfter) {
		t.Fatalf("the renewal did not move the expiry: %s -> %s",
			relay.Leaf.NotAfter, renewed.NotAfter)
	}
	// The kind of identity stays: a relay certificate still cannot pose as
	// a host.
	if len(renewed.URIs) != 1 || renewed.URIs[0].Host != "relay" {
		t.Fatalf("URI SAN after the renewal = %v", renewed.URIs)
	}
}

// TestRevokedRelayDoesNotRenew guards that revoking a relay is a cut-off,
// not a pause until the next renewal.
func TestRevokedRelayDoesNotRenew(t *testing.T) {
	h := newHarness(t)
	relay := h.enrollRelay(t, []string{"revoked-relay.flotestro.test"})

	ctx := context.Background()
	if _, err := h.database(ctx).Exec(ctx,
		`update relays set revoked_at = now(), revocation_reason = 'test'
		 where id = $1::uuid`, relay.ID); err != nil {
		t.Fatal(err)
	}

	_, status, body := h.renewRelayRaw(t, relay, relay.Names)
	if status == http.StatusOK {
		t.Fatal("the revoked relay renewed its certificate")
	}
	if !bytes.Contains(body, []byte("revoked")) {
		t.Fatalf("refusal without a reason: %s %s", http.StatusText(status), body)
	}
}

// enrollRelay brings a relay that does not exist into the fleet.
//
// The lab relay disappears together with the test: the registry entry would
// stay visible in the panel as a site that does not exist.
func (h *harness) enrollRelay(t *testing.T, names []string) testRelay {
	t.Helper()
	// The connection pool must exist before the cleanup is registered:
	// cleanups run in reverse order, so a pool opened later would close
	// before the relay is deleted and the entry would stay in the fleet.
	h.database(context.Background())

	var order struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "test relay", "site": "lab", "environment": "test",
		"kind": "relay", "purpose": "relay",
	}, &order, http.StatusCreated)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name := uniqueSubject("test-relay")
	csrPEM := relayCSR(t, key, name, names)

	body, err := json.Marshal(map[string]any{
		"enrollmentToken": order.Token,
		"machineId":       name,
		"hostname":        name,
		"csrPem":          csrPEM,
		"clientRequestId": uuid.NewString(),
		"build":           map[string]any{"agentVersion": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	response, status, raw := h.sendToEnrollment(t, body)
	if status != http.StatusOK {
		t.Fatalf("relay enrollment rejected: %d %s", status, raw)
	}
	var result struct {
		HostID         string `json:"hostId"`
		CertificatePem []byte `json:"certificatePem"`
	}
	if err := json.Unmarshal(response, &result); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := h.database(ctx).Exec(ctx,
			`delete from relays where id = $1::uuid`, result.HostID); err != nil {
			t.Logf("relay %s was not cleaned up: %v", result.HostID, err)
		}
	})

	cert, leaf := tlsPair(t, key, result.CertificatePem)
	return testRelay{ID: result.HostID, Key: key, Cert: cert, Leaf: leaf, Names: names}
}

// renewRelay performs a renewal and returns the issued certificate.
func (h *harness) renewRelay(t *testing.T, relay testRelay, requestedNames []string) *x509.Certificate {
	t.Helper()
	cert, status, body := h.renewRelayRaw(t, relay, requestedNames)
	if status != http.StatusOK {
		t.Fatalf("relay renewal rejected: %d %s", status, body)
	}
	return cert
}

// renewRelayRaw calls the renewal RPC and returns a refusal too.
func (h *harness) renewRelayRaw(t *testing.T, relay testRelay,
	requestedNames []string) (*x509.Certificate, int, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := relayCSR(t, key, relay.ID, requestedNames)
	body, err := json.Marshal(map[string]any{
		"clientRequestId": uuid.NewString(),
		"csrPem":          csrPEM,
		"build":           map[string]any{"agentVersion": "test"},
		"advertisedNames": requestedNames,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The renewal goes over mTLS with the relay's current certificate: it
	// is the proof of identity, not the request body.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{relay.Cert},
			RootCAs:      testTrustPool(),
			MinVersion:   tls.VersionTLS13,
		}},
	}
	address := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway) +
		"/flotestro.agent.v1.RelayService/RenewCertificate"
	request, err := http.NewRequest(http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("relay renewal: %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if response.StatusCode != http.StatusOK {
		return nil, response.StatusCode, raw
	}

	var result struct {
		CertificatePem []byte `json:"certificatePem"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	_, leaf := tlsPair(t, key, result.CertificatePem)
	return leaf, response.StatusCode, raw
}

// relayCSR composes a certificate request with network names.
func relayCSR(t *testing.T, key *ecdsa.PrivateKey, name string, names []string) []byte {
	t.Helper()
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}
	for _, entry := range names {
		if address := net.ParseIP(entry); address != nil {
			request.IPAddresses = append(request.IPAddresses, address)
			continue
		}
		request.DNSNames = append(request.DNSNames, entry)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// tlsPair composes a certificate with a key and also returns the parsed
// leaf.
func tlsPair(t *testing.T, key *ecdsa.PrivateKey, certPEM []byte) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("the response carries no PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}, leaf
}

// testTrustPool takes the fleet CA bundle from where the agents take it.
func testTrustPool() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if bundle, err := os.ReadFile(envOr("FLOTESTRO_TEST_CA", "/var/lib/flotestro/ca.pem")); err == nil {
		pool.AppendCertsFromPEM(bundle)
	}
	return pool
}

// sendToEnrollment calls the public enrollment endpoint of the test fleet.
func (h *harness) sendToEnrollment(t *testing.T, body []byte) ([]byte, int, []byte) {
	t.Helper()
	return h.sendToEnrollmentAt(t, envOr("FLOTESTRO_TEST_ENROLLMENT", defaultEnrollment), body)
}

// sendToEnrollmentAt calls the enrollment at the given address.
//
// The address is a separate argument, because a host in an isolated site
// does not know the address of the centre and enrolls through a relay - and
// that is the same service exposed in a different place.
func (h *harness) sendToEnrollmentAt(t *testing.T, base string, body []byte) ([]byte, int, []byte) {
	t.Helper()
	address := base + "/flotestro.agent.v1.EnrollmentService/Enroll"
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: testTrustPool(), MinVersion: tls.VersionTLS12,
		}},
	}
	request, err := http.NewRequest(http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("enrollment: %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	return raw, response.StatusCode, raw
}

// TestEnrollmentThroughARelayInAnIsolatedSite guards the path that is the
// only path of a host which does not see the centre: the token goes to the
// relay, and the relay attests to the centre which site the request came
// from.
//
// The relay signs nothing: the certificate is issued by the fleet CA in the
// centre.
func TestEnrollmentThroughARelayInAnIsolatedSite(t *testing.T) {
	h := newHarness(t)
	relayID, address := h.labRelay(t)

	var order struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "host behind the relay", "site": "lab", "environment": "test",
		"relay_id": relayID,
	}, &order, http.StatusCreated)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine := uniqueSubject("host-behind-relay")
	submission, err := json.Marshal(map[string]any{
		"enrollmentToken": order.Token,
		"machineId":       machine,
		"hostname":        machine,
		"csrPem":          relayCSR(t, key, machine, nil),
		"clientRequestId": uuid.NewString(),
		"build":           map[string]any{"agentVersion": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// A token bound to a relay must not work outside its site. Otherwise
	// the binding would mean nothing: carrying the token out would be
	// enough.
	_, status, body := h.sendToEnrollment(t, submission)
	if status == http.StatusOK {
		t.Fatal("a token bound to a relay enrolled a host directly")
	}

	response, status, body := h.sendToEnrollmentAt(t, address, submission)
	if status != http.StatusOK {
		t.Fatalf("enrollment through the relay rejected: %d %s", status, body)
	}
	var result struct {
		HostID         string `json:"hostId"`
		CertificatePem []byte `json:"certificatePem"`
	}
	if err := json.Unmarshal(response, &result); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := h.database(ctx).Exec(ctx,
			`delete from hosts where id = $1::uuid`, result.HostID); err != nil {
			t.Logf("host %s was not cleaned up: %v", result.HostID, err)
		}
	})

	_, leaf := tlsPair(t, key, result.CertificatePem)
	// The certificate comes from the centre and is a host certificate, not
	// a relay one: the relay forwards the request but grants no identity.
	if len(leaf.URIs) != 1 || leaf.URIs[0].Host != "host" {
		t.Fatalf("URI SAN of the issued certificate = %v", leaf.URIs)
	}
	if leaf.URIs[0].Path != "/"+result.HostID {
		t.Fatalf("the certificate describes %q, the panel returned %q", leaf.URIs[0].Path, result.HostID)
	}
}

// labRelay finds the relay of the test fleet and its address.
func (h *harness) labRelay(t *testing.T) (string, string) {
	t.Helper()
	ctx := context.Background()
	var relayID string
	var names []string
	err := h.database(ctx).QueryRow(ctx, `
		select id::text, advertised_names from relays
		where revoked_at is null order by enrolled_at desc limit 1`).Scan(&relayID, &names)
	if err != nil || len(names) == 0 {
		t.Skipf("the test fleet has no relay: %v", err)
	}
	return relayID, "https://" + names[0] + ":8453"
}
