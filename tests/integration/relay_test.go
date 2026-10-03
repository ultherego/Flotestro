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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// defaultGateway points at the agent gateway of the test fleet. A relay
// connects there just like an agent - only with a different kind of identity.
const defaultGateway = "https://192.168.56.10:8443"

// testRelay holds the identity of a relay enrolled for the test.
type testRelay struct {
	ID    string
	Key   *ecdsa.PrivateKey
	Cert  tls.Certificate
	Leaf  *x509.Certificate
	Names []string
}

// TestRelayRenewalKeepsTheNamesFromTheRegistry guards the property that makes
// relay renewal a separate RPC: the names come from the registry, not the call.
func TestRelayRenewalKeepsTheNamesFromTheRegistry(t *testing.T) {
	h := newHarness(t)
	relay := h.enrollRelay(t, []string{"test-relay.flotestro.test", "192.168.56.99"})

	// A relay certificate lives shorter than a host certificate: the relay sees
	// the traffic of the whole site, so the window of using a stolen key is to be
	// smaller.
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
func (h *harness) enrollRelay(t *testing.T, names []string) testRelay {
	t.Helper()
	// The connection pool must exist before the cleanup is registered: cleanups
	// run in reverse order, so a pool opened later would close before the relay
	// is deleted and the entry would stay in the fleet.
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
		// The sessions first: a relay that carried one is referenced from
		// agent_sessions, and the delete below then fails on the foreign key -
		// quietly, because this is a cleanup and its complaint only reached the
		// test log. Eight such records were found in the laboratory on 01.10,
		// and the suite had been choosing one of them as the relay to dial.
		for _, statement := range []string{
			`delete from agent_sessions where relay_id = $1::uuid`,
			`delete from enrollment_requests where relay_id = $1::uuid`,
		} {
			if _, err := h.database(ctx).Exec(ctx, statement, result.HostID); err != nil {
				t.Logf("what relay %s left behind was not cleaned up: %v", result.HostID, err)
			}
		}
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

// TestEnrollmentThroughARelayInAnIsolatedSite guards the path that is the only
// path of a host which does not see the centre: the token goes to the relay,
// and the relay attests to the centre which site the request came from.
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

	// A token bound to a relay must not work outside its site. Otherwise the
	// binding would mean nothing: carrying the token out would be enough.
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
	// The relay this laboratory runs is the one still calling home. The tests
	// above enrol relays of their own and leave the records behind, several of
	// them with a last_seen of their own minute, so neither "newest enrolled"
	// nor "has ever reported" picks the right one: on 01.10 the suite dialled
	// revoked-relay.flotestro.test, a record from a test that no process serves
	// and whose name is in no certificate. A running relay reports every half
	// minute; one that a test made stops the moment that test ends.
	err := h.database(ctx).QueryRow(ctx, `
		select id::text, advertised_names from relays
		where revoked_at is null and last_seen_at > now() - interval '5 minutes'
		order by last_seen_at desc limit 1`).Scan(&relayID, &names)
	if err != nil || len(names) == 0 {
		absent(t, "the test fleet has no relay: %v", err)
	}
	return relayID, "https://" + names[0] + ":8453"
}

// relayListItem is a relay as the panel lists it.
type relayListItem struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Site                string `json:"site"`
	State               string `json:"state"`
	HostsAttested       int    `json:"hosts_attested"`
	CertificateNotAfter string `json:"certificate_not_after"`
	LastSeenAt          string `json:"last_seen_at"`
	Buffer              *struct {
		BufferBytes    int64 `json:"buffer_bytes"`
		BufferMaxBytes int64 `json:"buffer_max_bytes"`
		BufferedItems  int   `json:"buffered_items"`
	} `json:"buffer"`
}

// TestRelayListCarriesTheStateAndTheAttestedHosts guards what the relay page
// is made of: the list says which state each relay is in and how many hosts
// come through it, the same way the metrics count them.
func TestRelayListCarriesTheStateAndTheAttestedHosts(t *testing.T) {
	h := newHarness(t)
	relayID, _ := h.labRelay(t)

	var list struct {
		Items []relayListItem `json:"items"`
	}
	h.get("/api/v1/relays", &list)
	var lab *relayListItem
	for i := range list.Items {
		if list.Items[i].ID == relayID {
			lab = &list.Items[i]
		}
	}
	if lab == nil {
		t.Fatalf("the lab relay %s is not in the list: %+v", relayID, list.Items)
	}
	switch lab.State {
	case "active", "silent", "never_seen":
	default:
		t.Fatalf("state = %q; the list has to say one of active, silent, never_seen for a relay that is not revoked", lab.State)
	}
	if lab.CertificateNotAfter == "" {
		t.Fatalf("the relay carries no certificate expiry: %+v", lab)
	}

	// The count of the list is the count of the open sessions attested by
	// the relay, as the database has them.
	ctx := context.Background()
	var attested int
	if err := h.database(ctx).QueryRow(ctx, `
		select count(*) from agent_sessions
		where relay_id = $1::uuid and ended_at is null`, relayID).Scan(&attested); err != nil {
		t.Fatal(err)
	}
	if lab.HostsAttested != attested {
		t.Fatalf("hosts_attested = %d, the database has %d open sessions through the relay", lab.HostsAttested, attested)
	}
	// A relay that attests hosts has been seen: a session marks it, and so
	// does its heartbeat.
	if attested > 0 && lab.State == "never_seen" {
		t.Fatalf("the relay attests %d hosts and is never_seen: %+v", attested, lab)
	}
}

// TestTheFleetComesThroughTheRelay is about the laboratory rather than the
// product: a relay nothing real connects through proves nothing, and the relay
// tests that open a session of their own would pass over an empty path.
func TestTheFleetComesThroughTheRelay(t *testing.T) {
	h := newHarness(t)
	relayID, _ := h.labRelay(t)
	ctx := context.Background()
	// Within a bound, because a session cut a moment ago comes back on its own and
	// a laboratory that never arranged this path does not. Looking once reported
	// the second where the first was true: on 02.10 this was absent in a run whose
	// fixtures had arranged the path and whose host was working throughout.
	deadline := time.Now().Add(hostOnlineBound)
	for {
		if hosts := relayedFleetHosts(ctx, t, h.database(ctx), relayID); len(hosts) > 0 {
			theRelaySaysSoItself(t, h, relayID)
			return
		}
		if time.Now().After(deadline) {
			absent(t, "no host of the fleet connects through the relay %s within %s, "+
				"so the path it exists for is untested", relayID, hostOnlineBound)
			return
		}
		time.Sleep(3 * time.Second)
	}
}

// theRelaySaysSoItself puts the panel's claim beside the relay's own words, about
// a session it has just watched open.
//
// The panel answers "this host comes through that relay" from the row it wrote
// when the session opened, and when the question is whether that row is right the
// row cannot be the evidence for itself. The first version of this read the last
// two thousand lines of the relay's journal and looked for the phrase and for the
// host separately: a line left by any session of any day satisfied both, so it
// could confirm today's row with last week's event.
//
// So the session is made, not found. The agent on the host behind the relay is
// restarted through the panel, the panel is waited for to attribute the new
// session to the relay, and only the journal written since then is read. What has
// to be there is one line: the attestation, naming this host, carrying the
// certificate it presented and the relay instance that carried it. Then an
// operation is ordered on that host and has to go through, because a session that
// was attested and carries nothing is not the path this scenario is about.
func theRelaySaysSoItself(t *testing.T, h *harness, relayID string) {
	t.Helper()
	ctx := context.Background()
	behind := h.hostByName(relayHostName(t, h))

	// The relay is restarted, not the agent: the agent's own unit is protected
	// against exactly this, and rightly - the panel does not get to restart the
	// thing that carries its orders. Taking the relay down cuts the sessions
	// through it, and the host opens a new one, which is the session to read back.
	restart, restartAttempts := h.runOperation(behind.ID, map[string]any{
		"action": "unit.restart", "reason": "a session of its own to read back",
		"payload": unitPayload("flotestro-relay.service"),
	}, 3*time.Minute)
	if restart.State != "succeeded" {
		absent(t, "the relay on %s could not be restarted, so there is no session to read back: %s",
			behind.Hostname, lastMessage(restartAttempts))
		return
	}

	// The panel has to place the new session behind the relay before its words are
	// worth comparing with anything.
	deadline := time.Now().Add(hostOnlineBound)
	var attributed bool
	for !attributed && time.Now().Before(deadline) {
		for _, id := range relayedFleetHosts(ctx, t, h.database(ctx), relayID) {
			attributed = attributed || id == behind.ID
		}
		if !attributed {
			time.Sleep(3 * time.Second)
		}
	}
	if !attributed {
		t.Fatalf("after its agent was restarted, %s did not come back through the relay %s within %s",
			behind.Hostname, relayID, hostOnlineBound)
	}

	// Only what was written since the restart. A window and not the whole journal:
	// the point is that this session was attested, not that some session once was.
	read, attempts := h.runOperation(behind.ID, map[string]any{
		"action": "journal.read", "reason": "what the relay says it attested just now",
		"payload": map[string]any{"journal": map[string]any{
			"unit": "flotestro-relay.service", "lines": 500, "since": relayWindow,
		}},
	}, 3*time.Minute)
	if read.State != "succeeded" {
		absent(t, "the journal of the relay on %s could not be read: %s",
			behind.Hostname, lastMessage(attempts))
		return
	}
	var journal strings.Builder
	for _, attempt := range attempts {
		journal.WriteString(attempt.Stdout)
	}
	if line := attestationLineFor(journal.String(), behind.ID); line == "" {
		t.Fatalf("the panel places the session of %s behind the relay %s, and the relay's "+
			"journal of the last %s carries no line attesting that host with a certificate "+
			"and an instance", behind.Hostname, relayID, relayWindow)
	}

	// And the attested session carries work. Without this the scenario would be
	// satisfied by a relay that announces a session and forwards nothing.
	work, workAttempts := h.runOperation(behind.ID, map[string]any{
		"action": "unit.status", "reason": "work through the session the relay attested",
		"payload": map[string]any{"unit_status": map[string]any{
			"units": []string{"flotestro-agent.service"}}},
	}, 2*time.Minute)
	if work.State != "succeeded" {
		t.Fatalf("the session the relay attested carries no work: %s/%s: %s",
			work.State, work.ResultErrorCode, lastMessage(workAttempts))
	}
}

// relayWindow is how far back the relay's journal is read: far enough to hold the
// restart just ordered, short enough that nothing older can answer for it.
const relayWindow = "-3min"

// attestationLineFor returns the line in which the relay attested this host, or
// nothing. One line and not three readings of the journal: the host, the
// certificate it presented and the relay that carried it have to be the same
// event, or they are three facts that never met.
func attestationLineFor(journal, hostID string) string {
	for _, line := range strings.Split(journal, "\n") {
		if !strings.Contains(line, "attested to the centre") {
			continue
		}
		if !strings.Contains(line, "host_id="+hostID) {
			continue
		}
		if !strings.Contains(line, "fingerprint=") || !strings.Contains(line, "relay_instance=") {
			continue
		}
		return line
	}
	return ""
}

// TestRelayPageListsTheAttestedHosts guards that the relay page names the
// hosts behind the relay, which is where an operator sees them. The host on the
// relay is this test's own: one that only passes when another test left a
// session behind is not a test of the page.
func TestRelayPageListsTheAttestedHosts(t *testing.T) {
	h := newHarness(t)
	relayID, address := h.labRelay(t)
	if conn, err := net.DialTimeout("tcp", strings.TrimPrefix(address, "https://"), 3*time.Second); err != nil {
		absent(t, "the relay %s does not answer at %s: %v", relayID, address, err)
	} else {
		_ = conn.Close()
	}

	ctx := context.Background()
	behind, identity := h.enrollSyntheticHostWithIdentity(t)
	session, err := openRelayedAgent(ctx, address, identity)
	if err != nil {
		t.Fatalf("the host %s did not open a session through the relay: %v", behind.Hostname, err)
	}
	defer session.close()
	// The relay attests the session to the panel, and the row it writes is what
	// the page is made of.
	deadline := time.Now().Add(30 * time.Second)
	for {
		var attested bool
		if err := h.database(ctx).QueryRow(ctx, `
			select exists (select 1 from agent_sessions
			               where relay_id = $1::uuid and host_id = $2::uuid and ended_at is null)`,
			relayID, behind.ID).Scan(&attested); err != nil {
			t.Fatal(err)
		}
		if attested {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the session of %s through the relay is not attested to the relay %s",
				behind.Hostname, relayID)
		}
		time.Sleep(time.Second)
	}

	var page struct {
		Relay relayListItem `json:"relay"`
		Hosts []struct {
			HostID      string `json:"host_id"`
			Hostname    string `json:"hostname"`
			ConnectedAt string `json:"connected_at"`
		} `json:"hosts"`
	}
	h.get("/api/v1/relays/"+relayID, &page)
	if page.Relay.ID != relayID || page.Relay.State != "active" {
		t.Fatalf("relay = %+v; a relay with an open session is active", page.Relay)
	}
	found := false
	for _, host := range page.Hosts {
		if host.HostID == behind.ID {
			found = true
			if host.Hostname != behind.Hostname || host.ConnectedAt == "" {
				t.Fatalf("the host behind the relay is listed without its name or session: %+v", host)
			}
		}
	}
	if !found {
		t.Fatalf("the host %s is not on the relay page: %+v", behind.Hostname, page.Hosts)
	}
	if page.Relay.HostsAttested != len(page.Hosts) {
		t.Fatalf("hosts_attested = %d, the page lists %d hosts", page.Relay.HostsAttested, len(page.Hosts))
	}

	// A relay nobody may read is a relay nobody sees: the page answers as
	// for a relay that does not exist rather than naming the site.
	viewer := h.createPrincipal(uniqueSubject("relay-viewer"),
		[]map[string]string{{"role": "viewer", "site": "*", "environment": "*"}})
	h.withToken(viewer).do(http.MethodGet, "/api/v1/relays/"+relayID, nil, nil, http.StatusForbidden)
}
