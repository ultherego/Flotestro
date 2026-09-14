package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/hosts"
)

// testAuthority is a CA minted for one test, with everything needed to
// sign leaves under it.
type testAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestAuthority(t *testing.T, name string, now time.Time) testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-400 * 24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testAuthority{cert: cert, key: key}
}

// leaf signs a client certificate naming the host, valid between the two
// moments.
func (a testAuthority) leaf(t *testing.T, hostID string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostID + ".example"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{{Scheme: "flotestro", Host: "host", Path: "/" + hostID}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func (a testAuthority) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	return pool
}

const testHostID = "6f1c3c2e-6d1a-4c8b-9d2e-0b1f9a7e5c11"

// TestClassifyClientCertificate: the refusal is named after what is wrong
// with the certificate, and the host is named only when the fleet signed
// the certificate - a stranger's certificate names nobody, whatever it
// claims.
func TestClassifyClientCertificate(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	fleet := newTestAuthority(t, "Flotestro Fleet CA", now)
	stranger := newTestAuthority(t, "Somebody Else", now)
	day := 24 * time.Hour

	cases := []struct {
		name   string
		leaf   *x509.Certificate
		code   string
		hostID string
	}{
		{
			name: "a live certificate of the fleet passes",
			leaf: fleet.leaf(t, testHostID, now.Add(-10*day), now.Add(20*day)),
		},
		{
			name:   "an expired certificate of the fleet names its host",
			leaf:   fleet.leaf(t, testHostID, now.Add(-40*day), now.Add(-10*day)),
			code:   hosts.RefusalCertificateExpired,
			hostID: testHostID,
		},
		{
			name:   "a certificate from the future names its host",
			leaf:   fleet.leaf(t, testHostID, now.Add(2*day), now.Add(32*day)),
			code:   hosts.RefusalCertificateNotYetValid,
			hostID: testHostID,
		},
		{
			name: "a live certificate of a stranger is unknown and names nobody",
			leaf: stranger.leaf(t, testHostID, now.Add(-10*day), now.Add(20*day)),
			code: hosts.RefusalUnknownCertificate,
		},
		{
			name: "an expired certificate of a stranger is unknown, not expired",
			leaf: stranger.leaf(t, testHostID, now.Add(-40*day), now.Add(-10*day)),
			code: hosts.RefusalUnknownCertificate,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict := ClassifyClientCertificate(tc.leaf, x509.NewCertPool(), fleet.pool(), now)
			if verdict.Code != tc.code {
				t.Fatalf("code = %q, want %q (detail: %s)", verdict.Code, tc.code, verdict.Detail)
			}
			if verdict.HostID != tc.hostID {
				t.Fatalf("host = %q, want %q", verdict.HostID, tc.hostID)
			}
			if tc.code == "" && verdict.Err != nil {
				t.Fatalf("an accepted certificate carries an error: %v", verdict.Err)
			}
			if tc.code != "" && verdict.Err == nil {
				t.Fatal("a refused certificate carries no error for the handshake")
			}
		})
	}
}

// TestRevokedCertificateIsRefusedAtTheSessionLayer: revocation is a fact of
// the database, not of the certificate, so the handshake cannot see it;
// the session layer refuses it and the code is the one the host page
// shows.
func TestRevokedCertificateIsRefusedAtTheSessionLayer(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	fleet := newTestAuthority(t, "Flotestro Fleet CA", now)
	leaf := fleet.leaf(t, testHostID, now.Add(-10*24*time.Hour), now.Add(20*24*time.Hour))

	// The certificate is the fleet's and in its window: the handshake lets
	// it through, and only the record says it was withdrawn.
	if verdict := ClassifyClientCertificate(leaf, x509.NewCertPool(), fleet.pool(), now); verdict.Code != "" {
		t.Fatalf("the handshake refused a live certificate: %s", verdict.Code)
	}
	cases := []struct {
		name   string
		status hosts.CertificateStatus
		code   string
	}{
		{
			name:   "a certificate nobody recorded",
			status: hosts.CertificateStatus{},
			code:   hosts.RefusalUnknownCertificate,
		},
		{
			name:   "a revoked certificate",
			status: hosts.CertificateStatus{Known: true, Revoked: true, HostID: testHostID, Serial: "42"},
			code:   hosts.RefusalRevokedCertificate,
		},
		{
			name:   "a certificate on record for another host",
			status: hosts.CertificateStatus{Known: true, HostID: "another-host", LifecycleState: hosts.StateActive},
			code:   hosts.RefusalIdentityMismatch,
		},
		{
			name:   "a quarantined host",
			status: hosts.CertificateStatus{Known: true, HostID: testHostID, LifecycleState: hosts.StateQuarantined},
			code:   "lifecycle_" + hosts.StateQuarantined,
		},
		{
			name:   "an active host with its own live certificate",
			status: hosts.CertificateStatus{Known: true, HostID: testHostID, LifecycleState: hosts.StateActive},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := certificateStatusRefusal(tc.status, testHostID, now)
			if code != tc.code {
				t.Fatalf("code = %q, want %q", code, tc.code)
			}
		})
	}
}

// recordingRefusals remembers what the verifier wrote.
type recordingRefusals struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingRefusals) RecordConnectionRefusal(_ context.Context, hostID, code, _ string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, hostID+":"+code)
	return true, nil
}

// TestVerifierRefusesTheHandshakeAndRecordsTheHost: the handshake hook ends
// the handshake for an expired certificate of the fleet and writes the
// refusal on the host; a stranger is refused without a host to write on;
// a retry within the quiet period costs no second row.
func TestVerifierRefusesTheHandshakeAndRecordsTheHost(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	fleet := newTestAuthority(t, "Flotestro Fleet CA", now)
	stranger := newTestAuthority(t, "Somebody Else", now)
	day := 24 * time.Hour

	store := &recordingRefusals{}
	verifier := NewClientVerifier(fleet.pool, store, nil, slog.New(slog.DiscardHandler))
	verifier.now = func() time.Time { return now }

	expired := fleet.leaf(t, testHostID, now.Add(-40*day), now.Add(-10*day))
	if err := verifier.VerifyPeerCertificate([][]byte{expired.Raw}, nil); err == nil {
		t.Fatal("the handshake was not refused")
	}
	if len(store.calls) != 1 || store.calls[0] != testHostID+":"+hosts.RefusalCertificateExpired {
		t.Fatalf("recorded refusals = %v", store.calls)
	}
	// The same dead certificate a moment later: the refusal stands, the
	// row is not rewritten.
	if err := verifier.VerifyPeerCertificate([][]byte{expired.Raw}, nil); err == nil {
		t.Fatal("the retry was not refused")
	}
	if len(store.calls) != 1 {
		t.Fatalf("a retry within the quiet period was recorded again: %v", store.calls)
	}

	foreign := stranger.leaf(t, testHostID, now.Add(-10*day), now.Add(20*day))
	if err := verifier.VerifyPeerCertificate([][]byte{foreign.Raw}, nil); err == nil {
		t.Fatal("a stranger's certificate was accepted")
	}
	if len(store.calls) != 1 {
		t.Fatalf("a stranger's certificate was written on a host: %v", store.calls)
	}

	live := fleet.leaf(t, testHostID, now.Add(-10*day), now.Add(20*day))
	if err := verifier.VerifyPeerCertificate([][]byte{live.Raw}, nil); err != nil {
		t.Fatalf("a live certificate of the fleet was refused: %v", err)
	}

	// The configuration the verifier installs: the built-in check is off
	// and the hook is in its place, never one without the other.
	config := &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}
	verifier.Apply(config)
	if config.ClientAuth != tls.RequireAnyClientCert || config.VerifyPeerCertificate == nil {
		t.Fatal("Apply left the listener without the verifier")
	}
}
