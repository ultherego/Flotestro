package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/relayproof"
)

const (
	testRelayID = "2f7d1a44-0f0e-4b2c-9c6f-3b1a2d5e7f80"
	testSerial  = "123456789"
)

// fakeRecords is the certificate and host record of one host, and the
// sequences it accepted, without a database.
type fakeRecords struct {
	certificate hosts.CertificateStatus
	host        *hosts.Host
	sequences   map[string]uint64
}

func (f *fakeRecords) LookupCertificateBySerial(_ context.Context, serial string) (hosts.CertificateStatus, error) {
	if serial != f.certificate.Serial {
		return hosts.CertificateStatus{}, nil
	}
	return f.certificate, nil
}

func (f *fakeRecords) Get(_ context.Context, hostID string) (*hosts.Host, error) {
	if f.host == nil || f.host.ID != hostID {
		return nil, hosts.ErrNotFound
	}
	return f.host, nil
}

func (f *fakeRecords) Accept(_ context.Context, hostID, sessionID string, sequence uint64) (bool, error) {
	key := hostID + "/" + sessionID
	if f.sequences[key] >= sequence {
		return false, nil
	}
	f.sequences[key] = sequence
	return true, nil
}

// testHost is a host with a live certificate on record, its key, and the
// verifier over it.
type testHost struct {
	key      *ecdsa.PrivateKey
	records  *fakeRecords
	verifier *RelayVerifier
	peer     RelayPeer
	leaf     *x509.Certificate
}

func newTestHost(t *testing.T, keyOnRecord bool) *testHost {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := new(big.Int).SetString(testSerial, 10)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-host"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		URIs:         []*url.URL{{Scheme: "flotestro", Host: "host", Path: "/" + testHostID}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(der)
	records := &fakeRecords{
		certificate: hosts.CertificateStatus{
			Known: true, HostID: testHostID, LifecycleState: hosts.StateActive, Serial: testSerial,
			NotBefore: template.NotBefore, NotAfter: template.NotAfter, Fingerprint: fingerprint[:],
		},
		host:      &hosts.Host{ID: testHostID, Site: "lab", Environment: "test", LifecycleState: hosts.StateActive},
		sequences: map[string]uint64{},
	}
	if keyOnRecord {
		records.certificate.PublicKeyDER = leaf.RawSubjectPublicKeyInfo
	}
	verifier := NewRelayVerifier(records, records, records)
	return &testHost{
		key: key, records: records, verifier: verifier, leaf: leaf,
		peer: RelayPeer{RelayID: testRelayID, Site: "lab", Environment: "test", HostID: testHostID},
	}
}

func (h *testHost) signer(sessionID string) *relayproof.Signer {
	return relayproof.NewSigner(h.key, testHostID, testSerial, testRelayID, sessionID)
}

func signedHello(t *testing.T, signer *relayproof.Signer) *agentv1.AgentMessage {
	t.Helper()
	message := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		AgentVersion: "0.54.0", BootId: uuid.NewString(),
	}}}
	if err := signer.SignMessage(message); err != nil {
		t.Fatal(err)
	}
	return message
}

func refusalCode(err error) string {
	if refusal := RelayRefusalOf(err); refusal != nil {
		return refusal.Code
	}
	if err == nil {
		return ""
	}
	return "error: " + err.Error()
}

// A session whose messages the host signed verifies message by message,
// the sequence counting up; the same message a second time is a replay,
// and a number below the last one is a replay too.
func TestASignedSessionVerifiesAndRefusesReplays(t *testing.T) {
	host := newTestHost(t, true)
	signer := host.signer(uuid.NewString())
	ctx := context.Background()

	hello := signedHello(t, signer)
	verified, err := host.verifier.VerifyMessage(ctx, host.peer, hello)
	if err != nil {
		t.Fatalf("the signed Hello was refused: %v", err)
	}
	if verified.Serial != testSerial || verified.LearnedKeyDER != nil {
		t.Fatalf("the verification reads %+v", verified)
	}
	heartbeat := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}
	if err := signer.SignMessage(heartbeat); err != nil {
		t.Fatal(err)
	}
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, heartbeat); err != nil {
		t.Fatalf("the signed heartbeat was refused: %v", err)
	}
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, heartbeat); refusalCode(err) != hosts.RefusalRelaySequenceReplayed {
		t.Fatalf("the heartbeat carried twice answered %q", refusalCode(err))
	}
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, hello); refusalCode(err) != hosts.RefusalRelaySequenceReplayed {
		t.Fatalf("the Hello carried after the heartbeat answered %q", refusalCode(err))
	}
	// Another session of the same host starts its own count.
	other := signedHello(t, host.signer(uuid.NewString()))
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, other); err != nil {
		t.Fatalf("the Hello of another session was refused: %v", err)
	}
}

// A payload changed after the signature is a hash mismatch; an envelope
// signed with another key is a bad signature; the two are told apart, and
// the message is refused before the sequence is spent.
func TestATamperedMessageIsRefusedWithItsCode(t *testing.T) {
	host := newTestHost(t, true)
	ctx := context.Background()

	tampered := signedHello(t, host.signer(uuid.NewString()))
	tampered.GetHello().AgentVersion = "0.54.1"
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, tampered); refusalCode(err) != hosts.RefusalRelayBodyHashMismatch {
		t.Fatalf("a changed payload answered %q", refusalCode(err))
	}

	impostor, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged := signedHello(t, relayproof.NewSigner(impostor, testHostID, testSerial, testRelayID, uuid.NewString()))
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, forged); refusalCode(err) != hosts.RefusalRelayHostSignatureInvalid {
		t.Fatalf("a message signed with another key answered %q", refusalCode(err))
	}
	if len(host.records.sequences) != 0 {
		t.Fatalf("a refused message spent a sequence: %v", host.records.sequences)
	}
}

// The envelope has to name the relay that forwarded it and the host the
// relay named, in the relay's scope, under a certificate that is live and
// the host's; a message without an envelope is invalid rather than
// unsigned.
func TestTheEnvelopeIsBoundToTheRelayTheHostAndTheCertificate(t *testing.T) {
	host := newTestHost(t, true)
	ctx := context.Background()

	otherRelay := host.peer
	otherRelay.RelayID = uuid.NewString()
	if _, err := host.verifier.VerifyMessage(ctx, otherRelay, signedHello(t, host.signer(uuid.NewString()))); refusalCode(err) != hosts.RefusalRelayEnvelopeInvalid {
		t.Fatalf("an envelope for another relay answered %q", refusalCode(err))
	}
	revoked := host.peer
	revoked.Revoked = true
	if _, err := host.verifier.VerifyMessage(ctx, revoked, signedHello(t, host.signer(uuid.NewString()))); refusalCode(err) != hosts.RefusalRelayEnvelopeInvalid {
		t.Fatalf("a revoked relay answered %q", refusalCode(err))
	}
	otherHost := host.peer
	otherHost.HostID = uuid.NewString()
	if _, err := host.verifier.VerifyMessage(ctx, otherHost, signedHello(t, host.signer(uuid.NewString()))); refusalCode(err) != hosts.RefusalRelayEnvelopeInvalid {
		t.Fatalf("an envelope naming another host answered %q", refusalCode(err))
	}
	otherSite := host.peer
	otherSite.Site = "elsewhere"
	if _, err := host.verifier.VerifyMessage(ctx, otherSite, signedHello(t, host.signer(uuid.NewString()))); refusalCode(err) != hosts.RefusalRelayScopeMismatch {
		t.Fatalf("a relay of another site answered %q", refusalCode(err))
	}
	otherEnvironment := host.peer
	otherEnvironment.Environment = "prod"
	if _, err := host.verifier.VerifyMessage(ctx, otherEnvironment, signedHello(t, host.signer(uuid.NewString()))); refusalCode(err) != hosts.RefusalRelayScopeMismatch {
		t.Fatalf("a relay of another environment answered %q", refusalCode(err))
	}
	unsigned := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{}}}
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, unsigned); refusalCode(err) != hosts.RefusalRelayEnvelopeInvalid {
		t.Fatalf("a message without an envelope answered %q", refusalCode(err))
	}
	unknownSerial := signedHello(t, relayproof.NewSigner(host.key, testHostID, "99", testRelayID, uuid.NewString()))
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, unknownSerial); refusalCode(err) != hosts.RefusalUnknownCertificate {
		t.Fatalf("an envelope naming an unknown certificate answered %q", refusalCode(err))
	}
	host.records.certificate.Revoked = true
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, signedHello(t, host.signer(uuid.NewString()))); refusalCode(err) != hosts.RefusalRevokedCertificate {
		t.Fatalf("a revoked certificate answered %q", refusalCode(err))
	}
	host.records.certificate.Revoked = false
	host.records.certificate.HostID = uuid.NewString()
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, signedHello(t, host.signer(uuid.NewString()))); refusalCode(err) != hosts.RefusalIdentityMismatch {
		t.Fatalf("another host's certificate answered %q", refusalCode(err))
	}
}

// A certificate issued before the record carried keys has none on record;
// the key comes from the certificate the relay presented, once its
// fingerprint is the one on record, and is handed back to be recorded. A
// certificate of another fingerprint supplies nothing, and without any
// key the envelope cannot be checked.
func TestTheKeyOfAnOlderCertificateComesFromTheRelay(t *testing.T) {
	host := newTestHost(t, false)
	ctx := context.Background()

	withCertificate := host.peer
	withCertificate.HostCertificate = host.leaf
	verified, err := host.verifier.VerifyMessage(ctx, withCertificate, signedHello(t, host.signer(uuid.NewString())))
	if err != nil {
		t.Fatalf("the envelope under a relay-presented certificate was refused: %v", err)
	}
	if string(verified.LearnedKeyDER) != string(host.leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("the learned key is not the certificate's")
	}
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, signedHello(t, host.signer(uuid.NewString()))); refusalCode(err) != hosts.RefusalRelayEnvelopeInvalid {
		t.Fatalf("an envelope without any key to check answered %q", refusalCode(err))
	}
	other := newTestHost(t, false)
	foreign := host.peer
	foreign.HostCertificate = other.leaf
	if _, err := host.verifier.VerifyMessage(ctx, foreign, signedHello(t, host.signer(uuid.NewString()))); refusalCode(err) != hosts.RefusalRelayEnvelopeInvalid {
		t.Fatalf("a certificate of another fingerprint supplied a key: %q", refusalCode(err))
	}
}

// A unary request is checked over its body with the identity cleared,
// within a short window, and spends no sequence.
func TestAUnaryRequestIsCheckedWithinItsWindow(t *testing.T) {
	host := newTestHost(t, true)
	ctx := context.Background()
	request := &agentv1.FetchSecretRequest{TaskId: "task-1", SecretName: "db.password"}
	envelope, err := host.signer(uuid.NewString()).SignRequest(relayproof.KindFetchSecret, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.verifier.VerifyRequest(ctx, host.peer, envelope, relayproof.KindFetchSecret, request); err != nil {
		t.Fatalf("the request was refused: %v", err)
	}
	if _, err := host.verifier.VerifyRequest(ctx, host.peer, envelope, relayproof.KindFetchSecret, request); err != nil {
		t.Fatalf("a unary envelope spent a sequence: %v", err)
	}
	if _, err := host.verifier.VerifyRequest(ctx, host.peer, envelope, relayproof.KindRenewCertificate, request); refusalCode(err) != hosts.RefusalRelayEnvelopeInvalid {
		t.Fatalf("an envelope of another kind answered %q", refusalCode(err))
	}
	host.verifier.now = func() time.Time { return time.Now().Add(relayproof.UnaryWindow + time.Minute) }
	if _, err := host.verifier.VerifyRequest(ctx, host.peer, envelope, relayproof.KindFetchSecret, request); refusalCode(err) != hosts.RefusalRelayEnvelopeInvalid {
		t.Fatalf("an envelope outside the window answered %q", refusalCode(err))
	}
}

// The certificate a relay presents in its attestation has to be the one
// of the fingerprint it names; one that is not is an attestation the
// gateway cannot read.
func TestTheRelayPresentedCertificateHasToMatchItsFingerprint(t *testing.T) {
	host := newTestHost(t, true)
	headers := http.Header{}
	headers.Set(relayHostFingerprintHeader, hex.EncodeToString(host.records.certificate.Fingerprint))
	headers.Set(relayHostSerialHeader, testSerial)
	headers.Set(relayHostCertificateHeader, base64.StdEncoding.EncodeToString(host.leaf.Raw))
	attestation, err := readRelayAttestation(headers)
	if err != nil || attestation == nil || attestation.Certificate == nil {
		t.Fatalf("a whole attestation with the certificate was not read: %v %v", attestation, err)
	}
	other := newTestHost(t, true)
	headers.Set(relayHostCertificateHeader, base64.StdEncoding.EncodeToString(other.leaf.Raw))
	if _, err := readRelayAttestation(headers); err == nil {
		t.Fatal("a certificate of another fingerprint was accepted")
	}
	headers.Set(relayHostCertificateHeader, "not base64!")
	if _, err := readRelayAttestation(headers); err == nil {
		t.Fatal("a certificate that is not base64 was accepted")
	}
	alone := http.Header{}
	alone.Set(relayHostCertificateHeader, base64.StdEncoding.EncodeToString(host.leaf.Raw))
	if _, err := readRelayAttestation(alone); err == nil {
		t.Fatal("a certificate without a fingerprint was accepted")
	}
}

// The strength a session records follows from how the host was
// identified: the host's own signature is end_to_end, the relay's word
// or attestation is relay_only, a direct connection records nothing.
func TestTheAuthStrengthFollowsTheRelayIdentity(t *testing.T) {
	for identity, want := range map[string]string{
		hosts.RelayIdentityEndToEnd: "end_to_end",
		hosts.RelayIdentityAttested: "relay_only",
		hosts.RelayIdentityWeak:     "relay_only",
		"":                          "",
	} {
		if got := hosts.AuthStrength(identity); got != want {
			t.Errorf("%q: %q, expected %q", identity, got, want)
		}
	}
}
