package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/identitystore"
	"github.com/ultherego/flotestro/internal/pki"
)

const enrollTestHost = "3f2a9c1e-0000-4000-8000-000000000001"

var enrollTestClock = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

// fakeIssuer behaves like the enrollment service of the panel: it keeps
// every attempt under its number and the digest of its request, answers a
// repeated attempt with the certificate it has already issued, and refuses a
// known number with another request. On top of that it loses answers on
// demand - after the certificate came into being, the way a network does.
type fakeIssuer struct {
	ca       *pki.CA
	requests []*agentv1.EnrollRequest
	issued   map[string][]byte
	digests  map[string][32]byte
	// lose says how many answers are still to be lost.
	lose int
	// refuse, when set, is the answer to every attempt.
	refuse error
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	ca, err := pki.EnsureCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &fakeIssuer{ca: ca, issued: map[string][]byte{}, digests: map[string][32]byte{}}
}

func (f *fakeIssuer) Enroll(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	f.requests = append(f.requests, request)
	if f.refuse != nil {
		return nil, f.refuse
	}
	digest := sha256.Sum256(request.GetCsrPem())
	if certPEM, ok := f.issued[request.GetClientRequestId()]; ok {
		if f.digests[request.GetClientRequestId()] != digest {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("the enrollment token is invalid"))
		}
		return &agentv1.EnrollResponse{HostId: enrollTestHost, CertificatePem: certPEM, CaBundlePem: f.ca.PEM}, nil
	}
	issued, err := f.ca.SignAgentCSR(request.GetCsrPem(), enrollTestHost)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	f.issued[request.GetClientRequestId()] = issued.PEM
	f.digests[request.GetClientRequestId()] = digest
	if f.lose > 0 {
		f.lose--
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the answer was lost"))
	}
	return &agentv1.EnrollResponse{HostId: enrollTestHost, CertificatePem: issued.PEM, CaBundlePem: f.ca.PEM}, nil
}

// testEnrollment wires an enrollment to a temporary directory, a clock the
// test moves and the fake issuer.
func testEnrollment(t *testing.T, issuer *fakeIssuer) (*Enrollment, *time.Time) {
	t.Helper()
	now := enrollTestClock
	enrollment := &Enrollment{
		Store:  identitystore.New(t.TempDir()),
		Issuer: issuer,
		Request: IdentityRequest{
			Token: "flt_abcd1234efgh5678", MachineID: "33d45072f9f04beeb492b07e91f61db5", Hostname: "web-01",
		},
		BootstrapPEM: issuer.ca.PEM,
		Now:          func() time.Time { return now },
		Random:       rand.Reader,
	}
	return enrollment, &now
}

// existingGeneration writes an identity issued by the same CA, the way a
// host that is already in the fleet has one.
func existingGeneration(t *testing.T, store *identitystore.Store, ca *pki.CA) *identitystore.Identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: enrollTestHost}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.SignAgentCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), enrollTestHost)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := store.Commit(identitystore.Generation{
		KeyPEM:         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		CertificatePEM: issued.PEM,
		TrustPEM:       ca.PEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// TestARetryRepeatsTheSameAttempt is the reason the pending record exists:
// after a lost answer the host asks again under the same number and with the
// same request, and gets the certificate that was already issued - instead
// of generating a new identity and being refused as a reuse of the request.
func TestARetryRepeatsTheSameAttempt(t *testing.T) {
	issuer := newFakeIssuer(t)
	issuer.lose = 1
	enrollment, _ := testEnrollment(t, issuer)

	_, err := enrollment.Run(context.Background())
	if ErrorCode(err) != CodeConnectFailed {
		t.Fatalf("the first attempt: %v, want %s", err, CodeConnectFailed)
	}
	// The attempt is on disk, readable by its owner alone, and nothing has
	// been switched.
	info, err := os.Stat(enrollment.Store.PendingPath())
	if err != nil {
		t.Fatalf("no pending record after a lost answer: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pending permissions = %04o", info.Mode().Perm())
	}
	if _, err := enrollment.Store.Current(); err == nil {
		t.Fatal("a lost answer produced an identity")
	}

	identity, err := enrollment.Run(context.Background())
	if err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if len(issuer.requests) != 2 {
		t.Fatalf("requests = %d", len(issuer.requests))
	}
	first, second := issuer.requests[0], issuer.requests[1]
	if first.GetClientRequestId() != second.GetClientRequestId() {
		t.Fatalf("the retry went under another number: %s then %s",
			first.GetClientRequestId(), second.GetClientRequestId())
	}
	if !bytes.Equal(first.GetCsrPem(), second.GetCsrPem()) {
		t.Fatal("the retry sent another request - the panel would refuse it as a reuse")
	}
	if identity.HostID != enrollTestHost {
		t.Fatalf("host_id = %q", identity.HostID)
	}
	// The certificate is the one issued at the first attempt: nothing came
	// into being twice.
	current, err := enrollment.Store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current.Certificate.Certificate[0], derOf(t, issuer.issued[first.GetClientRequestId()])) {
		t.Fatal("the written certificate is not the one issued at the first attempt")
	}
	if _, err := os.Stat(enrollment.Store.PendingPath()); !os.IsNotExist(err) {
		t.Fatal("the pending record stayed after the commit")
	}
}

func derOf(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}

// TestARefusalKeepsTheAttempt guards the codes the operator acts on and that
// a refused attempt can still be repeated once the reason is fixed.
func TestARefusalKeepsTheAttempt(t *testing.T) {
	issuer := newFakeIssuer(t)
	issuer.refuse = connect.NewError(connect.CodePermissionDenied, errors.New("the enrollment token is invalid"))
	enrollment, _ := testEnrollment(t, issuer)

	_, err := enrollment.Run(context.Background())
	if ErrorCode(err) != CodeTokenInvalid {
		t.Fatalf("a refused token: %v, want %s", err, CodeTokenInvalid)
	}
	pending, err := enrollment.Store.LoadPending()
	if err != nil {
		t.Fatalf("the attempt was not kept: %v", err)
	}
	if pending.TokenPrefix != "flt_abcd" {
		t.Fatalf("token prefix = %q", pending.TokenPrefix)
	}
	// The record must not keep the token itself.
	content, err := os.ReadFile(enrollment.Store.PendingPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte(enrollment.Request.Token)) {
		t.Fatal("the pending record carries the token")
	}

	// With a working token the same attempt goes out again.
	issuer.refuse = nil
	if _, err := enrollment.Run(context.Background()); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if issuer.requests[0].GetClientRequestId() != issuer.requests[1].GetClientRequestId() {
		t.Fatal("the retry after a refusal went under another number")
	}
}

// TestAStaleAttemptIsAbandoned: a token lives at most a day, so an attempt
// older than that has nothing to be repeated with and only a fresh key makes
// sense.
func TestAStaleAttemptIsAbandoned(t *testing.T) {
	issuer := newFakeIssuer(t)
	issuer.lose = 1
	enrollment, now := testEnrollment(t, issuer)
	if _, err := enrollment.Run(context.Background()); err == nil {
		t.Fatal("the lost answer was not lost")
	}
	old, err := enrollment.Store.LoadPending()
	if err != nil {
		t.Fatal(err)
	}

	*now = now.Add(identitystore.PendingMaxAge + time.Hour)
	if _, err := enrollment.Run(context.Background()); err != nil {
		t.Fatalf("the enrollment a day later: %v", err)
	}
	repeated := issuer.requests[1]
	if repeated.GetClientRequestId() == old.ClientRequestID {
		t.Fatal("an attempt older than a day was repeated")
	}
	if bytes.Equal(repeated.GetCsrPem(), old.CSRPEM) {
		t.Fatal("an attempt older than a day reused its key")
	}
}

// TestAFinishedAttemptIsNotRepeated covers an interruption after the commit
// and before the removal of the record: the record then describes the key
// the host already works with, and repeating it would ask for what the host
// has.
func TestAFinishedAttemptIsNotRepeated(t *testing.T) {
	issuer := newFakeIssuer(t)
	enrollment, _ := testEnrollment(t, issuer)
	if _, err := enrollment.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The record comes back as if the removal had not happened.
	current, err := enrollment.Store.Current()
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(current.Dir, identitystore.KeyName))
	if err != nil {
		t.Fatal(err)
	}
	finished := identitystore.Pending{
		ClientRequestID: issuer.requests[0].GetClientRequestId(),
		KeyPEM:          keyPEM,
		CSRPEM:          issuer.requests[0].GetCsrPem(),
		CreatedAt:       enrollTestClock,
	}
	if err := enrollment.Store.SavePending(finished); err != nil {
		t.Fatal(err)
	}

	if _, err := enrollment.Run(context.Background()); err != nil {
		t.Fatalf("the enrollment with a finished record: %v", err)
	}
	if issuer.requests[1].GetClientRequestId() == finished.ClientRequestID {
		t.Fatal("the finished attempt was repeated")
	}
}

// TestARejectedCertificateSwitchesNothing is the invariant of a recovery:
// the current generation works until the new one has been received and
// verified, and a certificate the gateway does not accept leaves the host
// as it was.
func TestARejectedCertificateSwitchesNothing(t *testing.T) {
	issuer := newFakeIssuer(t)
	enrollment, _ := testEnrollment(t, issuer)
	before := existingGeneration(t, enrollment.Store, issuer.ca)

	verified := 0
	enrollment.Verify = func(_ context.Context, identity *Identity) error {
		verified++
		if identity.Certificate.PrivateKey == nil || identity.CAPool == nil {
			t.Fatal("the candidate has no material for a handshake")
		}
		return errors.New("bad certificate")
	}
	_, err := enrollment.Run(context.Background())
	if ErrorCode(err) != CodeIdentityRejected {
		t.Fatalf("a refused handshake: %v, want %s", err, CodeIdentityRejected)
	}
	if verified != 1 {
		t.Fatalf("verifications = %d", verified)
	}
	after, err := enrollment.Store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if after.Dir != before.Dir {
		t.Fatal("the store switched to a certificate the gateway refused")
	}
	if _, err := enrollment.Store.LoadPending(); err != nil {
		t.Fatalf("the attempt is not kept for a retry: %v", err)
	}

	// Once the gateway accepts the certificate, the switch happens and the
	// previous generation stays on disk.
	enrollment.Verify = func(context.Context, *Identity) error { return nil }
	recovered, err := enrollment.Run(context.Background())
	if err != nil {
		t.Fatalf("the recovery: %v", err)
	}
	if recovered.HostID != enrollTestHost {
		t.Fatalf("host_id = %q", recovered.HostID)
	}
	current, err := enrollment.Store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if current.Dir == before.Dir {
		t.Fatal("the recovery did not switch the generation")
	}
	previous, err := enrollment.Store.Previous()
	if err != nil {
		t.Fatalf("the previous generation is gone: %v", err)
	}
	if previous.Dir != before.Dir {
		t.Fatalf("previous = %s, want %s", previous.Dir, before.Dir)
	}
}

// TestAnAnswerForAnotherKeyIsRejected: the panel signs what it was sent,
// but a bug or somebody in the middle could answer with a certificate for
// another key. Such an answer must not reach the disk.
func TestAnAnswerForAnotherKeyIsRejected(t *testing.T) {
	issuer := newFakeIssuer(t)
	enrollment, _ := testEnrollment(t, issuer)
	foreign := existingGeneration(t, identitystore.New(t.TempDir()), issuer.ca)
	enrollment.Issuer = issuerFunc(func(context.Context, *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
		return &agentv1.EnrollResponse{
			HostId:         enrollTestHost,
			CertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.Certificate.Certificate[0]}),
			CaBundlePem:    issuer.ca.PEM,
		}, nil
	})
	_, err := enrollment.Run(context.Background())
	if ErrorCode(err) != CodeIdentityRejected {
		t.Fatalf("a certificate for another key: %v, want %s", err, CodeIdentityRejected)
	}
	if !errors.Is(err, identitystore.ErrKeyPair) {
		t.Fatalf("the cause is not the pair: %v", err)
	}
	if _, err := enrollment.Store.Current(); err == nil {
		t.Fatal("somebody else's certificate was written")
	}
}

type issuerFunc func(context.Context, *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error)

func (f issuerFunc) Enroll(ctx context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	return f(ctx, request)
}

func TestTheDaemonDoesNotEnroll(t *testing.T) {
	// A host without an identity is an error for the daemon and nothing
	// else: no token is read, nothing goes to the network.
	_, err := LoadIdentity(t.TempDir())
	if !errors.Is(err, identitystore.ErrIdentityMissing) {
		t.Fatalf("an empty directory: %v, want identity_missing", err)
	}
}

func TestTheTokenPrefixTellsNothing(t *testing.T) {
	cases := map[string]string{
		"flt_abcd1234efgh5678ijkl": "flt_abcd",
		" flt_abcd1234efgh5678\n":  "flt_abcd",
		"flt_short":                "",
		"whatever-else":            "",
		"":                         "",
	}
	for token, want := range cases {
		if got := TokenPrefix(token); got != want {
			t.Errorf("TokenPrefix(%q) = %q, want %q", token, got, want)
		}
	}
}

func TestTheStatusDescribesTheAttempt(t *testing.T) {
	stateDir := t.TempDir()
	store := identitystore.New(stateDir)
	if ReadPendingAttempt(stateDir, enrollTestClock) != nil {
		t.Fatal("an empty store has an attempt")
	}
	pending, err := store.PreparePending(rand.Reader, enrollTestClock, "machine", nil, nil, "flt_ab12")
	if err != nil {
		t.Fatal(err)
	}
	attempt := ReadPendingAttempt(stateDir, enrollTestClock.Add(90*time.Minute))
	if attempt == nil || attempt.Err != "" {
		t.Fatalf("attempt = %+v", attempt)
	}
	if attempt.ClientRequestID != pending.ClientRequestID || attempt.TokenPrefix != "flt_ab12" {
		t.Fatalf("attempt = %+v", attempt)
	}
	if attempt.Age != 90*time.Minute || attempt.Stale {
		t.Fatalf("attempt = %+v", attempt)
	}
	if !ReadPendingAttempt(stateDir, enrollTestClock.Add(2*identitystore.PendingMaxAge)).Stale {
		t.Fatal("an attempt from two days ago is not stale")
	}

	discarded, err := DiscardPendingAttempt(stateDir)
	if err != nil || !discarded {
		t.Fatalf("discarding: %v, %v", discarded, err)
	}
	if discarded, err := DiscardPendingAttempt(stateDir); err != nil || discarded {
		t.Fatalf("discarding again: %v, %v", discarded, err)
	}
}
