package agent

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/ultherego/flotestro/internal/buildinfo"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/identitystore"
	"github.com/ultherego/flotestro/internal/pki"
)

// Version is the version of the agent reported to the control plane.
//
// A variable and not a constant: a release writes the package number here at
// build time (-ldflags -X). Without it the panel would see one version for the
// whole life of the fleet and would have no way of checking whether an upgrade
// really arrived.
var Version = buildinfo.Version

// Identity is the cryptographic material of the host stored locally.
type Identity struct {
	HostID      string
	Certificate tls.Certificate
	CAPool      *x509.CertPool
	NotAfter    time.Time
	// TrustPEM is the bundle that decides the trust of this identity. It is kept
	// in memory, because a renewal writes the whole generation at once - also
	// when the panel sent no new bundle.
	TrustPEM []byte
}

// fromIdentity translates a generation from the store into the identity of the
// agent.
func fromIdentity(identity *identitystore.Identity) *Identity {
	return &Identity{
		HostID: identity.HostID, Certificate: identity.Certificate, CAPool: identity.CAPool,
		NotAfter: identity.NotAfter, TrustPEM: identity.TrustPEM,
	}
}

// IdentityPaths points at the identity files in the state directory of the
// agent.
type IdentityPaths struct {
	Key  string
	Cert string
	CA   string
}

func paths(stateDir string) IdentityPaths {
	return IdentityPaths{
		Key:  filepath.Join(stateDir, "agent.key"),
		Cert: filepath.Join(stateDir, "agent.pem"),
		CA:   filepath.Join(stateDir, "ca.pem"),
	}
}

// The stable error codes of an enrollment.
//
// They are the contract with the operator: a refusal reaches a host that has
// no session with the panel, and the code is what the operator can act on
// without reading the source.
const (
	// CodeTokenInvalid is every refusal of the token. The panel tells no
	// more on purpose - the reason stays in its audit trail.
	CodeTokenInvalid = "enrollment_token_invalid"
	// CodeRequestReused is an attempt under a known number with another
	// request. Not retried: it is a mismatch to be looked into.
	CodeRequestReused = "enrollment_request_reused"
	// CodeAlreadyEnrolled is a host that has a working identity and asks for
	// a new one with an ordinary token. Replacing an identity is a recovery.
	CodeAlreadyEnrolled = "machine_already_enrolled"
	// CodeCommitFailed is a failure of the local write. The current
	// generation stays in force.
	CodeCommitFailed = "identity_commit_failed"
	// CodeIdentityRejected is a certificate the gateway did not accept in a
	// handshake. Nothing was switched.
	CodeIdentityRejected = "identity_rejected"
	// CodeRequestInvalid is a request the panel could not sign.
	CodeRequestInvalid = "csr_invalid"
	// CodeUnknownAuthority and CodeNameMismatch are the endpoint failing
	// the check against the bootstrap CA.
	CodeUnknownAuthority = "tls_unknown_authority"
	CodeNameMismatch     = "tls_name_mismatch"
	// CodeConnectFailed and CodeConnectTimeout are the network. Worth a
	// retry: the pending attempt is kept for exactly that.
	CodeConnectFailed  = "connect_failed"
	CodeConnectTimeout = "connect_timeout"
	// CodeEnrollmentFailed is everything the panel refused without a
	// recognisable reason.
	CodeEnrollmentFailed = "enrollment_failed"
	// CodePendingInvalid is a record of an attempt that cannot be repeated.
	CodePendingInvalid = "pending_invalid"
)

// EnrollmentError carries a stable code next to the cause.
type EnrollmentError struct {
	Code string
	Err  error
}

func (e *EnrollmentError) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}

// Unwrap keeps the cause reachable for errors.Is and errors.As.
func (e *EnrollmentError) Unwrap() error { return e.Err }

// ErrorCode returns the stable code of an error, or an empty string when the
// error carries none.
func ErrorCode(err error) string {
	var enrollment *EnrollmentError
	if errors.As(err, &enrollment) {
		return enrollment.Code
	}
	return ""
}

func coded(code string, err error) error { return &EnrollmentError{Code: code, Err: err} }

// IdentityRequest describes the identity declared during enrollment. The
// simulator gives synthetic values, the agent on a host reads them from the
// system.
type IdentityRequest struct {
	StateDir        string
	EnrollmentURL   string
	Token           string
	BootstrapCAPath string
	MachineID       string
	Hostname        string
	// Advertised are the network names the enrolling party is visible under. The
	// relay uses them: it also has to act as a server towards the agents of its
	// site, and an agent verifies the name in the certificate.
	Advertised   string
	OSFamily     string
	OSVersion    string
	Architecture string
	// HelperSocket is the socket of the root helper on this host. When it is
	// given, the enrollment hands the helper the panel's trust bundle - the
	// host identifier and the capability keys - right after the identity is
	// written. Empty means the daemon will do it at its first session.
	HelperSocket string
}

// LocalIdentityRequest fills the request in from the system.
func LocalIdentityRequest(stateDir, enrollmentURL, token, bootstrapCAPath string) (IdentityRequest, error) {
	machineID, err := MachineID()
	if err != nil {
		return IdentityRequest{}, fmt.Errorf("machine-id: %w", err)
	}
	hostname, _ := os.Hostname()
	osInfo := ReadOSInfo()
	return IdentityRequest{
		StateDir:        stateDir,
		EnrollmentURL:   enrollmentURL,
		Token:           token,
		BootstrapCAPath: bootstrapCAPath,
		MachineID:       machineID,
		Hostname:        hostname,
		OSFamily:        osInfo.Family,
		OSVersion:       osInfo.Version,
		Architecture:    runtime.GOARCH,
	}, nil
}

// LoadIdentity loads the identity the host already has.
//
// This is all the daemon does with the identity: it enrolls nothing. An
// enrollment needs a token, and a token has no place in the environment of a
// service that restarts on its own - it belongs to a one-time command of the
// operator, flotestro-agentctl enroll. A host without an identity is an
// error here, and the unit file keeps the daemon from starting at all.
func LoadIdentity(stateDir string) (*Identity, error) {
	store := identitystore.New(stateDir)
	if err := store.Clean(); err != nil {
		return nil, fmt.Errorf("tidying up the identity: %w", err)
	}
	identity, err := loadCurrent(store, stateDir)
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(identity.NotAfter) {
		return nil, fmt.Errorf("%w: the certificate of host/%s expired at %s",
			identitystore.ErrIdentityMissing, identity.HostID, identity.NotAfter.Format(time.RFC3339))
	}
	return identity, nil
}

// loadCurrent reads the current generation, moving an old layout first.
//
// A host set up before the store was introduced has the whole set loose in
// the state directory. It is moved once, without deleting the originals.
func loadCurrent(store *identitystore.Store, stateDir string) (*Identity, error) {
	if identity, err := store.Current(); err == nil {
		return fromIdentity(identity), nil
	}
	p := paths(stateDir)
	if moved, err := store.Migrate(p.Key, p.Cert, p.CA); moved && err == nil {
		if identity, err := store.Current(); err == nil {
			return fromIdentity(identity), nil
		}
	}
	return nil, fmt.Errorf("%w: no identity in %s; enroll the host: flotestro-agentctl enroll",
		identitystore.ErrIdentityMissing, stateDir)
}

// EnsureIdentityFor loads an existing identity or performs an enrollment.
//
// The relay and the simulator take this path: for them the enrollment is
// part of the start. The daemon of the agent does not - see LoadIdentity.
func EnsureIdentityFor(ctx context.Context, request IdentityRequest) (*Identity, error) {
	if err := os.MkdirAll(request.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("the state directory: %w", err)
	}
	store := identitystore.New(request.StateDir)
	if err := store.Clean(); err != nil {
		return nil, fmt.Errorf("tidying up the identity: %w", err)
	}
	if identity, err := loadCurrent(store, request.StateDir); err == nil && time.Now().Before(identity.NotAfter) {
		return identity, nil
	}
	return Enroll(ctx, request)
}

// Enroll registers the host with the panel and writes the identity.
//
// It refuses nothing about an identity that is already there: the callers
// decide that. The operator's tool refuses an ordinary enrollment of a
// registered host; a recovery replaces the identity on purpose.
func Enroll(ctx context.Context, request IdentityRequest) (*Identity, error) {
	enrollment, err := prepare(request)
	if err != nil {
		return nil, err
	}
	return enrollment.Run(ctx)
}

// Recover replaces the identity of the host with a recovery token.
//
// The difference from an enrollment is the verification: the new certificate
// has to open a handshake with the gateway before the store switches to it.
// The current generation works until then - a recovery that left the host
// with a certificate the fleet does not accept would be worse than no
// recovery at all.
func Recover(ctx context.Context, request IdentityRequest, gatewayURL string) (*Identity, error) {
	enrollment, err := prepare(request)
	if err != nil {
		return nil, err
	}
	enrollment.Verify = GatewayHandshake(gatewayURL)
	return enrollment.Run(ctx)
}

// prepare wires an enrollment to the network and the state directory.
func prepare(request IdentityRequest) (*Enrollment, error) {
	if err := os.MkdirAll(request.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("the state directory: %w", err)
	}
	caPEM, err := readCABundle(paths(request.StateDir).CA, request.BootstrapCAPath)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("the CA bundle contains no certificate")
	}
	return &Enrollment{
		Store:        identitystore.New(request.StateDir),
		Issuer:       NewEnrollmentIssuer(request.EnrollmentURL, caPool),
		Request:      request,
		BootstrapPEM: caPEM,
	}, nil
}

// Issuer answers an enrollment request.
//
// In production it is the enrollment service of the panel behind the
// bootstrap CA. A test replaces it with one that loses answers on purpose:
// the whole point of the pending record is what happens then.
type Issuer interface {
	Enroll(ctx context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error)
}

// NewEnrollmentIssuer returns the issuer behind the enrollment endpoint.
func NewEnrollmentIssuer(enrollmentURL string, caPool *x509.CertPool) Issuer {
	return enrollmentClient{client: agentv1connect.NewEnrollmentServiceClient(&http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}},
	}, enrollmentURL)}
}

type enrollmentClient struct {
	client agentv1connect.EnrollmentServiceClient
}

func (c enrollmentClient) Enroll(ctx context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	response, err := c.client.Enroll(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

// Enrollment carries one admission of a host into the fleet, with its parts
// replaceable.
//
// The clock, the source of randomness, the issuer and the directory are
// given from outside so that a test can prove the invariants rather than the
// happy path: that a retry repeats the same attempt, that an old attempt is
// abandoned, that a rejected certificate switches nothing.
type Enrollment struct {
	Store   *identitystore.Store
	Issuer  Issuer
	Request IdentityRequest
	// BootstrapPEM is the trust bundle the request went out under. It becomes
	// the bundle of the generation when the panel sends none.
	BootstrapPEM []byte
	// Verify checks the new identity before the store switches to it. Nil
	// means the store's own checks are enough - an enrollment has no
	// identity to lose yet.
	Verify func(ctx context.Context, identity *Identity) error
	// Now and Random default to the real clock and crypto/rand.
	Now    func() time.Time
	Random io.Reader
	// Log receives what happened with the helper's trust bundle. Nil means
	// the default logger.
	Log *slog.Logger
}

// Run carries the enrollment out.
//
// The order is the contract: the attempt is on disk before the first
// request, the answer is checked before the write, the write happens as one
// generation, and the record of the attempt goes away last.
func (e *Enrollment) Run(ctx context.Context) (*Identity, error) {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Random == nil {
		e.Random = rand.Reader
	}
	if e.Request.MachineID == "" {
		return nil, fmt.Errorf("the machine identifier is missing")
	}
	if err := e.Store.Clean(); err != nil {
		return nil, fmt.Errorf("tidying up the identity: %w", err)
	}

	pending, err := e.attempt()
	if err != nil {
		return nil, err
	}
	// The same attempt goes out as many times as needed: the same number
	// and the same request. That is what lets the panel answer a retry with
	// the certificate it has already issued.
	response, err := e.Issuer.Enroll(ctx, &agentv1.EnrollRequest{
		EnrollmentToken: e.Request.Token,
		MachineId:       e.Request.MachineID,
		Hostname:        e.Request.Hostname,
		CsrPem:          pending.CSRPEM,
		ClientRequestId: pending.ClientRequestID,
		Build: &agentv1.AgentBuild{
			AgentVersion: Version,
			OsFamily:     e.Request.OSFamily,
			OsVersion:    e.Request.OSVersion,
			Architecture: e.Request.Architecture,
		},
	})
	if err != nil {
		return nil, enrollmentFailure(err)
	}

	// The write goes as one generation: the key, the certificate and the
	// bundle either land on the disk together or do not land at all.
	bundle := response.GetCaBundlePem()
	if len(bundle) == 0 {
		bundle = e.BootstrapPEM
	}
	key, err := pending.Key()
	if err != nil {
		return nil, coded(CodePendingInvalid, err)
	}
	generation := identitystore.Generation{
		Key: key, CertificatePEM: response.GetCertificatePem(), TrustPEM: bundle,
	}
	if err := identitystore.Check(generation); err != nil {
		// The answer does not fit the key or the trust: the store would
		// refuse it as well, but the code has to say that it is the answer
		// that is wrong and not the disk.
		return nil, coded(CodeIdentityRejected, err)
	}
	if e.Verify != nil {
		candidate, err := inMemory(generation)
		if err != nil {
			return nil, coded(CodeIdentityRejected, err)
		}
		if err := e.Verify(ctx, candidate); err != nil {
			return nil, coded(CodeIdentityRejected, err)
		}
	}
	identity, err := e.Store.Commit(generation)
	if err != nil {
		return nil, coded(CodeCommitFailed, err)
	}
	// The attempt is closed: the next enrollment is a new matter and goes
	// under a new number. Should this removal fail, the next attempt
	// recognises the record by the key of the identity that is now current.
	_ = e.Store.RemovePending()
	// The helper learns the host identity and the panel's keys from the
	// panel's signed bundle, never from the agent's word. It is handed over
	// now when the socket is known, and by the daemon at its first session
	// otherwise; a helper that is not up yet is not a failed enrollment.
	if e.Request.HelperSocket != "" && response.GetHelperTrust() != nil {
		registerSessionHelper(NewHelperClient(e.Request.HelperSocket))
		deliverHelperTrust(ctx, response.GetHelperTrust(), e.Log)
	}
	return fromIdentity(identity), nil
}

// attempt loads the unfinished attempt or starts a new one.
//
// An attempt is repeated when its record is there, is not too old and does
// not belong to an identity that has already been written. Anything else is
// abandoned: a token lives at most a day, and an attempt whose answer has
// already been committed asks for what the host already has.
func (e *Enrollment) attempt() (*identitystore.Pending, error) {
	now := e.Now()
	pending, err := e.Store.LoadPending()
	switch {
	case err == nil:
		if !pending.Stale(now) && !e.finished(pending) {
			return pending, nil
		}
		if err := e.Store.RemovePending(); err != nil {
			return nil, coded(CodePendingInvalid, err)
		}
	case errors.Is(err, identitystore.ErrPendingMissing):
	default:
		// A record that cannot be repeated is not silently replaced: the
		// operator decides with identity reset --discard-pending, and the
		// status shows the record meanwhile.
		return nil, coded(CodePendingInvalid, err)
	}

	dns, addresses := advertised(e.Request.Advertised)
	// The subject in the CSR is only a hint; the identity is granted by the
	// control plane.
	pending, err = e.Store.PreparePending(e.Random, now, e.Request.MachineID,
		dns, addresses, TokenPrefix(e.Request.Token))
	if err != nil {
		return nil, coded(CodeCommitFailed, err)
	}
	return pending, nil
}

// finished says whether the attempt has already produced the current
// identity - an interruption after the commit and before the removal of the
// record.
func (e *Enrollment) finished(pending *identitystore.Pending) bool {
	current, err := e.Store.Current()
	if err != nil || current.Certificate.Leaf == nil {
		return false
	}
	key, err := pending.Key()
	if err != nil {
		return false
	}
	comparable, ok := key.Public().(interface{ Equal(x crypto.PublicKey) bool })
	return ok && comparable.Equal(current.Certificate.Leaf.PublicKey)
}

// advertised splits the network names of the enrolling party.
func advertised(list string) (dns []string, addresses []net.IP) {
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if address := net.ParseIP(name); address != nil {
			addresses = append(addresses, address)
			continue
		}
		dns = append(dns, name)
	}
	return dns, addresses
}

// tokenPrefixLength is how much of a token is kept as its name.
//
// The four letters of the scheme and four characters of the body: enough to
// tell two orders apart by eye, and a negligible part of the secret.
const tokenPrefixLength = 8

// TokenPrefix returns the non-secret opening of a fleet token, or an empty
// string for a value without the recognisable scheme.
func TokenPrefix(token string) string {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "flt_") || len(token) < 2*tokenPrefixLength {
		return ""
	}
	return token[:tokenPrefixLength]
}

// inMemory builds the identity of a generation without writing it.
func inMemory(generation identitystore.Generation) (*Identity, error) {
	block, _ := pem.Decode(generation.CertificatePEM)
	if block == nil {
		return nil, fmt.Errorf("the certificate carries no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(generation.TrustPEM) {
		return nil, identitystore.ErrTrust
	}
	_, hostID, err := pki.IdentityFromCert(leaf)
	if err != nil {
		hostID = leaf.Subject.CommonName
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{block.Bytes}, PrivateKey: generation.Key.Signer(), Leaf: leaf,
	}
	return &Identity{
		HostID: hostID, Certificate: certificate, CAPool: pool,
		NotAfter: leaf.NotAfter, TrustPEM: generation.TrustPEM,
	}, nil
}

// GatewayHandshake verifies an identity by opening a session with the
// gateway.
//
// The gateway requires and verifies the client certificate in the handshake
// itself, so a completed exchange is the proof: the fleet accepts this
// certificate. The request that follows the handshake asks for nothing - any
// answer at all means the connection was established with the new identity,
// and a certificate refused in the handshake never gets one.
func GatewayHandshake(gatewayURL string) func(ctx context.Context, identity *Identity) error {
	return func(ctx context.Context, identity *Identity) error {
		client := &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{identity.Certificate},
					RootCAs:      identity.CAPool,
					MinVersion:   tls.VersionTLS12,
				},
				ForceAttemptHTTP2: true,
			},
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(gatewayURL, "/")+"/", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("the gateway did not accept the new certificate: %w", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return response.Body.Close()
	}
}

// enrollmentFailure gives a refusal its stable code.
//
// The panel answers every refusal of the token in the same way, so that
// nothing about the orders can be probed from outside; the agent passes
// that on as one code. The network and the trust are told apart, because
// the operator fixes each of them somewhere else.
func enrollmentFailure(err error) error {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var timeout net.Error
	switch {
	case errors.As(err, &unknown):
		return coded(CodeUnknownAuthority, err)
	case errors.As(err, &hostname):
		return coded(CodeNameMismatch, err)
	}
	switch connect.CodeOf(err) {
	case connect.CodePermissionDenied, connect.CodeUnauthenticated:
		return coded(CodeTokenInvalid, err)
	case connect.CodeAlreadyExists, connect.CodeAborted:
		return coded(CodeRequestReused, err)
	case connect.CodeInvalidArgument:
		return coded(CodeRequestInvalid, err)
	case connect.CodeDeadlineExceeded:
		return coded(CodeConnectTimeout, err)
	case connect.CodeUnavailable:
		return coded(CodeConnectFailed, err)
	}
	if errors.As(err, &timeout) && timeout.Timeout() {
		return coded(CodeConnectTimeout, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return coded(CodeConnectTimeout, err)
	}
	return coded(CodeEnrollmentFailed, err)
}

func readCABundle(statePath, bootstrapPath string) ([]byte, error) {
	if data, err := os.ReadFile(statePath); err == nil && len(data) > 0 {
		return data, nil
	}
	if bootstrapPath == "" {
		return nil, fmt.Errorf("the CA bundle is missing: pass --ca-file at the first start")
	}
	data, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return nil, fmt.Errorf("the CA bundle: %w", err)
	}
	return data, nil
}

// PendingAttempt describes an unfinished enrollment for the operator.
//
// Without the key and the request: the status names the attempt, it does not
// repeat it.
type PendingAttempt struct {
	ClientRequestID string
	CreatedAt       time.Time
	Age             time.Duration
	// TokenPrefix is empty when the attempt was started with a token of
	// no recognisable scheme.
	TokenPrefix string
	Stale       bool
	// Err is set for a record that cannot be repeated. The attempt is then
	// shown as damaged rather than hidden.
	Err string
}

// ReadPendingAttempt reads the record of an unfinished attempt. Nil means
// there is none.
func ReadPendingAttempt(stateDir string, now time.Time) *PendingAttempt {
	store := identitystore.New(stateDir)
	pending, err := store.LoadPending()
	switch {
	case errors.Is(err, identitystore.ErrPendingMissing):
		return nil
	case err != nil:
		return &PendingAttempt{Err: err.Error()}
	}
	return &PendingAttempt{
		ClientRequestID: pending.ClientRequestID,
		CreatedAt:       pending.CreatedAt,
		Age:             pending.Age(now),
		TokenPrefix:     pending.TokenPrefix,
		Stale:           pending.Stale(now),
	}
}

// DiscardPendingAttempt abandons the unfinished attempt. It returns whether
// there was one.
func DiscardPendingAttempt(stateDir string) (bool, error) {
	store := identitystore.New(stateDir)
	_, err := os.Stat(store.PendingPath())
	if os.IsNotExist(err) {
		return false, nil
	}
	if err := store.RemovePending(); err != nil {
		return true, err
	}
	return true, nil
}
