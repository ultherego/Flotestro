package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/buildinfo"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/identitystore"
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
}

// EnsureIdentity loads an existing identity or performs an enrollment. The
// private key is generated locally and never leaves the host.
func EnsureIdentity(ctx context.Context, stateDir, enrollmentURL, token, bootstrapCAPath string) (*Identity, error) {
	machineID, err := MachineID()
	if err != nil {
		return nil, fmt.Errorf("machine-id: %w", err)
	}
	hostname, _ := os.Hostname()
	osInfo := ReadOSInfo()
	return EnsureIdentityFor(ctx, IdentityRequest{
		StateDir:        stateDir,
		EnrollmentURL:   enrollmentURL,
		Token:           token,
		BootstrapCAPath: bootstrapCAPath,
		MachineID:       machineID,
		Hostname:        hostname,
		OSFamily:        osInfo.Family,
		OSVersion:       osInfo.Version,
		Architecture:    runtime.GOARCH,
	})
}

// EnsureIdentityFor performs the enrollment for the given identity.
func EnsureIdentityFor(ctx context.Context, request IdentityRequest) (*Identity, error) {
	stateDir := request.StateDir
	enrollmentURL := request.EnrollmentURL
	token := request.Token
	bootstrapCAPath := request.BootstrapCAPath
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("the state directory: %w", err)
	}
	p := paths(stateDir)

	// The generation store is the source of the identity. Traces of interrupted
	// writes are cleaned at the start: a temporary directory left after a crash
	// is not a state.
	store := identitystore.New(stateDir)
	if err := store.Clean(); err != nil {
		return nil, fmt.Errorf("tidying up the identity: %w", err)
	}
	if identity, err := store.Current(); err == nil && time.Now().Before(identity.NotAfter) {
		return fromIdentity(identity), nil
	}
	// A host set up before the store was introduced has the whole set loose in
	// the state directory. It is moved once, without deleting the originals.
	if moved, err := store.Migrate(p.Key, p.Cert, p.CA); moved && err == nil {
		if identity, err := store.Current(); err == nil && time.Now().Before(identity.NotAfter) {
			return fromIdentity(identity), nil
		}
	}

	caPEM, err := readCABundle(p.CA, bootstrapCAPath)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("the CA bundle contains no certificate")
	}

	// The key is created by the store and not by this function: the store knows
	// whether the key is a file or stays inside a hardware chip. Enrollment is to
	// work the same way in both profiles.
	key, err := store.NewKey()
	if err != nil {
		return nil, err
	}
	machineID := request.MachineID
	if machineID == "" {
		return nil, fmt.Errorf("the machine identifier is missing")
	}
	hostname := request.Hostname

	var dns []string
	var addresses []net.IP
	for _, name := range strings.Split(request.Advertised, ",") {
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
	// The subject in the CSR is only a hint; the identity is granted by the
	// control plane.
	csrPEM, err := identitystore.Request(key, machineID, dns, addresses)
	if err != nil {
		return nil, err
	}

	client := agentv1connect.NewEnrollmentServiceClient(&http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}},
	}, enrollmentURL)

	// The attempt identifier survives a restart of the agent: when the answer is
	// lost in the network, the retry is to go under the same number and get the
	// same certificate instead of a "token used" refusal.
	attemptID, err := enrollmentAttemptID(stateDir)
	if err != nil {
		return nil, err
	}

	resp, err := client.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		EnrollmentToken: token,
		MachineId:       machineID,
		Hostname:        hostname,
		CsrPem:          csrPEM,
		ClientRequestId: attemptID,
		Build: &agentv1.AgentBuild{
			AgentVersion: Version,
			OsFamily:     request.OSFamily,
			OsVersion:    request.OSVersion,
			Architecture: request.Architecture,
		},
	}))
	if err != nil {
		return nil, fmt.Errorf("the enrollment was refused: %w", err)
	}

	// The write goes as one generation: the key, the certificate and the bundle
	// either land on the disk together or do not land at all.
	bundle := resp.Msg.GetCaBundlePem()
	if len(bundle) == 0 {
		bundle = caPEM
	}
	identity, err := store.Commit(identitystore.Generation{
		Key: key, CertificatePEM: resp.Msg.GetCertificatePem(), TrustPEM: bundle,
	})
	if err != nil {
		return nil, fmt.Errorf("writing the identity: %w", err)
	}
	// The attempt is closed: the next enrollment is a new matter and goes under a
	// new number.
	_ = os.Remove(filepath.Join(stateDir, enrollmentAttemptFile))
	return fromIdentity(identity), nil
}

// enrollmentAttemptFile holds the number of the current enrollment attempt.
const enrollmentAttemptFile = "enroll-request-id"

// enrollmentAttemptID returns a stable attempt number, creating it at first
// use.
//
// The number has to survive a restart of the agent during the enrollment: it is
// what tells "retry the same attempt" from "start a new one". A new number
// after every restart would burn a token at every attempt.
func enrollmentAttemptID(stateDir string) (string, error) {
	path := filepath.Join(stateDir, enrollmentAttemptFile)
	if stored, err := os.ReadFile(path); err == nil {
		if number, err := uuid.Parse(strings.TrimSpace(string(stored))); err == nil {
			return number.String(), nil
		}
	}
	number := uuid.NewString()
	if err := os.WriteFile(path, []byte(number+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("the enrollment attempt number: %w", err)
	}
	return number, nil
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

func loadIdentity(p IdentityPaths) (*Identity, error) {
	certPEM, err := os.ReadFile(p.Cert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(p.Key)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(p.CA)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate of the agent expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("the stored CA bundle is invalid")
	}
	certificate.Leaf = leaf
	return &Identity{
		HostID:      leaf.Subject.CommonName,
		Certificate: certificate,
		CAPool:      caPool,
		NotAfter:    leaf.NotAfter,
	}, nil
}
