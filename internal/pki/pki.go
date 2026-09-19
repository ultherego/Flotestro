// Package pki runs Flotestro's internal CA: the server certificate and the
// signing of agent CSRs. An agent's private key never reaches the CA.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// An agent certificate is short-lived; rotation is the normal mode of work.
	AgentCertTTL  = 30 * 24 * time.Hour
	serverCertTTL = 365 * 24 * time.Hour
	caTTL         = 10 * 365 * 24 * time.Hour

	// The scheme of the URI SAN carrying the host's identity.
	identityScheme = "flotestro"
)

// CA is the internal certificate authority of the control plane.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
	PEM         []byte
	// AgentTTL overrides the lifetime of an agent certificate.
	AgentTTL time.Duration
	// ReservedNames are the names and addresses the panel itself is seen under.
	ReservedNames []string
}

// The refusals of a CSR that the requester can act on.
var (
	// ErrKeyPolicy means a public key below the policy: EC P-256 or P-384,
	// or RSA of at least 3072 bits.
	ErrKeyPolicy = errors.New("csr_key_policy")
	// ErrRelayNameReserved means a relay asking for a name of the panel or
	// of the loopback.
	ErrRelayNameReserved = errors.New("relay_name_reserved")
)

// minimumRSABits is the smallest RSA key the fleet accepts. Below it the
// key is weaker than the P-256 curve the agents use by default.
const minimumRSABits = 3072

// checkKeyPolicy refuses the keys the fleet does not trust. The policy is
// short on purpose: two curves and a floor for RSA.
func checkKeyPolicy(key any) error {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return nil
		}
		return fmt.Errorf("%w: the curve %s is not accepted; use P-256 or P-384", ErrKeyPolicy,
			k.Curve.Params().Name)
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < minimumRSABits {
			return fmt.Errorf("%w: an RSA key of %d bits is below the floor of %d", ErrKeyPolicy,
				bits, minimumRSABits)
		}
		return nil
	default:
		return fmt.Errorf("%w: the key type %T is not accepted", ErrKeyPolicy, key)
	}
}

// checkRelayNames refuses a relay certificate that would carry a name of the
// panel or of the loopback.
func (ca *CA) checkRelayNames(dnsNames []string, addresses []net.IP) error {
	reserved := map[string]bool{"localhost": true}
	var reservedIPs []net.IP
	for _, name := range ca.ReservedNames {
		if ip := net.ParseIP(name); ip != nil {
			reservedIPs = append(reservedIPs, ip)
			continue
		}
		reserved[canonicalName(name)] = true
	}
	for _, name := range dnsNames {
		if reserved[canonicalName(name)] {
			return fmt.Errorf("%w: %s is a name of the panel", ErrRelayNameReserved, name)
		}
	}
	for _, address := range addresses {
		if address.IsLoopback() || address.IsUnspecified() {
			return fmt.Errorf("%w: %s is a loopback address", ErrRelayNameReserved, address)
		}
		for _, taken := range reservedIPs {
			if taken.Equal(address) {
				return fmt.Errorf("%w: %s is an address of the panel", ErrRelayNameReserved, address)
			}
		}
	}
	return nil
}

func canonicalName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// agentCertTTL returns the lifetime of an agent certificate.
func (ca *CA) agentCertTTL() time.Duration {
	if ca.AgentTTL > 0 {
		return ca.AgentTTL
	}
	return AgentCertTTL
}

// NotAfter returns the end of validity of the CA certificate.
func (ca *CA) NotAfter() time.Time {
	if ca == nil || ca.Certificate == nil {
		return time.Time{}
	}
	return ca.Certificate.NotAfter
}

// The names of the files of the signing CA in the state directory.
const (
	caCertFile = "ca.pem"
	caKeyFile  = "ca.key"
)

// The states of the CA material on disk that stop the panel. The codes
// are stable: they are what the log shows and what the runbook names.
var (
	// ErrNoMaterial means a state directory with no CA at all: neither a
	// certificate nor a key, nothing pending and nothing retired.
	ErrNoMaterial = errors.New("pki_no_material")
	// ErrIssuerKeyUnavailable means the certificate of the CA is there and its
	// private key is not.
	ErrIssuerKeyUnavailable = errors.New("issuer_key_unavailable")
	// ErrStateMismatch means material that does not fit together: a key without a
	// certificate, a pair whose key does not match the certificate, or a file
	// that does not parse.
	ErrStateMismatch = errors.New("pki_state_mismatch")
	// ErrMaterialExists refuses an initialisation over a directory that
	// already holds something.
	ErrMaterialExists = errors.New("pki_material_exists")
)

// HasAnyMaterial says whether the state directory holds any CA material: the
// signing pair or a part of it, a pending CA or a retired one.
func HasAnyMaterial(dir string) bool {
	for _, name := range []string{caCertFile, caKeyFile, pendingCertFile, pendingKeyFile, retiredDir} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// EnsureCA reads the CA from the state directory when it holds material and
// creates one only when the directory holds nothing at all.
func EnsureCA(dir string) (*CA, error) {
	if HasAnyMaterial(dir) {
		return Open(dir)
	}
	return Init(dir)
}

// Open reads the signing CA and refuses anything but a complete, matching
// pair.
func Open(dir string) (*CA, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		ca, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrStateMismatch, err)
		}
		if err := ca.VerifyPair(); err != nil {
			return nil, err
		}
		return ca, nil
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		if HasAnyMaterial(dir) {
			return nil, fmt.Errorf("%w: the directory holds CA material but no signing pair (%s, %s)",
				ErrStateMismatch, caCertFile, caKeyFile)
		}
		return nil, ErrNoMaterial
	case certErr == nil && os.IsNotExist(keyErr):
		return nil, fmt.Errorf("%w: %s is there and %s is not", ErrIssuerKeyUnavailable, caCertFile, caKeyFile)
	case os.IsNotExist(certErr) && keyErr == nil:
		return nil, fmt.Errorf("%w: %s is there and %s is not", ErrStateMismatch, caKeyFile, caCertFile)
	case certErr != nil:
		return nil, certErr
	default:
		return nil, keyErr
	}
}

// Init creates the first CA of an installation in a directory that holds no
// material.
func Init(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	if HasAnyMaterial(dir) {
		return nil, fmt.Errorf("%w: %s already holds CA material", ErrMaterialExists, dir)
	}
	_, certPEM, keyPEM, err := newCA()
	if err != nil {
		return nil, err
	}
	// The CA key is the most sensitive material in the system.
	if err := writeFileAtomic(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, caCertFile), certPEM, 0o644); err != nil {
		return nil, err
	}
	return Open(dir)
}

// VerifyPair checks that the private key is the one the certificate describes.
func (ca *CA) VerifyPair() error {
	if ca == nil || ca.Certificate == nil || ca.PrivateKey == nil {
		return fmt.Errorf("%w: the CA is incomplete", ErrStateMismatch)
	}
	public, ok := ca.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&ca.PrivateKey.PublicKey) {
		return fmt.Errorf("%w: the private key does not match the certificate %s",
			ErrStateMismatch, ca.Certificate.SerialNumber)
	}
	return nil
}

// IssuerID is the stable identifier of this CA as an issuer: a UUID derived
// from the certificate, so every panel of an installation derives the same one
// without a table to agree through, and a certificate row can name its issuer
func (ca *CA) IssuerID() string {
	if ca == nil || ca.Certificate == nil {
		return ""
	}
	return IssuerIDOf(ca.Certificate)
}

// IssuerIDOf derives the issuer identifier of a CA certificate.
func IssuerIDOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	var id [16]byte
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x50
	id[8] = (id[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

// FingerprintHex is the SHA-256 of the certificate as the API shows it.
func (ca *CA) FingerprintHex() string {
	if ca == nil || ca.Certificate == nil {
		return ""
	}
	return fingerprintHex(ca.Certificate.Raw)
}

func newCA() (*CA, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Flotestro Root CA", Organization: []string{"Flotestro"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &CA{Certificate: cert, PrivateKey: key, PEM: certPEM}, certPEM, keyPEM, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("ca.pem contains no PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca.pem: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca.key contains no PEM block")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca.key: %w", err)
	}
	return &CA{Certificate: cert, PrivateKey: key, PEM: certPEM}, nil
}

// IssueServerCert issues a certificate for the control plane's listeners.
func (ca *CA) IssueServerCert(dnsNames []string, ipAddresses []net.IP) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "flotestro-control-plane", Organization: []string{"Flotestro"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(serverCertTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// IssuedCert describes an issued agent certificate for recording in the database.
type IssuedCert struct {
	PEM         []byte
	Serial      string
	Fingerprint []byte
	NotBefore   time.Time
	NotAfter    time.Time
	CommonName  string
	// The issuer allows counting how many hosts a withdrawal of a given CA concerns.
	IssuerSubject string
	IssuerSerial  string
	// IssuerID is the stable identifier of the issuing CA (see IssuerID).
	IssuerID string
	// The network names issued in the certificate. Empty for hosts: only a
	// relay acts as a server towards anyone.
	DNSNames    []string
	IPAddresses []string
}

// relayCertTTL is shorter than the lifetime of an agent certificate.
const relayCertTTL = 7 * 24 * time.Hour

// SignRelayCSR signs a relay's CSR.
func (ca *CA) SignRelayCSR(csrPEM []byte, relayID string) (*IssuedCert, error) {
	return ca.signCSR(csrPEM, "relay", relayID, relayCertTTL, nil)
}

// SignRelayCSRWithNames issues a relay certificate with the names given by the
// panel instead of those from the CSR.
func (ca *CA) SignRelayCSRWithNames(csrPEM []byte, relayID string, names []string) (*IssuedCert, error) {
	return ca.signCSR(csrPEM, "relay", relayID, relayCertTTL, names)
}

// SignAgentCSR signs an agent's CSR, embedding the host's identity in the URI
// SAN.
func (ca *CA) SignAgentCSR(csrPEM []byte, hostID string) (*IssuedCert, error) {
	return ca.signCSR(csrPEM, "host", hostID, ca.agentCertTTL(), nil)
}

// signCSR issues a certificate of a fleet identity.
func (ca *CA) signCSR(csrPEM []byte, kind, id string, ttl time.Duration,
	names []string) (*IssuedCert, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("the CSR contains no PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	if err := checkKeyPolicy(csr.PublicKey); err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	identity := &url.URL{Scheme: identityScheme, Host: kind, Path: "/" + id}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id, OrganizationalUnit: []string{kind}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{identity},
	}
	if kind == "relay" {
		// A relay acts in both roles: as a server towards the agents of its site and
		// as a client towards the centre.
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		template.DNSNames = csr.DNSNames
		template.IPAddresses = csr.IPAddresses
		if names != nil {
			// The names imposed by the panel replace those from the CSR in full.
			template.DNSNames, template.IPAddresses = splitNames(names)
		}
		// The names are checked after the choice between the request and the
		// registry: a reserved name recorded at an earlier registration must not be
		// renewed either.
		if err := ca.checkRelayNames(template.DNSNames, template.IPAddresses); err != nil {
			return nil, err
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, csr.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	addresses := make([]string, 0, len(template.IPAddresses))
	for _, address := range template.IPAddresses {
		addresses = append(addresses, address.String())
	}
	return &IssuedCert{
		PEM:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:        serial.String(),
		Fingerprint:   sum[:],
		NotBefore:     template.NotBefore,
		NotAfter:      template.NotAfter,
		IssuerSubject: ca.Certificate.Subject.CommonName,
		IssuerSerial:  ca.Certificate.SerialNumber.String(),
		IssuerID:      ca.IssuerID(),
		CommonName:    id,
		DNSNames:      template.DNSNames,
		IPAddresses:   addresses,
	}, nil
}

// splitNames divides network names into IP addresses and DNS names.
func splitNames(names []string) ([]string, []net.IP) {
	var dns []string
	var addresses []net.IP
	for _, name := range names {
		if address := net.ParseIP(name); address != nil {
			addresses = append(addresses, address)
			continue
		}
		dns = append(dns, name)
	}
	return dns, addresses
}

// HostIDFromCert extracts the host's identity from the client certificate's URI SAN.
func HostIDFromCert(cert *x509.Certificate) (string, error) {
	return identityFromCert(cert, "host")
}

// RelayIDFromCert returns a relay's identity. The kind of identity is
// checked, so a host certificate does not pass as a relay certificate.
func RelayIDFromCert(cert *x509.Certificate) (string, error) {
	return identityFromCert(cert, "relay")
}

// IdentityFromCert returns the kind and the identifier from the URI SAN.
func IdentityFromCert(cert *x509.Certificate) (kind, id string, err error) {
	for _, uri := range cert.URIs {
		if uri.Scheme != identityScheme {
			continue
		}
		value := strings.TrimPrefix(uri.Path, "/")
		if value == "" {
			continue
		}
		return uri.Host, value, nil
	}
	return "", "", fmt.Errorf("the certificate carries no identity %s://<kind>/<id>", identityScheme)
}

func identityFromCert(cert *x509.Certificate, kind string) (string, error) {
	for _, uri := range cert.URIs {
		if uri.Scheme == identityScheme && uri.Host == kind {
			id := uri.Path
			if len(id) > 0 && id[0] == '/' {
				id = id[1:]
			}
			if id != "" {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("the certificate carries no identity %s://%s/<id>", identityScheme, kind)
}

// Fingerprint computes the SHA-256 of the certificate's DER.
func Fingerprint(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
