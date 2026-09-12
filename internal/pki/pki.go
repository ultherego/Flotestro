// Package pki runs Flotestro's internal CA: the server certificate and the
// signing of agent CSRs. An agent's private key never reaches the CA.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
	// AgentTTL overrides the lifetime of an agent certificate. Zero means the
	// default value; a shorter term shortens the window in which a stolen key
	// can be used, a longer one lowers the renewal traffic in a large
	// fleet.
	AgentTTL time.Duration
}

// agentCertTTL returns the lifetime of an agent certificate.
func (ca *CA) agentCertTTL() time.Duration {
	if ca.AgentTTL > 0 {
		return ca.AgentTTL
	}
	return AgentCertTTL
}

// NotAfter returns the end of validity of the CA certificate. An expiring CA
// immobilises the whole fleet at once, so this time has to be visible in the
// metrics.
func (ca *CA) NotAfter() time.Time {
	if ca == nil || ca.Certificate == nil {
		return time.Time{}
	}
	return ca.Certificate.NotAfter
}

// EnsureCA reads the CA from the state directory or creates one on the first start.
func EnsureCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return parseCA(certPEM, keyPEM)
	}
	if certErr != nil && !os.IsNotExist(certErr) {
		return nil, certErr
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return nil, keyErr
	}

	ca, certPEM, keyPEM, err := newCA()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	// The CA key is the most sensitive material in the system.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return ca, nil
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
	// The network names issued in the certificate. Empty for hosts: only a
	// relay acts as a server towards anyone.
	DNSNames    []string
	IPAddresses []string
}

// relayCertTTL is shorter than the lifetime of an agent certificate. A relay
// stands between the fleet and the centre and sees the traffic of a whole
// site, so the window in which its stolen key can be used is to be smaller.
const relayCertTTL = 7 * 24 * time.Hour

// SignRelayCSR signs a relay's CSR. A relay's identity is separate from a
// host's: a relay is not an agent and cannot impersonate a host with the
// certificate alone, because the panel reads the kind of identity from the
// URI SAN.
func (ca *CA) SignRelayCSR(csrPEM []byte, relayID string) (*IssuedCert, error) {
	return ca.signCSR(csrPEM, "relay", relayID, relayCertTTL, nil)
}

// SignRelayCSRWithNames issues a relay certificate with the names given by
// the panel instead of those from the CSR.
//
// A renewal goes this way: the network names are the boundary of trust
// towards the site's agents, so on a renewal they come from the registry
// rather than from the request. A relay that wants to act under a new name
// needs an operator's decision.
func (ca *CA) SignRelayCSRWithNames(csrPEM []byte, relayID string, names []string) (*IssuedCert, error) {
	return ca.signCSR(csrPEM, "relay", relayID, relayCertTTL, names)
}

// SignAgentCSR signs an agent's CSR, embedding the host's identity in the URI
// SAN. Every subject field coming from the CSR is ignored apart from the
// public key: the identity is granted by the control plane, not by the host
// that asks for it.
func (ca *CA) SignAgentCSR(csrPEM []byte, hostID string) (*IssuedCert, error) {
	return ca.signCSR(csrPEM, "host", hostID, ca.agentCertTTL(), nil)
}

// signCSR issues a certificate of a fleet identity. The kind of identity goes
// into the URI SAN, so a relay certificate cannot be used as a host
// certificate or the other way round.
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
		// A relay acts in both roles: as a server towards the agents of its
		// site and as a client towards the centre. We take the network names
		// from the CSR, because it is the relay that knows the address it is
		// seen at; the identity remains the URI SAN granted by the panel
		// rather than those names.
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		template.DNSNames = csr.DNSNames
		template.IPAddresses = csr.IPAddresses
		if names != nil {
			// The names imposed by the panel replace those from the CSR in
			// full. Adding them alongside would leave the relay able to give
			// itself a name the operator never approved.
			template.DNSNames, template.IPAddresses = splitNames(names)
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
		CommonName:    id,
		DNSNames:      template.DNSNames,
		IPAddresses:   addresses,
	}, nil
}

// splitNames divides network names into IP addresses and DNS names.
//
// A name that is an IP address has to land in the SAN as an address: browsers
// and TLS libraries do not match an address against a DNS entry, so such a
// certificate would look correct and the agent would reject it anyway.
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
//
// The kind is returned rather than checked: there are places that accept both
// fleet identities - the generation store is the same for an agent and for a
// relay, because it records a key and a certificate rather than a role.
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
