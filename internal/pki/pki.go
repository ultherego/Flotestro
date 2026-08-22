// Package pki obsluguje wewnetrzne CA Flotestro: certyfikat serwera oraz
// podpisywanie CSR agentow. Klucz prywatny agenta nigdy nie trafia do CA.
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
	"time"
)

const (
	// Certyfikat agenta jest krotkotrwaly; rotacja jest normalnym trybem pracy.
	AgentCertTTL  = 30 * 24 * time.Hour
	serverCertTTL = 365 * 24 * time.Hour
	caTTL         = 10 * 365 * 24 * time.Hour

	// Schemat URI SAN niosacego tozsamosc hosta.
	identityScheme = "flotestro"
)

// CA jest wewnetrznym urzedem certyfikacji control plane.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
	PEM         []byte
	// AgentTTL nadpisuje czas zycia certyfikatu agenta. Zero oznacza wartosc
	// domyslna; krotszy termin skraca okno wykorzystania skradzionego klucza,
	// dluzszy zmniejsza ruch odnowien w duzej flocie.
	AgentTTL time.Duration
}

// agentCertTTL zwraca czas zycia certyfikatu agenta.
func (ca *CA) agentCertTTL() time.Duration {
	if ca.AgentTTL > 0 {
		return ca.AgentTTL
	}
	return AgentCertTTL
}

// NotAfter zwraca koniec waznosci certyfikatu CA. Wygasajace CA unieruchamia
// cala flote naraz, wiec ten czas musi byc widoczny w metrykach.
func (ca *CA) NotAfter() time.Time {
	if ca == nil || ca.Certificate == nil {
		return time.Time{}
	}
	return ca.Certificate.NotAfter
}

// EnsureCA wczytuje CA z katalogu stanu lub tworzy nowe przy pierwszym starcie.
func EnsureCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("katalog stanu: %w", err)
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
	// Klucz CA jest najbardziej wrazliwym materialem w systemie.
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
		return nil, fmt.Errorf("ca.pem nie zawiera bloku PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca.pem: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca.key nie zawiera bloku PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca.key: %w", err)
	}
	return &CA{Certificate: cert, PrivateKey: key, PEM: certPEM}, nil
}

// IssueServerCert wystawia certyfikat dla listenerow control plane.
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

// IssuedCert opisuje wystawiony certyfikat agenta na potrzeby zapisu w bazie.
type IssuedCert struct {
	PEM         []byte
	Serial      string
	Fingerprint []byte
	NotBefore   time.Time
	NotAfter    time.Time
	CommonName  string
	// Wystawca pozwala policzyc, ilu hostow dotyczy wycofanie danego CA.
	IssuerSubject string
	IssuerSerial  string
}

// relayCertTTL jest krotszy niz czas zycia certyfikatu agenta. Relay stoi
// miedzy flota a centrala i widzi ruch calej lokalizacji, wiec okno
// wykorzystania jego skradzionego klucza ma byc mniejsze.
const relayCertTTL = 7 * 24 * time.Hour

// SignRelayCSR podpisuje CSR relaya. Tozsamosc relaya jest osobna od tozsamosci
// hosta: relay nie jest agentem i nie moze podszyc sie pod host samym
// certyfikatem, bo panel czyta rodzaj tozsamosci z URI SAN.
func (ca *CA) SignRelayCSR(csrPEM []byte, relayID string) (*IssuedCert, error) {
	return ca.signCSR(csrPEM, "relay", relayID, relayCertTTL)
}

// SignAgentCSR podpisuje CSR agenta, osadzajac tozsamosc hosta w URI SAN.
// Wszystkie pola podmiotu pochodzace z CSR sa ignorowane poza kluczem
// publicznym: tozsamosc nadaje control plane, nie zglaszajacy sie host.
func (ca *CA) SignAgentCSR(csrPEM []byte, hostID string) (*IssuedCert, error) {
	return ca.signCSR(csrPEM, "host", hostID, ca.agentCertTTL())
}

// signCSR wystawia certyfikat tozsamosci floty. Rodzaj tozsamosci wchodzi
// do URI SAN, wiec nie da sie uzyc certyfikatu relaya jako certyfikatu hosta
// ani odwrotnie.
func (ca *CA) signCSR(csrPEM []byte, kind, id string, ttl time.Duration) (*IssuedCert, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("CSR nie zawiera bloku PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("podpis CSR: %w", err)
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
		// Relay wystepuje w obu rolach: jako serwer wobec agentow swojej
		// lokalizacji i jako klient wobec centrali. Nazwy sieciowe bierzemy
		// z CSR, bo to relay wie, pod jakim adresem go widac; tozsamoscia
		// pozostaje URI SAN nadany przez panel, a nie te nazwy.
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		template.DNSNames = csr.DNSNames
		template.IPAddresses = csr.IPAddresses
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, csr.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &IssuedCert{
		PEM:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:        serial.String(),
		Fingerprint:   sum[:],
		NotBefore:     template.NotBefore,
		NotAfter:      template.NotAfter,
		IssuerSubject: ca.Certificate.Subject.CommonName,
		IssuerSerial:  ca.Certificate.SerialNumber.String(),
		CommonName:    id,
	}, nil
}

// HostIDFromCert wyciaga tozsamosc hosta z URI SAN certyfikatu klienta.
func HostIDFromCert(cert *x509.Certificate) (string, error) {
	return identityFromCert(cert, "host")
}

// RelayIDFromCert zwraca tozsamosc relaya. Rodzaj tozsamosci jest sprawdzany,
// wiec certyfikat hosta nie przejdzie jako certyfikat relaya.
func RelayIDFromCert(cert *x509.Certificate) (string, error) {
	return identityFromCert(cert, "relay")
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
	return "", fmt.Errorf("certyfikat nie zawiera tozsamosci %s://%s/<id>", identityScheme, kind)
}

// Fingerprint liczy SHA-256 z DER certyfikatu.
func Fingerprint(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
