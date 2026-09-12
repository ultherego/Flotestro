package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"

	"github.com/ultherego/flotestro/internal/pki"
)

func csr(t *testing.T, name string, dns []string, addresses []net.IP) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name}, DNSNames: dns, IPAddresses: addresses,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func newIssuer(t *testing.T) Issuer {
	t.Helper()
	trust, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return FromTrust(trust)
}

// TestTheIssuerGrantsTheIdentityOfAHost guards the rule that must not
// disappear when the place the key is kept in changes: the panel grants the
// identity rather than the requester. Everything in the CSR but the public key
// is ignored.
func TestTheIssuerGrantsTheIdentityOfAHost(t *testing.T) {
	w := newIssuer(t)
	cert, err := w.SignHost(context.Background(),
		csr(t, "somebody-elses-name", []string{"panel.example.com"}, nil), "host-1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cert.PEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "host-1" {
		t.Fatalf("common name = %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 0 {
		t.Fatalf("the certificate of the host carries names from the CSR: %v", leaf.DNSNames)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].Host != "host" {
		t.Fatalf("URI SAN = %v", leaf.URIs)
	}
}

// TestTheNamesOfARelayComeFromThePanel guards that the named ones replace the
// ones from the request as a whole. Adding them next to each other would leave
// the relay the possibility of adding a name the operator did not approve.
func TestTheNamesOfARelayComeFromThePanel(t *testing.T) {
	w := newIssuer(t)
	cert, err := w.SignRelay(context.Background(),
		csr(t, "relay", []string{"impersonated.example.com"}, nil),
		"relay-1", []string{"relay-waw-01.example.com", "192.168.56.70"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "relay-waw-01.example.com" {
		t.Fatalf("DNS names = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0] != "192.168.56.70" {
		t.Fatalf("addresses = %v", cert.IPAddresses)
	}
}

// TestTheFirstRegistrationOfARelayTakesTheNamesFromTheRequest guards the
// exception: at the first registration the panel has no names recorded yet, so
// it takes them from the only place it can - the request.
func TestTheFirstRegistrationOfARelayTakesTheNamesFromTheRequest(t *testing.T) {
	w := newIssuer(t)
	cert, err := w.SignRelay(context.Background(),
		csr(t, "relay", []string{"relay-waw-01.example.com"}, []net.IP{net.ParseIP("10.0.0.5")}),
		"relay-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || len(cert.IPAddresses) != 1 {
		t.Fatalf("names = %v, addresses = %v", cert.DNSNames, cert.IPAddresses)
	}
}

func TestTheTrustIsNotEmpty(t *testing.T) {
	bundle, err := newIssuer(t).Trust(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(bundle); block == nil {
		t.Fatal("the trust bundle carries no certificate")
	}
}
