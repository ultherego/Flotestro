package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

func TestEnsureCAIsStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()

	first, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("creating the CA for the first time: %v", err)
	}
	second, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("reading the CA again: %v", err)
	}

	// A restart of the control plane must not invalidate the whole fleet's certificates.
	if first.Certificate.SerialNumber.Cmp(second.Certificate.SerialNumber) != 0 {
		t.Fatal("the second start generated a new CA instead of reading the existing one")
	}
	if !second.Certificate.IsCA {
		t.Fatal("the certificate that was read is not a CA")
	}
}

func TestSignAgentCSRGrantsTheServersIdentity(t *testing.T) {
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatalf("CA: %v", err)
	}

	const hostID = "3f2a9c1e-0000-4000-8000-000000000001"
	// The host puts somebody else's identity in the CSR; the control plane
	// has to ignore it.
	csrPEM := makeCSR(t, "an-entirely-different-host")

	issued, err := ca.SignAgentCSR(csrPEM, hostID)
	if err != nil {
		t.Fatalf("signing the CSR: %v", err)
	}

	block, _ := pem.Decode(issued.PEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}

	got, err := HostIDFromCert(cert)
	if err != nil {
		t.Fatalf("reading the identity: %v", err)
	}
	if got != hostID {
		t.Fatalf("identity = %q, expected %q", got, hostID)
	}
	if cert.Subject.CommonName != hostID {
		t.Fatalf("CN = %q, expected %q", cert.Subject.CommonName, hostID)
	}
}

func TestSignAgentCSRRejectsABrokenSignature(t *testing.T) {
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatalf("CA: %v", err)
	}

	csrPEM := makeCSR(t, "host")
	block, _ := pem.Decode(csrPEM)
	// We break the last byte of the CSR's signature.
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	broken := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: block.Bytes})

	if _, err := ca.SignAgentCSR(broken, "host-id"); err == nil {
		t.Fatal("a CSR with a bad signature was signed")
	}
}

func TestHostIDFromCertRejectsACertificateWithoutAnIdentity(t *testing.T) {
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	if _, err := HostIDFromCert(ca.Certificate); err == nil {
		t.Fatal("a certificate without a URI SAN was accepted as a host identity")
	}
}

func makeCSR(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
