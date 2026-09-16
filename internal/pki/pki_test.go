package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
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

// A certificate without its key is the state of a restore that forgot the
// key, or of a key removed by hand. The fleet trusts that certificate, so
// a fresh CA in its place would cut every host off: the panel has to
// refuse to start and say which file is missing.
func TestAMissingKeyNextToTheCertificateIsNotANewCA(t *testing.T) {
	dir := t.TempDir()
	first, err := EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCA(dir); !errors.Is(err, ErrIssuerKeyUnavailable) {
		t.Fatalf("a missing key gave %v, want %v", err, ErrIssuerKeyUnavailable)
	}
	if _, err := Open(dir); !errors.Is(err, ErrIssuerKeyUnavailable) {
		t.Fatalf("open with a missing key gave %v, want %v", err, ErrIssuerKeyUnavailable)
	}
	// The certificate the fleet trusts is still there, untouched.
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(certPEM) != string(first.PEM) {
		t.Fatal("the certificate was replaced")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); !os.IsNotExist(err) {
		t.Fatal("a new key was generated next to the old certificate")
	}
	// The other half of the pair missing is a mismatch of the directory,
	// not a missing key: the fleet has nothing that trusts a key alone.
	if err := os.Remove(filepath.Join(dir, "ca.pem")); err != nil {
		t.Fatal(err)
	}
	keyDir := t.TempDir()
	if _, err := Init(keyDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(keyDir, "ca.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCA(keyDir); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("a key without a certificate gave %v, want %v", err, ErrStateMismatch)
	}
}

// A key that belongs to another certificate is detected at open: a CA
// signing with somebody else's key issues certificates no host can
// verify, and nothing before the first failed renewal would say so.
func TestAMismatchedPairIsDetected(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if _, err := Init(other); err != nil {
		t.Fatal(err)
	}
	otherKey, err := os.ReadFile(filepath.Join(other, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("a mismatched pair gave %v, want %v", err, ErrStateMismatch)
	}
	if _, err := EnsureCA(dir); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("EnsureCA over a mismatched pair gave %v, want %v", err, ErrStateMismatch)
	}
	// Initialisation refuses a directory that holds anything.
	if _, err := Init(dir); !errors.Is(err, ErrMaterialExists) {
		t.Fatalf("Init over material gave %v, want %v", err, ErrMaterialExists)
	}
	// An empty directory holds nothing to open.
	if _, err := Open(t.TempDir()); !errors.Is(err, ErrNoMaterial) {
		t.Fatalf("open of an empty directory gave %v, want %v", err, ErrNoMaterial)
	}
}

// The issuer identifier is derived from the certificate: the same on every
// panel, different for every CA, and shaped like the UUID column that
// records it.
func TestTheIssuerIDIsStableAndUnique(t *testing.T) {
	ca, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shape := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !shape.MatchString(ca.IssuerID()) {
		t.Fatalf("issuer id %q is not a UUID", ca.IssuerID())
	}
	if ca.IssuerID() != IssuerIDOf(ca.Certificate) {
		t.Fatal("the issuer id differs between the CA and its certificate")
	}
	if ca.IssuerID() == other.IssuerID() {
		t.Fatal("two CAs share an issuer id")
	}
	issued, err := ca.SignAgentCSR(makeCSR(t, "host"), "host-id")
	if err != nil {
		t.Fatal(err)
	}
	if issued.IssuerID != ca.IssuerID() {
		t.Fatalf("the issued certificate names the issuer %s, want %s", issued.IssuerID, ca.IssuerID())
	}
}
