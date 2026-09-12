package identitystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// nonExportableKey pretends to be a hardware key: it signs but does not give
// out the material, and writes only a handle to disk.
type nonExportableKey struct {
	key crypto.Signer
}

func (k *nonExportableKey) Public() crypto.PublicKey { return k.key.Public() }
func (k *nonExportableKey) Signer() crypto.Signer    { return k.key }
func (k *nonExportableKey) Save(dir string) error {
	return os.WriteFile(filepath.Join(dir, KeyName), []byte("tpm-handle\n"), 0o600)
}

// nonExportableSource is a profile in which the key is not a PEM file.
type nonExportableSource struct {
	keys map[string]crypto.Signer
}

func (z *nonExportableSource) New() (Key, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	z.keys["last"] = key
	return &nonExportableKey{key: key}, nil
}

func (z *nonExportableSource) Load(dir string) (Key, error) {
	content, err := os.ReadFile(filepath.Join(dir, KeyName))
	if err != nil {
		return nil, err
	}
	if string(content) != "tpm-handle\n" {
		return nil, errors.New("this is not a handle of this profile")
	}
	return &nonExportableKey{key: z.keys["last"]}, nil
}

// issueCertificate signs a certificate for the given public key.
func issueCertificate(t *testing.T, public crypto.PublicKey) (certPEM, caPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	derCA, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certCA, err := x509.ParseCertificate(derCA)
	if err != nil {
		t.Fatal(err)
	}
	uri := &url.URL{Scheme: "flotestro", Host: "host", Path: "/host-1"}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "host-1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, certCA, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCA})
}

// TestAGenerationWithANonExportableKey guards the property for which a key is
// an interface in this store rather than bytes: a hardware key gives out no
// material, and the identity has to work just the same.
func TestAGenerationWithANonExportableKey(t *testing.T) {
	source := &nonExportableSource{keys: map[string]crypto.Signer{}}
	store := NewWithSource(t.TempDir(), source)

	key, err := store.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, caPEM := issueCertificate(t, key.Public())

	identity, err := store.Commit(Generation{
		Key: key, CertificatePEM: certPEM, TrustPEM: caPEM,
	})
	if err != nil {
		t.Fatalf("a generation with a hardware key was rejected: %v", err)
	}
	if identity.HostID != "host-1" {
		t.Fatalf("identity = %q", identity.HostID)
	}
	if identity.Certificate.PrivateKey == nil {
		t.Fatal("an identity without a key for the TLS handshake")
	}

	// A handle lies on disk rather than a key. The store has to be able to
	// load it back through the same source.
	loaded, err := store.Current()
	if err != nil {
		t.Fatalf("loading the hardware generation: %v", err)
	}
	if loaded.HostID != "host-1" {
		t.Fatalf("the loaded identity = %q", loaded.HostID)
	}
}

// TestACertificateForAnotherKeyIsRejected guards that the check of the pair
// still works, although it no longer combines the key with the certificate.
func TestACertificateForAnotherKeyIsRejected(t *testing.T) {
	source := &nonExportableSource{keys: map[string]crypto.Signer{}}
	store := NewWithSource(t.TempDir(), source)
	key, err := store.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, caPEM := issueCertificate(t, &foreign.PublicKey)

	_, err = store.Commit(Generation{Key: key, CertificatePEM: certPEM, TrustPEM: caPEM})
	if !errors.Is(err, ErrKeyPair) {
		t.Fatalf("somebody else's certificate was accepted: %v", err)
	}
}

// TestTheRequestIsSignedWithTheKey guards that a CSR comes into being with a
// key that cannot be read - signing is enough.
func TestTheRequestIsSignedWithTheKey(t *testing.T) {
	source := &nonExportableSource{keys: map[string]crypto.Signer{}}
	key, err := source.New()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := Request(key, "host-1", []string{"host.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("the request is not in PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("the request signature: %v", err)
	}
	if csr.Subject.CommonName != "host-1" || len(csr.DNSNames) != 1 {
		t.Fatalf("request = %+v", csr.Subject)
	}
}
