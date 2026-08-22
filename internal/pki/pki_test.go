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
		t.Fatalf("pierwsze utworzenie CA: %v", err)
	}
	second, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("ponowne wczytanie CA: %v", err)
	}

	// Restart control plane nie moze uniewaznic certyfikatow calej floty.
	if first.Certificate.SerialNumber.Cmp(second.Certificate.SerialNumber) != 0 {
		t.Fatal("ponowny start wygenerowal nowe CA zamiast wczytac istniejace")
	}
	if !second.Certificate.IsCA {
		t.Fatal("wczytany certyfikat nie jest CA")
	}
}

func TestSignAgentCSRNadajeTozsamoscSerwera(t *testing.T) {
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatalf("CA: %v", err)
	}

	const hostID = "3f2a9c1e-0000-4000-8000-000000000001"
	// Host podaje w CSR cudza tozsamosc; control plane musi ja zignorowac.
	csrPEM := makeCSR(t, "zupelnie-inny-host")

	issued, err := ca.SignAgentCSR(csrPEM, hostID)
	if err != nil {
		t.Fatalf("podpisanie CSR: %v", err)
	}

	block, _ := pem.Decode(issued.PEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsowanie certyfikatu: %v", err)
	}

	got, err := HostIDFromCert(cert)
	if err != nil {
		t.Fatalf("odczyt tozsamosci: %v", err)
	}
	if got != hostID {
		t.Fatalf("tozsamosc = %q, oczekiwano %q", got, hostID)
	}
	if cert.Subject.CommonName != hostID {
		t.Fatalf("CN = %q, oczekiwano %q", cert.Subject.CommonName, hostID)
	}
}

func TestSignAgentCSROdrzucaUszkodzonyPodpis(t *testing.T) {
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatalf("CA: %v", err)
	}

	csrPEM := makeCSR(t, "host")
	block, _ := pem.Decode(csrPEM)
	// Psujemy ostatni bajt podpisu CSR.
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	broken := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: block.Bytes})

	if _, err := ca.SignAgentCSR(broken, "host-id"); err == nil {
		t.Fatal("CSR z bledym podpisem zostal podpisany")
	}
}

func TestHostIDFromCertOdrzucaCertyfikatBezTozsamosci(t *testing.T) {
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	if _, err := HostIDFromCert(ca.Certificate); err == nil {
		t.Fatal("certyfikat bez URI SAN zostal uznany za tozsamosc hosta")
	}
}

func makeCSR(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("klucz: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
