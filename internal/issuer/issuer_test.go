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

func csr(t *testing.T, nazwa string, dns []string, adresy []net.IP) []byte {
	t.Helper()
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: nazwa}, DNSNames: dns, IPAddresses: adresy,
	}, klucz)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func wystawca(t *testing.T) Wystawca {
	t.Helper()
	trust, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return ZZaufania(trust)
}

// TestWystawcaNadajeTozsamoscHosta pilnuje zasady, ktora nie moze zniknac
// przy zmianie miejsca przechowywania klucza: tozsamosc nadaje panel, a nie
// wnioskujacy. Wszystko z CSR poza kluczem publicznym jest ignorowane.
func TestWystawcaNadajeTozsamoscHosta(t *testing.T) {
	w := wystawca(t)
	cert, err := w.PodpiszHosta(context.Background(),
		csr(t, "cudza-nazwa", []string{"panel.example.com"}, nil), "host-1")
	if err != nil {
		t.Fatal(err)
	}
	blok, _ := pem.Decode(cert.PEM)
	lisc, err := x509.ParseCertificate(blok.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if lisc.Subject.CommonName != "host-1" {
		t.Fatalf("nazwa wlasna = %q", lisc.Subject.CommonName)
	}
	if len(lisc.DNSNames) != 0 {
		t.Fatalf("certyfikat hosta niesie nazwy z CSR: %v", lisc.DNSNames)
	}
	if len(lisc.URIs) != 1 || lisc.URIs[0].Host != "host" {
		t.Fatalf("URI SAN = %v", lisc.URIs)
	}
}

// TestNazwyRelayaPochodzaZPanelu pilnuje, ze wskazane nazwy zastepuja te
// z wniosku w calosci. Dopisanie ich obok zostawialoby relayowi mozliwosc
// dolozenia sobie nazwy, ktorej operator nie zatwierdzil.
func TestNazwyRelayaPochodzaZPanelu(t *testing.T) {
	w := wystawca(t)
	cert, err := w.PodpiszRelay(context.Background(),
		csr(t, "relay", []string{"podszyty.example.com"}, nil),
		"relay-1", []string{"relay-waw-01.example.com", "192.168.56.70"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "relay-waw-01.example.com" {
		t.Fatalf("nazwy DNS = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0] != "192.168.56.70" {
		t.Fatalf("adresy = %v", cert.IPAddresses)
	}
}

// TestPierwszaRejestracjaRelayaBierzeNazwyZWniosku pilnuje wyjatku: przy
// pierwszej rejestracji panel nie ma jeszcze zapisanych nazw, wiec bierze je
// stamtad, skad jedynie moze - z wniosku.
func TestPierwszaRejestracjaRelayaBierzeNazwyZWniosku(t *testing.T) {
	w := wystawca(t)
	cert, err := w.PodpiszRelay(context.Background(),
		csr(t, "relay", []string{"relay-waw-01.example.com"}, []net.IP{net.ParseIP("10.0.0.5")}),
		"relay-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || len(cert.IPAddresses) != 1 {
		t.Fatalf("nazwy = %v, adresy = %v", cert.DNSNames, cert.IPAddresses)
	}
}

func TestZaufanieNieJestPuste(t *testing.T) {
	bundle, err := wystawca(t).Zaufanie(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if blok, _ := pem.Decode(bundle); blok == nil {
		t.Fatal("bundle zaufania nie zawiera certyfikatu")
	}
}
