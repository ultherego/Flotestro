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

// kluczBezEksportu udaje klucz sprzetowy: podpisuje, ale nie oddaje materialu
// i na dysk zapisuje wylacznie uchwyt.
type kluczBezEksportu struct {
	klucz crypto.Signer
}

func (k *kluczBezEksportu) Publiczny() crypto.PublicKey { return k.klucz.Public() }
func (k *kluczBezEksportu) Signer() crypto.Signer       { return k.klucz }
func (k *kluczBezEksportu) Zapisz(katalog string) error {
	return os.WriteFile(filepath.Join(katalog, NazwaKlucza), []byte("uchwyt-tpm\n"), 0o600)
}

// zrodloBezEksportu jest profilem, w ktorym klucz nie jest plikiem PEM.
type zrodloBezEksportu struct {
	klucze map[string]crypto.Signer
}

func (z *zrodloBezEksportu) Nowy() (Klucz, error) {
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	z.klucze["ostatni"] = klucz
	return &kluczBezEksportu{klucz: klucz}, nil
}

func (z *zrodloBezEksportu) Wczytaj(katalog string) (Klucz, error) {
	tresc, err := os.ReadFile(filepath.Join(katalog, NazwaKlucza))
	if err != nil {
		return nil, err
	}
	if string(tresc) != "uchwyt-tpm\n" {
		return nil, errors.New("to nie jest uchwyt tego profilu")
	}
	return &kluczBezEksportu{klucz: z.klucze["ostatni"]}, nil
}

// wystawCertyfikat podpisuje certyfikat dla podanego klucza publicznego.
func wystawCertyfikat(t *testing.T, publiczny crypto.PublicKey) (certPEM, caPEM []byte) {
	t.Helper()
	kluczCA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	szablonCA := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "CA testu"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	derCA, err := x509.CreateCertificate(rand.Reader, szablonCA, szablonCA, &kluczCA.PublicKey, kluczCA)
	if err != nil {
		t.Fatal(err)
	}
	certCA, err := x509.ParseCertificate(derCA)
	if err != nil {
		t.Fatal(err)
	}
	uri := &url.URL{Scheme: "flotestro", Host: "host", Path: "/host-1"}
	szablon := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "host-1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, szablon, certCA, publiczny, kluczCA)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCA})
}

// TestGeneracjaZKluczemBezEksportu pilnuje wlasciwosci, dla ktorej klucz jest
// w tym magazynie interfejsem, a nie bajtami: klucz sprzetowy nie oddaje
// materialu, a tozsamosc ma dzialac tak samo.
func TestGeneracjaZKluczemBezEksportu(t *testing.T) {
	zrodlo := &zrodloBezEksportu{klucze: map[string]crypto.Signer{}}
	magazyn := NowyZeZrodlem(t.TempDir(), zrodlo)

	klucz, err := magazyn.NowyKlucz()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, caPEM := wystawCertyfikat(t, klucz.Publiczny())

	tozsamosc, err := magazyn.Zatwierdz(Generacja{
		Klucz: klucz, CertyfikatPEM: certPEM, ZaufaniePEM: caPEM,
	})
	if err != nil {
		t.Fatalf("generacja z kluczem sprzetowym odrzucona: %v", err)
	}
	if tozsamosc.HostID != "host-1" {
		t.Fatalf("tozsamosc = %q", tozsamosc.HostID)
	}
	if tozsamosc.Certificate.PrivateKey == nil {
		t.Fatal("tozsamosc bez klucza do uscisku TLS")
	}

	// Na dysku lezy uchwyt, a nie klucz. Magazyn musi umiec go wczytac
	// z powrotem przez to samo zrodlo.
	wczytana, err := magazyn.Biezaca()
	if err != nil {
		t.Fatalf("wczytanie generacji sprzetowej: %v", err)
	}
	if wczytana.HostID != "host-1" {
		t.Fatalf("wczytana tozsamosc = %q", wczytana.HostID)
	}
}

// TestCertyfikatNieDoKluczaJestOdrzucany pilnuje, ze sprawdzenie pary nadal
// dziala, choc nie sklada juz klucza z certyfikatem.
func TestCertyfikatNieDoKluczaJestOdrzucany(t *testing.T) {
	zrodlo := &zrodloBezEksportu{klucze: map[string]crypto.Signer{}}
	magazyn := NowyZeZrodlem(t.TempDir(), zrodlo)
	klucz, err := magazyn.NowyKlucz()
	if err != nil {
		t.Fatal(err)
	}
	obcy, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, caPEM := wystawCertyfikat(t, &obcy.PublicKey)

	_, err = magazyn.Zatwierdz(Generacja{Klucz: klucz, CertyfikatPEM: certPEM, ZaufaniePEM: caPEM})
	if !errors.Is(err, ErrParaKluczy) {
		t.Fatalf("cudzy certyfikat przyjety: %v", err)
	}
}

// TestWniosekJestPodpisanyKluczem pilnuje, ze CSR powstaje kluczem, ktorego
// nie da sie odczytac - podpisywanie wystarczy.
func TestWniosekJestPodpisanyKluczem(t *testing.T) {
	zrodlo := &zrodloBezEksportu{klucze: map[string]crypto.Signer{}}
	klucz, err := zrodlo.Nowy()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := Wniosek(klucz, "host-1", []string{"host.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	blok, _ := pem.Decode(csrPEM)
	if blok == nil {
		t.Fatal("wniosek nie jest w PEM")
	}
	csr, err := x509.ParseCertificateRequest(blok.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("podpis wniosku: %v", err)
	}
	if csr.Subject.CommonName != "host-1" || len(csr.DNSNames) != 1 {
		t.Fatalf("wniosek = %+v", csr.Subject)
	}
}
