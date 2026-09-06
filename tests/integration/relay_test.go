//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// domyslnaBrama wskazuje brame agentow floty testowej. Relay laczy sie tam
// tak samo jak agent - tylko innym rodzajem tozsamosci.
const domyslnaBrama = "https://192.168.56.10:8443"

// relayTestowy trzyma tozsamosc relaya zarejestrowanego na potrzeby testu.
type relayTestowy struct {
	ID    string
	Klucz *ecdsa.PrivateKey
	Cert  tls.Certificate
	Liscz *x509.Certificate
	Nazwy []string
}

// TestOdnowienieRelayaZachowujeNazwyZRejestru pilnuje wlasciwosci, dla ktorej
// odnowienie relaya jest osobnym RPC: nazwy sieciowe sa granica zaufania
// wobec agentow lokalizacji, wiec pochodza z rejestru panelu, a nie z zadania.
//
// Gdyby relay mogl je sobie wybrac przy odnowieniu, wystarczyloby jedno
// odnowienie, zeby wystapic agentom pod cudza nazwa.
func TestOdnowienieRelayaZachowujeNazwyZRejestru(t *testing.T) {
	h := newHarness(t)
	relay := h.zarejestrujRelay(t, []string{"relay-testowy.flotestro.test", "192.168.56.99"})

	// Certyfikat relaya zyje krocej niz certyfikat hosta: relay widzi ruch
	// calej lokalizacji, wiec okno uzycia skradzionego klucza ma byc mniejsze.
	zycie := relay.Liscz.NotAfter.Sub(relay.Liscz.NotBefore)
	if zycie > 8*24*time.Hour {
		t.Fatalf("certyfikat relaya zyje %s; dokument mowi o okolo siedmiu dniach", zycie)
	}

	odnowiony := h.odnowRelay(t, relay, []string{"relay-podszyty.flotestro.test"})
	if len(odnowiony.DNSNames) != 1 || odnowiony.DNSNames[0] != "relay-testowy.flotestro.test" {
		t.Fatalf("nazwy DNS po odnowieniu = %v; oczekiwano tych z rejestru", odnowiony.DNSNames)
	}
	if len(odnowiony.IPAddresses) != 1 || odnowiony.IPAddresses[0].String() != "192.168.56.99" {
		t.Fatalf("adresy po odnowieniu = %v", odnowiony.IPAddresses)
	}
	if odnowiony.NotAfter.Before(relay.Liscz.NotAfter) {
		t.Fatalf("odnowienie nie przesunelo terminu: %s -> %s",
			relay.Liscz.NotAfter, odnowiony.NotAfter)
	}
	// Rodzaj tozsamosci zostaje: certyfikatem relaya nadal nie da sie
	// podszyc pod hosta.
	if len(odnowiony.URIs) != 1 || odnowiony.URIs[0].Host != "relay" {
		t.Fatalf("URI SAN po odnowieniu = %v", odnowiony.URIs)
	}
}

// TestOdwolanyRelayNieOdnowiSie pilnuje, ze odwolanie relaya jest odcieciem,
// a nie przerwa do najblizszego odnowienia.
func TestOdwolanyRelayNieOdnowiSie(t *testing.T) {
	h := newHarness(t)
	relay := h.zarejestrujRelay(t, []string{"relay-odwolany.flotestro.test"})

	ctx := context.Background()
	if _, err := h.database(ctx).Exec(ctx,
		`update relays set revoked_at = now(), revocation_reason = 'test'
		 where id = $1::uuid`, relay.ID); err != nil {
		t.Fatal(err)
	}

	_, status, tresc := h.odnowRelaySurowo(t, relay, relay.Nazwy)
	if status == http.StatusOK {
		t.Fatal("odwolany relay odnowil certyfikat")
	}
	if !bytes.Contains(tresc, []byte("odwolany")) {
		t.Fatalf("odmowa bez powodu: %s %s", http.StatusText(status), tresc)
	}
}

// zarejestrujRelay wprowadza do floty relay, ktorego nie ma.
//
// Relay laboratoryjny znika razem z testem: wpis w rejestrze zostalby
// widoczny w panelu jako lokalizacja, ktora nie istnieje.
func (h *harness) zarejestrujRelay(t *testing.T, nazwy []string) relayTestowy {
	t.Helper()
	// Pula polaczen musi powstac przed rejestracja sprzatania: sprzatanie
	// idzie w odwrotnej kolejnosci, wiec pula otwarta pozniej zamknelaby sie
	// przed usunieciem relaya i wpis zostalby we flocie.
	h.database(context.Background())

	var zamowienie struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "relay testowy", "site": "lab", "environment": "test",
		"kind": "relay", "purpose": "relay",
	}, &zamowienie, http.StatusCreated)

	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nazwa := uniqueSubject("relay-testowy")
	csrPEM := csrRelaya(t, klucz, nazwa, nazwy)

	tresc, err := json.Marshal(map[string]any{
		"enrollmentToken": zamowienie.Token,
		"machineId":       nazwa,
		"hostname":        nazwa,
		"csrPem":          csrPEM,
		"clientRequestId": uuid.NewString(),
		"build":           map[string]any{"agentVersion": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	odpowiedz, status, body := h.wyslijDoEnrollmentu(t, tresc)
	if status != http.StatusOK {
		t.Fatalf("enrollment relaya odrzucony: %d %s", status, body)
	}
	var wynik struct {
		HostID         string `json:"hostId"`
		CertificatePem []byte `json:"certificatePem"`
	}
	if err := json.Unmarshal(odpowiedz, &wynik); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := h.database(ctx).Exec(ctx,
			`delete from relays where id = $1::uuid`, wynik.HostID); err != nil {
			t.Logf("nie posprzatano relaya %s: %v", wynik.HostID, err)
		}
	})

	cert, lisc := paraTLS(t, klucz, wynik.CertificatePem)
	return relayTestowy{ID: wynik.HostID, Klucz: klucz, Cert: cert, Liscz: lisc, Nazwy: nazwy}
}

// odnowRelay wykonuje odnowienie i zwraca wystawiony certyfikat.
func (h *harness) odnowRelay(t *testing.T, relay relayTestowy, zadaneNazwy []string) *x509.Certificate {
	t.Helper()
	cert, status, tresc := h.odnowRelaySurowo(t, relay, zadaneNazwy)
	if status != http.StatusOK {
		t.Fatalf("odnowienie relaya odrzucone: %d %s", status, tresc)
	}
	return cert
}

// odnowRelaySurowo wola RPC odnowienia i zwraca takze odpowiedz odmowna.
func (h *harness) odnowRelaySurowo(t *testing.T, relay relayTestowy,
	zadaneNazwy []string) (*x509.Certificate, int, []byte) {
	t.Helper()
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := csrRelaya(t, klucz, relay.ID, zadaneNazwy)
	tresc, err := json.Marshal(map[string]any{
		"clientRequestId": uuid.NewString(),
		"csrPem":          csrPEM,
		"build":           map[string]any{"agentVersion": "test"},
		"advertisedNames": zadaneNazwy,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Odnowienie idzie przez mTLS obecnym certyfikatem relaya: to on jest
	// dowodem tozsamosci, a nie tresc zadania.
	klient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{relay.Cert},
			RootCAs:      pulaZaufaniaTestu(),
			MinVersion:   tls.VersionTLS13,
		}},
	}
	adres := envOr("FLOTESTRO_TEST_GATEWAY", domyslnaBrama) +
		"/flotestro.agent.v1.RelayService/RenewCertificate"
	zadanie, err := http.NewRequest(http.MethodPost, adres, bytes.NewReader(tresc))
	if err != nil {
		t.Fatal(err)
	}
	zadanie.Header.Set("Content-Type", "application/json")
	odpowiedz, err := klient.Do(zadanie)
	if err != nil {
		t.Fatalf("odnowienie relaya: %v", err)
	}
	defer odpowiedz.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(odpowiedz.Body, 1<<16))
	if odpowiedz.StatusCode != http.StatusOK {
		return nil, odpowiedz.StatusCode, body
	}

	var wynik struct {
		CertificatePem []byte `json:"certificatePem"`
	}
	if err := json.Unmarshal(body, &wynik); err != nil {
		t.Fatal(err)
	}
	_, lisc := paraTLS(t, klucz, wynik.CertificatePem)
	return lisc, odpowiedz.StatusCode, body
}

// csrRelaya sklada wniosek o certyfikat z nazwami sieciowymi.
func csrRelaya(t *testing.T, klucz *ecdsa.PrivateKey, nazwa string, nazwy []string) []byte {
	t.Helper()
	wniosek := &x509.CertificateRequest{Subject: pkix.Name{CommonName: nazwa}}
	for _, wpis := range nazwy {
		if adres := net.ParseIP(wpis); adres != nil {
			wniosek.IPAddresses = append(wniosek.IPAddresses, adres)
			continue
		}
		wniosek.DNSNames = append(wniosek.DNSNames, wpis)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, wniosek, klucz)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// paraTLS sklada certyfikat z kluczem i zwraca takze sparsowany lisc.
func paraTLS(t *testing.T, klucz *ecdsa.PrivateKey, certPEM []byte) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	blok, _ := pem.Decode(certPEM)
	if blok == nil {
		t.Fatal("odpowiedz nie zawiera certyfikatu w PEM")
	}
	lisc, err := x509.ParseCertificate(blok.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{blok.Bytes}, PrivateKey: klucz, Leaf: lisc}, lisc
}

// pulaZaufaniaTestu bierze bundle CA floty stad, skad biora go agenci.
func pulaZaufaniaTestu() *x509.CertPool {
	pula, err := x509.SystemCertPool()
	if err != nil || pula == nil {
		pula = x509.NewCertPool()
	}
	if bundle, err := os.ReadFile(envOr("FLOTESTRO_TEST_CA", "/var/lib/flotestro/ca.pem")); err == nil {
		pula.AppendCertsFromPEM(bundle)
	}
	return pula
}

// wyslijDoEnrollmentu wola publiczny endpoint enrollmentu floty testowej.
func (h *harness) wyslijDoEnrollmentu(t *testing.T, tresc []byte) ([]byte, int, []byte) {
	t.Helper()
	adres := envOr("FLOTESTRO_TEST_ENROLLMENT", domyslnyEnrollment) +
		"/flotestro.agent.v1.EnrollmentService/Enroll"
	klient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pulaZaufaniaTestu(), MinVersion: tls.VersionTLS12,
		}},
	}
	zadanie, err := http.NewRequest(http.MethodPost, adres, bytes.NewReader(tresc))
	if err != nil {
		t.Fatal(err)
	}
	zadanie.Header.Set("Content-Type", "application/json")
	odpowiedz, err := klient.Do(zadanie)
	if err != nil {
		t.Fatalf("enrollment: %v", err)
	}
	defer odpowiedz.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(odpowiedz.Body, 1<<16))
	return body, odpowiedz.StatusCode, body
}
