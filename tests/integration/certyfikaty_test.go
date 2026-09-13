//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

const powodCertyfikatu = "test integracyjny modulu certyfikatow"

type kluczCertyfikatuView struct {
	Path          string `json:"path"`
	Exists        bool   `json:"exists"`
	Mode          string `json:"mode"`
	WorldReadable bool   `json:"world_readable"`
	Reason        string `json:"reason"`
}

type certyfikatView struct {
	Path              string                `json:"path"`
	Subject           string                `json:"subject"`
	FingerprintSHA256 string                `json:"fingerprint_sha256"`
	NotAfter          *time.Time            `json:"not_after"`
	Source            string                `json:"source"`
	Renewal           string                `json:"renewal"`
	Status            string                `json:"status"`
	DaysToExpiry      *int                  `json:"days_to_expiry"`
	Watched           bool                  `json:"watched"`
	Managed           bool                  `json:"managed"`
	KeySecret         string                `json:"key_secret"`
	Key               *kluczCertyfikatuView `json:"key"`
	Reason            string                `json:"unavailable_reason"`
}

type celCertyfikatuView struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	KeyPath   string `json:"key_path"`
	KeySecret string `json:"key_secret"`
}

type raportCertyfikatowView struct {
	Certificates  []certyfikatView     `json:"certificates"`
	Targets       []celCertyfikatuView `json:"targets"`
	Status        string               `json:"status"`
	TrackingKnown bool                 `json:"tracking_known"`
	KeysKnown     bool                 `json:"keys_known"`
	Stale         bool                 `json:"stale"`
}

// paraTestowa wystawia certyfikat i klucz na potrzeby jednego przebiegu.
func paraTestowa(t *testing.T, nazwa string, waznosc time.Duration) (certPEM, kluczPEM, odcisk string) {
	t.Helper()
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("klucz: %v", err)
	}
	szablon := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: nazwa},
		DNSNames:              []string{nazwa},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(waznosc),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, szablon, szablon, &klucz.PublicKey, klucz)
	if err != nil {
		t.Fatalf("certyfikat: %v", err)
	}
	dane, err := x509.MarshalPKCS8PrivateKey(klucz)
	if err != nil {
		t.Fatalf("zapis klucza: %v", err)
	}
	suma := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dane})),
		hex.EncodeToString(suma[:])
}

// TestWdrozenieCertyfikatuZMagazynu przechodzi pelna droge modulu: obserwacja
// sciezki, wdrozenie certyfikatu z kluczem z magazynu i odczyt tego, co
// naprawde wyladowalo na hoscie.
func TestWdrozenieCertyfikatuZMagazynu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	nazwa := host.Hostname
	sciezka := fmt.Sprintf("/etc/pki/tls/certs/flotestro-integracja-%d.crt", time.Now().UnixNano())
	sciezkaKlucza := strings.Replace(strings.Replace(sciezka, "/certs/", "/private/", 1), ".crt", ".key", 1)

	certPEM, kluczPEM, odcisk := paraTestowa(t, nazwa, 40*24*time.Hour)
	sekret := nowySekret(t, h, kluczPEM)

	// Zakres obserwacji nie jest operacja na hoscie: zmienia to, czego panel
	// pilnuje, a nie stan maszyny.
	var cel celCertyfikatuView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/certificates/targets", map[string]any{
		"path": sciezka, "key_path": sciezkaKlucza, "key_secret": sekret.Name,
		"service": "integracja",
	}, &cel, http.StatusOK)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/certificates/targets?path="+sciezka, nil, nil, 0)
		// Plik zostaje na hoscie, jesli go nie usuniemy: kolejne przebiegi
		// zapelniaja rejestr celow i wypychaja z odczytu certyfikaty, ktore
		// host naprawde ma.
		for _, doUsuniecia := range []string{sciezka, sciezkaKlucza} {
			h.runOperation(host.ID, map[string]any{
				"action": "file.remove", "reason": powodCertyfikatu,
				"payload": map[string]any{"file": map[string]any{"path": doUsuniecia}},
			}, 2*time.Minute)
		}
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "certificate.deploy", "reason": powodCertyfikatu,
		"payload": map[string]any{"certificate": map[string]any{
			"path": sciezka, "key_path": sciezkaKlucza, "certificate": certPEM,
			"key_secret": map[string]any{"name": sekret.Name},
		}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("wdrozenie zakonczylo sie stanem %s: %+v", zadanie.State, proby)
	}

	raport := certyfikatyHosta(h, host.ID)
	wdrozony := znajdzCertyfikat(t, raport, sciezka)
	if wdrozony.FingerprintSHA256 != odcisk {
		t.Fatalf("na hoscie lezy certyfikat o odcisku %q, wdrozono %q",
			wdrozony.FingerprintSHA256, odcisk)
	}
	if !wdrozony.Managed || wdrozony.Source != "flotestro" {
		t.Errorf("certyfikat wdrozony przez panel opisany jako %+v", wdrozony)
	}
	if wdrozony.Status != "valid" || wdrozony.DaysToExpiry == nil || *wdrozony.DaysToExpiry < 30 {
		t.Errorf("ocena terminu = %s, dni = %v", wdrozony.Status, wdrozony.DaysToExpiry)
	}
	// Klucz prywatny nie moze byc czytelny dla nikogo poza wlascicielem.
	if wdrozony.Key == nil || !wdrozony.Key.Exists {
		t.Fatalf("panel nie zna stanu klucza: %+v", wdrozony.Key)
	}
	if wdrozony.Key.WorldReadable || wdrozony.Key.Mode != "0600" {
		t.Errorf("klucz ma prawa %q (world_readable=%v)", wdrozony.Key.Mode, wdrozony.Key.WorldReadable)
	}
	// Certmonger odpowiedzial, ze tego pliku nie pilnuje - to jest ustalenie,
	// a nie brak wiedzy.
	if !raport.TrackingKnown || wdrozony.Renewal != "manual" {
		t.Errorf("odnawianie opisane jako %q przy tracking_known=%v",
			wdrozony.Renewal, raport.TrackingKnown)
	}

	// Wartosc klucza nie moze byc nigdzie poza magazynem.
	fragment := strings.Split(strings.TrimSpace(kluczPEM), "\n")[1]
	sprawdzBrakWartosci(t, h, fragment)

	// Certyfikat z cudzym kluczem host odrzuca przed podmiana: na dysku
	// zostaje to, co dzialalo.
	obcyCert, _, _ := paraTestowa(t, nazwa, 40*24*time.Hour)
	odrzucone, _ := h.runOperation(host.ID, map[string]any{
		"action": "certificate.deploy", "reason": powodCertyfikatu,
		"payload": map[string]any{"certificate": map[string]any{
			"path": sciezka, "key_path": sciezkaKlucza, "certificate": obcyCert,
			"key_secret": map[string]any{"name": sekret.Name},
		}},
	}, 3*time.Minute)
	if odrzucone.State == "succeeded" {
		t.Fatal("certyfikat niepasujacy do klucza zostal wdrozony")
	}
	po := znajdzCertyfikat(t, certyfikatyHosta(h, host.ID), sciezka)
	if po.FingerprintSHA256 != odcisk {
		t.Fatalf("po odrzuconym wdrozeniu na hoscie lezy %q", po.FingerprintSHA256)
	}
}

// TestCertyfikatPozaZakresemOdpadaPrzyZlecaniu pilnuje granicy modulu:
// magazyn zaufania i tozsamosc agenta nie sa certyfikatami uslug.
func TestCertyfikatPozaZakresemOdpadaPrzyZlecaniu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	certPEM, _, _ := paraTestowa(t, host.Hostname, 40*24*time.Hour)

	poza := []string{
		"/etc/pki/ca-trust/source/anchors/obcy.crt",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/certs/3513523f.0",
		"/etc/flotestro/agent/agent.crt",
		"/etc/passwd",
	}
	for _, sciezka := range poza {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
			"action": "certificate.deploy", "reason": powodCertyfikatu,
			"payload": map[string]any{"certificate": map[string]any{
				"path": sciezka, "certificate": certPEM,
			}},
		}, nil, http.StatusBadRequest)

		// Ta sama regula obowiazuje zakres obserwacji: sciezka, ktorej panel
		// nie zapisze, nie jest tez sciezka, o ktorej tresc pyta.
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/certificates/targets",
			map[string]any{"path": sciezka}, nil, http.StatusBadRequest)
	}

	// Popsuty material tez odpada przy zlecaniu, a nie po zatwierdzeniu.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "certificate.deploy", "reason": powodCertyfikatu,
		"payload": map[string]any{"certificate": map[string]any{
			"path": "/etc/ssl/private/flotestro-integracja.crt", "certificate": "to nie jest PEM",
		}},
	}, nil, http.StatusBadRequest)
}

// TestSkanCertyfikatowNieZgadujeStanu pilnuje, zeby brak wiedzy mial powod,
// a pusty wynik nie udawal hosta bez certyfikatow.
func TestSkanCertyfikatowNieZgadujeStanu(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	sciezka := fmt.Sprintf("/etc/ssl/certs/flotestro-nie-ma-%d.pem", time.Now().UnixNano())

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "certificate.scan",
		"payload": map[string]any{"certificate": map[string]any{
			"targets": []map[string]any{{"path": sciezka}},
		}},
	}, 2*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("skan zakonczyl sie stanem %s: %+v", zadanie.State, proby)
	}

	raport := certyfikatyHosta(h, host.ID)
	brakujacy := znajdzCertyfikat(t, raport, sciezka)
	if brakujacy.Reason == "" {
		t.Fatal("plik, ktorego nie ma, nie zostal opisany powodem")
	}
	if brakujacy.Status != "unknown" {
		t.Errorf("plik nieodczytany oceniony jako %q", brakujacy.Status)
	}
	if brakujacy.NotAfter != nil {
		t.Errorf("plik nieodczytany ma termin waznosci %v", brakujacy.NotAfter)
	}
	if !raport.TrackingKnown {
		t.Error("nie ustalono, co odnawia certyfikaty na tym hoscie")
	}
}

// TestOdnowienieBezOpiekiOdmawia pilnuje granicy odnowienia: panel nie podaje
// tresci certyfikatu, tylko prosi demona hosta - a host bez zlecenia nie ma
// czego odnowic i musi to powiedziec wprost.
func TestOdnowienieBezOpiekiOdmawia(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	sciezka := fmt.Sprintf("/etc/pki/tls/certs/flotestro-bez-opieki-%d.crt", time.Now().UnixNano())

	// Kampania odnawiajaca ten sam certyfikat na calej flocie moze wskazac
	// tylko sciezke: identyfikator zlecenia certmongera jest inny na kazdym
	// hoscie. Dlatego sciezka jest tu dozwolonym sposobem wskazania.
	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "certificate.renew", "reason": powodCertyfikatu,
		"payload": map[string]any{"certificate": map[string]any{"path": sciezka}},
	}, 2*time.Minute)
	if zadanie.State == "succeeded" {
		t.Fatal("odnowiono certyfikat, ktorego nikt nie pilnuje")
	}
	if len(proby) == 0 || !strings.Contains(proby[len(proby)-1].Message, "certmonger") {
		t.Fatalf("odmowa nie mowi, czego brakuje: %+v", proby)
	}

	// Bez zlecenia i bez sciezki nie ma czego odnawiac - i to odpada juz
	// przy zlecaniu.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "certificate.renew", "reason": powodCertyfikatu,
		"payload": map[string]any{"certificate": map[string]any{}},
	}, nil, http.StatusBadRequest)
}

// certyfikatyHosta czyta zakladke certyfikatow hosta.
func certyfikatyHosta(h *harness, hostID string) raportCertyfikatowView {
	h.t.Helper()
	var raport raportCertyfikatowView
	h.get("/api/v1/hosts/"+hostID+"/certificates", &raport)
	return raport
}

func znajdzCertyfikat(t *testing.T, raport raportCertyfikatowView, sciezka string) certyfikatView {
	t.Helper()
	for _, certyfikat := range raport.Certificates {
		if certyfikat.Path == sciezka {
			return certyfikat
		}
	}
	t.Fatalf("zakladka nie zna pliku %s: %+v", sciezka, raport.Certificates)
	return certyfikatView{}
}

// sprawdzBrakWartosci pilnuje wlasciwosci, dla ktorej magazyn istnieje:
// wartosc klucza nie moze pojawic sie w zadaniu, audycie ani inwentarzu.
func sprawdzBrakWartosci(t *testing.T, h *harness, fragment string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := h.database(ctx)
	wzorzec := "%" + fragment + "%"

	zapytania := map[string]string{
		"jobs":                    `select count(*) from jobs where payload::text like $1`,
		"job_attempts":            `select count(*) from job_attempts where coalesce(result_detail::text, '') || coalesce(message, '') like $1`,
		"audit_events":            `select count(*) from audit_events where detail::text like $1`,
		"host_module_inventory":   `select count(*) from host_module_inventory where payload::text like $1`,
		"certificate_deployments": `select count(*) from certificate_deployments where certificate like $1`,
	}
	for tabela, zapytanie := range zapytania {
		var ile int
		if err := pool.QueryRow(ctx, zapytanie, wzorzec).Scan(&ile); err != nil {
			t.Fatalf("%s: %v", tabela, err)
		}
		if ile != 0 {
			t.Fatalf("wartosc klucza trafila do tabeli %s (%d wierszy)", tabela, ile)
		}
	}
}

// urzadTestowy wystawia urzad na potrzeby jednego przebiegu testu rotacji.
func urzadTestowy(t *testing.T, nazwa string) (certPEM, kluczPEM string) {
	t.Helper()
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("klucz urzedu: %v", err)
	}
	szablon := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: nazwa},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(8760 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, szablon, szablon, &klucz.PublicKey, klucz)
	if err != nil {
		t.Fatalf("urzad: %v", err)
	}
	dane, err := x509.MarshalPKCS8PrivateKey(klucz)
	if err != nil {
		t.Fatalf("zapis klucza urzedu: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dane}))
}

// paraZUrzedu wystawia certyfikat uslugi podpisany wskazanym urzedem.
type paraZUrzedu struct {
	certyfikat string
	klucz      string
	odcisk     string
}

func liscZUrzedu(t *testing.T, nazwa, urzadPEM, kluczUrzeduPEM string) paraZUrzedu {
	t.Helper()
	blokUrzedu, _ := pem.Decode([]byte(urzadPEM))
	urzad, err := x509.ParseCertificate(blokUrzedu.Bytes)
	if err != nil {
		t.Fatalf("urzad: %v", err)
	}
	blokKlucza, _ := pem.Decode([]byte(kluczUrzeduPEM))
	kluczUrzedu, err := x509.ParsePKCS8PrivateKey(blokKlucza.Bytes)
	if err != nil {
		t.Fatalf("klucz urzedu: %v", err)
	}
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("klucz liscia: %v", err)
	}
	szablon := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: nazwa},
		DNSNames:              []string{nazwa},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(720 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, szablon, urzad, &klucz.PublicKey, kluczUrzedu)
	if err != nil {
		t.Fatalf("lisc: %v", err)
	}
	dane, err := x509.MarshalPKCS8PrivateKey(klucz)
	if err != nil {
		t.Fatalf("zapis klucza liscia: %v", err)
	}
	suma := sha256.Sum256(der)
	return paraZUrzedu{
		certyfikat: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		klucz:      string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dane})),
		odcisk:     hex.EncodeToString(suma[:]),
	}
}

// TestWidokFlotyMaOsWaznosci sprawdza to, czego posortowana lista nie mowi:
// kiedy bedzie nastepna fala odnowien. Lista odpowiada na pytanie "co pali
// sie teraz", os - na pytanie "co planowac".
func TestWidokFlotyMaOsWaznosci(t *testing.T) {
	h := newHarness(t)
	var widok struct {
		Items []struct {
			DaysToExpiry *int `json:"days_to_expiry"`
		} `json:"items"`
		Timeline []struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"timeline"`
	}
	h.get("/api/v1/certificates", &widok)
	if len(widok.Items) == 0 {
		t.Skip("flota nie zglasza zadnego certyfikatu")
	}
	if len(widok.Timeline) == 0 {
		t.Fatal("widok floty nie ma osi waznosci")
	}

	okna := map[string]int{}
	suma := 0
	for _, okno := range widok.Timeline {
		okna[okno.Reason] = okno.Count
		suma += okno.Count
	}
	for _, nazwa := range []string{"expired", "7 days", "30 days", "90 days", "later", "no expiry"} {
		if _, mamy := okna[nazwa]; !mamy {
			t.Errorf("os nie ma okna %q: %+v", widok.Timeline, nazwa)
		}
	}
	// Kazdy certyfikat nalezy dokladnie do jednego okna. Os, ktora nie
	// sumuje sie do calosci, opisuje inna flote niz ta lista.
	if suma < len(widok.Items) {
		t.Errorf("os sumuje sie do %d, certyfikatow jest co najmniej %d", suma, len(widok.Items))
	}
	// Certyfikat bez terminu nie moze wpasc do okna "pozniej": brak wiedzy
	// to nie jest odleglosc w czasie.
	bezTerminu := 0
	for _, pozycja := range widok.Items {
		if pozycja.DaysToExpiry == nil {
			bezTerminu++
		}
	}
	if bezTerminu > 0 && okna["no expiry"] == 0 {
		t.Errorf("certyfikaty bez terminu (%d) nie trafily do wlasnego okna", bezTerminu)
	}
}

// TestKluczPrywatnyNieTrafiaDoDziennikaHosta pilnuje wlasciwosci, dla ktorej
// magazyn sekretow w ogole istnieje - i ktorej nie widac w API: material
// klucza przechodzi przez agenta i helpera w chwili wdrozenia, wiec jedno
// nieostrozne logowanie zostawiloby go w dzienniku hosta na zawsze.
func TestKluczPrywatnyNieTrafiaDoDziennikaHosta(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	sciezka := fmt.Sprintf("/etc/pki/tls/certs/flotestro-dziennik-%d.crt", time.Now().UnixNano())
	sciezkaKlucza := strings.Replace(strings.Replace(sciezka, "/certs/", "/private/", 1), ".crt", ".key", 1)

	certPEM, kluczPEM, _ := paraTestowa(t, host.Hostname, 40*24*time.Hour)
	sekret := nowySekret(t, h, kluczPEM)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/certificates/targets?path="+sciezka, nil, nil, 0)
		for _, doUsuniecia := range []string{sciezka, sciezkaKlucza} {
			h.runOperation(host.ID, map[string]any{
				"action": "file.remove", "reason": powodCertyfikatu,
				"payload": map[string]any{"file": map[string]any{"path": doUsuniecia}},
			}, 2*time.Minute)
		}
	})

	zadanie, proby := h.runOperation(host.ID, map[string]any{
		"action": "certificate.deploy", "reason": powodCertyfikatu,
		"payload": map[string]any{"certificate": map[string]any{
			"path": sciezka, "key_path": sciezkaKlucza, "certificate": certPEM,
			"key_secret": map[string]any{"name": sekret.Name},
		}},
	}, 3*time.Minute)
	if zadanie.State != "succeeded" {
		t.Fatalf("wdrozenie: stan = %s, %s", zadanie.State, ostatniKomunikat(proby))
	}

	// Szukamy w dzienniku fragmentu klucza w postaci, w jakiej przechodzi
	// przez panel: jednego wiersza base64 ze srodka materialu.
	fragment := strings.Split(strings.TrimSpace(kluczPEM), "\n")[1]
	for _, jednostka := range []string{"flotestro-agent", "flotestro-helper"} {
		odczyt, proby := h.runOperation(host.ID, map[string]any{
			"action": "journal.read", "reason": powodCertyfikatu,
			"payload": map[string]any{"journal": map[string]any{
				"unit": jednostka + ".service", "lines": 400}},
		}, 2*time.Minute)
		if odczyt.State != "succeeded" {
			t.Fatalf("odczyt dziennika %s: stan = %s, %s", jednostka, odczyt.State,
				ostatniKomunikat(proby))
		}
		for _, proba := range proby {
			if strings.Contains(proba.Stdout, fragment) {
				t.Fatalf("dziennik %s niesie material klucza prywatnego", jednostka)
			}
			// Sama nazwa sekretu w dzienniku jest w porzadku - to odnosnik,
			// a nie wartosc. Wartosci nie moze byc w zadnej postaci.
			if strings.Contains(proba.Stdout, "BEGIN PRIVATE KEY") {
				t.Fatalf("dziennik %s niesie klucz w postaci PEM", jednostka)
			}
		}
	}
}
