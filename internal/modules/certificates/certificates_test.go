package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// wystaw tworzy pare klucz-certyfikat do testow.
func wystaw(t *testing.T, nazwa string, wystawca *x509.Certificate,
	kluczWystawcy *ecdsa.PrivateKey, waznosc time.Duration, ca bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("klucz: %v", err)
	}
	szablon := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: nazwa},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(waznosc),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  ca,
		BasicConstraintsValid: true,
	}
	if !ca {
		szablon.DNSNames = []string{nazwa}
		szablon.IPAddresses = []net.IP{net.ParseIP("10.10.10.10")}
	}
	rodzic, kluczRodzica := szablon, klucz
	if wystawca != nil {
		rodzic, kluczRodzica = wystawca, kluczWystawcy
	}
	der, err := x509.CreateCertificate(rand.Reader, szablon, rodzic, &klucz.PublicKey, kluczRodzica)
	if err != nil {
		t.Fatalf("certyfikat: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsowanie: %v", err)
	}
	return cert, klucz, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func kluczPEM(t *testing.T, klucz *ecdsa.PrivateKey) []byte {
	t.Helper()
	dane, err := x509.MarshalPKCS8PrivateKey(klucz)
	if err != nil {
		t.Fatalf("klucz PKCS8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dane})
}

func TestOpiszCzytaNazwyITerminy(t *testing.T) {
	_, _, ca := wystaw(t, "Flotestro Test CA", nil, nil, 24*time.Hour, true)
	_ = ca
	cert, _, lisc := wystaw(t, "panel.flotestro.test", nil, nil, 48*time.Hour, false)

	certy, err := ParsujPEM(lisc)
	if err != nil {
		t.Fatalf("ParsujPEM: %v", err)
	}
	opis := Opisz("/etc/pki/tls/certs/panel.crt", certy)
	if opis.FingerprintSHA256 != Odcisk(cert) {
		t.Fatalf("odcisk %q nie zgadza sie z certyfikatem", opis.FingerprintSHA256)
	}
	if opis.KeyAlgorithm != "ECDSA" || opis.KeyBits != 256 {
		t.Fatalf("klucz opisany jako %s/%d", opis.KeyAlgorithm, opis.KeyBits)
	}
	if len(opis.SANs) != 2 || opis.SANs[0] != "panel.flotestro.test" {
		t.Fatalf("nazwy alternatywne: %v", opis.SANs)
	}
	if !opis.SelfSigned {
		t.Fatal("certyfikat podpisany sam sobie nie zostal rozpoznany")
	}
	// Modul zbiera fakty; ocena terminu nalezy do panelu, wiec opis nie
	// zawiera zadnego stanu poza samym terminem.
	if opis.NotAfter.IsZero() {
		t.Fatal("brak terminu waznosci")
	}
}

func TestParsujPEMPomijaKluczWPliku(t *testing.T) {
	_, klucz, lisc := wystaw(t, "usluga.test", nil, nil, time.Hour, false)
	razem := append(append([]byte{}, kluczPEM(t, klucz)...), lisc...)
	certy, err := ParsujPEM(razem)
	if err != nil {
		t.Fatalf("ParsujPEM: %v", err)
	}
	if len(certy) != 1 {
		t.Fatalf("oczekiwano jednego certyfikatu, jest %d", len(certy))
	}
}

func TestDopasujKluczRozpoznajeCudzyKlucz(t *testing.T) {
	cert, klucz, _ := wystaw(t, "usluga.test", nil, nil, time.Hour, false)
	_, obcy, _ := wystaw(t, "inna.test", nil, nil, time.Hour, false)

	if err := DopasujKlucz(cert, kluczPEM(t, klucz)); err != nil {
		t.Fatalf("wlasny klucz odrzucony: %v", err)
	}
	err := DopasujKlucz(cert, kluczPEM(t, obcy))
	if err == nil {
		t.Fatal("cudzy klucz zostal przyjety")
	}
	// Komunikat nie moze niesc tresci klucza: to jedyne miejsce modulu,
	// w ktorym klucz w ogole jest czytany.
	if strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("komunikat niesie tresc klucza: %v", err)
	}
}

func TestSprawdzLancuchOdrzucaZlaKolejnosc(t *testing.T) {
	ca, kluczCA, caPEM := wystaw(t, "Flotestro Test CA", nil, nil, 72*time.Hour, true)
	_, _, liscPEM := wystaw(t, "usluga.test", ca, kluczCA, 48*time.Hour, false)

	dobry, err := ParsujPEM(append(append([]byte{}, liscPEM...), caPEM...))
	if err != nil {
		t.Fatalf("ParsujPEM: %v", err)
	}
	if err := SprawdzLancuch(dobry); err != nil {
		t.Fatalf("poprawny lancuch odrzucony: %v", err)
	}

	odwrotny, err := ParsujPEM(append(append([]byte{}, caPEM...), liscPEM...))
	if err != nil {
		t.Fatalf("ParsujPEM: %v", err)
	}
	if err := SprawdzLancuch(odwrotny); err == nil {
		t.Fatal("lancuch w zlej kolejnosci zostal przyjety")
	}
}

func TestSprawdzOdrzucaMaterialPrzedZapisem(t *testing.T) {
	cert, klucz, liscPEM := wystaw(t, "usluga.test", nil, nil, 48*time.Hour, false)
	_, obcy, _ := wystaw(t, "inna.test", nil, nil, time.Hour, false)
	_ = cert

	podstawa := Wdrozenie{
		Path: "/etc/pki/tls/certs/usluga.crt", KeyPath: "/etc/pki/tls/private/usluga.key",
		Certyfikat: liscPEM, Klucz: kluczPEM(t, klucz),
	}
	if _, err := Sprawdz(podstawa, time.Now()); err != nil {
		t.Fatalf("poprawne wdrozenie odrzucone: %v", err)
	}

	zObcymKluczem := podstawa
	zObcymKluczem.Klucz = kluczPEM(t, obcy)
	if _, err := Sprawdz(zObcymKluczem, time.Now()); err == nil {
		t.Fatal("wdrozenie z cudzym kluczem zostalo przyjete")
	}

	poTerminie := podstawa
	if _, err := Sprawdz(poTerminie, time.Now().Add(72*time.Hour)); err == nil {
		t.Fatal("certyfikat po terminie zostal przyjety")
	}

	// Sonda ma potwierdzic wlasnie ten certyfikat: cel spoza jego nazw
	// oznacza test, ktory i tak nie potwierdzilby wdrozenia.
	obcyCel := podstawa
	obcyCel.Cel = "inna.test:443"
	if _, err := Sprawdz(obcyCel, time.Now()); err == nil {
		t.Fatal("cel spoza certyfikatu zostal przyjety")
	}

	wlasnyCel := podstawa
	wlasnyCel.Cel = "usluga.test:8443"
	if _, err := Sprawdz(wlasnyCel, time.Now()); err != nil {
		t.Fatalf("cel z certyfikatu odrzucony: %v", err)
	}
}

func TestWalidujSciezkaChroniMagazynZaufaniaITozsamoscAgenta(t *testing.T) {
	dozwolone := []string{
		"/etc/pki/tls/certs/usluga.crt",
		"/etc/ssl/private/usluga.key",
		"/etc/nginx/ssl/panel.pem",
		// Debian trzyma certyfikat serwera w katalogu magazynu zaufania:
		// sam plik lezacy tam niczego nie czyni zaufanym.
		"/etc/ssl/certs/usluga.pem",
	}
	for _, sciezka := range dozwolone {
		if err := WalidujSciezke(sciezka); err != nil {
			t.Fatalf("sciezka %s odrzucona: %v", sciezka, err)
		}
	}
	zakazane := []string{
		"/etc/pki/ca-trust/source/anchors/obcy.crt",
		"/etc/ssl/certs/ca-certificates.crt",
		// Dowiazanie po skrocie nazwy jest wpisem magazynu zaufania:
		// plik pod taka nazwa dodaje urzad, a nie certyfikat uslugi.
		"/etc/ssl/certs/3513523f.0",
		"/etc/pki/tls/certs/002c0b4f.1",
		"/etc/flotestro/agent/agent.crt",
		"/etc/pki/tls/certs/../../../root/.ssh/id_rsa",
		"etc/pki/tls/certs/usluga.crt",
		"/etc/shadow",
	}
	for _, sciezka := range zakazane {
		if err := WalidujSciezke(sciezka); err == nil {
			t.Fatalf("sciezka %s zostala przyjeta", sciezka)
		}
	}
}

func TestParsujGetcertLaczyZlecenieZePlikiem(t *testing.T) {
	wyjscie := `Number of certificates and requests being tracked: 2.
Request ID '20250101120000':
	status: MONITORING
	stuck: no
	key pair storage: type=FILE,location='/etc/pki/tls/private/httpd.key'
	certificate: type=FILE,location='/etc/pki/tls/certs/httpd.crt'
	CA: IPA
	expires: 2026-12-01 10:00:00 UTC
	auto-renew: yes
Request ID '20250202130000':
	status: CA_UNREACHABLE
	key pair storage: type=FILE,location='/etc/pki/tls/private/ldap.key'
	certificate: type=FILE,location='/etc/pki/tls/certs/ldap.crt'
	CA: IPA
	auto-renew: no
`
	sledzenia := ParsujGetcert(wyjscie)
	if len(sledzenia) != 2 {
		t.Fatalf("rozpoznano %d zlecen: %v", len(sledzenia), sledzenia)
	}
	httpd, ok := sledzenia["/etc/pki/tls/certs/httpd.crt"]
	if !ok {
		t.Fatalf("brak zlecenia dla httpd: %v", sledzenia)
	}
	if httpd.Request != "20250101120000" || httpd.Status != "MONITORING" || httpd.CA != "IPA" {
		t.Fatalf("zlecenie httpd odczytane jako %+v", httpd)
	}
	if httpd.KeyPath != "/etc/pki/tls/private/httpd.key" {
		t.Fatalf("klucz httpd: %q", httpd.KeyPath)
	}
	if httpd.AutoRenew == nil || !*httpd.AutoRenew {
		t.Fatal("auto-renew httpd nie zostalo odczytane")
	}
	if httpd.Expires == nil || httpd.Expires.Year() != 2026 {
		t.Fatalf("termin httpd: %v", httpd.Expires)
	}
	ldap := sledzenia["/etc/pki/tls/certs/ldap.crt"]
	if ldap.AutoRenew == nil || *ldap.AutoRenew {
		t.Fatal("auto-renew ldap powinno byc falszem, a nie brakiem wiedzy")
	}
}

func TestSkanBrakWiedzyNieJestBrakiemPliku(t *testing.T) {
	snapshot := Skanuj([]Cel{{
		Path:    "/etc/pki/tls/certs/nie-ma-takiego.crt",
		KeyPath: "/etc/pki/tls/private/nie-ma-takiego.key",
	}})
	if len(snapshot.Certificates) != 1 {
		t.Fatalf("skan zwrocil %d pozycji", len(snapshot.Certificates))
	}
	if snapshot.Certificates[0].UnavailableReason == "" {
		t.Fatal("plik, ktorego nie ma, nie zostal opisany powodem")
	}
	// Metadanych klucza bez roota nie widac: to ma byc brak wiedzy z powodem,
	// a nie cicha odpowiedz "klucza nie ma".
	if _, brak := snapshot.Missing[FaktMetadaneKluczy]; !brak {
		t.Fatalf("brak faktu o kluczach nie zostal zgloszony: %v", snapshot.Missing)
	}
	if snapshot.KeysKnown {
		t.Fatal("stan kluczy zostal uznany za znany")
	}
}

func TestUzupelnijWstawiaSledzenieIKlucze(t *testing.T) {
	snapshot := Snapshot{
		Certificates: []Certyfikat{{
			Path:    "/etc/pki/tls/certs/httpd.crt",
			Renewal: OdnawianieNieznane,
			Source:  ZrodloZewnetrzne,
			Key:     &MetadaneKlucza{Path: "/etc/pki/tls/private/httpd.key"},
		}, {
			Path:    "/etc/pki/tls/certs/reczny.crt",
			Renewal: OdnawianieNieznane,
			Source:  ZrodloZewnetrzne,
		}},
		Missing: map[string]string{FaktSledzenie: "wymaga roota", FaktMetadaneKluczy: "wymaga roota"},
	}
	prawda := true
	uzupelniony := snapshot.Uzupelnij(Uzupelnienie{
		Keys: map[string]MetadaneKlucza{
			"/etc/pki/tls/private/httpd.key": {Path: "/etc/pki/tls/private/httpd.key",
				Exists: true, Mode: "0600", Owner: "root"},
		},
		Tracking: map[string]Sledzenie{
			"/etc/pki/tls/certs/httpd.crt": {Request: "1", Status: "MONITORING", AutoRenew: &prawda},
		},
		TrackingKnown: true,
	})

	if !uzupelniony.KeysKnown || !uzupelniony.TrackingKnown {
		t.Fatal("fakty helpera nie zostaly odnotowane jako znane")
	}
	if len(uzupelniony.Missing) != 0 {
		t.Fatalf("po uzupelnieniu zostaly braki: %v", uzupelniony.Missing)
	}
	if uzupelniony.Certificates[0].Renewal != OdnawianieSledzone ||
		uzupelniony.Certificates[0].Source != ZrodloCertmonger {
		t.Fatalf("certyfikat pod opieka certmongera opisany jako %+v", uzupelniony.Certificates[0])
	}
	if uzupelniony.Certificates[0].Key.Mode != "0600" {
		t.Fatalf("metadane klucza nie zostaly wstawione: %+v", uzupelniony.Certificates[0].Key)
	}
	// Plik bez zlecenia jest odnawiany recznie - i to jest ustalenie,
	// a nie brak wiedzy: demon odpowiedzial, ze go nie pilnuje.
	if uzupelniony.Certificates[1].Renewal != OdnawianieReczne {
		t.Fatalf("plik bez zlecenia opisany jako %q", uzupelniony.Certificates[1].Renewal)
	}
}

func TestDodajSledzonePomijaSciezkiPozaZakresem(t *testing.T) {
	cele := DodajSledzone([]Cel{{Path: "/etc/pki/tls/certs/znany.crt"}}, map[string]Sledzenie{
		"/etc/pki/tls/certs/znany.crt": {Request: "1"},
		"/etc/pki/tls/certs/nowy.crt":  {Request: "2", KeyPath: "/etc/pki/tls/private/nowy.key"},
		"/etc/pki/ca-trust/obcy.crt":   {Request: "3"},
	})
	if len(cele) != 2 {
		t.Fatalf("zakres ma %d celow: %+v", len(cele), cele)
	}
	for _, cel := range cele {
		if strings.HasPrefix(cel.Path, "/etc/pki/ca-trust/") {
			t.Fatal("magazyn zaufania trafil do zakresu skanu")
		}
	}
}
