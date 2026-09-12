package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// certyfikatTestowy sklada certyfikat samopodpisany w PEM.
func certyfikatTestowy(t *testing.T, nazwa string, waznyOd, waznyDo time.Time) string {
	t.Helper()
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	szablon := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: nazwa},
		DNSNames:     []string{nazwa},
		NotBefore:    waznyOd,
		NotAfter:     waznyDo,
	}
	dane, err := x509.CreateCertificate(rand.Reader, &szablon, &szablon, &klucz.PublicKey, klucz)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dane}))
}

func TestPlanCertyfikatuOdrozniaStanZastany(t *testing.T) {
	teraz := time.Now()
	nowy := certyfikatTestowy(t, "panel.flotestro.test", teraz.Add(-time.Hour), teraz.Add(720*time.Hour))
	zamowienie := Zamowienie{
		Path: "/etc/ssl/certs/flotestro.pem", KeyPath: "/etc/ssl/private/flotestro.key",
		Certyfikat: nowy, KeySecret: "pki/panel#3", MaKlucz: true,
		Jednostka: "nginx.service", Cel: "panel.flotestro.test:443",
	}

	powstanie := Zaplanuj(Certyfikat{}, zamowienie, teraz)
	if powstanie.Action != PlanTworzy || powstanie.Refusal != "" || powstanie.Exists {
		t.Fatalf("plik, ktorego nie ma: %+v", powstanie)
	}
	if len(powstanie.Changes) != 4 || powstanie.DesiredFingerprint == "" {
		t.Errorf("zmiany: %v", powstanie.Changes)
	}
	// Klucz prywatny nie ma prawa pojawic sie w planie ani w odcisku.
	if strings.Contains(strings.Join(powstanie.Changes, " "), "BEGIN") {
		t.Error("plan niesie material klucza")
	}

	obecny := Certyfikat{Path: zamowienie.Path, Subject: "CN=stary",
		FingerprintSHA256: strings.Repeat("a", 64)}
	zmiana := Zaplanuj(obecny, zamowienie, teraz)
	if zmiana.Action != PlanZmienia || !strings.Contains(zmiana.Changes[0], "certyfikat z aaaaaaaaaaaaaaaa na ") {
		t.Errorf("podmiana certyfikatu: %+v", zmiana)
	}

	bezZmian := Zaplanuj(Certyfikat{Path: zamowienie.Path,
		FingerprintSHA256: powstanie.DesiredFingerprint}, zamowienie, teraz)
	if bezZmian.Action != PlanBezZmian || len(bezZmian.Changes) != 0 {
		t.Errorf("ten sam certyfikat: %+v", bezZmian)
	}
	if powstanie.PlanHash == zmiana.PlanHash || zmiana.PlanHash == bezZmian.PlanHash {
		t.Error("odciski planow nie roznia sie")
	}
}

func TestPlanCertyfikatuOdmawiaMaterialuICeluPozaZakresem(t *testing.T) {
	teraz := time.Now()
	wygasly := certyfikatTestowy(t, "panel.flotestro.test", teraz.Add(-48*time.Hour), teraz.Add(-time.Hour))
	plan := Zaplanuj(Certyfikat{}, Zamowienie{
		Path: "/etc/ssl/certs/flotestro.pem", Certyfikat: wygasly}, teraz)
	if !strings.Contains(plan.Refusal, "stracil waznosc") || plan.PlanHash == "" {
		t.Errorf("wygasly certyfikat: %+v", plan)
	}

	dobry := certyfikatTestowy(t, "panel.flotestro.test", teraz.Add(-time.Hour), teraz.Add(time.Hour))
	cudzy := Zaplanuj(Certyfikat{}, Zamowienie{
		Path: "/etc/ssl/certs/flotestro.pem", Certyfikat: dobry,
		Cel: "inny.flotestro.test:443"}, teraz)
	if !strings.Contains(cudzy.Refusal, "nie obejmuje nazwy inny.flotestro.test") {
		t.Errorf("cel poza zakresem: %+v", cudzy)
	}

	bezSekretu := Zaplanuj(Certyfikat{}, Zamowienie{
		Path: "/etc/ssl/certs/flotestro.pem", KeyPath: "/etc/ssl/private/flotestro.key",
		Certyfikat: dobry}, teraz)
	if !strings.Contains(bezSekretu.Refusal, "magazynu sekretow") {
		t.Errorf("klucz bez odnosnika: %+v", bezSekretu)
	}
}

func TestPlanCertyfikatuOdrozniaBrakPlikuOdNieodczytanego(t *testing.T) {
	teraz := time.Now()
	dobry := certyfikatTestowy(t, "panel.flotestro.test", teraz.Add(-time.Hour), teraz.Add(time.Hour))
	zamowienie := Zamowienie{Path: "/etc/ssl/certs/flotestro.pem", Certyfikat: dobry}

	brak := Zaplanuj(Certyfikat{Path: zamowienie.Path,
		UnavailableReason: "open /etc/ssl/certs/flotestro.pem: no such file or directory"},
		zamowienie, teraz)
	if brak.Action != PlanTworzy || brak.Exists || brak.Refusal != "" {
		t.Errorf("plik, ktorego nie ma: %+v", brak)
	}

	nieodczytany := Zaplanuj(Certyfikat{Path: zamowienie.Path,
		UnavailableReason: "permission denied"}, zamowienie, teraz)
	if !strings.Contains(nieodczytany.Refusal, "nie odczytano certyfikatu zastanego") {
		t.Errorf("plik nieodczytany: %+v", nieodczytany)
	}
}
