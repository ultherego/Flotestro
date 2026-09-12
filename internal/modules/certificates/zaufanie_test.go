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

// urzadTestowy sklada zaswiadczenie urzedu w PEM.
func urzadTestowy(t *testing.T, nazwa string, waznyDo time.Time) string {
	t.Helper()
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	szablon := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: nazwa},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              waznyDo,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	dane, err := x509.CreateCertificate(rand.Reader, &szablon, &szablon, &klucz.PublicKey, klucz)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dane}))
}

func magazynTestowy() MagazynZaufania {
	return MagazynZaufania{Adapter: AdapterDebian,
		Directory: KatalogKotwicDebian, Tool: SciezkaUpdateCACertificates}
}

func TestSciezkaKotwicyZalezyOdNarzedzia(t *testing.T) {
	debian := SciezkaKotwicy(magazynTestowy(), "lab-ca")
	if debian != "/usr/local/share/ca-certificates/flotestro-lab-ca.crt" {
		t.Errorf("sciezka na debianie = %q", debian)
	}
	rhel := SciezkaKotwicy(MagazynZaufania{Adapter: AdapterRHEL,
		Directory: KatalogKotwicRHEL}, "lab-ca")
	if rhel != "/etc/pki/ca-trust/source/anchors/flotestro-lab-ca.pem" {
		t.Errorf("sciezka na rhelu = %q", rhel)
	}
	// Koncowka jest czescia umowy z narzedziem, wiec nie moze zalezec od
	// nazwy kotwicy.
	if SciezkaKotwicy(MagazynZaufania{}, "lab-ca") != "" {
		t.Error("host bez magazynu dostal sciezke kotwicy")
	}
	if err := WalidujKotwice("../etc/passwd"); err == nil {
		t.Error("nazwa ze sciezka przeszla walidacje")
	}
}

func TestPlanKotwicyOdrozniaStanZastany(t *testing.T) {
	teraz := time.Now()
	material := urzadTestowy(t, "Flotestro Lab CA", teraz.Add(8760*time.Hour))

	nowa := ZaplanujKotwice(magazynTestowy(), "lab-ca", material, teraz)
	if nowa.Action != PlanTworzy || nowa.Refusal != "" || len(nowa.Changes) != 2 {
		t.Fatalf("kotwica, ktorej host nie ma: %+v", nowa)
	}

	magazyn := magazynTestowy()
	magazyn.Anchors = []Kotwica{{
		ID: "lab-ca", Managed: true, Subject: nowa.DesiredSubject,
		Path: nowa.Path, FingerprintSHA256: nowa.DesiredFingerprint,
	}}
	bez := ZaplanujKotwice(magazyn, "lab-ca", material, teraz)
	if bez.Action != PlanBezZmian || len(bez.Changes) != 0 || !bez.Exists {
		t.Errorf("kotwica juz zaufana: %+v", bez)
	}

	magazyn.Anchors[0].FingerprintSHA256 = strings.Repeat("b", 64)
	podmiana := ZaplanujKotwice(magazyn, "lab-ca", material, teraz)
	if podmiana.Action != PlanZmienia || !strings.Contains(podmiana.Changes[0], "bbbbbbbbbbbbbbbb na ") {
		t.Errorf("podmiana kotwicy: %+v", podmiana)
	}
	if nowa.PlanHash == bez.PlanHash || bez.PlanHash == podmiana.PlanHash {
		t.Error("odciski planow nie roznia sie")
	}
}

func TestPlanKotwicyOdmawiaMaterialuKtoryNieJestUrzedem(t *testing.T) {
	teraz := time.Now()
	lisc := certyfikatTestowy(t, "panel.flotestro.test", teraz.Add(-time.Hour), teraz.Add(time.Hour))
	plan := ZaplanujKotwice(magazynTestowy(), "lab-ca", lisc, teraz)
	if !strings.Contains(plan.Refusal, "nie jest zaswiadczeniem urzedu") {
		t.Errorf("lisc jako kotwica: %+v", plan)
	}
	wygasly := urzadTestowy(t, "Stary CA", teraz.Add(-time.Hour))
	if p := ZaplanujKotwice(magazynTestowy(), "lab-ca", wygasly, teraz); p.Refusal == "" {
		t.Error("wygasly urzad przeszedl bez odmowy")
	}
	bezMagazynu := ZaplanujKotwice(MagazynZaufania{UnavailableReason: "brak narzedzia"},
		"lab-ca", urzadTestowy(t, "CA", teraz.Add(time.Hour)), teraz)
	if bezMagazynu.Refusal != "brak narzedzia" || bezMagazynu.PlanHash == "" {
		t.Errorf("host bez magazynu: %+v", bezMagazynu)
	}
}

// Usuniecie urzedu, ktory nadal cos podpisuje, zrywa zaufanie klientom,
// ktorzy niczego nie zmieniali. To jest granica rotacji: stary urzad znika
// dopiero, gdy zaden certyfikat hosta nie pochodzi juz od niego.
func TestPlanUsunieciaKotwicyPatrzyNaCertyfikatyHosta(t *testing.T) {
	magazyn := magazynTestowy()
	magazyn.Anchors = []Kotwica{{ID: "lab-ca", Managed: true, Subject: "CN=Flotestro Lab CA",
		Path:              "/usr/local/share/ca-certificates/flotestro-lab-ca.crt",
		FingerprintSHA256: strings.Repeat("c", 64)}}

	wUzyciu := ZaplanujUsuniecieKotwicy(magazyn, "lab-ca", []Certyfikat{
		{Path: "/etc/ssl/certs/usluga.pem", Issuer: "CN=Flotestro Lab CA"},
	})
	if !strings.Contains(wUzyciu.Refusal, "nadal podpisuje") || len(wUzyciu.InUseBy) != 1 {
		t.Errorf("urzad w uzyciu: %+v", wUzyciu)
	}

	wolna := ZaplanujUsuniecieKotwicy(magazyn, "lab-ca", []Certyfikat{
		{Path: "/etc/ssl/certs/usluga.pem", Issuer: "CN=Nowy CA"},
	})
	if wolna.Action != PlanUsuwa || wolna.Refusal != "" || len(wolna.Changes) != 2 {
		t.Errorf("urzad bez certyfikatow: %+v", wolna)
	}

	brak := ZaplanujUsuniecieKotwicy(magazynTestowy(), "lab-ca", nil)
	if brak.Action != PlanJuzUsuniety || brak.Refusal != "" {
		t.Errorf("kotwica, ktorej nie ma: %+v", brak)
	}
	if wUzyciu.PlanHash == wolna.PlanHash || wolna.PlanHash == brak.PlanHash {
		t.Error("odciski planow nie roznia sie")
	}
}

func TestWykryjMagazynRozstrzygaNarzedziem(t *testing.T) {
	debian := WykryjMagazyn(func(sciezka string) bool {
		return sciezka == SciezkaUpdateCACertificates || sciezka == KatalogKotwicDebian
	})
	if debian.Adapter != AdapterDebian || debian.Directory != KatalogKotwicDebian {
		t.Errorf("debian: %+v", debian)
	}
	arch := WykryjMagazyn(func(sciezka string) bool {
		return sciezka == SciezkaUpdateCATrust || sciezka == KatalogKotwicArch
	})
	if arch.Adapter != AdapterRHEL || arch.Directory != KatalogKotwicArch {
		t.Errorf("arch: %+v", arch)
	}
	brak := WykryjMagazyn(func(string) bool { return false })
	if brak.UnavailableReason == "" || brak.Adapter != "" {
		t.Errorf("host bez magazynu: %+v", brak)
	}
}
