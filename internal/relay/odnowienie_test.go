package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// certyfikatOd tworzy certyfikat o zadanym okresie waznosci.
func certyfikatOd(t *testing.T, od, do time.Time) tls.Certificate {
	t.Helper()
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	szablon := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay"},
		NotBefore:    od,
		NotAfter:     do,
	}
	der, err := x509.CreateCertificate(rand.Reader, szablon, szablon, &klucz.PublicKey, klucz)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: klucz}
}

// TestOdnowieniePrzedOstatniaTrzecia pilnuje wlasciwosci, dla ktorej ten prog
// w ogole istnieje: relay ma czas na ponowienia przy niedostepnej centrali,
// a nie jedna probe w ostatniej godzinie waznosci.
func TestOdnowieniePrzedOstatniaTrzecia(t *testing.T) {
	teraz := time.Now()
	przypadki := []struct {
		nazwa      string
		od, do     time.Time
		oczekiwane bool
	}{
		{"swiezy", teraz.Add(-time.Hour), teraz.Add(7 * 24 * time.Hour), false},
		{"polowa zycia", teraz.Add(-84 * time.Hour), teraz.Add(84 * time.Hour), false},
		{"ostatnia trzecia", teraz.Add(-6 * 24 * time.Hour), teraz.Add(24 * time.Hour), true},
		{"wygasly", teraz.Add(-8 * 24 * time.Hour), teraz.Add(-time.Hour), true},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.nazwa, func(t *testing.T) {
			tozsamosc := Tozsamosc{
				Certificate: certyfikatOd(t, przypadek.od, przypadek.do),
				NotAfter:    przypadek.do,
			}
			if got := wymagaOdnowienia(tozsamosc); got != przypadek.oczekiwane {
				t.Fatalf("wymagaOdnowienia = %v, oczekiwano %v", got, przypadek.oczekiwane)
			}
		})
	}
}

// TestNieznanyTerminJestPowodem pilnuje zasady, ze nieznane nie jest zerem:
// certyfikat bez czytelnego terminu nie moze znaczyc "jeszcze dlugo".
func TestNieznanyTerminJestPowodem(t *testing.T) {
	if !wymagaOdnowienia(Tozsamosc{}) {
		t.Fatal("tozsamosc bez terminu nie wymaga odnowienia")
	}
}

// TestPodmianaJestWidocznaOdRazu pilnuje tego, po co ta tozsamosc jest zywa:
// listener siega po certyfikat przy kazdym uscisku, wiec odnowienie nie
// wymaga restartu procesu i nie zrywa sesji agentow lokalizacji.
func TestPodmianaJestWidocznaOdRazu(t *testing.T) {
	stary := certyfikatOd(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	nowy := certyfikatOd(t, time.Now(), time.Now().Add(7*24*time.Hour))
	zywa := NowaZywa(Tozsamosc{RelayID: "r1", Certificate: stary})

	przed, err := zywa.Certyfikat(nil)
	if err != nil {
		t.Fatal(err)
	}
	zywa.Podmien(Tozsamosc{RelayID: "r1", Certificate: nowy})
	po, err := zywa.Certyfikat(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(przed.Certificate[0]) == string(po.Certificate[0]) {
		t.Fatal("listener podaje wciaz stary certyfikat")
	}
}

// TestOdstepMiesciSieWGranicach pilnuje, ze jitter rozprasza relaye, ale nie
// wypuszcza sprawdzania poza rozsadne granice.
func TestOdstepMiesciSieWGranicach(t *testing.T) {
	teraz := time.Now()
	tozsamosc := Tozsamosc{
		Certificate: certyfikatOd(t, teraz, teraz.Add(7*24*time.Hour)),
		NotAfter:    teraz.Add(7 * 24 * time.Hour),
	}
	for i := 0; i < 50; i++ {
		odstep := odstepSprawdzenia(tozsamosc)
		if odstep < minOdstepSprawdzenia || odstep > maxOdstepSprawdzenia {
			t.Fatalf("odstep %s poza granicami", odstep)
		}
	}
}

// TestNazwySieciowe pilnuje, ze adres IP trafia do SAN jako adres. Wpisany
// jako nazwa DNS wygladalby poprawnie, a agent laczacy sie po adresie i tak
// odrzucilby certyfikat.
func TestNazwySieciowe(t *testing.T) {
	dns, adresy := rozdzielNazwy([]string{"relay-waw-01.example.com", "192.168.56.70"})
	if len(dns) != 1 || dns[0] != "relay-waw-01.example.com" {
		t.Fatalf("nazwy DNS = %v", dns)
	}
	if len(adresy) != 1 || adresy[0].String() != "192.168.56.70" {
		t.Fatalf("adresy = %v", adresy)
	}
}
