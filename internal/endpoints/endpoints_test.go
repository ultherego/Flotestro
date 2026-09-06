package endpoints

import (
	"errors"
	"testing"
	"time"
)

var teraz = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func menedzer() *Menedzer {
	return Nowy([]string{"https://a:8443", "https://b:8443"}, time.Second, time.Minute)
}

// TestPierwszaBramaJestPriorytetem pilnuje, ze lista jest kolejnoscia, a nie
// zbiorem: po powrocie glownej bramy flota ma z niej korzystac, a nie zostac
// na zapasowej.
func TestPierwszaBramaJestPriorytetem(t *testing.T) {
	m := menedzer()
	brama, err := m.Wybierz(teraz)
	if err != nil || brama == nil || brama.URL != "https://a:8443" {
		t.Fatalf("wybrano %v (%v)", brama, err)
	}

	m.Blad("https://a:8443", KlasaSieci, teraz)
	brama, err = m.Wybierz(teraz)
	if err != nil || brama == nil || brama.URL != "https://b:8443" {
		t.Fatalf("po bledzie pierwszej wybrano %v (%v)", brama, err)
	}

	// Okno pierwszej minelo - wracamy na nia.
	brama, err = m.Wybierz(teraz.Add(2 * time.Minute))
	if err != nil || brama == nil || brama.URL != "https://a:8443" {
		t.Fatalf("po oknie wybrano %v (%v)", brama, err)
	}
}

// TestOdwolanaTozsamoscZatrzymujeProby pilnuje wlasciwosci z dokumentu:
// odwolany certyfikat nie jest awaria lacza i agent ma przestac sie dobijac,
// a nie przelaczac miedzy bramami w nieskonczonosc.
func TestOdwolanaTozsamoscZatrzymujeProby(t *testing.T) {
	m := menedzer()
	m.Blad("https://a:8443", KlasaTozsamosci, teraz)
	if _, err := m.Wybierz(teraz.Add(time.Hour)); !errors.Is(err, ErrTozsamoscOdrzucona) {
		t.Fatalf("po odrzuceniu tozsamosci menedzer zwrocil %v", err)
	}
}

// TestBladKonfiguracjiCzekaDluzej pilnuje, ze zla konfiguracja nie zamienia
// sie w petle ponowien: naprawia ja czlowiek, a nie kolejna proba.
func TestBladKonfiguracjiCzekaDluzej(t *testing.T) {
	m := Nowy([]string{"https://a:8443"}, time.Second, time.Minute)
	m.Blad("https://a:8443", KlasaKonfiguracji, teraz)
	stan := m.Bramy()[0]
	if stan.NastepnaProba.Sub(teraz) > BackoffKonfiguracji {
		t.Fatalf("okno %s przekracza granice", stan.NastepnaProba.Sub(teraz))
	}
	if _, err := m.Wybierz(teraz.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Po minucie brama moze byc jeszcze niegotowa - to jest cel. Sprawdzamy
	// tylko, ze menedzer nie kaze czekac dluzej niz wynika z klasy bledu.
	if czekanie := m.DoNastepnej(teraz); czekanie > BackoffKonfiguracji {
		t.Fatalf("czekanie %s przekracza granice", czekanie)
	}
}

// TestBackoffNiePrzekreca pilnuje, ze dlugo niedostepna brama nie dostaje
// ujemnego okna po przekreceniu przesuniecia bitowego.
func TestBackoffNiePrzekreca(t *testing.T) {
	m := Nowy([]string{"https://a:8443"}, time.Second, time.Minute)
	for i := 0; i < 80; i++ {
		m.Blad("https://a:8443", KlasaSieci, teraz)
		stan := m.Bramy()[0]
		okno := stan.NastepnaProba.Sub(teraz)
		if okno < 0 || okno > time.Minute {
			t.Fatalf("po %d bledach okno = %s", i+1, okno)
		}
	}
}

// TestSukcesKasujeHistorie pilnuje, ze brama, ktora znowu dziala, wraca do
// pelnej dostepnosci zamiast dzwigac backoff sprzed awarii.
func TestSukcesKasujeHistorie(t *testing.T) {
	m := menedzer()
	m.Blad("https://a:8443", KlasaSieci, teraz)
	m.Sukces("https://a:8443", teraz)
	brama, err := m.Wybierz(teraz)
	if err != nil || brama.URL != "https://a:8443" || brama.Bledy != 0 {
		t.Fatalf("po sukcesie stan = %+v (%v)", brama, err)
	}
}

func TestRozpoznanieKlasBledow(t *testing.T) {
	przypadki := []struct {
		tresc string
		klasa Klasa
	}{
		{"certyfikat odwolany", KlasaTozsamosci},
		{"x509: certificate signed by unknown authority", KlasaKonfiguracji},
		{"x509: certificate is valid for panel, not gateway", KlasaKonfiguracji},
		{"dial tcp 10.0.0.1:8443: connect: connection refused", KlasaSieci},
		{"context deadline exceeded", KlasaSieci},
	}
	for _, przypadek := range przypadki {
		t.Run(przypadek.tresc, func(t *testing.T) {
			if got := Rozpoznaj(errors.New(przypadek.tresc)); got != przypadek.klasa {
				t.Fatalf("Rozpoznaj = %q, oczekiwano %q", got, przypadek.klasa)
			}
		})
	}
}

// TestDuplikatyBramSaPomijane pilnuje, ze ta sama brama wpisana dwa razy nie
// dostaje podwojnej szansy w kolejce ponowien.
func TestDuplikatyBramSaPomijane(t *testing.T) {
	m := Nowy([]string{"https://a:8443", "https://a:8443", ""}, time.Second, time.Minute)
	if len(m.Bramy()) != 1 {
		t.Fatalf("bramy = %+v", m.Bramy())
	}
}
