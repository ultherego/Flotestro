package certificates

import (
	"testing"
	"time"
)

func TestStanOcenieTerminWzgledemProgow(t *testing.T) {
	teraz := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	chwila := func(przesuniecie time.Duration) *time.Time {
		wartosc := teraz.Add(przesuniecie)
		return &wartosc
	}
	przypadki := []struct {
		nazwa    string
		notAfter *time.Time
		stan     string
	}{
		{"brak terminu", nil, StanNieznany},
		{"wygasl wczoraj", chwila(-24 * time.Hour), StanWygasl},
		{"wygasa jutro", chwila(24 * time.Hour), StanPilny},
		{"wygasa za dwa tygodnie", chwila(14 * 24 * time.Hour), StanOstrzezenie},
		{"wygasa za rok", chwila(365 * 24 * time.Hour), StanWazny},
	}
	for _, przypadek := range przypadki {
		if stan := Stan(przypadek.notAfter, teraz); stan != przypadek.stan {
			t.Fatalf("%s: stan %q, oczekiwano %q", przypadek.nazwa, stan, przypadek.stan)
		}
	}
}

func TestGorszyStawiaBrakWiedzyPonadOstrzezenie(t *testing.T) {
	// Brak wiedzy o certyfikacie uslugi nie jest dobra wiadomoscia: host
	// opisuje wtedy stan gorszy niz ten z odleglym terminem.
	if Gorszy(StanWazny, StanNieznany) != StanNieznany {
		t.Fatal("nieznany przegral z waznym")
	}
	if Gorszy(StanNieznany, StanOstrzezenie) != StanNieznany {
		t.Fatal("ostrzezenie przeslonilo brak wiedzy")
	}
	if Gorszy(StanNieznany, StanWygasl) != StanWygasl {
		t.Fatal("wygasly przegral z nieznanym")
	}
	if Gorszy("", StanPilny) != StanPilny {
		t.Fatal("pusty stan nie zostal zastapiony")
	}
}

func TestNieswiezyOpisujeStaryOdczyt(t *testing.T) {
	teraz := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	if Nieswiezy(teraz.Add(-time.Hour), teraz) {
		t.Fatal("odczyt sprzed godziny uznany za nieswiezy")
	}
	if !Nieswiezy(teraz.Add(-48*time.Hour), teraz) {
		t.Fatal("odczyt sprzed dwoch dob uznany za swiezy")
	}
	if !Nieswiezy(time.Time{}, teraz) {
		t.Fatal("brak odczytu uznany za swiezy")
	}
}
