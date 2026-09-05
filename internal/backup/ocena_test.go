package backup

import (
	"testing"
	"time"
)

func TestStanOcenieWiekKopii(t *testing.T) {
	teraz := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	chwila := func(przesuniecie time.Duration) *time.Time {
		wartosc := teraz.Add(przesuniecie)
		return &wartosc
	}
	przypadki := []struct {
		nazwa    string
		ostatnia *time.Time
		stan     string
	}{
		// Brak kopii to osobny stan, a nie kopia bardzo stara: to dwie rozne
		// sytuacje i dwie rozne decyzje operatora.
		{"nigdy", nil, StanBrak},
		{"godzina temu", chwila(-time.Hour), StanDobry},
		{"dobe temu", chwila(-24 * time.Hour), StanDobry},
		{"dwie doby temu", chwila(-48 * time.Hour), StanUwaga},
		{"tydzien temu", chwila(-7 * 24 * time.Hour), StanPilny},
	}
	for _, przypadek := range przypadki {
		if stan := Stan(przypadek.ostatnia, teraz); stan != przypadek.stan {
			t.Fatalf("%s: stan %q, oczekiwano %q", przypadek.nazwa, stan, przypadek.stan)
		}
	}
}

func TestGorszyStawiaBrakKopiiNajwyzej(t *testing.T) {
	if Gorszy(StanDobry, StanBrak) != StanBrak {
		t.Fatal("brak kopii przegral z kopia swieza")
	}
	if Gorszy(StanPilny, StanBrak) != StanBrak {
		t.Fatal("brak kopii przegral ze stara kopia")
	}
	if Gorszy(StanUwaga, StanDobry) != StanUwaga {
		t.Fatal("ostrzezenie przegralo ze stanem dobrym")
	}
	if Gorszy("", StanUwaga) != StanUwaga {
		t.Fatal("pusty stan nie zostal zastapiony")
	}
}

func TestNiesprawdzonaKopiaJestObietnica(t *testing.T) {
	teraz := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	niedawno := teraz.Add(-24 * time.Hour)
	dawno := teraz.Add(-60 * 24 * time.Hour)
	if Niesprawdzona(&niedawno, teraz) {
		t.Fatal("kopia sprawdzona wczoraj uznana za niesprawdzona")
	}
	if !Niesprawdzona(&dawno, teraz) {
		t.Fatal("kopia sprawdzona dwa miesiace temu uznana za sprawdzona")
	}
	if !Niesprawdzona(nil, teraz) {
		t.Fatal("kopia, ktorej nikt nie sprawdzil, uznana za sprawdzona")
	}
}
