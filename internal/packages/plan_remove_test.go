package packages

import (
	"strings"
	"testing"
)

// Zbior usuwanych jest liczony ponownie tuz przed operacja. Roznica oznacza,
// ze host zmienil sie od czasu planu - a wtedy usunieciu podleglby inny
// zestaw, niz operator zatwierdzil.
func TestPorownanieZbiorowWykrywaKazdaRoznice(t *testing.T) {
	if roznica := porownajZbiory([]string{"a", "b"}, []string{"b", "a"}); roznica != "" {
		t.Errorf("rowne zbiory uznane za rozne: %q", roznica)
	}

	roznica := porownajZbiory([]string{"a"}, []string{"a", "b"})
	if !strings.Contains(roznica, "takze: b") {
		t.Errorf("nie wykryto dodatkowego pakietu: %q", roznica)
	}

	roznica = porownajZbiory([]string{"a", "b"}, []string{"a"})
	if !strings.Contains(roznica, "nie podlegaja") {
		t.Errorf("nie wykryto brakujacego pakietu: %q", roznica)
	}

	roznica = porownajZbiory([]string{"a", "b"}, []string{"a", "c"})
	if !strings.Contains(roznica, "doszly: c") || !strings.Contains(roznica, "odpadly: b") {
		t.Errorf("niepelny opis roznicy: %q", roznica)
	}
}

// Operacja nieodwracalna nie moze isc bez podstawy: pusty zbior oczekiwany
// oznacza brak zatwierdzonego planu, a nie zgode na wszystko.
func TestBrakPlanuJestRoznica(t *testing.T) {
	if porownajZbiory(nil, []string{"a"}) == "" {
		t.Error("brak planu zostal uznany za zgodnosc")
	}
	if porownajZbiory(nil, nil) == "" {
		t.Error("brak planu przy pustym zbiorze zostal uznany za zgodnosc")
	}
}

// Linia "Remv" jest jedynym zrodlem listy usuwanych. Format jest stabilny
// przy LC_ALL=C i nie zalezy od jezyka interfejsu.
func TestParsowanieLiniiUsuniecia(t *testing.T) {
	nazwa, ok := parseAptRemvLine("Remv libfoo [1.0-1]")
	if !ok || nazwa != "libfoo" {
		t.Errorf("nazwa = %q, ok = %v", nazwa, ok)
	}
	for _, linia := range []string{
		"Inst libfoo [1.0-1] (1.0-2 Debian:13 [amd64])",
		"Conf libfoo (1.0-2)",
		"",
		"Remv",
	} {
		if _, ok := parseAptRemvLine(linia); ok {
			t.Errorf("linia %q zostala uznana za usuniecie", linia)
		}
	}
}
