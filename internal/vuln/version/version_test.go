package version

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Para jest jednym porownaniem z korpusu.
type Para struct {
	Rodzaj     string
	A, B       string
	Oczekiwany int
	Wiersz     int
}

// Korpus czyta plik porownan wspolny dla testu jednostkowego i integracyjnego.
func Korpus(t *testing.T, sciezka string) []Para {
	t.Helper()
	plik, err := os.Open(sciezka)
	if err != nil {
		t.Fatalf("korpus: %v", err)
	}
	defer plik.Close()

	var pary []Para
	skaner := bufio.NewScanner(plik)
	numer := 0
	for skaner.Scan() {
		numer++
		linia := strings.TrimSpace(skaner.Text())
		if linia == "" || strings.HasPrefix(linia, "#") {
			continue
		}
		pola := strings.Split(linia, "\t")
		if len(pola) != 4 {
			t.Fatalf("korpus, wiersz %d: %d kolumn", numer, len(pola))
		}
		oczekiwany, err := strconv.Atoi(pola[3])
		if err != nil {
			t.Fatalf("korpus, wiersz %d: %v", numer, err)
		}
		pary = append(pary, Para{
			Rodzaj: pola[0], A: pola[1], B: pola[2], Oczekiwany: oczekiwany, Wiersz: numer,
		})
	}
	if err := skaner.Err(); err != nil {
		t.Fatalf("korpus: %v", err)
	}
	if len(pary) == 0 {
		t.Fatal("korpus jest pusty")
	}
	return pary
}

// Znak sprowadza wynik porownania do -1, 0 albo 1.
func Znak(wynik int) int {
	switch {
	case wynik < 0:
		return -1
	case wynik > 0:
		return 1
	}
	return 0
}

func TestKorpusPorownanWersji(t *testing.T) {
	for _, para := range Korpus(t, "testdata/corpus.tsv") {
		var wynik int
		switch para.Rodzaj {
		case "deb":
			wynik = Znak(PorownajDeb(para.A, para.B))
		case "rpm":
			wynik = Znak(PorownajRPM(para.A, para.B))
		default:
			t.Fatalf("wiersz %d: nieznany rodzaj %q", para.Wiersz, para.Rodzaj)
		}
		if wynik != para.Oczekiwany {
			t.Errorf("wiersz %d: %s %q ? %q = %d, oczekiwano %d",
				para.Wiersz, para.Rodzaj, para.A, para.B, wynik, para.Oczekiwany)
		}
		// Porownanie musi byc antysymetryczne: inaczej ta sama para wersji
		// daje rozne odpowiedzi zaleznie od kolejnosci argumentow.
		var odwrotny int
		if para.Rodzaj == "deb" {
			odwrotny = Znak(PorownajDeb(para.B, para.A))
		} else {
			odwrotny = Znak(PorownajRPM(para.B, para.A))
		}
		if odwrotny != -para.Oczekiwany {
			t.Errorf("wiersz %d: porownanie nie jest antysymetryczne (%d wobec %d)",
				para.Wiersz, wynik, odwrotny)
		}
	}
}

func TestPorownanieJestPrzechodnie(t *testing.T) {
	// Uporzadkowany ciag wersji: kazda nastepna musi byc nowsza od kazdej
	// poprzedniej. To wychwytuje bledy, ktorych same pary nie pokazuja.
	ciagi := map[string][]string{
		// "1.0a" stoi po "1.0-2" nie przez pomylke: czlon upstream porownuje
		// sie przed rewizja, wiec "1.0a" jest nowsze od kazdego "1.0-N".
		"deb": {"1.0~~", "1.0~rc1", "1.0", "1.0-1", "1.0-2", "1.0a", "1.0+deb12u1-1", "1:0.9", "2:0.1"},
		"rpm": {"1.0~rc1-1", "1.0-1", "1.0-2", "1.0^20260101-1", "1.1-1", "1:0.9-1", "2:0.1-1"},
	}
	for rodzaj, ciag := range ciagi {
		for i := 0; i < len(ciag); i++ {
			for j := i + 1; j < len(ciag); j++ {
				var wynik int
				if rodzaj == "deb" {
					wynik = Znak(PorownajDeb(ciag[i], ciag[j]))
				} else {
					wynik = Znak(PorownajRPM(ciag[i], ciag[j]))
				}
				if wynik != -1 {
					t.Errorf("%s: %q powinno byc starsze od %q, wynik %d",
						rodzaj, ciag[i], ciag[j], wynik)
				}
			}
		}
	}
}
