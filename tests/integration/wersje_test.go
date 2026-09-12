//go:build integration

package integration

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Corpus porownan wersji lezy przy implementacji: ten sam plik czyta test
// jednostkowy i ten test, ktory pyta o kazda pare prawdziwe narzedzie.
const sciezkaKorpusu = "../../internal/vuln/version/testdata/corpus.tsv"

type paraWersji struct {
	Kind     string
	A, B     string
	Expected int
	Line     int
}

func korpusWersji(t *testing.T) []paraWersji {
	t.Helper()
	plik, err := os.Open(filepath.Clean(sciezkaKorpusu))
	if err != nil {
		t.Fatalf("korpus: %v", err)
	}
	defer plik.Close()

	var pary []paraWersji
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
		pary = append(pary, paraWersji{
			Kind: pola[0], A: pola[1], B: pola[2], Expected: oczekiwany, Line: numer,
		})
	}
	return pary
}

// TestKorpusZgadzaSieZDpkg pyta dpkg o kazda pare wersji Debiana.
//
// Wlasna implementacja porownania wersji predzej czy pozniej rozjedzie sie
// z menedzerem pakietow. Rozjazd w jedna strone daje falszywy alarm, w druga -
// podatnosc uznana za naprawiona. Dlatego korpus jest sprawdzany narzedziem,
// a nie samym testem jednostkowym.
func TestKorpusZgadzaSieZDpkg(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("ta maszyna nie ma dpkg")
	}
	sprawdzone := 0
	for _, para := range korpusWersji(t) {
		if para.Kind != "deb" {
			continue
		}
		sprawdzone++
		wynik := 0
		if exec.Command("dpkg", "--compare-versions", para.A, "lt", para.B).Run() == nil {
			wynik = -1
		} else if exec.Command("dpkg", "--compare-versions", para.A, "gt", para.B).Run() == nil {
			wynik = 1
		}
		if wynik != para.Expected {
			t.Errorf("wiersz %d: dpkg mowi %d dla %q ? %q, korpus %d",
				para.Line, wynik, para.A, para.B, para.Expected)
		}
	}
	if sprawdzone == 0 {
		t.Fatal("korpus nie ma ani jednej pary Debiana")
	}
	t.Logf("dpkg potwierdzil %d par", sprawdzone)
}

// skryptRPM pyta librpm o porownanie pary wersji.
//
// Wydanie porownujemy tylko wtedy, gdy obie strony je maja - tak samo jak
// korelator, bo advisory czesto podaje sama wersje bez wydania.
const skryptRPM = `
import rpm, sys
def rozbij(evr):
    epoka = "0"
    if ":" in evr:
        epoka, evr = evr.split(":", 1)
    if "-" in evr:
        wersja, wydanie = evr.split("-", 1)
    else:
        wersja, wydanie = evr, None
    return (epoka, wersja, wydanie)
a, b = rozbij(sys.argv[1]), rozbij(sys.argv[2])
if a[2] is None or b[2] is None:
    a, b = (a[0], a[1], None), (b[0], b[1], None)
print(rpm.labelCompare(a, b))
`

// TestKorpusZgadzaSieZLibrpm pyta librpm o kazda pare wersji RPM.
func TestKorpusZgadzaSieZLibrpm(t *testing.T) {
	if exec.Command("python3", "-c", "import rpm").Run() != nil {
		t.Skip("ta maszyna nie ma powiazan pythona z librpm (python3-rpm)")
	}
	sprawdzone := 0
	for _, para := range korpusWersji(t) {
		if para.Kind != "rpm" {
			continue
		}
		sprawdzone++
		wyjscie, err := exec.Command("python3", "-c", skryptRPM, para.A, para.B).Output()
		if err != nil {
			t.Fatalf("wiersz %d: librpm: %v", para.Line, err)
		}
		wynik, err := strconv.Atoi(strings.TrimSpace(string(wyjscie)))
		if err != nil {
			t.Fatalf("wiersz %d: odpowiedz librpm %q", para.Line, wyjscie)
		}
		if wynik != para.Expected {
			t.Errorf("wiersz %d: librpm mowi %d dla %q ? %q, korpus %d",
				para.Line, wynik, para.A, para.B, para.Expected)
		}
	}
	if sprawdzone == 0 {
		t.Fatal("korpus nie ma ani jednej pary RPM")
	}
	t.Logf("librpm potwierdzil %d par", sprawdzone)
}
