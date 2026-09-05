package debian

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ultherego/flotestro/internal/vuln"
)

// zrzutTestowy odwzorowuje ksztalt prawdziwego zrzutu trackera, razem
// z pulapkami, ktore w nim sa.
const zrzutTestowy = `{
  "openssl": {
    "CVE-2026-1000": {
      "description": "Blad w obsludze certyfikatow",
      "scope": "remote",
      "releases": {
        "trixie": {"status": "resolved", "urgency": "high", "fixed_version": "3.5.6-1~deb13u2"},
        "bookworm": {"status": "open", "urgency": "medium", "fixed_version": ""}
      }
    },
    "CVE-2026-1001": {
      "description": "Wydanie nigdy nie bylo podatne",
      "releases": {
        "trixie": {"status": "resolved", "urgency": "not yet assigned", "fixed_version": "0"}
      }
    }
  },
  "bash": {
    "CVE-2026-2000": {
      "description": "Producent nie wyda poprawki w tym wydaniu",
      "releases": {
        "trixie": {"status": "open", "urgency": "unimportant", "fixed_version": "",
                   "nodsa": "Minor issue", "nodsa_reason": "postponed"}
      }
    },
    "CVE-2026-2001": {
      "description": "Jeszcze nie rozstrzygniete",
      "releases": {
        "trixie": {"status": "undetermined", "urgency": "not yet assigned"}
      }
    }
  }
}`

func TestParsujCzytaUstaleniaWybranegoWydania(t *testing.T) {
	ustalenia, err := Parsuj(strings.NewReader(zrzutTestowy), []string{"trixie"})
	if err != nil {
		t.Fatalf("Parsuj: %v", err)
	}
	if len(ustalenia) != 4 {
		t.Fatalf("odczytano %d ustalen: %+v", len(ustalenia), ustalenia)
	}
	for _, ustalenie := range ustalenia {
		if ustalenie.Release != "trixie" {
			t.Errorf("ustalenie spoza wybranego wydania: %+v", ustalenie)
		}
		if ustalenie.Distribution != "debian" || ustalenie.Provider != Dostawca {
			t.Errorf("ustalenie bez zrodla: %+v", ustalenie)
		}
	}

	poNazwie := map[string]vuln.Advisory{}
	for _, ustalenie := range ustalenia {
		poNazwie[ustalenie.AdvisoryID] = ustalenie
	}

	// Wersja naprawiona to wersja z numeracji Debiana, a nie upstreamu.
	naprawione := poNazwie["CVE-2026-1000"]
	if naprawione.Status != vuln.StatusNaprawione || naprawione.FixedVersion != "3.5.6-1~deb13u2" {
		t.Errorf("ustalenie naprawione: %+v", naprawione)
	}
	if naprawione.VendorSeverity != "high" {
		t.Errorf("waga = %q", naprawione.VendorSeverity)
	}

	// Pulapka trackera: "resolved" z wersja "0" znaczy "to wydanie nigdy nie
	// bylo podatne", a nie "naprawione w wersji zero".
	nieDotyczy := poNazwie["CVE-2026-1001"]
	if nieDotyczy.Status != vuln.StatusNieDotyczy || nieDotyczy.FixedVersion != "" {
		t.Errorf("ustalenie 'nie dotyczy': %+v", nieDotyczy)
	}

	// nodsa oznacza decyzje producenta, a nie brak odpowiedzi.
	odroczone := poNazwie["CVE-2026-2000"]
	if odroczone.Status != vuln.StatusOdroczone {
		t.Errorf("ustalenie odroczone: %+v", odroczone)
	}

	badane := poNazwie["CVE-2026-2001"]
	if badane.Status != vuln.StatusBadane {
		t.Errorf("ustalenie badane: %+v", badane)
	}
	// "not yet assigned" nie jest waga: to brak wagi i tak ma zostac.
	if badane.VendorSeverity != "" {
		t.Errorf("waga nieprzypisana zamieniona na %q", badane.VendorSeverity)
	}
}

func TestParsujPomijaWydaniaSpozaZakresu(t *testing.T) {
	ustalenia, err := Parsuj(strings.NewReader(zrzutTestowy), []string{"bookworm"})
	if err != nil {
		t.Fatalf("Parsuj: %v", err)
	}
	if len(ustalenia) != 1 || ustalenia[0].Release != "bookworm" {
		t.Fatalf("odczytano %+v", ustalenia)
	}
	// Host bez wydania w feedzie nie moze dostac cudzych ustalen.
	puste, err := Parsuj(strings.NewReader(zrzutTestowy), []string{"buster"})
	if err != nil {
		t.Fatalf("Parsuj: %v", err)
	}
	if len(puste) != 0 {
		t.Fatalf("wydanie spoza zrzutu zwrocilo %d ustalen", len(puste))
	}
}

func TestOdciskZalezyOdTresci(t *testing.T) {
	pierwsze, _ := Parsuj(strings.NewReader(zrzutTestowy), []string{"trixie"})
	drugie, _ := Parsuj(strings.NewReader(zrzutTestowy), []string{"trixie"})
	if Odcisk(pierwsze) != Odcisk(drugie) {
		t.Fatal("te same dane daly rozne odciski")
	}
	// Zmiana wersji naprawionej musi zmienic odcisk: inaczej panel nie
	// przeliczylby floty po opublikowaniu poprawki.
	zmienione := append([]vuln.Advisory{}, pierwsze...)
	zmienione[0].FixedVersion += "u3"
	if Odcisk(zmienione) == Odcisk(pierwsze) {
		t.Fatal("zmiana wersji naprawionej nie zmienila odcisku")
	}
}

func TestOpisPrzycinamyPoZnakachANieBajtach(t *testing.T) {
	// Ciecie po bajtach rozcina znak wielobajtowy na pol i zostawia sekwencje,
	// ktorej nie da sie zapisac w bazie - a wtedy caly import przepada.
	dlugi := strings.Repeat("ą", 400)
	wynik := skrocony(dlugi)
	if !utf8.ValidString(wynik) {
		t.Fatal("przyciety opis nie jest poprawnym UTF-8")
	}
	if len([]rune(wynik)) != 300 {
		t.Fatalf("przyciety opis ma %d znakow", len([]rune(wynik)))
	}
	// Bajt spoza kodowania znika, zamiast wywracac import.
	if !utf8.ValidString(skrocony("opis z \xe2\x80 urwanym znakiem")) {
		t.Fatal("urwany znak zostal w opisie")
	}
}
