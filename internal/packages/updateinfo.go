package packages

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Advisory jest ustaleniem producenta znanym hostowi z metadanych repozytoriow.
//
// To sa fakty, a nie ocena: host mowi, jakie ustalenia wydal jego producent
// i ktore wersje pakietow je zamykaja. Czy dotycza tego hosta, rozstrzyga
// panel - tak samo, jak przy kazdym innym module.
type Advisory struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title,omitempty"`
	// CVEIDs zbieramy z opisu i z odnosnikow: producent podaje je w obu
	// miejscach i nie zawsze w tym samym.
	CVEIDs []string `json:"cve_ids,omitempty"`
	// Packages wylicza wersje, ktore ustalenie zamyka.
	Packages []AdvisoryPackage `json:"packages,omitempty"`
	IssuedAt *time.Time        `json:"issued_at,omitempty"`
}

// AdvisoryPackage jest jedna wersja pakietu zamykajaca ustalenie.
type AdvisoryPackage struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture,omitempty"`
	// EVR jest pelna wersja z epoka, jesli producent ja podal.
	EVR string `json:"evr"`
}

// TypSecurity oznacza ustalenie bezpieczenstwa. Pozostale typy - poprawki
// bledow i nowe funkcje - nie sa podatnosciami i nie moga trafic do oceny.
const TypSecurity = "security"

// wzorzecCVE wylapuje identyfikatory CVE w dowolnym miejscu opisu.
var wzorzecCVE = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// Ustalenia czyta ustalenia producenta znane hostowi.
//
// Dla dnf sa w metadanych repozytoriow, ktore host i tak ma: to jest zrodlo
// rozstrzygajace dla Fedory, bo mowi o wersjach z tych samych repozytoriow,
// z ktorych host bierze pakiety.
func Ustalenia(ctx context.Context, menedzer string,
	zainstalowane []InstalledPackage) ([]Advisory, string) {
	if menedzer != "dnf" {
		// APT nie ma updateinfo: dla Debiana i Ubuntu ustalenia pobiera panel
		// wprost z trackera producenta.
		return nil, ""
	}
	// --all: takze ustalenia juz zastosowane. Panel i tak porownuje wersje,
	// a lista samych oczekujacych zalezalaby od tego, kiedy host ostatnio
	// odswiezyl metadane.
	wynik := run(ctx, 5*time.Minute, dnfPath, "updateinfo", "info", "--all", "--with-cve")
	if !wynik.Ran || wynik.ExitCode != 0 {
		return nil, "dnf updateinfo: " + wynik.Reason()
	}
	return ZawezDoZainstalowanych(ParsujUpdateinfo(wynik.Stdout), zainstalowane), ""
}

// ZawezDoZainstalowanych zostawia ustalenia bezpieczenstwa dotyczace pakietow,
// ktore na tym hoscie naprawde sa.
//
// Pelna lista ustalen wydania to tysiace pozycji razy kilkadziesiat pakietow
// kazda - i wiekszosc dotyczy rzeczy, ktorych host nie ma. Zawezenie jest tu
// zakresem korelacji, a nie oszczednoscia: panel ocenia to, co lezy na hoscie.
func ZawezDoZainstalowanych(ustalenia []Advisory, zainstalowane []InstalledPackage) []Advisory {
	if len(zainstalowane) == 0 {
		return nil
	}
	obecne := map[string]bool{}
	for _, pakiet := range zainstalowane {
		obecne[pakiet.Name+"\x1f"+pakiet.Architecture] = true
		obecne[pakiet.Name+"\x1fnoarch"] = obecne[pakiet.Name+"\x1fnoarch"] || pakiet.Architecture == "noarch"
	}

	var wynik []Advisory
	for _, ustalenie := range ustalenia {
		// Poprawki bledow i nowe funkcje nie sa podatnosciami i nie moga
		// trafic do oceny bezpieczenstwa.
		if ustalenie.Type != TypSecurity {
			continue
		}
		var pasujace []AdvisoryPackage
		for _, pakiet := range ustalenie.Packages {
			if obecne[pakiet.Name+"\x1f"+pakiet.Architecture] {
				pasujace = append(pasujace, pakiet)
			}
		}
		if len(pasujace) == 0 {
			continue
		}
		ustalenie.Packages = pasujace
		wynik = append(wynik, ustalenie)
	}
	return wynik
}

// ParsujUpdateinfo czyta blokowy format "dnf updateinfo info".
//
// Format jest kolumnowy: klucz ustalenia stoi przy lewej krawedzi, a klucze
// zagniezdzone - w odnosnikach i w kolekcji pakietow - sa wciete. Rozroznienie
// ma znaczenie, bo nazwy sie powtarzaja: "Type" ustalenia mowi "security",
// a "Type" odnosnika - "bugzilla". Bez tego kazde ustalenie z odnosnikiem
// traci swoj typ i wypada z oceny.
func ParsujUpdateinfo(wyjscie string) []Advisory {
	var ustalenia []Advisory
	var biezace *Advisory
	wPakietach := false

	zapisz := func() {
		if biezace != nil && biezace.ID != "" {
			biezace.CVEIDs = unikalne(biezace.CVEIDs)
			ustalenia = append(ustalenia, *biezace)
		}
		biezace, wPakietach = nil, false
	}

	for _, linia := range strings.Split(wyjscie, "\n") {
		if strings.TrimSpace(linia) == "" {
			zapisz()
			continue
		}
		klucz, wartosc, ok := rozdzielWiersz(linia)
		if !ok {
			continue
		}
		wciety := linia[0] == ' ' || linia[0] == '\t'

		if klucz == "Name" && !wciety {
			zapisz()
			biezace = &Advisory{ID: wartosc}
			continue
		}
		if biezace == nil {
			continue
		}

		switch {
		case klucz == "" && wPakietach:
			// Kolejny pakiet kolekcji: wiersz bez klucza kontynuuje liste.
			if pakiet, ok := ParsujNEVRA(wartosc); ok {
				biezace.Packages = append(biezace.Packages, pakiet)
			}
			continue
		case klucz == "Packages" && wciety:
			wPakietach = true
			if pakiet, ok := ParsujNEVRA(wartosc); ok {
				biezace.Packages = append(biezace.Packages, pakiet)
			}
			continue
		case wciety:
			// Klucz zagniezdzony: nie opisuje ustalenia, ale moze niesc CVE
			// w tytule odnosnika.
			wPakietach = false
			biezace.CVEIDs = append(biezace.CVEIDs, wzorzecCVE.FindAllString(wartosc, -1)...)
			continue
		}

		wPakietach = false
		switch klucz {
		case "Title":
			if biezace.Title == "" {
				biezace.Title = wartosc
			}
		case "Type":
			biezace.Type = strings.ToLower(wartosc)
		case "Severity":
			biezace.Severity = WagaFedory(wartosc)
		case "Issued":
			if chwila, err := time.Parse("2006-01-02 15:04:05", wartosc); err == nil {
				chwilaUTC := chwila.UTC()
				biezace.IssuedAt = &chwilaUTC
			}
		}
		// CVE bywa w opisie, w tytule odnosnika albo w obu: zbieramy je
		// z calego bloku, zamiast ufac jednemu miejscu.
		biezace.CVEIDs = append(biezace.CVEIDs, wzorzecCVE.FindAllString(wartosc, -1)...)
	}
	zapisz()
	return ustalenia
}

// rozdzielWiersz dzieli wiersz na klucz i wartosc.
func rozdzielWiersz(linia string) (klucz, wartosc string, ok bool) {
	dwukropek := strings.Index(linia, ":")
	if dwukropek < 0 {
		return "", "", false
	}
	klucz = strings.TrimSpace(linia[:dwukropek])
	wartosc = strings.TrimSpace(linia[dwukropek+1:])
	return klucz, wartosc, true
}

// ParsujNEVRA czyta nazwe pliku pakietu w postaci nazwa-wersja-wydanie.arch.
//
// Nazwa moze zawierac myslniki, wiec czytamy od konca: architektura po
// ostatniej kropce, potem wydanie i wersja po dwoch ostatnich myslnikach.
func ParsujNEVRA(wpis string) (AdvisoryPackage, bool) {
	wpis = strings.TrimSpace(wpis)
	if wpis == "" {
		return AdvisoryPackage{}, false
	}
	kropka := strings.LastIndex(wpis, ".")
	if kropka <= 0 {
		return AdvisoryPackage{}, false
	}
	architektura := wpis[kropka+1:]
	reszta := wpis[:kropka]

	ostatni := strings.LastIndex(reszta, "-")
	if ostatni <= 0 {
		return AdvisoryPackage{}, false
	}
	wydanie := reszta[ostatni+1:]
	reszta = reszta[:ostatni]

	przedostatni := strings.LastIndex(reszta, "-")
	if przedostatni <= 0 {
		return AdvisoryPackage{}, false
	}
	wersja := reszta[przedostatni+1:]
	nazwa := reszta[:przedostatni]
	if nazwa == "" || wersja == "" || wydanie == "" {
		return AdvisoryPackage{}, false
	}
	return AdvisoryPackage{
		Name: nazwa, Architecture: architektura, EVR: wersja + "-" + wydanie,
	}, true
}

// WagaFedory tlumaczy wage producenta na jednolite nazewnictwo.
func WagaFedory(waga string) string {
	switch strings.ToLower(strings.TrimSpace(waga)) {
	case "critical", "urgent":
		return "critical"
	case "important", "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low", "minor":
		return "low"
	}
	// "None" nie jest waga: to brak wagi i tak ma zostac.
	return ""
}

// unikalne usuwa powtorzenia, zachowujac porzadek alfabetyczny.
func unikalne(wartosci []string) []string {
	if len(wartosci) == 0 {
		return nil
	}
	zbior := map[string]bool{}
	var wynik []string
	for _, wartosc := range wartosci {
		if zbior[wartosc] {
			continue
		}
		zbior[wartosc] = true
		wynik = append(wynik, wartosc)
	}
	sort.Strings(wynik)
	return wynik
}
