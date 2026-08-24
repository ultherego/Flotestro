// Package compliance liczy zgodnosc hosta z profilem hardeningu.
//
// Sprawdzenia zyja w panelu, a nie na hoscie, z trzech powodow. Sa
// wersjonowane, wiec wynik da sie powtorzyc i porownac miedzy hostami. Licza
// sie z faktow, ktore host i tak zglasza w inwentarzu, wiec nie potrzeba
// dodatkowego przebiegu po flocie. I nie sa skryptami: kazde sprawdzenie ma
// typ, oczekiwana wartosc, dowod i - jesli naprawa istnieje - wskazanie
// konkretnej typowanej operacji modulu, ktory za dana rzecz odpowiada.
//
// Panel nie ma przycisku "napraw wszystko". Naprawa jest planem, ktory
// operator oglada, i osobnymi zadaniami, ktore przechodza przez uprawnienia
// swoich modulow.
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Wagi ustalen. Waga mowi, co sie stanie, gdy nikt nic nie zrobi, a nie jak
// trudno to naprawic.
const (
	WagaHigh   = "high"
	WagaMedium = "medium"
	WagaLow    = "low"
	WagaInfo   = "info"
)

// Fragment to stan jednego modulu hosta wraz z jego rewizja.
type Fragment struct {
	Module            string
	Revision          string
	Payload           json.RawMessage
	ObservedAt        time.Time
	UnavailableReason string
}

// Host niesie fakty, ktore panel zna sam, bez pytania modulu.
type Host struct {
	Hostname string
	OSFamily string
	// Puste wskazniki oznaczaja stan nieustalony, nie zero.
	PendingSecurityUpdates *int
	RebootRequired         *bool
}

// Wejscie to wszystko, z czego licza sie sprawdzenia.
type Wejscie struct {
	Host      Host
	Fragmenty map[string]Fragment
}

// Fragment zwraca fragment modulu i informacje, czy w ogole jest.
func (w Wejscie) Fragment(modul string) (Fragment, bool) {
	fragment, ok := w.Fragmenty[modul]
	if !ok || len(fragment.Payload) == 0 {
		return Fragment{}, false
	}
	return fragment, true
}

// Naprawa wskazuje typowana operacje, ktora usunie ustalenie.
//
// Naprawa nie jest osobnym mechanizmem: to zwykla operacja modulu, ktory za
// dana rzecz odpowiada, z jej wlasnym uprawnieniem i wlasnym ryzykiem.
// Ustalenie bez naprawy nie jest bledem - czesc rzeczy wymaga decyzji, ktorej
// panel nie moze podjac za operatora.
type Naprawa struct {
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
	// Note mowi, czego operacja nie zalatwia albo dlaczego naprawy nie ma.
	Note string `json:"note,omitempty"`
}

// Ustalenie to wynik jednego sprawdzenia na jednym hoscie.
type Ustalenie struct {
	CheckID      string `json:"check_id"`
	CheckVersion int    `json:"check_version"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	// Rationale mowi, co sie stanie, gdy nikt nic nie zrobi.
	Rationale string `json:"rationale"`
	// Passed i Unknown to trzy stany, nie dwa: sprawdzenie moze przejsc,
	// nie przejsc albo nie miec z czego sie policzyc.
	Passed  bool `json:"passed"`
	Unknown bool `json:"unknown"`
	// Expected i Observed sa zapisane tak, zeby dalo sie je pokazac obok
	// siebie bez tlumaczenia.
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Evidence string `json:"evidence,omitempty"`
	// Module, Revision i ObservedAt czynia wynik powtarzalnym: mowia,
	// z ktorego odczytu powstal.
	Module     string    `json:"module"`
	Revision   string    `json:"revision,omitempty"`
	ObservedAt time.Time `json:"observed_at"`

	Remediation *Naprawa `json:"remediation,omitempty"`
}

// Wymaga mowi, czy ustalenie czeka na dzialanie.
func (u Ustalenie) Wymaga() bool { return !u.Passed && !u.Unknown }

// Wynik jest odpowiedzia sprawdzenia.
type Wynik struct {
	Passed      bool
	Unknown     bool
	Observed    string
	Evidence    string
	Remediation *Naprawa
}

// Check to jedno wersjonowane sprawdzenie.
type Check struct {
	ID        string
	Version   int
	Title     string
	Severity  string
	Rationale string
	// Module wskazuje fragment inwentarza, z ktorego sprawdzenie liczy wynik.
	Module string
	// Expected opisuje stan docelowy slowami operatora.
	Expected string
	Ocen     func(Wejscie) Wynik
}

// Raport to komplet ustalen dla jednego hosta.
type Raport struct {
	HostID   string      `json:"host_id"`
	Findings []Ustalenie `json:"findings"`
	// PlanHash wiaze plan naprawy z ustaleniami, z ktorych powstal. Zmiana
	// stanu hosta zmienia hash, wiec zatwierdzony plan nie moze zostac
	// wykonany wobec innego stanu, niz operator ogladal.
	PlanHash    string    `json:"plan_hash"`
	GeneratedAt time.Time `json:"generated_at"`
	// Counts streszcza raport bez liczenia po stronie interfejsu.
	Counts map[string]int `json:"counts"`
}

// Ocen liczy ustalenia dla hosta.
func Ocen(hostID string, wejscie Wejscie, teraz time.Time) Raport {
	ustalenia := make([]Ustalenie, 0, len(Checks))
	for _, check := range Checks {
		ustalenia = append(ustalenia, uruchom(check, wejscie))
	}
	sort.SliceStable(ustalenia, func(i, j int) bool {
		if kolejnoscWagi(ustalenia[i]) != kolejnoscWagi(ustalenia[j]) {
			return kolejnoscWagi(ustalenia[i]) < kolejnoscWagi(ustalenia[j])
		}
		return ustalenia[i].CheckID < ustalenia[j].CheckID
	})
	return Raport{
		HostID:      hostID,
		Findings:    ustalenia,
		PlanHash:    HashPlanu(ustalenia),
		GeneratedAt: teraz,
		Counts:      podsumowanie(ustalenia),
	}
}

// uruchom wykonuje jedno sprawdzenie i opisuje wynik.
func uruchom(check Check, wejscie Wejscie) Ustalenie {
	ustalenie := Ustalenie{
		CheckID: check.ID, CheckVersion: check.Version, Title: check.Title,
		Severity: check.Severity, Rationale: check.Rationale,
		Expected: check.Expected, Module: check.Module,
	}
	if fragment, ok := wejscie.Fragment(check.Module); ok {
		ustalenie.Revision = fragment.Revision
		ustalenie.ObservedAt = fragment.ObservedAt
		// Modul, ktorego host nie odczytal, nie jest modulem pustym.
		if fragment.UnavailableReason != "" {
			ustalenie.Unknown = true
			ustalenie.Observed = "nie odczytano: " + fragment.UnavailableReason
			return ustalenie
		}
	} else if check.Module != "" {
		ustalenie.Unknown = true
		ustalenie.Observed = "host nie zglosil modulu " + check.Module
		return ustalenie
	}

	wynik := check.Ocen(wejscie)
	ustalenie.Passed = wynik.Passed
	ustalenie.Unknown = wynik.Unknown
	ustalenie.Observed = wynik.Observed
	ustalenie.Evidence = wynik.Evidence
	// Naprawe niesie wylacznie ustalenie, ktore czeka na dzialanie: plan
	// naprawy stanu poprawnego byl by zaproszeniem do zmiany bez powodu.
	if !wynik.Passed && !wynik.Unknown {
		ustalenie.Remediation = wynik.Remediation
	}
	return ustalenie
}

// HashPlanu liczy odcisk ustalen, ktore czekaja na dzialanie.
//
// Do odcisku wchodzi sprawdzenie, jego wersja i tresc naprawy - czyli
// dokladnie to, co operator zatwierdza. Stan, ktory sie zmienil, daje inny
// odcisk i plan trzeba obejrzec na nowo.
func HashPlanu(ustalenia []Ustalenie) string {
	czesci := make([]string, 0, len(ustalenia))
	for _, ustalenie := range ustalenia {
		if !ustalenie.Wymaga() {
			continue
		}
		czesc := ustalenie.CheckID + "\n" + itoa(ustalenie.CheckVersion) + "\n" + ustalenie.Observed
		if ustalenie.Remediation != nil {
			czesc += "\n" + ustalenie.Remediation.Action + "\n" + string(ustalenie.Remediation.Payload)
		}
		czesci = append(czesci, czesc)
	}
	sort.Strings(czesci)
	suma := sha256.Sum256([]byte(strings.Join(czesci, "\n--\n")))
	return hex.EncodeToString(suma[:])
}

// podsumowanie liczy ustalenia wedlug stanu i wagi.
func podsumowanie(ustalenia []Ustalenie) map[string]int {
	liczby := map[string]int{"passed": 0, "failed": 0, "unknown": 0}
	for _, ustalenie := range ustalenia {
		switch {
		case ustalenie.Unknown:
			liczby["unknown"]++
		case ustalenie.Passed:
			liczby["passed"]++
		default:
			liczby["failed"]++
			liczby[ustalenie.Severity]++
		}
	}
	return liczby
}

func kolejnoscWagi(ustalenie Ustalenie) int {
	if ustalenie.Passed {
		return 9
	}
	switch ustalenie.Severity {
	case WagaHigh:
		return 0
	case WagaMedium:
		return 1
	case WagaLow:
		return 2
	}
	return 3
}

func itoa(wartosc int) string {
	if wartosc == 0 {
		return "0"
	}
	cyfry := ""
	for wartosc > 0 {
		cyfry = string(rune('0'+wartosc%10)) + cyfry
		wartosc /= 10
	}
	return cyfry
}
