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
	"strconv"
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

// Kody powodu dla ustalen bez wyniku.
//
// Stan nieustalony bez kodu jest bezuzyteczny: operator nie wie, czy ma
// poczekac na nastepny odczyt, naprawic agenta, czy dac komus uprawnienia.
const (
	// PowodBrakFaktu: host nie zglosil modulu, z ktorego sprawdzenie liczy.
	PowodBrakFaktu = "fact_missing"
	// PowodNieobslugiwane: host nie ma komponentu, ktorego sprawdzenie dotyczy.
	// Uzywany przy stanie "nie dotyczy", a nie przy nieustalonym.
	PowodNieobslugiwane = "unsupported_system"
	// PowodBladOdczytu: fakt istnieje, ale odczyt sie nie powiodl.
	PowodBladOdczytu = "read_failed"
	// PowodBrakUprawnienia: odczytu odmowiono z braku uprawnien.
	PowodBrakUprawnienia = "permission_denied"
	// PowodNieaktualny: odczyt jest za stary, zeby cokolwiek z niego orzekac.
	PowodNieaktualny = "inventory_stale"
)

// MaksymalnyWiekOdczytu wyznacza, jak stary moze byc fakt, zeby dalo sie na
// nim oprzec ocene.
//
// Cykl inwentarza jest krotszy o rzad wielkosci, wiec przekroczenie tego progu
// oznacza hosta, ktory nie odzywa sie od dawna - a nie hosta zgodnego.
const MaksymalnyWiekOdczytu = 6 * time.Hour

// WersjaKanonizacji wersjonuje postac, z ktorej liczy sie odcisk planu.
//
// Zmiana postaci zmienia wszystkie odciski, wiec numer jest czescia napisu:
// plan zatwierdzony przy poprzedniej wersji nie moze zostac wykonany po
// zmianie zasad liczenia, bo nie wiadomo, co wtedy zatwierdzono.
const WersjaKanonizacji = 1

const naglowekKanonizacji = "flotestro/compliance-plan/v"

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
	// RequiresReboot oznacza krok, po ktorym host musi wstac na nowo.
	// Plan moze miec najwyzej jeden taki krok i konczy sie nim.
	RequiresReboot bool `json:"requires_reboot,omitempty"`
}

// Ustalenie to wynik jednego sprawdzenia na jednym hoscie.
type Ustalenie struct {
	CheckID      string `json:"check_id"`
	CheckVersion int    `json:"check_version"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	// Rationale mowi, co sie stanie, gdy nikt nic nie zrobi.
	Rationale string `json:"rationale"`
	// Applicable mowi, czy sprawdzenie ma na tym hoscie zastosowanie. Host
	// z AppArmorem nie przegrywa sprawdzenia wymagajacego SELinuksa - ono go
	// po prostu nie dotyczy, i to jest osobna odpowiedz od "nie przeszedl".
	Applicable bool `json:"applicable"`
	// Passed i Unknown maja sens wylacznie dla sprawdzen, ktore dotycza.
	Passed  bool `json:"passed"`
	Unknown bool `json:"unknown"`
	// ReasonCode nazywa powod braku wyniku. Stan nieustalony bez kodu zmusza
	// operatora do zgadywania, czy czekac, naprawiac agenta, czy nadac prawa.
	ReasonCode string `json:"reason_code,omitempty"`
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
func (u Ustalenie) Wymaga() bool { return u.Applicable && !u.Passed && !u.Unknown }

// Wynik jest odpowiedzia sprawdzenia.
type Wynik struct {
	Passed bool
	// NotApplicable zwraca sprawdzenie, ktore na tym hoscie nie ma sensu.
	NotApplicable bool
	Unknown       bool
	// ReasonCode jest wymagany przy Unknown i przy NotApplicable.
	ReasonCode  string
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
	PlanHash string `json:"plan_hash"`
	// PlanHashVersion mowi, ktora postac kanoniczna liczyla odcisk.
	PlanHashVersion int       `json:"plan_hash_version"`
	GeneratedAt     time.Time `json:"generated_at"`
	// Counts streszcza raport bez liczenia po stronie interfejsu.
	Counts map[string]int `json:"counts"`
}

// Ocen liczy ustalenia dla hosta.
func Ocen(hostID string, wejscie Wejscie, teraz time.Time) Raport {
	ustalenia := make([]Ustalenie, 0, len(Checks))
	for _, check := range Checks {
		ustalenia = append(ustalenia, uruchom(check, wejscie, teraz))
	}
	sort.SliceStable(ustalenia, func(i, j int) bool {
		if kolejnoscWagi(ustalenia[i]) != kolejnoscWagi(ustalenia[j]) {
			return kolejnoscWagi(ustalenia[i]) < kolejnoscWagi(ustalenia[j])
		}
		return ustalenia[i].CheckID < ustalenia[j].CheckID
	})
	return Raport{
		HostID:          hostID,
		Findings:        ustalenia,
		PlanHash:        HashPlanu(hostID, ustalenia),
		PlanHashVersion: WersjaKanonizacji,
		GeneratedAt:     teraz,
		Counts:          podsumowanie(ustalenia),
	}
}

// uruchom wykonuje jedno sprawdzenie i opisuje wynik.
func uruchom(check Check, wejscie Wejscie, teraz time.Time) Ustalenie {
	ustalenie := Ustalenie{
		CheckID: check.ID, CheckVersion: check.Version, Title: check.Title,
		Severity: check.Severity, Rationale: check.Rationale,
		Expected: check.Expected, Module: check.Module, Applicable: true,
	}
	if check.Module != "" {
		fragment, ok := wejscie.Fragment(check.Module)
		if !ok {
			ustalenie.Unknown = true
			ustalenie.ReasonCode = PowodBrakFaktu
			ustalenie.Observed = "host nie zglosil modulu " + check.Module
			return ustalenie
		}
		ustalenie.Revision = fragment.Revision
		ustalenie.ObservedAt = fragment.ObservedAt
		// Modul, ktorego host nie odczytal, nie jest modulem pustym.
		if fragment.UnavailableReason != "" {
			ustalenie.Unknown = true
			ustalenie.ReasonCode = PowodBladOdczytu
			ustalenie.Observed = "nie odczytano: " + fragment.UnavailableReason
			return ustalenie
		}
		// Odczyt sprzed doby opisuje hosta sprzed doby. Ocena na nim oparta
		// mowilaby o stanie, ktorego juz moze nie byc.
		if !fragment.ObservedAt.IsZero() && teraz.Sub(fragment.ObservedAt) > MaksymalnyWiekOdczytu {
			ustalenie.Unknown = true
			ustalenie.ReasonCode = PowodNieaktualny
			ustalenie.Observed = "ostatni odczyt: " + fragment.ObservedAt.Format(time.RFC3339)
			return ustalenie
		}
	}

	wynik := check.Ocen(wejscie)
	ustalenie.Observed = wynik.Observed
	ustalenie.Evidence = wynik.Evidence
	ustalenie.ReasonCode = wynik.ReasonCode

	switch {
	case wynik.NotApplicable:
		// Sprawdzenie, ktore hosta nie dotyczy, nie jest ani przejsciem, ani
		// porazka: nie wchodzi do zadnej z tych liczb.
		ustalenie.Applicable = false
		if ustalenie.ReasonCode == "" {
			ustalenie.ReasonCode = PowodNieobslugiwane
		}
	case wynik.Unknown:
		ustalenie.Unknown = true
		if ustalenie.ReasonCode == "" {
			ustalenie.ReasonCode = PowodBrakFaktu
		}
	case wynik.Passed:
		ustalenie.Passed = true
	}

	// Naprawe niesie wylacznie ustalenie, ktore czeka na dzialanie: plan
	// naprawy stanu poprawnego byl by zaproszeniem do zmiany bez powodu.
	if ustalenie.Wymaga() {
		ustalenie.Remediation = wynik.Remediation
	}
	return ustalenie
}

// HashPlanu liczy odcisk ustalen, ktore czekaja na dzialanie.
//
// Postac kanoniczna niesie wersje kanonizacji, hosta, a dla kazdego kroku:
// sprawdzenie, jego wersje, rewizje odczytu, z ktorego wynik powstal, oraz
// operacje naprawcza z payloadem. Zmiana czegokolwiek z tej listy zmienia
// odcisk - i plan trzeba obejrzec na nowo.
func HashPlanu(hostID string, ustalenia []Ustalenie) string {
	kroki := make([]string, 0, len(ustalenia))
	for _, ustalenie := range ustalenia {
		if !ustalenie.Wymaga() {
			continue
		}
		pola := []string{
			ustalenie.CheckID,
			strconv.Itoa(ustalenie.CheckVersion),
			ustalenie.Module,
			ustalenie.Revision,
			ustalenie.Observed,
		}
		if ustalenie.Remediation != nil {
			pola = append(pola, ustalenie.Remediation.Action, string(ustalenie.Remediation.Payload))
		} else {
			pola = append(pola, "", "")
		}
		kroki = append(kroki, strings.Join(pola, "\x1f"))
	}
	sort.Strings(kroki)

	kanoniczna := naglowekKanonizacji + strconv.Itoa(WersjaKanonizacji) + "\n" + hostID + "\n" +
		strings.Join(kroki, "\n")
	suma := sha256.Sum256([]byte(kanoniczna))
	return hex.EncodeToString(suma[:])
}

// podsumowanie liczy ustalenia wedlug stanu i wagi.
func podsumowanie(ustalenia []Ustalenie) map[string]int {
	liczby := map[string]int{"passed": 0, "failed": 0, "unknown": 0, "not_applicable": 0}
	for _, ustalenie := range ustalenia {
		switch {
		case !ustalenie.Applicable:
			liczby["not_applicable"]++
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
	if !ustalenie.Applicable {
		return 8
	}
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
