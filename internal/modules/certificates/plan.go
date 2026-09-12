package certificates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Plan opisuje roznice miedzy certyfikatem, ktory host ma pod sciezka,
// a tym, ktory ma tam trafic.
//
// Ten sam certyfikat wdrazany na dwa hosty prawie nigdy nie jest ta sama
// zmiana: jeden ma tam certyfikat wygasajacy jutro, drugi ten sam co
// zamowiony, trzeci nie ma pliku wcale, a kazdy przeladowuje inna usluge.
// Zgoda operatora ma dotyczyc tych roznic.
//
// Klucza prywatnego nie ma w planie i nie ma go w odcisku: plan jest
// zapisywany w bazie i pokazywany w panelu, wiec bylby miejscem wycieku.
// Plan mowi o kluczu tyle, skad host go wezmie - nazwa i wersja sekretu.
type Plan struct {
	// Kind nazywa rodzaj planu. Modul certyfikatow liczy trzy rozne plany
	// tym samym zadaniem, a odbiorca nie ma ich rozpoznawac po tym, ktore
	// pola akurat sa puste.
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	KeyPath string `json:"key_path,omitempty"`
	// Action nazywa to, co by sie stalo: create, update albo no_change.
	Action string `json:"action"`

	// Stan zastany. Brak odcisku przy Exists = true oznacza plik, ktorego
	// nie udalo sie odczytac - i wtedy niesie to Powodem.
	Exists             bool       `json:"exists"`
	CurrentSubject     string     `json:"current_subject,omitempty"`
	CurrentFingerprint string     `json:"current_fingerprint,omitempty"`
	CurrentNotAfter    *time.Time `json:"current_not_after,omitempty"`
	Powodem            string     `json:"unavailable_reason,omitempty"`

	// Stan docelowy: to, co panel przysłal jawnie. Certyfikat jest
	// materialem publicznym, wiec plan opisuje go wprost.
	DesiredSubject     string    `json:"desired_subject,omitempty"`
	DesiredFingerprint string    `json:"desired_fingerprint,omitempty"`
	DesiredNotAfter    time.Time `json:"desired_not_after,omitempty"`
	DesiredSANs        []string  `json:"desired_sans,omitempty"`
	ChainLength        int       `json:"chain_length,omitempty"`

	// KeySecret nazywa sekret, po ktory host siegnie tuz przed podmiana.
	// Nigdy jego wartosc.
	KeySecret   string `json:"key_secret,omitempty"`
	ReloadUnit  string `json:"reload_unit,omitempty"`
	ProbeTarget string `json:"probe_target,omitempty"`

	Changes []string `json:"changes,omitempty"`
	// Refusal nazywa powod, dla ktorego wdrozenie nie wejdzie na ten host:
	// material, ktorego host nie przyjmie, cel poza zakresem certyfikatu,
	// brak odnosnika do klucza. Plan z odmowa jest odpowiedzia, ktora
	// operator ma zobaczyc przed zgoda.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Rodzaje planow modulu certyfikatow.
const (
	RodzajWdrozenia  = "certificate"
	RodzajOdnowienia = "renewal"
	RodzajZaufania   = "trust"
)

// Nazwy dzialan planu.
const (
	PlanTworzy      = "create"
	PlanZmienia     = "update"
	PlanBezZmian    = "no_change"
	PlanUsuwa       = "remove"
	PlanJuzUsuniety = "remove_absent"
)

// Zamowienie opisuje wdrozenie widziane przez planer. Klucza tu nie ma:
// plan powstaje bez siegania do magazynu sekretow.
type Zamowienie struct {
	Path       string
	KeyPath    string
	Certyfikat string
	KeySecret  string
	Jednostka  string
	Cel        string
	MaKlucz    bool
}

// Zaplanuj liczy roznice miedzy certyfikatem zastanym a zamowionym.
//
// Brak pliku i plik nieodczytany to dwie rozne odpowiedzi: pierwsza znaczy
// "certyfikat powstanie", druga "nie wiadomo, co tam lezy" - i ta druga
// nie moze udawac pierwszej.
func Zaplanuj(obecny Certyfikat, zamowienie Zamowienie, teraz time.Time) Plan {
	plan := Plan{
		Kind: RodzajWdrozenia,
		Path: zamowienie.Path, KeyPath: zamowienie.KeyPath,
		KeySecret: zamowienie.KeySecret, ReloadUnit: zamowienie.Jednostka,
		ProbeTarget: zamowienie.Cel,
	}
	if obecny.FingerprintSHA256 != "" || (obecny.UnavailableReason != "" && !BrakPliku(obecny.UnavailableReason)) {
		plan.Exists = true
		plan.CurrentSubject = obecny.Subject
		plan.CurrentFingerprint = obecny.FingerprintSHA256
		plan.CurrentNotAfter = obecny.NotAfter
		plan.Powodem = obecny.UnavailableReason
	}

	if err := WalidujSciezke(zamowienie.Path); err != nil {
		return plan.zOdmowa(err.Error())
	}
	if zamowienie.KeyPath != "" {
		if err := WalidujSciezke(zamowienie.KeyPath); err != nil {
			return plan.zOdmowa(err.Error())
		}
	}
	if err := WalidujJednostke(zamowienie.Jednostka); err != nil {
		return plan.zOdmowa(err.Error())
	}
	if zamowienie.Cel != "" {
		if err := WalidujCel(zamowienie.Cel); err != nil {
			return plan.zOdmowa(err.Error())
		}
	}
	// Klucz prywatny jedzie na host wylacznie jako odnosnik do magazynu.
	// Wdrozenie bez niego zostawiloby nowy certyfikat przy starym kluczu,
	// a usluga nie wstalaby po przeladowaniu.
	if zamowienie.KeyPath != "" && !zamowienie.MaKlucz {
		return plan.zOdmowa("wdrozenie klucza wymaga odnosnika do magazynu sekretow")
	}

	certy, err := ParsujPEM([]byte(zamowienie.Certyfikat))
	if err != nil {
		return plan.zOdmowa(err.Error())
	}
	if err := SprawdzTerminy(certy[0], teraz); err != nil {
		return plan.zOdmowa(err.Error())
	}
	if err := SprawdzLancuch(certy); err != nil {
		return plan.zOdmowa(err.Error())
	}
	// Cel sondy poza zakresem certyfikatu konczylby sie cofnieciem wdrozenia
	// po podmianie plikow. Lepiej powiedziec to przed zgoda.
	if zamowienie.Cel != "" {
		if nazwa := nazwaCelu(zamowienie.Cel); nazwa != "" && !Obejmuje(certy[0], nazwa) {
			return plan.zOdmowa("certyfikat nie obejmuje nazwy " + nazwa +
				", pod ktora host mial sprawdzic wdrozenie")
		}
	}

	plan.DesiredSubject = certy[0].Subject.String()
	plan.DesiredFingerprint = Odcisk(certy[0])
	plan.DesiredNotAfter = certy[0].NotAfter.UTC()
	plan.DesiredSANs = NazwyAlternatywne(certy[0])
	plan.ChainLength = len(certy)

	switch {
	case plan.Exists && plan.CurrentFingerprint == "":
		// Pliku nie udalo sie odczytac. To nie znaczy "powstanie" i nie
		// znaczy "bez zmian": operator ma zobaczyc powod przed zgoda.
		return plan.zOdmowa("nie odczytano certyfikatu zastanego: " + plan.Powodem)
	case !plan.Exists:
		plan.Action = PlanTworzy
		plan.Changes = []string{"certyfikat powstanie, wazny do " +
			plan.DesiredNotAfter.Format(time.RFC3339)}
	case plan.CurrentFingerprint == plan.DesiredFingerprint:
		plan.Action = PlanBezZmian
	default:
		plan.Action = PlanZmienia
		plan.Changes = []string{fmt.Sprintf("certyfikat z %s na %s",
			skrocony(plan.CurrentFingerprint), skrocony(plan.DesiredFingerprint))}
		if plan.CurrentNotAfter != nil {
			plan.Changes = append(plan.Changes, "waznosc z "+
				plan.CurrentNotAfter.UTC().Format(time.RFC3339)+" na "+
				plan.DesiredNotAfter.Format(time.RFC3339))
		}
	}
	if plan.Action != PlanBezZmian {
		if zamowienie.KeyPath != "" {
			plan.Changes = append(plan.Changes, "klucz prywatny zostanie podmieniony z sekretu "+
				lubBrakSekretu(zamowienie.KeySecret))
		}
		if zamowienie.Jednostka != "" {
			plan.Changes = append(plan.Changes, "usluga "+zamowienie.Jednostka+" zostanie przeladowana")
		}
		if zamowienie.Cel != "" {
			plan.Changes = append(plan.Changes, "host sprawdzi wdrozenie sonda do "+zamowienie.Cel)
		}
	}
	plan.PlanHash = odciskPlanu(plan)
	return plan
}

// Odmow wpisuje powod odmowy poznany po policzeniu roznic i liczy odcisk
// na nowo: plan z odmowa jest inna odpowiedzia niz plan bez niej.
func (p *Plan) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanu(*p)
}

func (p Plan) zOdmowa(powod string) Plan {
	p.Refusal = powod
	p.PlanHash = odciskPlanu(p)
	return p
}

// nazwaCelu wyciaga nazwe hosta z celu sondy "host:port".
func nazwaCelu(cel string) string {
	if i := strings.LastIndex(cel, ":"); i > 0 {
		return cel[:i]
	}
	return cel
}

func skrocony(odcisk string) string {
	if len(odcisk) <= 16 {
		return lubBrakSekretu(odcisk)
	}
	return odcisk[:16]
}

func lubBrakSekretu(wartosc string) string {
	if wartosc == "" {
		return "brak"
	}
	return wartosc
}

// odciskPlanu liczy odcisk planu poza samym odciskiem. Klucza prywatnego
// w planie nie ma, wiec nie ma go takze w odcisku.
func odciskPlanu(plan Plan) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}

// BrakPliku mowi, czy powod niedostepnosci opisuje plik, ktorego nie ma.
//
// Plik nieistniejacy i plik nieodczytany to dwie rozne odpowiedzi: pierwsza
// jest stanem docelowym do utworzenia, druga jest brakiem wiedzy.
func BrakPliku(powod string) bool {
	return strings.Contains(powod, "no such file or directory") ||
		strings.Contains(powod, os.ErrNotExist.Error())
}

// PlanOdnowienia opisuje odnowienie certyfikatu przez demona hosta.
//
// Odnowienie jest inna zmiana niz wdrozenie: panel nie przysyla materialu,
// tylko prosi demona, zeby poszedl po nowy certyfikat do swojego urzedu.
// Dlatego plan mowi o tym, co host ma teraz i czy w ogole ma komu zlecic
// odnowienie - a nie o tresci, ktora przyjdzie.
type PlanOdnowienia struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Action string `json:"action"`

	// Stan zastany: certyfikat i to, co go pilnuje.
	CurrentFingerprint string     `json:"current_fingerprint,omitempty"`
	CurrentNotAfter    *time.Time `json:"current_not_after,omitempty"`
	DaysToExpiry       *int       `json:"days_to_expiry,omitempty"`
	// Request jest identyfikatorem zlecenia certmongera na tym hoscie. Ten
	// sam certyfikat ma na kazdym hoscie inny identyfikator, wiec kampania
	// podaje sciezke, a host odnajduje zlecenie sam.
	Request string `json:"request,omitempty"`
	Status  string `json:"status,omitempty"`
	CA      string `json:"ca,omitempty"`
	// AutoRenew mowi, czy demon odnowilby ten certyfikat takze sam.
	AutoRenew *bool `json:"auto_renew,omitempty"`

	ReloadUnit string   `json:"reload_unit,omitempty"`
	Changes    []string `json:"changes,omitempty"`
	Refusal    string   `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// ZaplanujOdnowienie liczy plan odnowienia wobec stanu hosta.
func ZaplanujOdnowienie(obecny Certyfikat, sledzenie *Sledzenie, maDemona bool,
	sciezka, jednostka string, teraz time.Time) PlanOdnowienia {
	plan := PlanOdnowienia{Kind: RodzajOdnowienia, Path: sciezka,
		ReloadUnit: jednostka, Action: PlanZmienia}
	if err := WalidujSciezke(sciezka); err != nil {
		return plan.zOdmowa(err.Error())
	}
	if err := WalidujJednostke(jednostka); err != nil {
		return plan.zOdmowa(err.Error())
	}
	// Demon hosta jest tu jedynym, kto umie odnowic: panel nie ma klucza ani
	// uzgodnienia z urzedem. Host bez demona nie jest hostem do naprawienia
	// zmiana - jest hostem, ktory tej zmiany nie przyjmie.
	if !maDemona {
		return plan.zOdmowa("ten host nie ma certmongera, wiec nie ma komu zlecic odnowienia")
	}
	if obecny.FingerprintSHA256 != "" {
		plan.CurrentFingerprint = obecny.FingerprintSHA256
		plan.CurrentNotAfter = obecny.NotAfter
		plan.DaysToExpiry = obecny.DniDoWygasniecia(teraz)
	}
	if sledzenie == nil || sledzenie.Request == "" {
		return plan.zOdmowa("certmonger nie pilnuje pliku " + sciezka + ", wiec nie ma czego odnowic")
	}
	plan.Request = sledzenie.Request
	plan.Status = sledzenie.Status
	plan.CA = sledzenie.CA
	plan.AutoRenew = sledzenie.AutoRenew

	plan.Changes = []string{"host poprosi urzad " + lubBrakSekretu(sledzenie.CA) +
		" o nowy certyfikat dla " + sciezka}
	if plan.DaysToExpiry != nil {
		plan.Changes = append(plan.Changes,
			fmt.Sprintf("obecny certyfikat traci waznosc za %d dni", *plan.DaysToExpiry))
	}
	// Stan zlecenia jest tu wazniejszy niz sam fakt, ze demon je zna:
	// CA_UNREACHABLE znaczy opieke, ktora nie dziala, i operator ma to
	// zobaczyc przed zgoda, a nie po niej.
	if sledzenie.Status != "" && sledzenie.Status != "MONITORING" {
		plan.Changes = append(plan.Changes, "certmonger zglasza stan "+sledzenie.Status)
	}
	if jednostka != "" {
		plan.Changes = append(plan.Changes, "usluga "+jednostka+" zostanie przeladowana")
	}
	plan.PlanHash = odciskPlanuOdnowienia(plan)
	return plan
}

// Odmow wpisuje powod odmowy poznany po policzeniu planu.
func (p *PlanOdnowienia) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanuOdnowienia(*p)
}

func (p PlanOdnowienia) zOdmowa(powod string) PlanOdnowienia {
	p.Refusal = powod
	p.Action = ""
	p.PlanHash = odciskPlanuOdnowienia(p)
	return p
}

// odciskPlanuOdnowienia liczy odcisk planu poza samym odciskiem.
//
// Identyfikator zlecenia jest inny na kazdym hoscie i zmienia sie przy
// kazdym nowym zleceniu, wiec wchodzi do odcisku: odnowienie zatwierdzone
// dla jednego zlecenia nie moze wejsc na inne.
func odciskPlanuOdnowienia(plan PlanOdnowienia) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}
