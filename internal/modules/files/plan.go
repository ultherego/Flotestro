package files

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Plan opisuje roznice miedzy plikiem zastanym a stanem docelowym.
//
// Dwa hosty z tym samym stanem docelowym prawie nigdy nie maja tego samego
// diffu: jeden ma plik o innej tresci, drugi nie ma go wcale, trzeci ma go
// z innymi prawami. Zgoda operatora ma dotyczyc tych roznic, a nie samego
// zamiaru - i dlatego plan powstaje osobno na kazdym hoscie.
type Plan struct {
	Path string `json:"path"`
	// Action nazywa to, co by sie stalo: create, update, no_change, remove
	// albo remove_absent. Bez tego lista planow jest lista sciezek.
	Action string `json:"action"`

	// Stan zastany. Puste pola przy Exists = false nie sa zerem: pliku nie ma
	// i nie ma o czym mowic.
	Exists  bool   `json:"exists"`
	SHA256  string `json:"sha256,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Group   string `json:"group,omitempty"`
	Size    int64  `json:"size_bytes,omitempty"`
	Powodem string `json:"unavailable_reason,omitempty"`

	// Stan docelowy.
	DesiredSHA256 string `json:"desired_sha256,omitempty"`
	DesiredMode   string `json:"desired_mode,omitempty"`
	DesiredOwner  string `json:"desired_owner,omitempty"`
	DesiredGroup  string `json:"desired_group,omitempty"`

	// Changes wylicza po ludzku, co sie zmieni. Odcisk tresci nie mowi
	// operatorowi nic; "tresc" i "prawa z 0644 na 0600" mowia.
	Changes []string `json:"changes,omitempty"`

	// ValidatorOutput jest wynikiem sprawdzenia tresci docelowej. Plan, ktory
	// nie przeszedl walidacji, jest odpowiedzia - a nie bledem odczytu.
	ValidatorOutput string `json:"validator_output,omitempty"`
	ValidatorFailed bool   `json:"validator_failed,omitempty"`

	// PlanHash wiaze plan z ta konkretna roznica. Wchodzi do odcisku zgody,
	// a przy zapisie host sprawdza jeszcze raz, czy plik nadal wyglada tak,
	// jak w chwili planu.
	PlanHash string `json:"plan_hash"`
}

// Nazwy dzialan planu.
const (
	PlanTworzy      = "create"
	PlanZmienia     = "update"
	PlanBezZmian    = "no_change"
	PlanUsuwa       = "remove"
	PlanJuzUsuniety = "remove_absent"
)

// Zaplanuj liczy roznice miedzy plikiem zastanym a stanem docelowym.
//
// Tresc docelowa jest tu jawna, bo panel ja przyslal. Plik z sekretu jest
// wyjatkiem: jego tresci nie ma w planie i nie ma jej w odcisku - inaczej
// sam plan bylby miejscem wycieku.
func Zaplanuj(obecny Plik, trescDocelowa []byte, tryb, wlasciciel, grupa string,
	zSekretu, usuwanie bool) Plan {
	plan := Plan{
		Path: obecny.Path, Exists: obecny.Exists, Mode: obecny.Mode,
		Owner: obecny.Owner, Group: obecny.Group, Size: obecny.SizeBytes,
		Powodem: obecny.UnavailableReason, SHA256: obecny.SHA256,
		DesiredMode: tryb, DesiredOwner: wlasciciel, DesiredGroup: grupa,
	}

	if usuwanie {
		plan.Action = PlanUsuwa
		if !obecny.Exists {
			// Usuniecie pliku, ktorego nie ma, nie jest bledem i nie jest
			// zmiana. Operator ma to zobaczyc przed zatwierdzeniem, a nie
			// dowiedziec sie z raportu.
			plan.Action = PlanJuzUsuniety
		}
		plan.DesiredMode, plan.DesiredOwner, plan.DesiredGroup = "", "", ""
		plan.PlanHash = odciskPlanu(plan)
		return plan
	}

	if !zSekretu {
		suma := sha256.Sum256(trescDocelowa)
		plan.DesiredSHA256 = hex.EncodeToString(suma[:])
	}

	switch {
	case !obecny.Exists:
		plan.Action = PlanTworzy
		plan.Changes = []string{"plik powstanie"}
	default:
		plan.Changes = roznice(plan, zSekretu)
		plan.Action = PlanZmienia
		if len(plan.Changes) == 0 {
			plan.Action = PlanBezZmian
		}
	}
	plan.PlanHash = odciskPlanu(plan)
	return plan
}

// roznice wylicza zmiany widoczne dla czlowieka.
func roznice(plan Plan, zSekretu bool) []string {
	var zmiany []string
	switch {
	case zSekretu:
		// Tresci z magazynu nie porownujemy: nie ma jej w planie, wiec nie
		// mozemy twierdzic ani ze sie zmieni, ani ze nie.
		zmiany = append(zmiany, "tresc pochodzi z magazynu sekretow i nie jest porownywana")
	case plan.SHA256 == "":
		// Odcisku zastanego nie udalo sie policzyc. To nie znaczy "bez zmian".
		zmiany = append(zmiany, "tresci zastanej nie udalo sie odczytac")
	case plan.SHA256 != plan.DesiredSHA256:
		zmiany = append(zmiany, "tresc")
	}
	if plan.DesiredMode != "" && plan.Mode != "" && plan.DesiredMode != plan.Mode {
		zmiany = append(zmiany, fmt.Sprintf("prawa z %s na %s", plan.Mode, plan.DesiredMode))
	}
	if plan.DesiredOwner != "" && plan.Owner != "" && plan.DesiredOwner != plan.Owner {
		zmiany = append(zmiany, fmt.Sprintf("wlasciciel z %s na %s", plan.Owner, plan.DesiredOwner))
	}
	if plan.DesiredGroup != "" && plan.Group != "" && plan.DesiredGroup != plan.Group {
		zmiany = append(zmiany, fmt.Sprintf("grupa z %s na %s", plan.Group, plan.DesiredGroup))
	}
	sort.Strings(zmiany)
	return zmiany
}

// odciskPlanu liczy odcisk calego planu poza samym odciskiem.
//
// Obejmuje stan zastany i docelowy razem: plan policzony na hoscie, ktory
// w miedzyczasie sie zmienil, ma dac inny odcisk - bo to juz inna zmiana.
func odciskPlanu(plan Plan) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	// Wynik walidatora bywa dlugi i nie opisuje samej roznicy, wiec nie
	// wchodzi do odcisku: ten sam diff ma dac ten sam odcisk.
	bezOdcisku.ValidatorOutput = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}
