package czas

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

// Plan opisuje roznice miedzy zrodlami czasu, ktore panel ma na hoscie,
// a zadanymi.
//
// Ta sama lista serwerow na dwoch hostach jest dwiema zmianami: jeden ma
// chrony z katalogiem zrodel i przeladuje sie bez restartu, drugi ma
// timesyncd i zrestartuje demona, trzeci nie wlacza zadnego katalogu
// i wymaga dopisania wiersza do cudzego pliku. Operator ma to zobaczyc
// przed zgoda, nie w polowie floty.
type Plan struct {
	// Service nazywa demona czasu hosta; Action - to, co by sie stalo:
	// update albo no_change.
	Service string `json:"service,omitempty"`
	Action  string `json:"action"`

	// CurrentServers to serwery zapisane przez panel; DesiredServers -
	// zamowienie.
	CurrentServers []string `json:"current_servers,omitempty"`
	DesiredServers []string `json:"desired_servers"`
	// ManagedPath jest plikiem, ktory zapis nadpisze; pusty oznacza, ze
	// host nie ma gdzie przyjac zmiany bez wlaczenia katalogu.
	ManagedPath string `json:"managed_path,omitempty"`
	ManagedHash string `json:"managed_hash,omitempty"`
	// EnablesSourceDir mowi, ze zmiana dopisze katalog panelu do glownego
	// pliku chronyego - jedyne miejsce, w ktorym panel dotyka cudzej
	// konfiguracji.
	EnablesSourceDir bool `json:"enables_source_dir,omitempty"`
	// Restart mowi, czy demon zostanie zrestartowany, czy tylko przeladuje
	// zrodla. Restart to chwila bez synchronizacji.
	Restart bool `json:"restart,omitempty"`

	Changes []string `json:"changes,omitempty"`
	Refusal string   `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Nazwy dzialan planu.
const (
	PlanZmienia  = "update"
	PlanBezZmian = "no_change"
)

// Zaplanuj liczy roznice dla zmiany zrodel czasu.
func Zaplanuj(stan Snapshot, serwery []string, zgodaNaKatalog bool) Plan {
	plan := Plan{Service: stan.Service, DesiredServers: append([]string(nil), serwery...),
		ManagedPath: stan.ManagedPath}
	if stan.Managed != "" {
		plan.ManagedHash = odciskTekstu(stan.Managed)
	}
	for _, serwer := range stan.Configured {
		if serwer.Managed {
			plan.CurrentServers = append(plan.CurrentServers, serwer.Address)
		}
	}
	if stan.UnavailableReason != "" {
		return plan.zOdmowa(stan.UnavailableReason)
	}
	if err := WalidujSerwery(serwery); err != nil {
		return plan.zOdmowa(err.Error())
	}

	var tresc string
	switch stan.Service {
	case DemonChrony:
		if stan.ManagedPath == "" {
			if !zgodaNaKatalog {
				powod := stan.WriteReason
				if powod == "" {
					powod = "chrony na tym hoscie nie wlacza zadnego katalogu konfiguracji"
				}
				return plan.zOdmowa(powod)
			}
			if !stan.CanAddSourceDir || stan.ConfigPath == "" {
				return plan.zOdmowa("nie znaleziono glownego pliku chronyego, do ktorego mozna dopisac katalog zrodel")
			}
			plan.EnablesSourceDir = true
			plan.Restart = true
			plan.ManagedPath = filepath.Join(KatalogZrodelPanelu, NazwaPlikuChrony(RodzajZrodel))
		}
		rodzaj := RodzajKonfiguracji
		if filepath.Ext(plan.ManagedPath) == ".sources" {
			rodzaj = RodzajZrodel
		}
		if rodzaj != RodzajZrodel {
			plan.Restart = true
		}
		tresc, _ = SkladajChrony(serwery, rodzaj)
	case DemonTimesyncd:
		plan.ManagedPath = PlikTimesyncd
		plan.Restart = true
		tresc, _ = SkladajTimesyncd(serwery)
	default:
		return plan.zOdmowa("ten host nie ma demona czasu, ktoremu panel moglby wskazac serwery")
	}

	if !tenSamZbior(plan.CurrentServers, serwery) {
		plan.Changes = append(plan.Changes, "serwery panelu z "+lista(plan.CurrentServers)+
			" na "+lista(serwery))
	}
	switch {
	case stan.Managed == "" && stan.ManagedPath == "":
		plan.Changes = append(plan.Changes, "plik panelu "+plan.ManagedPath+" powstanie")
	case stan.Managed != tresc:
		if stan.Managed == "" {
			plan.Changes = append(plan.Changes, "plik panelu "+plan.ManagedPath+" powstanie")
		} else {
			plan.Changes = append(plan.Changes, "plik panelu "+plan.ManagedPath+" zostanie nadpisany")
		}
	}
	if plan.EnablesSourceDir {
		plan.Changes = append(plan.Changes,
			"do "+stan.ConfigPath+" zostanie dopisany katalog zrodel panelu")
	}
	if len(plan.Changes) > 0 {
		if plan.Restart {
			plan.Changes = append(plan.Changes, "demon czasu zostanie zrestartowany")
		} else {
			plan.Changes = append(plan.Changes, "zrodla zostana przeladowane bez restartu demona")
		}
	}

	plan.Action = PlanZmienia
	if len(plan.Changes) == 0 {
		plan.Action = PlanBezZmian
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

func tenSamZbior(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

func lista(elementy []string) string {
	if len(elementy) == 0 {
		return "brak"
	}
	return strings.Join(elementy, ",")
}

func odciskTekstu(tekst string) string {
	suma := sha256.Sum256([]byte(tekst))
	return hex.EncodeToString(suma[:])
}

// odciskPlanu liczy odcisk planu poza samym odciskiem.
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
