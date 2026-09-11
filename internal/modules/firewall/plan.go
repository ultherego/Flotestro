package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
)

// Plan opisuje roznice miedzy regula zastana a zadana na jednym hoscie.
//
// Ta sama regula zamowiona na dwoch hostach prawie nigdy nie jest ta sama
// zmiana: jeden host juz ja ma, drugi ma ja w innym ksztalcie, trzeci nie ma
// jej wcale - a kazdy ma inny zestaw regul, wobec ktorego zmiana sie liczy.
// Zgoda operatora ma dotyczyc tych roznic, a nie samego zamiaru.
type Plan struct {
	RuleID string `json:"rule_id"`
	// Action nazywa to, co by sie stalo: create, update, no_change, remove
	// albo remove_absent.
	Action string `json:"action"`

	// Current jest regula panelu, ktora host ma teraz. Brak oznacza, ze host
	// tej reguly nie zna.
	Current *RuleSpec `json:"current,omitempty"`
	// Desired jest regula zadana. Brak przy usuwaniu.
	Desired *RuleSpec `json:"desired,omitempty"`
	// Changes wylicza po ludzku, co sie zmieni.
	Changes []string `json:"changes,omitempty"`

	// RulesetHash jest odciskiem calego zestawu regul, jaki host mial przy
	// planowaniu. Zmiana wraca na host z tym odciskiem: zestaw zmieniony po
	// planowaniu zatrzymuje ja zamiast wejsc na cudza regule.
	RulesetHash string `json:"ruleset_hash"`
	// Adapter mowi, jaki mechanizm host ma pod spodem. Plan dla hosta bez
	// nftables jest odmowa, a nie pusta lista zmian.
	Adapter string `json:"adapter,omitempty"`
	// Refusal nazywa powod, dla ktorego zmiana nie moze wejsc na ten host:
	// odcinalaby kanal zarzadzania albo regula nie nalezy do panelu. Plan
	// z odmowa jest odpowiedzia - operator ma ja zobaczyc przed zgoda.
	Refusal string `json:"refusal,omitempty"`

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

// ZaplanujRegule liczy roznice dla zalozenia albo zmiany reguly.
func ZaplanujRegule(rejestr Rejestr, zadana RuleSpec, rulesetHash, adapter string) Plan {
	plan := Plan{RuleID: zadana.ID, RulesetHash: rulesetHash, Adapter: adapter}
	docelowa := zadana
	plan.Desired = &docelowa

	obecna, jest := rejestr.Znajdz(zadana.ID)
	switch {
	case !jest:
		plan.Action = PlanTworzy
		plan.Changes = []string{"regula powstanie"}
	case reflect.DeepEqual(znormalizuj(obecna), znormalizuj(zadana)):
		zastana := obecna
		plan.Current = &zastana
		plan.Action = PlanBezZmian
	default:
		zastana := obecna
		plan.Current = &zastana
		plan.Action = PlanZmienia
		plan.Changes = roznice(obecna, zadana)
	}
	plan.PlanHash = odciskPlanu(plan)
	return plan
}

// ZaplanujUsuniecie liczy roznice dla usuniecia reguly.
func ZaplanujUsuniecie(rejestr Rejestr, id, rulesetHash, adapter string) Plan {
	plan := Plan{RuleID: id, RulesetHash: rulesetHash, Adapter: adapter}
	obecna, jest := rejestr.Znajdz(id)
	if !jest {
		// Usuniecie reguly, ktorej host nie zna, nie jest bledem i nie jest
		// zmiana. Operator ma to zobaczyc przed zatwierdzeniem.
		plan.Action = PlanJuzUsuniety
	} else {
		zastana := obecna
		plan.Current = &zastana
		plan.Action = PlanUsuwa
	}
	plan.PlanHash = odciskPlanu(plan)
	return plan
}

// Znajdz zwraca regule panelu o danym identyfikatorze.
func (r Rejestr) Znajdz(id string) (RuleSpec, bool) {
	for _, regula := range r.Rules {
		if regula.ID == id {
			return regula, true
		}
	}
	return RuleSpec{}, false
}

// znormalizuj sprowadza regule do postaci porownywalnej: kolejnosc portow
// i zrodel nie jest decyzja operatora.
func znormalizuj(regula RuleSpec) RuleSpec {
	kopia := regula
	kopia.Ports = append([]string(nil), regula.Ports...)
	kopia.Sources = append([]string(nil), regula.Sources...)
	sort.Strings(kopia.Ports)
	sort.Strings(kopia.Sources)
	if len(kopia.Ports) == 0 {
		kopia.Ports = nil
	}
	if len(kopia.Sources) == 0 {
		kopia.Sources = nil
	}
	return kopia
}

// roznice wylicza zmiany widoczne dla czlowieka.
func roznice(obecna, zadana RuleSpec) []string {
	a, b := znormalizuj(obecna), znormalizuj(zadana)
	var zmiany []string
	if a.Chain != b.Chain {
		zmiany = append(zmiany, "lancuch z "+a.Chain+" na "+b.Chain)
	}
	if a.Action != b.Action {
		zmiany = append(zmiany, "dzialanie z "+a.Action+" na "+b.Action)
	}
	if a.Protocol != b.Protocol {
		zmiany = append(zmiany, "protokol z "+lubDowolny(a.Protocol)+" na "+lubDowolny(b.Protocol))
	}
	if !reflect.DeepEqual(a.Ports, b.Ports) {
		zmiany = append(zmiany, "porty")
	}
	if !reflect.DeepEqual(a.Sources, b.Sources) {
		zmiany = append(zmiany, "zrodla")
	}
	if a.Interface != b.Interface {
		zmiany = append(zmiany, "interfejs z "+lubDowolny(a.Interface)+" na "+lubDowolny(b.Interface))
	}
	if a.Comment != b.Comment {
		zmiany = append(zmiany, "komentarz")
	}
	sort.Strings(zmiany)
	return zmiany
}

func lubDowolny(wartosc string) string {
	if wartosc == "" {
		return "dowolny"
	}
	return wartosc
}

// odciskPlanu liczy odcisk planu poza samym odciskiem.
//
// Obejmuje odcisk zestawu regul: ten sam diff policzony wobec innego zestawu
// jest inna zmiana, bo wchodzi w inne sasiedztwo regul.
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
