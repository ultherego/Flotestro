package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// ModulePlan opisuje roznice miedzy blokada modulu zastana a zadana na
// jednym hoscie.
//
// "Zablokuj modul X" na jednym hoscie jest wpisem w pliku, na drugim juz
// jest, a na trzecim modul akurat dziala i trzyma inne moduly - wtedy wpis
// zadziala dopiero po restarcie. Operator ma to zobaczyc przed zgoda.
type ModulePlan struct {
	Module string `json:"module"`
	// Blacklist mowi, czy zamowienie blokuje, czy odblokowuje.
	Blacklist bool `json:"blacklist"`

	// Stan zastany: czy panel juz blokuje modul i czy jadro go ma
	// zaladowany, a jesli tak - kto go uzywa.
	Blacklisted bool     `json:"blacklisted"`
	Loaded      bool     `json:"loaded"`
	UsedBy      []string `json:"used_by,omitempty"`

	// Action nazywa to, co by sie stalo: create (blokada powstanie),
	// remove (blokada zniknie) albo no_change.
	Action  string   `json:"action"`
	Changes []string `json:"changes,omitempty"`

	// ManagedHash jest odciskiem pliku blokad panelu: zapis nadpisuje go
	// w calosci, wiec plik zmieniony po planowaniu jest inna zmiana.
	ManagedHash string `json:"managed_hash,omitempty"`
	Refusal     string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Nazwy dzialan planu.
const (
	PlanTworzy   = "create"
	PlanUsuwa    = "remove"
	PlanBezZmian = "no_change"
)

// ZaplanujBlokade liczy roznice dla blokady albo odblokowania modulu.
func ZaplanujBlokade(stan Snapshot, modul string, blokuj bool) ModulePlan {
	plan := ModulePlan{Module: modul, Blacklist: blokuj}
	if stan.Managed != "" {
		plan.ManagedHash = textFingerprint(stan.Managed)
	}
	if stan.UnavailableReason != "" {
		return plan.zOdmowa(stan.UnavailableReason)
	}
	if err := WalidujModul(modul); err != nil {
		return plan.zOdmowa(err.Error())
	}
	for _, nazwa := range stan.Blacklist {
		if nazwa == modul {
			plan.Blacklisted = true
		}
	}
	for _, zaladowany := range stan.Modules {
		if zaladowany.Name == modul {
			plan.Loaded = true
			plan.UsedBy = append([]string(nil), zaladowany.UsedBy...)
		}
	}

	switch {
	case blokuj && !plan.Blacklisted:
		plan.Action = PlanTworzy
		plan.Changes = []string{"blokada modulu " + modul + " powstanie"}
		if powod := InitramfsWymagany(modul, plan.Loaded); powod != "" {
			plan.Changes = append(plan.Changes, powod)
		}
		if len(plan.UsedBy) > 0 {
			plan.Changes = append(plan.Changes,
				"modulu uzywaja: "+strings.Join(plan.UsedBy, ", "))
		}
	case !blokuj && plan.Blacklisted:
		plan.Action = PlanUsuwa
		plan.Changes = []string{"blokada modulu " + modul + " zniknie"}
	default:
		plan.Action = PlanBezZmian
	}
	plan.PlanHash = odciskPlanuModulu(plan)
	return plan
}

// Odmow wpisuje powod odmowy poznany po policzeniu roznic i liczy odcisk
// na nowo: plan z odmowa jest inna odpowiedzia niz plan bez niej.
func (p *ModulePlan) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanuModulu(*p)
}

func (p ModulePlan) zOdmowa(powod string) ModulePlan {
	p.Refusal = powod
	p.PlanHash = odciskPlanuModulu(p)
	return p
}

func textFingerprint(tekst string) string {
	suma := sha256.Sum256([]byte(tekst))
	return hex.EncodeToString(suma[:])
}

// odciskPlanuModulu liczy odcisk planu poza samym odciskiem.
func odciskPlanuModulu(plan ModulePlan) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}
