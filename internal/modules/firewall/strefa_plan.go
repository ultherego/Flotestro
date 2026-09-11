package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ZonePlan opisuje roznice miedzy strefa firewalld zastana a zadana na
// jednym hoscie.
//
// "Otworz 8080/tcp w strefie public" na jednym hoscie jest zmiana, na drugim
// jest juz otwarte, a trzeci nie ma firewalld albo tej strefy. Strefa jest
// zbiorem: plan mowi, czy wpis w nim jest, a nie ktora regula pasuje.
type ZonePlan struct {
	Zone string `json:"zone"`
	// Kind nazywa rodzaj wpisu: port albo service; Entry jest wpisem
	// w postaci, w jakiej pokazuje go firewalld ("8080/tcp", "http").
	Kind  string `json:"kind"`
	Entry string `json:"entry"`
	// Enable mowi, czy zamowienie otwiera, czy zamyka.
	Enable bool `json:"enable"`

	// Stan zastany strefy.
	ZoneExists bool `json:"zone_exists"`
	ZoneActive bool `json:"zone_active,omitempty"`
	Present    bool `json:"present"`

	// Action nazywa to, co by sie stalo: create (wpis powstanie), remove
	// (wpis zniknie) albo no_change.
	Action  string   `json:"action"`
	Changes []string `json:"changes,omitempty"`

	// RulesetHash jest odciskiem calego zestawu regul hosta przy planowaniu;
	// firewalld przepisuje nftables przy kazdej zmianie strefy, wiec zestaw
	// zmieniony po planowaniu zatrzymuje zmiane.
	RulesetHash string `json:"ruleset_hash"`
	Adapter     string `json:"adapter,omitempty"`
	Refusal     string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Rodzaje wpisow strefy.
const (
	WpisPortu  = "port"
	WpisUslugi = "service"
)

// ZaplanujPort liczy roznice dla otwarcia albo zamkniecia portu w strefie.
func ZaplanujPort(strefy []Zone, strefa, port, protokol string, otworz bool,
	rulesetHash, adapter string) ZonePlan {
	plan := ZonePlan{
		Zone: strefa, Kind: WpisPortu, Entry: port + "/" + protokol, Enable: otworz,
		RulesetHash: rulesetHash, Adapter: adapter,
	}
	if _, err := ArgumentyOtwarciaPortu(strefa, port, protokol, otworz); err != nil {
		return plan.zOdmowa(err.Error())
	}
	return plan.wobec(strefy, func(z Zone) []string { return z.Ports })
}

// ZaplanujUsluge liczy roznice dla wlaczenia albo wylaczenia uslugi w strefie.
func ZaplanujUsluge(strefy []Zone, strefa, usluga string, wlacz bool,
	rulesetHash, adapter string) ZonePlan {
	plan := ZonePlan{
		Zone: strefa, Kind: WpisUslugi, Entry: usluga, Enable: wlacz,
		RulesetHash: rulesetHash, Adapter: adapter,
	}
	if _, err := ArgumentyUslugi(strefa, usluga, wlacz); err != nil {
		return plan.zOdmowa(err.Error())
	}
	return plan.wobec(strefy, func(z Zone) []string { return z.Services })
}

// Odmow wpisuje powod odmowy poznany po policzeniu roznic i liczy odcisk
// na nowo: plan z odmowa jest inna odpowiedzia niz plan bez niej.
func (p *ZonePlan) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanuStrefy(*p)
}

func (p ZonePlan) zOdmowa(powod string) ZonePlan {
	p.Refusal = powod
	p.PlanHash = odciskPlanuStrefy(p)
	return p
}

// wobec porownuje zamowienie ze strefa, ktora host ma.
func (p ZonePlan) wobec(strefy []Zone, wpisy func(Zone) []string) ZonePlan {
	var zastana *Zone
	for i := range strefy {
		if strefy[i].Name == p.Zone {
			zastana = &strefy[i]
			break
		}
	}
	if zastana == nil {
		// Strefy nie ma: firewalld odmowilby przy zapisie, a lepiej, zeby
		// operator zobaczyl to w planie, a nie w polowie floty.
		return p.zOdmowa(fmt.Sprintf("host nie ma strefy %s", p.Zone))
	}
	p.ZoneExists = true
	p.ZoneActive = zastana.Active
	for _, wpis := range wpisy(*zastana) {
		if wpis == p.Entry {
			p.Present = true
			break
		}
	}
	switch {
	case p.Enable && !p.Present:
		p.Action = PlanTworzy
		p.Changes = []string{p.Kind + " " + p.Entry + " zostanie otwarty w strefie " + p.Zone}
	case !p.Enable && p.Present:
		p.Action = PlanUsuwa
		p.Changes = []string{p.Kind + " " + p.Entry + " zostanie zamkniety w strefie " + p.Zone}
	default:
		p.Action = PlanBezZmian
	}
	if !zastana.Active && p.Action != PlanBezZmian {
		// Zmiana w nieaktywnej strefie jest legalna, ale nie zmienia tego,
		// co host przyjmuje. Operator ma o tym wiedziec przed zgoda.
		p.Changes = append(p.Changes, "strefa "+p.Zone+" nie jest aktywna na zadnym interfejsie")
	}
	p.PlanHash = odciskPlanuStrefy(p)
	return p
}

// odciskPlanuStrefy liczy odcisk planu poza samym odciskiem.
func odciskPlanuStrefy(plan ZonePlan) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}
