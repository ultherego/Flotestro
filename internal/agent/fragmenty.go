package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Nazwy modulow inventory. Modul odpowiada zakladce hosta, wiec interfejs
// pobiera dokladnie to, co pokazuje, a nie caly raport.
const (
	ModulSystem     = "system"
	ModulPackages   = "packages"
	ModulServices   = "services"
	ModulIdentity   = "identity"
	ModulAccounts   = "accounts"
	ModulNetwork    = "network"
	ModulContainers = "containers"
)

// Fragment to stan jednego modulu hosta wraz z jego wlasna rewizja.
//
// Rewizja liczona osobno dla kazdego modulu ma dwa skutki. Zmiana jednego
// modulu nie przepisuje calego inventory, a interfejs wie, jak swieza jest
// akurat ta zakladka, ktora operator oglada - dotad wszystkie zakladki
// dzielily jeden znacznik i jedna date.
type Fragment struct {
	Module            string          `json:"module"`
	Revision          string          `json:"revision"`
	Source            string          `json:"source"`
	Payload           json.RawMessage `json:"payload"`
	UnavailableReason string          `json:"unavailable_reason,omitempty"`
	ObservedAt        time.Time       `json:"observed_at"`
}

// Fragments rozbija raport na moduly.
func (f Facts) Fragments() ([]Fragment, error) {
	menedzer := "agent/packages"
	if f.Packages.Manager != "" {
		menedzer = "agent/" + f.Packages.Manager
	}

	// Nieodczytany stan jednostek nie moze wygladac jak pusta lista jednostek
	// w bledzie, wiec brak wiedzy jest tu powodem, a nie cisza.
	powodUslug := ""
	if !f.FailedUnitsKnown {
		powodUslug = "unit states could not be read from systemd"
	}

	opisy := []struct {
		modul  string
		zrodlo string
		powod  string
		tresc  any
	}{
		{ModulSystem, "agent/os-release+procfs", "", struct {
			OS       OSInfo   `json:"os"`
			Hardware Hardware `json:"hardware"`
			Hostname string   `json:"hostname"`
			BootID   string   `json:"boot_id"`
		}{f.OS, f.Hardware, f.Hostname, f.BootID}},

		{ModulPackages, menedzer, f.Packages.UnavailableReason, f.Packages},

		{ModulServices, "agent/systemctl", powodUslug, struct {
			FailedUnits []string `json:"failed_units"`
			Known       bool     `json:"failed_units_known"`
		}{f.FailedUnits, f.FailedUnitsKnown}},

		{ModulIdentity, "agent/sssd", f.Identity.UnavailableReason, f.Identity},

		{ModulAccounts, "agent/passwd", "", struct {
			Accounts []LocalAccount `json:"accounts"`
		}{f.LocalAccounts}},

		{ModulNetwork, "agent/net", "", struct {
			Interfaces []string `json:"interfaces"`
		}{f.Interfaces}},

		{ModulContainers, "agent/docker-engine", powodKontenerow(f), podsumowanieKontenerow(f)},
	}

	fragmenty := make([]Fragment, 0, len(opisy))
	for _, opis := range opisy {
		payload, err := json.Marshal(opis.tresc)
		if err != nil {
			return nil, err
		}
		suma := sha256.Sum256(payload)
		fragmenty = append(fragmenty, Fragment{
			Module:            opis.modul,
			Revision:          hex.EncodeToString(suma[:16]),
			Source:            opis.zrodlo,
			Payload:           payload,
			UnavailableReason: opis.powod,
			ObservedAt:        f.CollectedAt,
		})
	}
	return fragmenty, nil
}

// powodKontenerow zwraca powod, dla ktorego stanu silnika nie ustalono.
func powodKontenerow(f Facts) string {
	if f.Containers == nil {
		return "this host does not run a container engine"
	}
	return f.Containers.UnavailableReason
}

// podsumowanieKontenerow zwraca stan silnika albo pusty, gdy silnika nie ma.
// Brak silnika i silnik nieodpytany rozroznia powod, a nie tresc.
func podsumowanieKontenerow(f Facts) any {
	if f.Containers == nil {
		return struct{}{}
	}
	return f.Containers
}
