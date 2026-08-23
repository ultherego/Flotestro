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
	ModulDNS        = "dns"
	ModulFirewall   = "firewall"
	ModulStorage    = "storage"
	ModulSSH        = "ssh"
	ModulKernel     = "kernel"
	ModulFiles      = "files"
	ModulContainers = "containers"
	ModulSchedules  = "schedules"
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

		{ModulContainers, "agent/docker-engine", powodKontenerow(f), podsumowanieKontenerow(f)},

		{ModulSchedules, "agent/cron+systemd", powodHarmonogramow(f), harmonogramy(f)},

		// Modul sieci zastapil sama liste nazw interfejsow: nazwa bez adresu,
		// stanu i tras nie odpowiadala na zadne pytanie operatora.
		{ModulNetwork, "agent/iproute2", powodSieci(f), siec(f)},

		{ModulDNS, "agent/resolvectl+resolv.conf", powodStanuResolvera(f), resolver(f)},

		{ModulFirewall, "agent/nftables", powodZapory(f), zapora(f)},

		{ModulStorage, "agent/lsblk+mountinfo", powodPrzestrzeni(f), przestrzen(f)},

		{ModulSSH, "agent/sshd", powodSSH(f), konfiguracjaSSH(f)},

		{ModulKernel, "agent/procfs+sysctl", powodJadra(f), jadro(f)},

		{ModulFiles, "agent/managed-files", powodPlikow(f), plikiZarzadzane(f)},
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

// powodHarmonogramow zwraca powod, dla ktorego zadan cyklicznych nie ustalono.
func powodHarmonogramow(f Facts) string {
	if f.Schedules == nil {
		return "this host has no cron directory"
	}
	return f.Schedules.UnavailableReason
}

// harmonogramy zwraca zadania cykliczne albo pusty stan.
func harmonogramy(f Facts) any {
	if f.Schedules == nil {
		return struct{}{}
	}
	return f.Schedules
}

// powodSieci zwraca powod, dla ktorego stanu sieci nie ustalono.
func powodSieci(f Facts) string {
	if f.Network == nil {
		return "this host did not report its network state"
	}
	return f.Network.UnavailableReason
}

// siec zwraca stan sieci albo pusty obraz.
func siec(f Facts) any {
	if f.Network == nil {
		return struct{}{}
	}
	return f.Network
}

// powodStanuResolvera zwraca powod, dla ktorego stanu resolvera nie ustalono.
func powodStanuResolvera(f Facts) string {
	if f.DNS == nil {
		return "this host did not report its resolver state"
	}
	return f.DNS.UnavailableReason
}

// resolver zwraca stan resolvera albo pusty obraz.
func resolver(f Facts) any {
	if f.DNS == nil {
		return struct{}{}
	}
	return f.DNS
}

// powodZapory zwraca powod, dla ktorego stanu zapory nie ustalono.
func powodZapory(f Facts) string {
	if f.Firewall == nil {
		return "this host did not report its firewall state"
	}
	return f.Firewall.UnavailableReason
}

// zapora zwraca stan zapory albo pusty obraz.
func zapora(f Facts) any {
	if f.Firewall == nil {
		return struct{}{}
	}
	return f.Firewall
}

// powodPrzestrzeni zwraca powod, dla ktorego topologii nie ustalono.
func powodPrzestrzeni(f Facts) string {
	if f.Storage == nil {
		return "this host did not report its storage layout"
	}
	return f.Storage.UnavailableReason
}

// przestrzen zwraca obraz przestrzeni dyskowej albo pusty stan.
func przestrzen(f Facts) any {
	if f.Storage == nil {
		return struct{}{}
	}
	return f.Storage
}

// powodSSH zwraca powod, dla ktorego konfiguracji sshd nie ustalono.
func powodSSH(f Facts) string {
	if f.SSH == nil {
		return "this host has no sshd"
	}
	return f.SSH.UnavailableReason
}

// konfiguracjaSSH zwraca konfiguracje serwera albo pusty stan.
func konfiguracjaSSH(f Facts) any {
	if f.SSH == nil {
		return struct{}{}
	}
	return f.SSH
}

// powodJadra zwraca powod, dla ktorego ustawien jadra nie ustalono.
func powodJadra(f Facts) string {
	if f.Kernel == nil {
		return "this host did not report its kernel settings"
	}
	return f.Kernel.UnavailableReason
}

// jadro zwraca ustawienia jadra albo pusty stan.
func jadro(f Facts) any {
	if f.Kernel == nil {
		return struct{}{}
	}
	return f.Kernel
}

// powodPlikow zwraca powod, dla ktorego stanu plikow nie ustalono.
func powodPlikow(f Facts) string {
	if f.Files == nil {
		return "this host did not report its managed files"
	}
	return f.Files.UnavailableReason
}

// plikiZarzadzane zwraca stan plikow albo pusty obraz.
func plikiZarzadzane(f Facts) any {
	if f.Files == nil {
		return struct{}{}
	}
	return f.Files
}
