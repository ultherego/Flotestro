// Package opspec definiuje operacje typowane wspolne dla control plane,
// agenta i helpera. Pakiet nie ma zaleznosci poza biblioteka standardowa,
// dzieki czemu hash planu jest liczony jedna implementacja po obu stronach.
package opspec

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ActionType jest typem operacji. Kazdy typ ma wersje kontraktu i wlasne
// uprawnienie; nie istnieje typ "dowolne polecenie".
type ActionType string

const (
	ActionUnitStart   ActionType = "unit.start"
	ActionUnitStop    ActionType = "unit.stop"
	ActionUnitRestart ActionType = "unit.restart"
	ActionUnitReload  ActionType = "unit.reload"
	ActionReadJournal ActionType = "journal.read"

	ActionPackagePlan    ActionType = "packages.plan"
	ActionPackageUpgrade ActionType = "packages.upgrade"

	ActionSystemReboot ActionType = "system.reboot"
	ActionUnitStatus   ActionType = "unit.status"

	ActionDomainEnroll    ActionType = "identity.host.enroll"
	ActionDomainPreflight ActionType = "identity.host.preflight"
)

// ActionVersion jest wersja kontraktu payloadu. Zmiana znaczenia pol wymaga
// podniesienia wersji, a nie cichej reinterpretacji.
const ActionVersion = 1

// Known sprawdza, czy typ operacji jest obslugiwany.
func (a ActionType) Known() bool {
	_, ok := actionSpecs[a]
	return ok
}

// Mutating mowi, czy operacja zmienia stan hosta.
func (a ActionType) Mutating() bool {
	spec, ok := actionSpecs[a]
	return ok && spec.mutating
}

// RequiredCapability zwraca zdolnosc hosta, bez ktorej operacja nie ma sensu.
func (a ActionType) RequiredCapability() string {
	return actionSpecs[a].capability
}

// Permission zwraca uprawnienie wymagane do zlecenia operacji.
func (a ActionType) Permission() string {
	return actionSpecs[a].permission
}

// DefaultTimeout zwraca domyslny limit czasu wykonania w sekundach.
func (a ActionType) DefaultTimeout() int {
	return actionSpecs[a].timeoutSeconds
}

type actionSpec struct {
	mutating       bool
	capability     string
	permission     string
	timeoutSeconds int
}

var actionSpecs = map[ActionType]actionSpec{
	ActionUnitStart:   {mutating: true, capability: "systemd", permission: "unit.start", timeoutSeconds: 120},
	ActionUnitStop:    {mutating: true, capability: "systemd", permission: "unit.stop", timeoutSeconds: 120},
	ActionUnitRestart: {mutating: true, capability: "systemd", permission: "unit.restart", timeoutSeconds: 120},
	ActionUnitReload:  {mutating: true, capability: "systemd", permission: "unit.reload", timeoutSeconds: 60},
	ActionReadJournal: {mutating: false, capability: "journald", permission: "journal.read", timeoutSeconds: 60},

	// Planowanie nie zmienia stanu systemu, ale odswiezenie metadanych juz tak,
	// wiec plan tez ma wlasne uprawnienie.
	ActionPackagePlan: {mutating: false, capability: "packages", permission: "packages.plan", timeoutSeconds: 300},
	// Transakcja pakietowa jest najbardziej ryzykowna operacja w systemie.
	ActionPackageUpgrade: {mutating: true, capability: "packages", permission: "packages.upgrade", timeoutSeconds: 1800},
	// Restart jest osobna, zatwierdzana faza kampanii, a nie efektem ubocznym
	// aktualizacji.
	ActionSystemReboot: {mutating: true, capability: "systemd", permission: "system.reboot", timeoutSeconds: 120},
	// Odczyt stanu jednostek jest niemutujacy i sluzy health checkom kampanii.
	ActionUnitStatus: {mutating: false, capability: "systemd", permission: "unit.status", timeoutSeconds: 60},

	// Dolaczenie do domeny zmienia uwierzytelnianie calego hosta.
	ActionDomainEnroll: {mutating: true, capability: "systemd", permission: "identity.host.enroll", timeoutSeconds: 900},
	// Preflight niczego nie zmienia, wiec nie wymaga zatwierdzenia.
	ActionDomainPreflight: {mutating: false, capability: "systemd", permission: "identity.read", timeoutSeconds: 120},
}

// AllActions zwraca posortowana liste obslugiwanych operacji.
func AllActions() []ActionType {
	actions := make([]ActionType, 0, len(actionSpecs))
	for action := range actionSpecs {
		actions = append(actions, action)
	}
	for i := 1; i < len(actions); i++ {
		for j := i; j > 0 && actions[j] < actions[j-1]; j-- {
			actions[j], actions[j-1] = actions[j-1], actions[j]
		}
	}
	return actions
}

// UnitPayload opisuje operacje na jednostce systemd.
type UnitPayload struct {
	Unit string `json:"unit"`
}

// JournalPayload opisuje odczyt dziennika.
type JournalPayload struct {
	Unit string `json:"unit,omitempty"`
	// Lines ogranicza rozmiar wyniku; odczyt bez limitu nie jest dozwolony.
	Lines uint32 `json:"lines"`
	// MaxPriority wg syslog: 0 emerg ... 7 debug. Pusty oznacza brak filtra.
	MaxPriority *uint32 `json:"max_priority,omitempty"`
	Since       string  `json:"since,omitempty"`
}

// PackagePlanPayload opisuje planowanie aktualizacji.
type PackagePlanPayload struct {
	// RefreshMetadata wymaga roota i blokady repozytorium, wiec jest jawnym
	// wyborem, a nie efektem ubocznym kazdego planu.
	RefreshMetadata bool     `json:"refresh_metadata"`
	OnlyPackages    []string `json:"only_packages,omitempty"`
	SecurityOnly    bool     `json:"security_only,omitempty"`
}

// PackageUpgradePayload opisuje wykonanie transakcji aktualizacji.
type PackageUpgradePayload struct {
	// PlanHash wiaze wykonanie z konkretnym planem. Pusty oznacza brak
	// weryfikacji i jest dopuszczalny wylacznie poza kampania.
	PlanHash     string   `json:"plan_hash,omitempty"`
	Packages     []string `json:"packages,omitempty"`
	SecurityOnly bool     `json:"security_only,omitempty"`
}

// RebootPayload opisuje kontrolowany restart hosta.
type RebootPayload struct {
	// DelaySeconds daje czas na zamkniecie sesji i odeslanie wyniku, zanim
	// host zniknie z sieci.
	DelaySeconds uint32 `json:"delay_seconds,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// UnitStatusPayload opisuje odczyt stanu jednostek.
type UnitStatusPayload struct {
	Units []string `json:"units"`
}

// Payload jest suma typow payloadow. Dokladnie jedno pole jest wypelnione.
type Payload struct {
	Unit           *UnitPayload           `json:"unit,omitempty"`
	Journal        *JournalPayload        `json:"journal,omitempty"`
	PackagePlan    *PackagePlanPayload    `json:"package_plan,omitempty"`
	PackageUpgrade *PackageUpgradePayload `json:"package_upgrade,omitempty"`
	Reboot         *RebootPayload         `json:"reboot,omitempty"`
	UnitStatus     *UnitStatusPayload     `json:"unit_status,omitempty"`
	DomainEnroll   *DomainEnrollPayload   `json:"domain_enroll,omitempty"`
}

// DomainEnrollPayload opisuje dolaczenie hosta do domeny.
//
// Payload nie zawiera hasla: jednorazowe poswiadczenie jest pobierane
// z katalogu w chwili wysylki i wstrzykiwane do koperty. Przechowywanie go
// w bazie oznaczaloby sekret lezacy na dysku przez caly czas zycia zadania.
type DomainEnrollPayload struct {
	Domain   string `json:"domain"`
	Realm    string `json:"realm"`
	Server   string `json:"server,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// Validate sprawdza spojnosc typu operacji z payloadem.
func Validate(action ActionType, payload Payload) error {
	if !action.Known() {
		return fmt.Errorf("nieznany typ operacji %q", action)
	}
	switch action {
	case ActionPackagePlan:
		if payload.PackagePlan == nil {
			return fmt.Errorf("operacja %s wymaga payloadu package_plan", action)
		}
		return validatePackageNames(payload.PackagePlan.OnlyPackages)

	case ActionDomainEnroll, ActionDomainPreflight:
		if payload.DomainEnroll == nil {
			return fmt.Errorf("operacja %s wymaga payloadu domain_enroll", action)
		}
		if payload.DomainEnroll.Domain == "" || payload.DomainEnroll.Realm == "" {
			return fmt.Errorf("dolaczenie wymaga domeny i realmu")
		}
		if !domainPattern.MatchString(payload.DomainEnroll.Domain) {
			return fmt.Errorf("nieprawidlowa nazwa domeny %q", payload.DomainEnroll.Domain)
		}
		return nil

	case ActionUnitStatus:
		if payload.UnitStatus == nil || len(payload.UnitStatus.Units) == 0 {
			return fmt.Errorf("operacja %s wymaga listy jednostek", action)
		}
		if len(payload.UnitStatus.Units) > 50 {
			return fmt.Errorf("lista jednostek jest zbyt dluga")
		}
		return nil

	case ActionSystemReboot:
		if payload.Reboot == nil {
			return fmt.Errorf("operacja %s wymaga payloadu reboot", action)
		}
		if payload.Reboot.DelaySeconds > 3600 {
			return fmt.Errorf("opoznienie restartu nie moze przekraczac godziny")
		}
		return nil

	case ActionPackageUpgrade:
		if payload.PackageUpgrade == nil {
			return fmt.Errorf("operacja %s wymaga payloadu package_upgrade", action)
		}
		return validatePackageNames(payload.PackageUpgrade.Packages)

	case ActionReadJournal:
		if payload.Journal == nil {
			return fmt.Errorf("operacja %s wymaga payloadu journal", action)
		}
		if payload.Journal.Lines == 0 || payload.Journal.Lines > 10000 {
			return fmt.Errorf("liczba linii musi byc z zakresu 1-10000")
		}
		if priority := payload.Journal.MaxPriority; priority != nil && *priority > 7 {
			return fmt.Errorf("priorytet syslog musi byc z zakresu 0-7")
		}
	default:
		if payload.Unit == nil {
			return fmt.Errorf("operacja %s wymaga payloadu unit", action)
		}
		if strings.TrimSpace(payload.Unit.Unit) == "" {
			return fmt.Errorf("nazwa jednostki jest pusta")
		}
	}
	return nil
}

// packageNamePattern odpowiada nazwom pakietow Debiana i RPM. Nazwa nigdy nie
// trafia do powloki, ale walidacja jest druga linia obrony i odrzuca ksztalty,
// ktore nie moga byc nazwa pakietu.
// domainPattern odrzuca nazwy, ktore nie moga byc domena DNS.
var domainPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)

var packageNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._-]*$`)

func validatePackageNames(names []string) error {
	if len(names) > 500 {
		return fmt.Errorf("lista pakietow jest zbyt dluga")
	}
	for _, name := range names {
		if !packageNamePattern.MatchString(name) {
			return fmt.Errorf("nieprawidlowa nazwa pakietu %q", name)
		}
	}
	return nil
}

// PayloadHash liczy hash planu w postaci kanonicznej. Agent liczy go tak samo
// i porownuje z kopertą, wiec podmiana payloadu po zatwierdzeniu jest wykrywalna.
//
// Kanoniczna postac to: "<typ>\n<wersja>\n<JSON payloadu>". JSON pochodzi
// z encoding/json, ktory serializuje pola struktury w kolejnosci deklaracji,
// wiec wynik jest deterministyczny.
func PayloadHash(action ActionType, version int, payload Payload) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\n%d\n%s", action, version, encoded))
	return sum[:], nil
}
