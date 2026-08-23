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
	// Naprawa odblokowuje operacje pakietowe na hoscie: ustawia odpowiedzi
	// operatora na pytania konfiguracyjne i konczy konfiguracje pakietow.
	ActionPackageRepair ActionType = "packages.repair"

	ActionSystemReboot ActionType = "system.reboot"
	ActionUnitStatus   ActionType = "unit.status"

	ActionDomainEnroll    ActionType = "identity.host.enroll"
	ActionDomainPreflight ActionType = "identity.host.preflight"

	ActionLocalUserCreate ActionType = "localuser.create"
	ActionLocalUserLock   ActionType = "localuser.lock"
	ActionLocalUserUnlock ActionType = "localuser.unlock"
	ActionLocalSSHKeysSet ActionType = "localuser.sshkeys.set"

	// Odczyt stanu silnika kontenerow. Pelne listy sa pobierane na zadanie
	// operatora; inventory niesie samo podsumowanie.
	ActionDockerRead ActionType = "docker.read"

	ActionDockerStart   ActionType = "docker.container.start"
	ActionDockerStop    ActionType = "docker.container.stop"
	ActionDockerRestart ActionType = "docker.container.restart"
	ActionDockerRemove  ActionType = "docker.container.remove"
	ActionDockerPull    ActionType = "docker.image.pull"
	// Sprzatanie usuwa wskazane obiekty, a nie wszystko, co pasuje do filtru.
	ActionDockerPrune ActionType = "docker.prune"

	// Plan projektu Compose liczy roznice miedzy stanem hosta a manifestem.
	ActionComposePlan ActionType = "docker.compose.plan"
	// Wdrozenie projektu jest zwiazane z konkretnym planem.
	ActionComposeDeploy ActionType = "docker.compose.deploy"
)

// ActionVersion jest wersja kontraktu payloadu. Zmiana znaczenia pol wymaga
// podniesienia wersji, a nie cichej reinterpretacji.
const ActionVersion = 1

// RiskLevel opisuje, czym grozi operacja. Poziom nie jest etykieta w
// interfejsie: decyduje o swiezosci uwierzytelnienia, o potwierdzeniu celu
// i o domyslnej polityce kampanii.
type RiskLevel string

const (
	// RiskLow to odczyt i planowanie: niczego nie zmienia.
	RiskLow RiskLevel = "low"
	// RiskMedium zmienia stan odwracalnie i lokalnie.
	RiskMedium RiskLevel = "medium"
	// RiskHigh przerywa usluge albo zmienia zawartosc systemu.
	RiskHigh RiskLevel = "high"
	// RiskCritical moze odciac dostep do hosta albo zmienic jego tozsamosc.
	// Wymaga swiezego uwierzytelnienia operatora.
	RiskCritical RiskLevel = "critical"
	// RiskDestructive niszczy dane nieodwracalnie. Wymaga wpisania nazwy celu
	// i domyslnie nie dziala masowo.
	RiskDestructive RiskLevel = "destructive"
)

// LockClass nazywa zasob hosta, ktorego operacja uzywa na wylacznosc.
// Jednoczesnie moze dzialac jedna mutacja w danej klasie: dwie transakcje
// pakietowe na tej samej bazie moga ja uszkodzic.
const (
	LockNone       = ""
	LockPackages   = "packages"
	LockUnits      = "units"
	LockContainers = "containers"
	LockIdentity   = "identity"
	LockAccounts   = "accounts"
)

// Spec jest pelnym kontraktem jednej operacji.
type Spec struct {
	Action         ActionType `json:"action"`
	Version        uint32     `json:"version"`
	Capability     string     `json:"capability,omitempty"`
	Permission     string     `json:"permission"`
	Mutating       bool       `json:"mutating"`
	Risk           RiskLevel  `json:"risk"`
	DefaultTimeout int        `json:"default_timeout_seconds"`
	MaxOutputBytes uint64     `json:"max_output_bytes"`
	LockClass      string     `json:"lock_class,omitempty"`
	// RequiresPlan oznacza operacje, ktorej nie wolno zlecic bez planu
	// zatwierdzonego przez czlowieka. Hash planu wiaze zatwierdzenie
	// z konkretnym diffem.
	RequiresPlan bool `json:"requires_plan"`
}

// Describe zwraca pelny kontrakt operacji.
func (a ActionType) Describe() Spec {
	spec := actionSpecs[a]
	return Spec{
		Action:         a,
		Version:        ActionVersion,
		Capability:     spec.capability,
		Permission:     spec.permission,
		Mutating:       spec.mutating,
		Risk:           spec.risk,
		DefaultTimeout: spec.timeoutSeconds,
		MaxOutputBytes: spec.maxOutputBytes,
		LockClass:      spec.lockClass,
		RequiresPlan:   spec.requiresPlan,
	}
}

// Risk zwraca poziom ryzyka operacji.
func (a ActionType) Risk() RiskLevel {
	if spec, ok := actionSpecs[a]; ok {
		return spec.risk
	}
	// Nieznana operacja nie jest operacja bezpieczna. Domyslny poziom nie
	// moze byc najnizszy tylko dlatego, ze czegos nie opisano.
	return RiskCritical
}

// LockClass zwraca klase zasobu hosta uzywanego na wylacznosc.
func (a ActionType) LockClass() string {
	return actionSpecs[a].lockClass
}

// MaxOutputBytes ogranicza rozmiar wyniku operacji.
func (a ActionType) MaxOutputBytes() uint64 {
	if spec, ok := actionSpecs[a]; ok && spec.maxOutputBytes > 0 {
		return spec.maxOutputBytes
	}
	return domyslnyLimitWyniku
}

// RequiresPlan mowi, czy operacji nie wolno zlecic bez zatwierdzonego planu.
func (a ActionType) RequiresPlan() bool {
	return actionSpecs[a].requiresPlan
}

// RequiresFreshAuth mowi, czy operator musi potwierdzic tozsamosc tuz przed
// zleceniem. Operacja, ktora moze odciac dostep do hosta, nie moze isc
// z sesji sprzed godziny.
func (a ActionType) RequiresFreshAuth() bool {
	switch a.Risk() {
	case RiskCritical, RiskDestructive:
		return true
	}
	return false
}

// RequiresTargetConfirmation mowi, czy operator musi wpisac nazwe celu.
// Klikniecie nie jest wystarczajaca decyzja przy operacji nieodwracalnej.
func (a ActionType) RequiresTargetConfirmation() bool {
	return a.Risk() == RiskDestructive
}

// domyslnyLimitWyniku obowiazuje operacje, ktore nie podaja wlasnego.
const domyslnyLimitWyniku = 64 << 10

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
	risk           RiskLevel
	lockClass      string
	maxOutputBytes uint64
	requiresPlan   bool
}

// Poziomy ryzyka i klasy blokad ida za rozdzialami 6.1 i 8 specyfikacji.
// Ryzyko nie jest etykieta: krytyczne wymaga swiezego uwierzytelnienia,
// niszczace dodatkowo wpisania nazwy celu. Klasa blokady mowi, ktore operacje
// nie moga dzialac naraz na tym samym hoscie.
var actionSpecs = map[ActionType]actionSpec{
	ActionUnitStart: {mutating: true, capability: "systemd", permission: "unit.start",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockUnits},
	// Zatrzymanie uslugi przerywa jej dzialanie, wiec jest wyzej niz start.
	ActionUnitStop: {mutating: true, capability: "systemd", permission: "unit.stop",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockUnits},
	ActionUnitRestart: {mutating: true, capability: "systemd", permission: "unit.restart",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockUnits},
	ActionUnitReload: {mutating: true, capability: "systemd", permission: "unit.reload",
		timeoutSeconds: 60, risk: RiskMedium, lockClass: LockUnits},
	ActionReadJournal: {mutating: false, capability: "journald", permission: "journal.read",
		timeoutSeconds: 60, risk: RiskLow, maxOutputBytes: 256 << 10},

	// Planowanie nie zmienia stanu systemu, ale odswiezenie metadanych juz tak,
	// wiec plan tez ma wlasne uprawnienie.
	ActionPackagePlan: {mutating: false, capability: "packages", permission: "packages.plan",
		timeoutSeconds: 300, risk: RiskLow, lockClass: LockPackages},
	// Transakcja pakietowa jest najbardziej ryzykowna operacja w systemie.
	ActionPackageUpgrade: {mutating: true, capability: "packages", permission: "packages.upgrade",
		timeoutSeconds: 1800, risk: RiskHigh, lockClass: LockPackages, requiresPlan: true},

	// Naprawa zmienia stan hosta i moze dotyczyc pakietow o duzym znaczeniu,
	// z bootloaderem wlacznie, wiec ma wlasne uprawnienie i wlasny timeout.
	//
	// Wymaganie jest wezsze niz sama obecnosc menedzera pakietow: naprawa
	// odpowiada na pytania debconfa i istnieje tylko dla apta. Host, ktory jej
	// nie ma, ma to powiedziec przy zlecaniu, a nie po dostarczeniu zadania.
	ActionPackageRepair: {mutating: true, capability: "packages.repair", permission: "packages.repair",
		timeoutSeconds: 1800, risk: RiskCritical, lockClass: LockPackages},
	// Restart jest osobna, zatwierdzana faza kampanii, a nie efektem ubocznym
	// aktualizacji. Odciecie hosta na czas restartu czyni go krytycznym.
	ActionSystemReboot: {mutating: true, capability: "systemd", permission: "system.reboot",
		timeoutSeconds: 120, risk: RiskCritical},
	// Odczyt stanu jednostek jest niemutujacy i sluzy health checkom kampanii.
	ActionUnitStatus: {mutating: false, capability: "systemd", permission: "unit.status",
		timeoutSeconds: 60, risk: RiskLow},

	// Dolaczenie do domeny zmienia uwierzytelnianie calego hosta.
	ActionDomainEnroll: {mutating: true, capability: "systemd", permission: "identity.host.enroll",
		timeoutSeconds: 900, risk: RiskCritical, lockClass: LockIdentity},
	// Preflight niczego nie zmienia, wiec nie wymaga zatwierdzenia.
	ActionDomainPreflight: {mutating: false, capability: "systemd", permission: "identity.read",
		timeoutSeconds: 120, risk: RiskLow, lockClass: LockIdentity},

	// Konta lokalne nie zaleza od systemd ani od katalogu: modul dziala takze
	// tam, gdzie klient zostaje przy zwyklej autoryzacji SSH.
	// Blokada i odblokowanie maja osobne uprawnienia: w reakcji na incydent
	// odciecie konta bywa dozwolone tam, gdzie przywrocenie dostepu juz nie.
	ActionLocalUserCreate: {mutating: true, capability: "", permission: "localuser.create",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockAccounts},
	ActionLocalUserLock: {mutating: true, capability: "", permission: "localuser.lock",
		timeoutSeconds: 60, risk: RiskMedium, lockClass: LockAccounts},
	// Przywrocenie dostepu jest zawsze powazniejsze niz jego odebranie.
	ActionLocalUserUnlock: {mutating: true, capability: "", permission: "localuser.unlock",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockAccounts},
	ActionLocalSSHKeysSet: {mutating: true, capability: "", permission: "localuser.sshkeys.write",
		timeoutSeconds: 60, risk: RiskHigh, lockClass: LockAccounts},

	// Odczyt kontenerow niczego nie zmienia, ale potrafi byc ciezki: pelna
	// lista obrazow na hoscie budowlanym to megabajty, wiec ma wlasna klase
	// zasobu i wlasny limit wyniku.
	ActionDockerRead: {mutating: false, capability: "docker", permission: "docker.read",
		timeoutSeconds: 120, risk: RiskLow, lockClass: LockContainers, maxOutputBytes: 4 << 20},

	// Uruchomienie kontenera przywraca usluge; zatrzymanie ja przerywa,
	// wiec stop i restart sa wyzej niz start.
	ActionDockerStart: {mutating: true, capability: "docker", permission: "docker.container.start",
		timeoutSeconds: 120, risk: RiskMedium, lockClass: LockContainers},
	ActionDockerStop: {mutating: true, capability: "docker", permission: "docker.container.stop",
		timeoutSeconds: 120, risk: RiskHigh, lockClass: LockContainers},
	ActionDockerRestart: {mutating: true, capability: "docker", permission: "docker.container.restart",
		timeoutSeconds: 180, risk: RiskHigh, lockClass: LockContainers},
	// Usuniecie kontenera jest nieodwracalne: dane spoza wolumenow gina razem
	// z nim, wiec operator wpisuje nazwe celu, zanim operacja ruszy.
	ActionDockerRemove: {mutating: true, capability: "docker", permission: "docker.container.remove",
		timeoutSeconds: 120, risk: RiskDestructive, lockClass: LockContainers},
	// Pobranie obrazu zmienia to, co wstanie przy nastepnym uruchomieniu,
	// ale samo w sobie nie rusza dzialajacych kontenerow.
	ActionDockerPull: {mutating: true, capability: "docker", permission: "docker.image.pull",
		timeoutSeconds: 1800, risk: RiskMedium, lockClass: LockContainers},
	// Sprzatanie usuwa dane bezpowrotnie i domyslnie nie dziala masowo.
	ActionDockerPrune: {mutating: true, capability: "docker", permission: "docker.prune",
		timeoutSeconds: 900, risk: RiskDestructive, lockClass: LockContainers},

	// Plan niczego nie zmienia, ale uruchamia compose na hoscie i pobiera
	// metadane obrazow, wiec ma wlasne uprawnienie.
	ActionComposePlan: {mutating: false, capability: "docker.compose",
		permission: "docker.compose.plan", timeoutSeconds: 300,
		risk: RiskLow, lockClass: LockContainers, maxOutputBytes: 1 << 20},
	// Wdrozenie manifestu uruchamia na hoscie obrazy wskazane przez operatora.
	// Jest to najdalej idaca operacja tego modulu i nie wolno jej zlecic bez
	// planu zatwierdzonego przez czlowieka.
	ActionComposeDeploy: {mutating: true, capability: "docker.compose",
		permission: "docker.compose.deploy", timeoutSeconds: 1800,
		risk: RiskCritical, lockClass: LockContainers, requiresPlan: true,
		maxOutputBytes: 1 << 20},
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

// nazwaProjektuCompose powtarza wzorzec modulu kontenerow. Nazwa trafia do
// argumentu polecenia i do nazw kontenerow.
var nazwaProjektuCompose = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// maksymalnyManifestCompose ogranicza rozmiar manifestu. Plik wiekszy od tego
// nie jest juz konfiguracja projektu, tylko czyms, czego operator nie
// przeczyta przed zatwierdzeniem.
const maksymalnyManifestCompose = 256 << 10

// identyfikatorKontenera dopuszcza wylacznie szesnastkowy identyfikator
// silnika. Identyfikator trafia do sciezki zapytania Engine API, wiec nie
// moze niesc niczego, co ta sciezke zmienia.
var identyfikatorKontenera = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

func poprawnyIdentyfikatorKontenera(id string) bool {
	return identyfikatorKontenera.MatchString(id)
}

// odwolanieObrazu dopuszcza nazwe repozytorium z opcjonalnym rejestrem,
// tagiem albo digestem. Odwolanie idzie do silnika jako parametr zapytania,
// a nie do powloki, ale wezsza walidacja i tak jest tansza niz ufanie.
var odwolanieObrazu = regexp.MustCompile(
	`^[a-z0-9]+([._\-/][a-z0-9]+)*(:[0-9]{2,5})?(/[a-z0-9]+([._\-/][a-z0-9]+)*)*` +
		`(:[\w][\w.\-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

func poprawneOdwolanieObrazu(reference string) error {
	if reference == "" {
		return fmt.Errorf("odwolanie do obrazu jest puste")
	}
	if len(reference) > 512 {
		return fmt.Errorf("odwolanie do obrazu jest zbyt dlugie")
	}
	if !odwolanieObrazu.MatchString(reference) {
		return fmt.Errorf("nieprawidlowe odwolanie do obrazu %q", reference)
	}
	return nil
}

// identyfikatorObrazu dopuszcza identyfikator silnika z prefiksem algorytmu.
var identyfikatorObrazu = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// nazwaWolumenu dopuszcza nazwy, ktore tworzy Docker i Compose.
var nazwaWolumenu = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$`)

// maksymalnieObiektowSprzatania ogranicza jedna operacje sprzatania. Lista
// dluzsza od tego nie jest juz decyzja operatora, tylko filtrem w przebraniu.
const maksymalnieObiektowSprzatania = 200

func sprawdzListeSprzatania(payload *DockerPrunePayload) error {
	razem := len(payload.ImageIDs) + len(payload.VolumeName) + len(payload.NetworkIDs)
	if razem == 0 {
		return fmt.Errorf("operacja sprzatania nie wskazuje zadnego obiektu")
	}
	if razem > maksymalnieObiektowSprzatania {
		return fmt.Errorf("lista obiektow do usuniecia jest zbyt dluga (%d)", razem)
	}
	for _, id := range payload.ImageIDs {
		if !identyfikatorObrazu.MatchString(id) {
			return fmt.Errorf("nieprawidlowy identyfikator obrazu %q", id)
		}
	}
	for _, nazwa := range payload.VolumeName {
		if !nazwaWolumenu.MatchString(nazwa) {
			return fmt.Errorf("nieprawidlowa nazwa wolumenu %q", nazwa)
		}
	}
	for _, id := range payload.NetworkIDs {
		if !identyfikatorKontenera.MatchString(id) {
			return fmt.Errorf("nieprawidlowy identyfikator sieci %q", id)
		}
	}
	return nil
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
	Unit            *UnitPayload            `json:"unit,omitempty"`
	Journal         *JournalPayload         `json:"journal,omitempty"`
	PackagePlan     *PackagePlanPayload     `json:"package_plan,omitempty"`
	PackageUpgrade  *PackageUpgradePayload  `json:"package_upgrade,omitempty"`
	Reboot          *RebootPayload          `json:"reboot,omitempty"`
	UnitStatus      *UnitStatusPayload      `json:"unit_status,omitempty"`
	DomainEnroll    *DomainEnrollPayload    `json:"domain_enroll,omitempty"`
	LocalUser       *LocalUserPayload       `json:"local_user,omitempty"`
	PackageRepair   *PackageRepairPayload   `json:"package_repair,omitempty"`
	DockerRead      *DockerReadPayload      `json:"docker_read,omitempty"`
	DockerContainer *DockerContainerPayload `json:"docker_container,omitempty"`
	DockerImage     *DockerImagePayload     `json:"docker_image,omitempty"`
	DockerPrune     *DockerPrunePayload     `json:"docker_prune,omitempty"`
	Compose         *ComposePayload         `json:"compose,omitempty"`
}

// ComposePayload niesie manifest projektu Compose.
//
// Manifest jest czescia payloadu, a nie odwolaniem do pliku na hoscie:
// operator zatwierdza tresc, ktora obejrzal, a hash payloadu wiaze
// zatwierdzenie wlasnie z nia.
type ComposePayload struct {
	Project  string `json:"project"`
	Manifest string `json:"manifest"`
	// PlanDigest wiaze wdrozenie z planem. Pusty jest dopuszczalny wylacznie
	// przy planowaniu; wdrozenie bez niego nie ma podstawy.
	PlanDigest string `json:"plan_digest,omitempty"`
}

// DockerContainerPayload wskazuje kontener operacji.
//
// Celem jest identyfikator, a nie nazwa. Nazwa kontenera jest etykieta:
// moze zostac przypisana innemu kontenerowi miedzy planem a wykonaniem,
// a operator zatwierdzil konkretny obiekt.
type DockerContainerPayload struct {
	ContainerID string `json:"container_id"`
	// Name sluzy wylacznie potwierdzeniu i audytowi: operator ma w oknie
	// nazwe, a w sladzie zostaje to, co widzial.
	Name string `json:"name,omitempty"`
	// TimeoutSeconds daje kontenerowi czas na zamkniecie przed zabiciem.
	TimeoutSeconds uint32 `json:"timeout_seconds,omitempty"`
	// RemoveVolumes dotyczy wylacznie usuwania i domyslnie jest wylaczone:
	// wolumen przezywa kontener wlasnie po to, zeby dane przezyly.
	RemoveVolumes bool `json:"remove_volumes,omitempty"`
}

// DockerImagePayload opisuje obraz do pobrania.
type DockerImagePayload struct {
	// Reference jest pelnym odwolaniem do obrazu, np. "nginx:1.27".
	Reference string `json:"reference"`
}

// DockerPrunePayload wylicza obiekty do usuniecia.
//
// Sprzatanie po filtrze usuwa to, co pasuje w chwili wykonania - a wiec takze
// obiekt utworzony po tym, jak operator obejrzal podglad. Dlatego operacja
// przyjmuje wprost liste obiektow: usuwa dokladnie to, co zostalo pokazane,
// albo nic.
type DockerPrunePayload struct {
	ImageIDs   []string `json:"image_ids,omitempty"`
	VolumeName []string `json:"volume_names,omitempty"`
	NetworkIDs []string `json:"network_ids,omitempty"`
}

// DockerReadPayload opisuje odczyt stanu silnika kontenerow. Payload jest
// pusty z zalozenia: zakres odczytu wynika z operacji, a nie z parametru -
// inaczej "odczytaj kontenery" i "odczytaj wszystko" bylyby ta sama operacja
// z rozna cena dla hosta.
type DockerReadPayload struct{}

// PackageRepairPayload niesie odpowiedzi operatora na pytania konfiguracyjne
// pakietow, ktore blokuja operacje pakietowe.
//
// Payload moze byc pusty: samo dokonczenie konfiguracji wystarcza, gdy
// poprzednia transakcja zostala przerwana i nic nie czeka na decyzje.
type PackageRepairPayload struct {
	Answers []DebconfAnswer `json:"answers,omitempty"`
}

// DebconfAnswer jest jedna odpowiedzia na pytanie konfiguracyjne pakietu.
type DebconfAnswer struct {
	Package  string `json:"package"`
	Question string `json:"question"`
	Type     string `json:"type"`
	Value    string `json:"value"`
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

// LocalUserPayload opisuje zmiane konta lokalnego.
//
// Payload nie zawiera hasla ani hasza. Konto zakladane przez panel jest
// dostepne wylacznie kluczem SSH, wiec nie istnieje sekret, ktory panel
// musialby przechowywac lub przenosic.
type LocalUserPayload struct {
	Name   string   `json:"name"`
	Gecos  string   `json:"gecos,omitempty"`
	Shell  string   `json:"shell,omitempty"`
	Groups []string `json:"groups,omitempty"`
	// SSHKeys jest pelna, zamierzona lista kluczy. Pusta lista przy operacji
	// ustawiania kluczy odbiera dostep i jest swiadoma zmiana, nie brakiem danych.
	SSHKeys    []string `json:"ssh_keys,omitempty"`
	CreateHome bool     `json:"create_home,omitempty"`
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

	case ActionPackageRepair:
		if payload.PackageRepair == nil {
			return fmt.Errorf("operacja %s wymaga payloadu package_repair", action)
		}
		for _, answer := range payload.PackageRepair.Answers {
			if err := validatePackageNames([]string{answer.Package}); err != nil {
				return err
			}
			if !debconfQuestionPattern.MatchString(answer.Question) {
				return fmt.Errorf("nieprawidlowa nazwa pytania %q", answer.Question)
			}
			if !debconfTypePattern.MatchString(answer.Type) {
				return fmt.Errorf("nieobslugiwany typ pytania %q", answer.Type)
			}
			// Znak nowej linii pozwalalby dopisac ustawienia, o ktore nikt
			// nie prosil: kazdy wiersz wejscia debconfa jest osobnym wpisem.
			if strings.ContainsAny(answer.Value, "\n\r") {
				return fmt.Errorf("wartosc odpowiedzi nie moze zawierac znaku nowej linii")
			}
		}
		return nil

	case ActionLocalUserCreate, ActionLocalUserLock, ActionLocalUserUnlock, ActionLocalSSHKeysSet:
		if payload.LocalUser == nil {
			return fmt.Errorf("operacja %s wymaga payloadu local_user", action)
		}
		if !localUserNamePattern.MatchString(payload.LocalUser.Name) {
			return fmt.Errorf("nieprawidlowa nazwa konta %q", payload.LocalUser.Name)
		}
		if len(payload.LocalUser.SSHKeys) > 64 {
			return fmt.Errorf("zbyt wiele kluczy SSH: %d", len(payload.LocalUser.SSHKeys))
		}
		for _, key := range payload.LocalUser.SSHKeys {
			if err := validatePublicKeyShape(key); err != nil {
				return err
			}
		}
		for _, group := range payload.LocalUser.Groups {
			if !localUserNamePattern.MatchString(group) {
				return fmt.Errorf("nieprawidlowa nazwa grupy %q", group)
			}
		}
		if shell := payload.LocalUser.Shell; shell != "" && !strings.HasPrefix(shell, "/") {
			return fmt.Errorf("powloka musi byc sciezka bezwzgledna, otrzymano %q", shell)
		}
		if strings.ContainsAny(payload.LocalUser.Gecos, ":\n") {
			return fmt.Errorf("pole opisu nie moze zawierac dwukropka ani znaku nowej linii")
		}
		return nil

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

	case ActionDockerRead:
		if payload.DockerRead == nil {
			return fmt.Errorf("operacja %s wymaga payloadu docker_read", action)
		}
		return nil

	case ActionDockerStart, ActionDockerStop, ActionDockerRestart, ActionDockerRemove:
		if payload.DockerContainer == nil {
			return fmt.Errorf("operacja %s wymaga payloadu docker_container", action)
		}
		if !poprawnyIdentyfikatorKontenera(payload.DockerContainer.ContainerID) {
			return fmt.Errorf("nieprawidlowy identyfikator kontenera %q",
				payload.DockerContainer.ContainerID)
		}
		if payload.DockerContainer.TimeoutSeconds > 3600 {
			return fmt.Errorf("czas na zamkniecie kontenera jest zbyt dlugi")
		}
		if payload.DockerContainer.RemoveVolumes && action != ActionDockerRemove {
			return fmt.Errorf("operacja %s nie usuwa wolumenow", action)
		}
		return nil

	case ActionDockerPull:
		if payload.DockerImage == nil {
			return fmt.Errorf("operacja %s wymaga payloadu docker_image", action)
		}
		return poprawneOdwolanieObrazu(payload.DockerImage.Reference)

	case ActionComposePlan, ActionComposeDeploy:
		if payload.Compose == nil {
			return fmt.Errorf("operacja %s wymaga payloadu compose", action)
		}
		if !nazwaProjektuCompose.MatchString(payload.Compose.Project) {
			return fmt.Errorf("nieprawidlowa nazwa projektu %q", payload.Compose.Project)
		}
		if strings.TrimSpace(payload.Compose.Manifest) == "" {
			return fmt.Errorf("manifest projektu jest pusty")
		}
		if len(payload.Compose.Manifest) > maksymalnyManifestCompose {
			return fmt.Errorf("manifest projektu jest zbyt duzy (%d bajtow)",
				len(payload.Compose.Manifest))
		}
		// Wdrozenie bez planu nie ma podstawy: operator zatwierdzilby zmiane,
		// ktorej nie widzial.
		if action == ActionComposeDeploy && payload.Compose.PlanDigest == "" {
			return fmt.Errorf("wdrozenie projektu wymaga hasha zatwierdzonego planu")
		}
		return nil

	case ActionDockerPrune:
		if payload.DockerPrune == nil {
			return fmt.Errorf("operacja %s wymaga payloadu docker_prune", action)
		}
		return sprawdzListeSprzatania(payload.DockerPrune)

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
// localUserNamePattern odpowiada zakresowi nazw akceptowanemu przez useradd.
// Walidacja po stronie panelu nie zastepuje walidacji w helperze; obie
// istnieja, bo koperta moze dotrzec do agenta inna droga niz przez panel.
var localUserNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)

// validatePublicKeyShape odrzuca material, ktory nie jest kluczem publicznym.
// Panel nie przyjmuje klucza prywatnego nawet przez pomylke operatora.
func validatePublicKeyShape(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("pusty klucz SSH")
	}
	if strings.ContainsAny(trimmed, "\n\r") {
		return fmt.Errorf("klucz SSH nie moze zawierac znaku nowej linii")
	}
	if strings.Contains(trimmed, "PRIVATE KEY") {
		return fmt.Errorf("przekazano klucz prywatny; panel przyjmuje wylacznie klucze publiczne")
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return fmt.Errorf("klucz SSH musi miec postac \"typ material [komentarz]\"")
	}
	if !allowedKeyTypes[fields[0]] {
		return fmt.Errorf("nieobslugiwany typ klucza %q", fields[0])
	}
	if len(trimmed) > 16384 {
		return fmt.Errorf("klucz SSH jest zbyt dlugi")
	}
	return nil
}

// allowedKeyTypes wyklucza typy wycofane, w tym ssh-dss i ssh-rsa z SHA-1.
var allowedKeyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// debconfQuestionPattern odpowiada nazwom pytan konfiguracyjnych, na przyklad
// grub-pc/install_devices.
var debconfQuestionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9._+-]+)+$`)

// debconfTypePattern ogranicza typy do tych, ktore maja sens w odpowiedzi
// przekazanej z panelu.
var debconfTypePattern = regexp.MustCompile(`^(select|multiselect|boolean|string|password|note)$`)

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
