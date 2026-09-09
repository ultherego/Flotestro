// Package campaigns realizuje kampanie: zmiane flotowa prowadzona przez canary
// i fale, z progami zatrzymania i raportem koncowym. Kampania jest glownym
// mechanizmem zmian, a nie petla po hostach.
package campaigns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// State jest stanem kampanii.
type State string

const (
	// StatePlanning jest faza, w ktorej kazdy host liczy wlasny plan.
	// Kampania niczego jeszcze nie zmienia: plan jest odczytem, a jego
	// zestaw - tym, co operator za chwile zatwierdzi.
	StatePlanning         State = "planning"
	StatePlanned          State = "planned"
	StateAwaitingApproval State = "awaiting_approval"
	StateCanary           State = "canary"
	StateRunning          State = "running"
	StatePaused           State = "paused"
	StateCompleted        State = "completed"
	StateFailed           State = "failed"
	StateCanceled         State = "canceled"
)

// Active mowi, czy kampania jest w toku.
func (s State) Active() bool {
	return s == StateCanary || s == StateRunning
}

// Terminal mowi, czy stan jest koncowy.
func (s State) Terminal() bool {
	switch s {
	case StateCompleted, StateFailed, StateCanceled:
		return true
	default:
		return false
	}
}

// TargetState jest stanem pojedynczego hosta w kampanii.
type TargetState string

const (
	TargetPending TargetState = "pending"
	// TargetPlanning oznacza hosta, ktory liczy wlasny plan zmiany.
	TargetPlanning  TargetState = "planning"
	TargetRunning   TargetState = "running"
	TargetRebooting TargetState = "rebooting"
	TargetVerifying TargetState = "verifying"
	TargetSucceeded TargetState = "succeeded"
	TargetFailed    TargetState = "failed"
	TargetSkipped   TargetState = "skipped"
	TargetCanceled  TargetState = "canceled"
)

// Finished mowi, czy host zakonczyl udzial w kampanii.
func (t TargetState) Finished() bool {
	switch t {
	case TargetSucceeded, TargetFailed, TargetSkipped, TargetCanceled:
		return true
	default:
		return false
	}
}

// RebootPolicy okresla, kiedy kampania restartuje hosta.
type RebootPolicy string

const (
	RebootNever      RebootPolicy = "never"
	RebootIfRequired RebootPolicy = "if_required"
	RebootAlways     RebootPolicy = "always"
)

// KnownRebootPolicy sprawdza poprawnosc polityki.
func KnownRebootPolicy(policy RebootPolicy) bool {
	switch policy {
	case RebootNever, RebootIfRequired, RebootAlways:
		return true
	default:
		return false
	}
}

// Selector opisuje, ktore hosty wchodza do kampanii. Jest zapisywany dla
// audytu; wiazaca jest migawka celow utworzona przy planowaniu.
type Selector struct {
	Site        string   `json:"site,omitempty"`
	Environment string   `json:"environment,omitempty"`
	OSFamily    string   `json:"os_family,omitempty"`
	HostIDs     []string `json:"host_ids,omitempty"`
}

// Empty mowi, czy selektor niczego nie zawezа.
func (s Selector) Empty() bool {
	return s.Site == "" && s.Environment == "" && s.OSFamily == "" && len(s.HostIDs) == 0
}

// Spec opisuje kampanie do utworzenia.
type Spec struct {
	Name                     string
	ActionType               string
	Payload                  json.RawMessage
	Selector                 Selector
	CanarySize               int
	WaveSize                 int
	MaxConcurrent            int
	FailureThresholdPercent  int
	FailureThresholdAbsolute int
	MaintenanceStart         *time.Time
	MaintenanceEnd           *time.Time
	RebootPolicy             RebootPolicy
	HealthCheckUnits         []string
	JobTimeoutSeconds        int
	RequiresApproval         bool
	CreatedBy                string
	RequestID                string
}

// Validate sprawdza spojnosc opisu kampanii.
func (s Spec) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("kampania wymaga nazwy")
	}
	if s.WaveSize <= 0 {
		return fmt.Errorf("rozmiar fali musi byc dodatni")
	}
	if s.MaxConcurrent <= 0 {
		return fmt.Errorf("limit rownoleglosci musi byc dodatni")
	}
	if s.CanarySize < 0 {
		return fmt.Errorf("rozmiar canary nie moze byc ujemny")
	}
	if s.FailureThresholdPercent < 0 || s.FailureThresholdPercent > 100 {
		return fmt.Errorf("prog bledow w procentach musi byc z zakresu 0-100")
	}
	if !KnownRebootPolicy(s.RebootPolicy) {
		return fmt.Errorf("nieznana polityka restartu %q", s.RebootPolicy)
	}
	if s.MaintenanceStart != nil && s.MaintenanceEnd != nil &&
		!s.MaintenanceEnd.After(*s.MaintenanceStart) {
		return fmt.Errorf("okno serwisowe konczy sie przed rozpoczeciem")
	}
	return nil
}

// Odcisk liczy odcisk zatwierdzenia kampanii.
//
// Zgoda ma dotyczyc dokladnie tego, co operator zobaczyl: tej samej operacji,
// tego samego payloadu, tej samej listy hostow i tej samej polityki
// rozwijania. Gdyby odcisk obejmowal sam identyfikator kampanii, zatwierdzenie
// przenosiloby sie na kazda zmiane, ktora ktos wprowadzilby po drodze.
//
// Hosty sa sortowane, bo kolejnosc migawki nie jest decyzja. Wszystko inne
// wchodzi w takiej postaci, w jakiej zostalo zapisane.
func Odcisk(spec Spec, targets []TargetHost) (string, error) {
	hosty := make([]string, 0, len(targets))
	for _, target := range targets {
		hosty = append(hosty, target.ID)
	}
	sort.Strings(hosty)

	payload := spec.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	tresc := struct {
		Wersja     int             `json:"campaign_version"`
		Akcja      string          `json:"action"`
		Payload    json.RawMessage `json:"payload"`
		Hosty      []string        `json:"targets"`
		Rozwijanie struct {
			Canary      int          `json:"canary_size"`
			Fala        int          `json:"wave_size"`
			Rownolegle  int          `json:"max_concurrent"`
			ProgProcent int          `json:"failure_threshold_percent"`
			ProgLiczba  int          `json:"failure_threshold_absolute"`
			Restart     RebootPolicy `json:"reboot_policy"`
			Jednostki   []string     `json:"health_check_units"`
			LimitCzasu  int          `json:"job_timeout_seconds"`
			OknoOd      *time.Time   `json:"maintenance_start,omitempty"`
			OknoDo      *time.Time   `json:"maintenance_end,omitempty"`
		} `json:"rollout"`
	}{Wersja: WersjaKampanii, Akcja: spec.ActionType, Payload: payload, Hosty: hosty}
	tresc.Rozwijanie.Canary = spec.CanarySize
	tresc.Rozwijanie.Fala = spec.WaveSize
	tresc.Rozwijanie.Rownolegle = spec.MaxConcurrent
	tresc.Rozwijanie.ProgProcent = spec.FailureThresholdPercent
	tresc.Rozwijanie.ProgLiczba = spec.FailureThresholdAbsolute
	tresc.Rozwijanie.Restart = spec.RebootPolicy
	tresc.Rozwijanie.Jednostki = spec.HealthCheckUnits
	tresc.Rozwijanie.LimitCzasu = spec.JobTimeoutSeconds
	tresc.Rozwijanie.OknoOd = spec.MaintenanceStart
	tresc.Rozwijanie.OknoDo = spec.MaintenanceEnd

	encoded, err := json.Marshal(tresc)
	if err != nil {
		return "", err
	}
	suma := sha256.Sum256(encoded)
	return hex.EncodeToString(suma[:]), nil
}

// OdciskZPlanami przelicza odcisk zatwierdzenia razem z zestawem planow.
//
// Po fazie planowania zgoda dotyczy juz nie samego zamowienia, tylko tego,
// co kazdy host naprawde zrobi. Plan przeliczony na innym stanie hosta daje
// inny odcisk zestawu, wiec uniewaznia zgode.
func OdciskZPlanami(campaign Campaign, planSetHash string) (string, error) {
	if campaign.ApprovalFingerprint == "" {
		return "", fmt.Errorf("kampania %s nie ma odcisku zamowienia", campaign.ID)
	}
	// Odcisk zamowienia powstal przy tworzeniu kampanii i obejmuje operacje,
	// payload, liste hostow i polityke rozwijania. Zestaw planow dokleja sie
	// do niego, wiec zgoda dotyczy jednego i drugiego.
	return odciskTekstu([]string{campaign.ApprovalFingerprint, planSetHash}), nil
}

// odciskTekstu liczy odcisk z uporzadkowanej listy tekstow.
func odciskTekstu(czesci []string) string {
	suma := sha256.Sum256([]byte(strings.Join(czesci, "\n")))
	return hex.EncodeToString(suma[:])
}

// WersjaKampanii jest wersja semantyki kampanii. Zmiana wersji uniewaznia
// zatwierdzenia: zgoda dotyczyla innych regul.
const WersjaKampanii = 2

// Campaign jest widokiem kampanii zwracanym przez API.
type Campaign struct {
	ID                       string          `json:"id"`
	Name                     string          `json:"name"`
	ActionType               string          `json:"action_type"`
	Payload                  json.RawMessage `json:"payload"`
	Selector                 json.RawMessage `json:"selector"`
	State                    State           `json:"state"`
	CanarySize               int             `json:"canary_size"`
	WaveSize                 int             `json:"wave_size"`
	MaxConcurrent            int             `json:"max_concurrent"`
	FailureThresholdPercent  int             `json:"failure_threshold_percent"`
	FailureThresholdAbsolute int             `json:"failure_threshold_absolute"`
	MaintenanceStart         *time.Time      `json:"maintenance_start,omitempty"`
	MaintenanceEnd           *time.Time      `json:"maintenance_end,omitempty"`
	RebootPolicy             RebootPolicy    `json:"reboot_policy"`
	HealthCheckUnits         []string        `json:"health_check_units"`
	JobTimeoutSeconds        int             `json:"job_timeout_seconds"`
	RequiresApproval         bool            `json:"requires_approval"`
	// ApprovalFingerprint jest odciskiem tego, co zatwierdzajacy widzi.
	// Zgoda podana wobec innego odcisku dotyczy innej kampanii.
	ApprovalFingerprint string `json:"approval_fingerprint"`
	// PlanSetHash jest odciskiem zestawu planow per host. Pusty oznacza
	// kampanie, ktora planow nie potrzebuje.
	PlanSetHash string     `json:"plan_set_hash,omitempty"`
	ApprovedBy  string     `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
	PausedBy    string     `json:"paused_by,omitempty"`
	PauseReason string     `json:"pause_reason,omitempty"`
	CanceledBy  string     `json:"canceled_by,omitempty"`
	CreatedBy   string     `json:"created_by"`
	RequestID   string     `json:"request_id,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Target jest hostem w kampanii.
type Target struct {
	ID         string      `json:"id"`
	CampaignID string      `json:"campaign_id"`
	HostID     string      `json:"host_id"`
	Hostname   string      `json:"hostname,omitempty"`
	Wave       int         `json:"wave"`
	Position   int         `json:"position"`
	State      TargetState `json:"state"`
	JobID      *string     `json:"job_id,omitempty"`
	// PlanJobID jest zadaniem, ktore policzylo plan tego hosta.
	PlanJobID    *string    `json:"plan_job_id,omitempty"`
	RebootJobID  *string    `json:"reboot_job_id,omitempty"`
	HealthJobID  *string    `json:"health_job_id,omitempty"`
	BootIDBefore string     `json:"boot_id_before,omitempty"`
	ErrorCode    string     `json:"error_code,omitempty"`
	Message      string     `json:"message,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
}

// Report podsumowuje przebieg kampanii.
type Report struct {
	CampaignID string         `json:"campaign_id"`
	State      State          `json:"state"`
	Totals     map[string]int `json:"totals"`
	Waves      []WaveSummary  `json:"waves"`
	Failures   []Target       `json:"failures"`
	// RebootRequired to hosty, ktore po zmianie nadal czekaja na restart.
	RebootPending []string `json:"reboot_pending,omitempty"`
}

// WaveSummary opisuje jedna fale.
type WaveSummary struct {
	Wave      int            `json:"wave"`
	IsCanary  bool           `json:"is_canary"`
	Totals    map[string]int `json:"totals"`
	Completed bool           `json:"completed"`
}

// ThresholdExceeded sprawdza, czy liczba bledow przekroczyla prog kampanii.
// Prog bezwzgledny liczy sie od pierwszego bledu, procentowy dopiero gdy jest
// z czego liczyc - inaczej pojedynczy blad w canary zawsze konczylby kampanie.
func ThresholdExceeded(failed, finished, total, percentThreshold, absoluteThreshold int) (bool, string) {
	if absoluteThreshold > 0 && failed >= absoluteThreshold {
		return true, fmt.Sprintf("liczba bledow %d osiagnela prog %d", failed, absoluteThreshold)
	}
	if percentThreshold > 0 && finished > 0 {
		percent := failed * 100 / finished
		if percent >= percentThreshold {
			return true, fmt.Sprintf("udzial bledow %d%% osiagnal prog %d%%", percent, percentThreshold)
		}
	}
	return false, ""
}

// WithinMaintenanceWindow mowi, czy w danej chwili wolno prowadzic kampanie.
// Brak okna oznacza brak ograniczenia.
func WithinMaintenanceWindow(now time.Time, start, end *time.Time) bool {
	if start != nil && now.Before(*start) {
		return false
	}
	if end != nil && now.After(*end) {
		return false
	}
	return true
}
