// Package campaigns runs campaigns: a fleet-wide change carried out through a
// canary and waves, with stop thresholds and a final report. A campaign is the
// main mechanism of change rather than a loop over hosts.
package campaigns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

// State is the state of a campaign.
type State string

const (
	// StatePlanning is the phase in which every host computes its own plan.
	// The campaign changes nothing yet: a plan is a read, and the set of them
	// is what the operator is about to approve.
	StatePlanning         State = "planning"
	StatePlanned          State = "planned"
	StateAwaitingApproval State = "awaiting_approval"
	StateCanary           State = "canary"
	// StateManualGate is the stop after the canary: the campaign asked for
	// an explicit decision before the waves, and nothing starts until an
	// operator advances it. Like a pause, it waits for a human rather than
	// for the machinery.
	StateManualGate State = "manual_gate"
	StateRunning    State = "running"
	StatePaused     State = "paused"
	StateCompleted  State = "completed"
	StateFailed     State = "failed"
	StateCanceled   State = "canceled"
)

// Active says whether the campaign is under way.
func (s State) Active() bool {
	return s == StateCanary || s == StateRunning
}

// Terminal says whether the state is final.
func (s State) Terminal() bool {
	switch s {
	case StateCompleted, StateFailed, StateCanceled:
		return true
	default:
		return false
	}
}

// TargetState is the state of a single host in a campaign.
type TargetState string

const (
	TargetPending TargetState = "pending"
	// TargetPlanning marks a host that is computing its own plan of the change.
	TargetPlanning TargetState = "planning"
	// TargetAwaitingBudget marks a host ready for the change that waits for
	// the capacity of the fleet or of the site. It takes no execution slot
	// and is not an error - but it has to be visible, because otherwise the
	// campaign stands still with no reason given.
	TargetAwaitingBudget TargetState = "awaiting_budget"
	// TargetIneligible marks a host that cannot carry out this operation: it
	// lacks the required adapter or does not meet a precondition. That is not
	// an execution failure and does not count towards the failure threshold -
	// but the host stays in the snapshot, because nobody can manage something
	// that disappears silently.
	TargetIneligible TargetState = "ineligible"
	// TargetQueuedOffline marks a host that was not connected when its turn
	// came and whose campaign waits for it. It takes no slot and no budget
	// token: nothing runs on it. It goes back to the queue when the host
	// comes back and ends skipped when the campaign's deadline passes.
	TargetQueuedOffline TargetState = "queued_offline"
	TargetRunning       TargetState = "running"
	TargetRebooting     TargetState = "rebooting"
	TargetVerifying     TargetState = "verifying"
	TargetSucceeded     TargetState = "succeeded"
	TargetFailed        TargetState = "failed"
	TargetSkipped       TargetState = "skipped"
	TargetCanceled      TargetState = "canceled"
)

// Waiting says whether the host is ready to start but has not started yet.
//
// Waiting for a budget is the same place in the queue as pending: the host
// takes no slot and asks for capacity again on every pass. A host queued
// offline waits in the same place - for its connection rather than for a
// token.
func (t TargetState) Waiting() bool {
	return t == TargetPending || t == TargetAwaitingBudget || t == TargetQueuedOffline
}

// HoldsWave says whether the host keeps its wave open. A host queued
// offline does not: the wave's verdict comes from the hosts that ran, and
// the offline one gets its turn when it comes back - otherwise a single
// unplugged machine would hold the whole fleet until the deadline.
func (t TargetState) HoldsWave() bool {
	return !t.Finished() && t != TargetQueuedOffline
}

// Finished says whether the host has finished taking part in the campaign.
func (t TargetState) Finished() bool {
	switch t {
	case TargetSucceeded, TargetFailed, TargetSkipped, TargetCanceled, TargetIneligible:
		return true
	default:
		return false
	}
}

// RebootPolicy decides when a campaign reboots a host.
type RebootPolicy string

const (
	RebootNever      RebootPolicy = "never"
	RebootIfRequired RebootPolicy = "if_required"
	RebootAlways     RebootPolicy = "always"
)

// KnownRebootPolicy checks that the policy is valid.
func KnownRebootPolicy(policy RebootPolicy) bool {
	switch policy {
	case RebootNever, RebootIfRequired, RebootAlways:
		return true
	default:
		return false
	}
}

// Selector describes which hosts enter a campaign. It is recorded for the
// audit trail; what binds is the snapshot of targets created while
// planning.
type Selector struct {
	Site        string   `json:"site,omitempty"`
	Environment string   `json:"environment,omitempty"`
	OSFamily    string   `json:"os_family,omitempty"`
	HostIDs     []string `json:"host_ids,omitempty"`
}

// Empty says whether the selector narrows nothing.
func (s Selector) Empty() bool {
	return s.Site == "" && s.Environment == "" && s.OSFamily == "" && len(s.HostIDs) == 0
}

// Spec describes the campaign to create.
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
	// OfflinePolicy says what happens to a host that is not connected when
	// its turn comes. Empty means the operation's own policy; the handler
	// resolves it before the campaign is created, so the record always
	// carries the policy that really applies.
	OfflinePolicy opspec.OfflinePolicy
	// DeadlineMinutes bounds the wait for offline hosts, counted from the
	// creation. Zero means the default of a day.
	DeadlineMinutes int
	// ManualGate stops the campaign after the canary until an operator
	// advances it into the waves.
	ManualGate bool
	// ConnectivityLostAbsolute pauses the campaign once that many hosts
	// lost their session while their task ran. Zero disables the check.
	ConnectivityLostAbsolute int
	CreatedBy                string
	RequestID                string
	// IdempotencyKey lets a caller repeat the order without a second
	// campaign; empty means every order is new.
	IdempotencyKey string
}

// DefaultDeadline is how long a campaign waits for offline hosts when the
// order names no deadline.
const DefaultDeadline = 24 * time.Hour

// Deadline returns the wait for offline hosts as a duration.
func (s Spec) Deadline() time.Duration {
	if s.DeadlineMinutes <= 0 {
		return DefaultDeadline
	}
	return time.Duration(s.DeadlineMinutes) * time.Minute
}

// Validate checks that the description of the campaign holds together.
func (s Spec) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("a campaign requires a name")
	}
	if s.WaveSize <= 0 {
		return fmt.Errorf("the wave size has to be positive")
	}
	if s.MaxConcurrent <= 0 {
		return fmt.Errorf("the concurrency limit has to be positive")
	}
	if s.CanarySize < 0 {
		return fmt.Errorf("the canary size must not be negative")
	}
	if s.FailureThresholdPercent < 0 || s.FailureThresholdPercent > 100 {
		return fmt.Errorf("the failure threshold in percent has to be in the range 0-100")
	}
	if !KnownRebootPolicy(s.RebootPolicy) {
		return fmt.Errorf("unknown reboot policy %q", s.RebootPolicy)
	}
	if s.MaintenanceStart != nil && s.MaintenanceEnd != nil &&
		!s.MaintenanceEnd.After(*s.MaintenanceStart) {
		return fmt.Errorf("the maintenance window ends before it starts")
	}
	if s.OfflinePolicy != "" && !opspec.KnownOfflinePolicy(s.OfflinePolicy) {
		return fmt.Errorf("unknown offline policy %q", s.OfflinePolicy)
	}
	if s.DeadlineMinutes < 0 {
		return fmt.Errorf("the deadline must not be negative")
	}
	if s.ConnectivityLostAbsolute < 0 {
		return fmt.Errorf("the connectivity loss threshold must not be negative")
	}
	// A gate after the canary needs a canary to gate on; without one it
	// would stop the campaign before anything ran at all.
	if s.ManualGate && s.CanarySize <= 0 {
		return fmt.Errorf("a manual gate needs a canary")
	}
	return nil
}

// PlanTTL bounds a per-host plan in time. A plan is a description of a
// change against the state the host had when it was computed; a day later
// the vendor may have published other versions and the change would differ
// from the one the approver read, digest or no digest. A host whose plan
// is older is not started; the campaign is planned again.
const PlanTTL = 24 * time.Hour

// ErrPlanExpired means the host's plan is older than PlanTTL.
var ErrPlanExpired = errors.New("the plan expired")

// Approval is the evidence of a consent: who approved which fingerprint,
// on the strength of what authentication, and why. It is written once.
type Approval struct {
	ID                  string `json:"id"`
	CampaignID          string `json:"campaign_id"`
	ApprovalFingerprint string `json:"approval_fingerprint"`
	RequestedBy         string `json:"requested_by"`
	ApprovedBy          string `json:"approved_by"`
	// Authentication is "session" or "api_token". A token cannot
	// re-authenticate; the record says so instead of pretending.
	Authentication  string     `json:"authentication"`
	ACR             string     `json:"acr,omitempty"`
	AMR             []string   `json:"amr,omitempty"`
	AuthenticatedAt *time.Time `json:"authenticated_at,omitempty"`
	Reason          string     `json:"reason,omitempty"`
	ChangeTicket    string     `json:"change_ticket,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Fingerprint computes the approval fingerprint of a campaign.
//
// The consent is to concern exactly what the operator saw: the same
// operation, the same payload, the same list of hosts and the same rollout
// policy. If the fingerprint covered the campaign identifier alone, an
// approval would carry over to every change somebody made along the way.
//
// The hosts are sorted, because the order of the snapshot is not a decision.
// Everything else enters in the shape in which it was recorded.
func Fingerprint(spec Spec, targets []TargetHost) (string, error) {
	// The fingerprint also carries the host's starting state. The consent
	// concerns what will really run: a campaign in which a host was
	// ineligible and, after being computed again, is ready, is a different
	// campaign from the approved one.
	hosts := make([]string, 0, len(targets))
	for _, target := range targets {
		entry := target.ID
		if target.State != "" {
			entry += ":" + string(target.State)
		}
		hosts = append(hosts, entry)
	}
	sort.Strings(hosts)

	payload := spec.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	content := struct {
		Version int             `json:"campaign_version"`
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload"`
		Targets []string        `json:"targets"`
		Rollout struct {
			Canary           int          `json:"canary_size"`
			Wave             int          `json:"wave_size"`
			Concurrent       int          `json:"max_concurrent"`
			ThresholdPercent int          `json:"failure_threshold_percent"`
			ThresholdCount   int          `json:"failure_threshold_absolute"`
			Reboot           RebootPolicy `json:"reboot_policy"`
			Units            []string     `json:"health_check_units"`
			Timeout          int          `json:"job_timeout_seconds"`
			WindowFrom       *time.Time   `json:"maintenance_start,omitempty"`
			WindowTo         *time.Time   `json:"maintenance_end,omitempty"`
			// What happens to an offline host, how long the campaign waits
			// for it, whether it stops after the canary and when a loss of
			// connectivity halts it are decisions the approver read too.
			Offline          opspec.OfflinePolicy `json:"offline_policy"`
			DeadlineMinutes  int                  `json:"deadline_minutes"`
			ManualGate       bool                 `json:"manual_gate"`
			ConnectivityLost int                  `json:"connectivity_lost_absolute"`
		} `json:"rollout"`
	}{Version: CampaignVersion, Action: spec.ActionType, Payload: payload, Targets: hosts}
	content.Rollout.Canary = spec.CanarySize
	content.Rollout.Wave = spec.WaveSize
	content.Rollout.Concurrent = spec.MaxConcurrent
	content.Rollout.ThresholdPercent = spec.FailureThresholdPercent
	content.Rollout.ThresholdCount = spec.FailureThresholdAbsolute
	content.Rollout.Reboot = spec.RebootPolicy
	content.Rollout.Units = spec.HealthCheckUnits
	content.Rollout.Timeout = spec.JobTimeoutSeconds
	content.Rollout.WindowFrom = spec.MaintenanceStart
	content.Rollout.WindowTo = spec.MaintenanceEnd
	content.Rollout.Offline = spec.OfflinePolicy
	content.Rollout.DeadlineMinutes = int(spec.Deadline() / time.Minute)
	content.Rollout.ManualGate = spec.ManualGate
	content.Rollout.ConnectivityLost = spec.ConnectivityLostAbsolute

	encoded, err := json.Marshal(content)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// FingerprintWithPlans recomputes the approval fingerprint together with the
// set of plans.
//
// After the planning phase the consent no longer concerns the request alone
// but what every host will really do. A plan computed against a different
// host state gives a different set digest and therefore invalidates the
// consent.
func FingerprintWithPlans(campaign Campaign, planSetHash string) (string, error) {
	if campaign.ApprovalFingerprint == "" {
		return "", fmt.Errorf("the campaign %s has no request fingerprint", campaign.ID)
	}
	// The request fingerprint came into being when the campaign was created
	// and covers the operation, the payload, the list of hosts and the
	// rollout policy. The set of plans is appended to it, so the consent
	// concerns both.
	return textFingerprint([]string{campaign.ApprovalFingerprint, planSetHash}), nil
}

// textFingerprint computes a fingerprint from an ordered list of strings.
func textFingerprint(parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

// CampaignVersion is the version of the campaign semantics. Changing the
// version invalidates approvals: the consent concerned different rules.
const CampaignVersion = 2

// Campaign is the view of a campaign returned by the API.
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
	// OfflinePolicy is what the campaign does with a host that is not
	// connected when its turn comes; DeadlineAt is how long it waits for
	// such a host under a waiting policy.
	OfflinePolicy opspec.OfflinePolicy `json:"offline_policy"`
	DeadlineAt    *time.Time           `json:"deadline_at,omitempty"`
	// ManualGate stops the campaign after the canary; the gate fields say
	// who let it into the waves and when.
	ManualGate     bool       `json:"manual_gate"`
	GateAdvancedBy string     `json:"gate_advanced_by,omitempty"`
	GateAdvancedAt *time.Time `json:"gate_advanced_at,omitempty"`
	// ConnectivityLostAbsolute is the number of hosts that may lose their
	// session mid-task before the campaign pauses; zero means no such
	// check.
	ConnectivityLostAbsolute int `json:"connectivity_lost_absolute"`
	// ApprovalFingerprint is the fingerprint of what the approver sees. A
	// consent given against a different fingerprint concerns a different
	// campaign.
	ApprovalFingerprint string `json:"approval_fingerprint"`
	// PlanSetHash is the digest of the set of per-host plans. Empty means a
	// campaign that needs no plans.
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

// Target is a host within a campaign.
type Target struct {
	ID         string      `json:"id"`
	CampaignID string      `json:"campaign_id"`
	HostID     string      `json:"host_id"`
	Hostname   string      `json:"hostname,omitempty"`
	Wave       int         `json:"wave"`
	Position   int         `json:"position"`
	State      TargetState `json:"state"`
	JobID      *string     `json:"job_id,omitempty"`
	// PlanJobID is the task that computed this host's plan.
	PlanJobID    *string    `json:"plan_job_id,omitempty"`
	RebootJobID  *string    `json:"reboot_job_id,omitempty"`
	HealthJobID  *string    `json:"health_job_id,omitempty"`
	BootIDBefore string     `json:"boot_id_before,omitempty"`
	ErrorCode    string     `json:"error_code,omitempty"`
	Message      string     `json:"message,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
}

// Report summarises the course of a campaign.
type Report struct {
	CampaignID string         `json:"campaign_id"`
	State      State          `json:"state"`
	Totals     map[string]int `json:"totals"`
	Waves      []WaveSummary  `json:"waves"`
	Failures   []Target       `json:"failures"`
	// RebootPending are the hosts that still wait for a reboot after the change.
	RebootPending []string `json:"reboot_pending,omitempty"`
	// PlanChanged are the hosts that came back from being offline with a
	// state that gives a different plan than the approved one. They ran
	// nothing: the consent covered the old plan.
	PlanChanged []Target `json:"plan_changed,omitempty"`
	// OfflineQueued are the hosts still waiting for their connection.
	OfflineQueued []string `json:"offline_queued,omitempty"`
}

// ConnectivityLostCode is the error code of a host whose session broke
// while its task ran. The outcome on the host is unknown, and the
// campaign counts such hosts separately from failures of the change.
const ConnectivityLostCode = "lease_expired"

// ConnectivityLost says whether the host ended because its session broke
// while its task ran rather than because the change failed.
func (t Target) ConnectivityLost() bool {
	return t.State == TargetFailed && t.ErrorCode == ConnectivityLostCode
}

// WaveSummary describes one wave.
type WaveSummary struct {
	Wave      int            `json:"wave"`
	IsCanary  bool           `json:"is_canary"`
	Totals    map[string]int `json:"totals"`
	Completed bool           `json:"completed"`
}

// ThresholdExceeded checks whether the number of failures has crossed the
// campaign's threshold. The absolute threshold counts from the first failure,
// the percentage one only once there is something to compute it from -
// otherwise a single failure in the canary would always end the campaign.
func ThresholdExceeded(failed, finished, total, percentThreshold, absoluteThreshold int) (bool, string) {
	if absoluteThreshold > 0 && failed >= absoluteThreshold {
		return true, fmt.Sprintf("the number of failures %d reached the threshold %d", failed, absoluteThreshold)
	}
	if percentThreshold > 0 && finished > 0 {
		percent := failed * 100 / finished
		if percent >= percentThreshold {
			return true, fmt.Sprintf("the failure share %d%% reached the threshold %d%%", percent, percentThreshold)
		}
	}
	return false, ""
}

// WithinMaintenanceWindow says whether the campaign may run at the given
// moment. No window means no limitation.
func WithinMaintenanceWindow(now time.Time, start, end *time.Time) bool {
	if start != nil && now.Before(*start) {
		return false
	}
	if end != nil && now.After(*end) {
		return false
	}
	return true
}
