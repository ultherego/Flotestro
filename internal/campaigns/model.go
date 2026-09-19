// Package campaigns runs campaigns: a fleet-wide change carried out through a
// canary and waves, with stop thresholds and a final report.
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
	"github.com/ultherego/flotestro/internal/selector"
)

// State is the state of a campaign.
type State string

const (
	// StatePlanning is the phase in which every host computes its own plan.
	StatePlanning         State = "planning"
	StatePlanned          State = "planned"
	StateAwaitingApproval State = "awaiting_approval"
	StateCanary           State = "canary"
	// StateManualGate is the stop after the canary: the campaign asked for an
	// explicit decision before the waves, and nothing starts until an operator
	// advances it.
	StateManualGate State = "manual_gate"
	StateRunning    State = "running"
	// StatePausing is a pause ordered while hosts are still carrying their tasks.
	StatePausing State = "pausing"
	StatePaused  State = "paused"
	// StateCanceling is a cancel ordered while hosts are still carrying their
	// tasks.
	StateCanceling State = "canceling"
	StateCompleted State = "completed"
	// StateCompletedWithIssues is a campaign that finished under its threshold
	// but not cleanly: hosts failed or ended unknown along the way.
	StateCompletedWithIssues State = "completed_with_issues"
	StateFailed              State = "failed"
	// StatePlanFailed is a planning phase that ended with no host to run on:
	// every plan was refused, failed or never computed.
	StatePlanFailed State = "plan_failed"
	// StateExpired is a campaign whose plans passed their time limit before any
	// host started - waiting for an approval or for its window.
	StateExpired  State = "expired"
	StateCanceled State = "canceled"
)

// Active says whether the campaign is under way.
func (s State) Active() bool {
	return s == StateCanary || s == StateRunning
}

// Terminal says whether the state is final.
func (s State) Terminal() bool {
	switch s {
	case StateCompleted, StateCompletedWithIssues, StateFailed, StatePlanFailed,
		StateExpired, StateCanceled:
		return true
	default:
		return false
	}
}

// Launching says whether the campaign may start a host now: a campaign in its
// planning phase, its canary or its waves hands tasks to hosts, and so does a
// planned one - approved, or in need of no approval - whose first pass is
func (s State) Launching() bool {
	return s == StatePlanning || s == StatePlanned || s == StateCanary || s == StateRunning
}

// mayBecome says whether the orchestrator may move a campaign from this state
// to the given one.
func (s State) mayBecome(to State) bool {
	if s.Terminal() || s == to {
		return false
	}
	switch to {
	case StateCanary, StateRunning:
		return s == StatePlanned || s == StateCanary
	case StateManualGate:
		// A campaign resumed after a pause in its canary stands planned
		// when it reaches the gate.
		return s == StatePlanned || s == StateCanary || s == StateRunning
	case StatePausing:
		return s == StatePlanned || s == StateCanary || s == StateRunning
	case StatePaused:
		return s == StatePlanned || s == StateCanary || s == StateRunning || s == StatePausing
	case StateExpired:
		return s == StatePlanned || s == StateAwaitingApproval
	case StatePlanFailed:
		return s == StatePlanning
	case StateCompleted, StateCompletedWithIssues, StateFailed:
		// A planning phase in which every host settled - already in the
		// desired state, refused by its plan - ends completed too.
		return s == StatePlanning || s == StatePlanned || s == StateCanary || s == StateRunning
	case StateCanceled:
		return s == StateCanceling
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
	// TargetAwaitingBudget marks a host ready for the change that waits for the
	// capacity of the fleet or of the site.
	TargetAwaitingBudget TargetState = "awaiting_budget"
	// TargetIneligible marks a host that cannot carry out this operation: it
	// lacks the required adapter or does not meet a precondition.
	TargetIneligible TargetState = "ineligible"
	// TargetExcluded marks a host the operator left out by name when the campaign
	// was ordered.
	TargetExcluded TargetState = "excluded"
	// TargetQueuedOffline marks a host that was not connected when its turn came
	// and whose campaign waits for it.
	TargetQueuedOffline TargetState = "queued_offline"
	// TargetDispatched marks a host whose task exists and has not started on the
	// agent's word: queued, leased, or handed over and not yet acknowledged as
	// started.
	TargetDispatched TargetState = "dispatched"
	// TargetAwaitingLock marks a host whose agent holds the task and waits for a
	// resource of the host - another task's package transaction, a unit restart
	// under way.
	TargetAwaitingLock TargetState = "awaiting_lock"
	TargetRunning      TargetState = "running"
	TargetRebooting    TargetState = "rebooting"
	TargetVerifying    TargetState = "verifying"
	TargetSucceeded    TargetState = "succeeded"
	// TargetNoChange marks a host that already had the desired state: its plan
	// found nothing to do, or the host reported that it changed nothing.
	TargetNoChange TargetState = "no_change"
	TargetFailed   TargetState = "failed"
	// TargetUnknown marks a host whose task ended without a result: the session
	// broke while it ran, or the agent came back from a restart with the
	// operation half done.
	TargetUnknown  TargetState = "unknown"
	TargetSkipped  TargetState = "skipped"
	TargetCanceled TargetState = "canceled"
)

// Waiting says whether the host is ready to start but has not started yet.
func (t TargetState) Waiting() bool {
	return t == TargetPending || t == TargetAwaitingBudget || t == TargetQueuedOffline
}

// UnderWay says whether the host is carrying a task of the change: from the
// dispatch of its task to the end of its verification.
func (t TargetState) UnderWay() bool {
	switch t {
	case TargetDispatched, TargetAwaitingLock, TargetRunning, TargetRebooting, TargetVerifying:
		return true
	default:
		return false
	}
}

// Succeeded says whether the host ended with the desired state on it: the
// change landed and was verified, or nothing needed to change.
func (t TargetState) Succeeded() bool {
	return t == TargetSucceeded || t == TargetNoChange
}

// HoldsWave says whether the host keeps its wave open. A settled host does
// not.
func (t Target) HoldsWave() bool {
	if t.State.Finished() {
		return false
	}
	return t.State != TargetQueuedOffline || t.Wave == 0
}

// mayBecome says whether a target may move from this state to the given one.
func (t TargetState) mayBecome(to TargetState) bool {
	if t.Finished() {
		return false
	}
	// The same state written again carries a new reason or message - a host
	// waiting for another budget than a moment ago - and is a change of the row,
	// not of the course.
	if t == to {
		return true
	}
	// Any open host may settle, and any open host may be canceled.
	if to.Finished() {
		return true
	}
	switch to {
	case TargetPending:
		return t == TargetAwaitingBudget || t == TargetQueuedOffline || t == TargetPlanning
	case TargetAwaitingBudget, TargetQueuedOffline, TargetPlanning:
		return t.Waiting() || t == TargetPlanning
	case TargetDispatched:
		return t.Waiting() || t == TargetAwaitingLock || t == TargetRunning
	case TargetAwaitingLock, TargetRunning:
		return t.Waiting() || t == TargetDispatched || t == TargetAwaitingLock || t == TargetRunning
	case TargetRebooting:
		return t == TargetDispatched || t == TargetAwaitingLock || t == TargetRunning
	case TargetVerifying:
		return t == TargetDispatched || t == TargetAwaitingLock || t == TargetRunning || t == TargetRebooting
	default:
		return false
	}
}

// Finished says whether the host has finished taking part in the campaign.
func (t TargetState) Finished() bool {
	switch t {
	case TargetSucceeded, TargetNoChange, TargetFailed, TargetUnknown, TargetSkipped,
		TargetCanceled, TargetIneligible, TargetExcluded:
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
// audit trail; what binds is the snapshot of targets created while planning.
type Selector struct {
	Site        string   `json:"site,omitempty"`
	Environment string   `json:"environment,omitempty"`
	OSFamily    string   `json:"os_family,omitempty"`
	HostIDs     []string `json:"host_ids,omitempty"`
	// Expression is the typed selector; see the selector package for its
	// grammar.
	Expression *selector.Expression `json:"expression,omitempty"`
	// Exclude names hosts the selector matches that are to stay out, with the
	// reason the operator gave.
	Exclude       []string `json:"exclude,omitempty"`
	ExcludeReason string   `json:"exclude_reason,omitempty"`
}

// Empty says whether the selector narrows nothing.
func (s Selector) Empty() bool {
	return s.Site == "" && s.Environment == "" && s.OSFamily == "" && len(s.HostIDs) == 0 &&
		s.Expression == nil
}

// Excluded says whether the host is on the exclusion list.
func (s Selector) Excluded(hostID string) bool {
	for _, excluded := range s.Exclude {
		if excluded == hostID {
			return true
		}
	}
	return false
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
	// RebootTimeoutSeconds bounds the wait for a host to come back after the
	// reboot the campaign ordered.
	RebootTimeoutSeconds int
	RequiresApproval     bool
	// OfflinePolicy says what happens to a host that is not connected when its
	// turn comes.
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
	// CompensatesCampaignID names the campaign this one undoes: the reverse
	// operation on the hosts that campaign changed.
	CompensatesCampaignID string
	// RetriesCampaignID names the finished campaign whose failed hosts this one
	// runs again with the same order.
	RetriesCampaignID string
	// PolicyID and PolicyVersion name the desired-state policy that ordered the
	// campaign as its remediation, and the version of the document that judged
	// the drift.
	PolicyID      string
	PolicyVersion int
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

// The bounds of the wait for a rebooted host.
const (
	DefaultRebootTimeout = 15 * time.Minute
	MinRebootTimeout     = time.Minute
	MaxRebootTimeout     = 2 * time.Hour
)

// RebootTimeout returns the wait for a rebooted host as a duration.
func (s Spec) RebootTimeout() time.Duration {
	return rebootTimeoutOf(s.RebootTimeoutSeconds)
}

// rebootTimeoutOf resolves the recorded seconds to a duration; zero is the
// default, so a campaign from before the field waits as it always did.
func rebootTimeoutOf(seconds int) time.Duration {
	if seconds <= 0 {
		return DefaultRebootTimeout
	}
	return time.Duration(seconds) * time.Second
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
	// Zero is "the default"; anything else has to be a wait the bounds allow, a
	// negative number included - it is not an absence, it is a mistake.
	if s.RebootTimeoutSeconds != 0 && (s.RebootTimeoutSeconds < int(MinRebootTimeout/time.Second) ||
		s.RebootTimeoutSeconds > int(MaxRebootTimeout/time.Second)) {
		return fmt.Errorf("the reboot timeout has to be between %d and %d seconds",
			int(MinRebootTimeout/time.Second), int(MaxRebootTimeout/time.Second))
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

// PlanTTL bounds a per-host plan in time.
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
func Fingerprint(spec Spec, targets []TargetHost) (string, error) {
	// The fingerprint also carries the host's starting state.
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
	// The exclusions are part of the consent too: a campaign that leaves the
	// database master out is a different campaign from one that does not, even
	// when the rest of the snapshot is the same.
	excluded := append([]string(nil), spec.Selector.Exclude...)
	sort.Strings(excluded)
	var expression json.RawMessage
	if spec.Selector.Expression != nil {
		encoded, err := json.Marshal(spec.Selector.Expression)
		if err != nil {
			return "", err
		}
		expression = encoded
	}
	content := struct {
		Version    int             `json:"campaign_version"`
		Action     string          `json:"action"`
		Payload    json.RawMessage `json:"payload"`
		Targets    []string        `json:"targets"`
		Expression json.RawMessage `json:"expression,omitempty"`
		Excluded   []string        `json:"excluded,omitempty"`
		Reason     string          `json:"exclude_reason,omitempty"`
		// What the campaign undoes is part of what the approver consents to: "the
		// rollback of last night's rollout" is a different decision from the same
		// file write ordered on its own.
		Compensates string `json:"compensates_campaign_id,omitempty"`
		// A retry is a decision about a campaign that went wrong, not the same order
		// twice: "the second go at last night's rollout" is consented to as that.
		Retries string `json:"retries_campaign_id,omitempty"`
		Rollout struct {
			Canary           int          `json:"canary_size"`
			Wave             int          `json:"wave_size"`
			Concurrent       int          `json:"max_concurrent"`
			ThresholdPercent int          `json:"failure_threshold_percent"`
			ThresholdCount   int          `json:"failure_threshold_absolute"`
			Reboot           RebootPolicy `json:"reboot_policy"`
			Units            []string     `json:"health_check_units"`
			Timeout          int          `json:"job_timeout_seconds"`
			RebootTimeout    int          `json:"reboot_timeout_seconds"`
			WindowFrom       *time.Time   `json:"maintenance_start,omitempty"`
			WindowTo         *time.Time   `json:"maintenance_end,omitempty"`
			// What happens to an offline host, how long the campaign waits for it,
			// whether it stops after the canary and when a loss of connectivity halts
			// it are decisions the approver read too.
			Offline          opspec.OfflinePolicy `json:"offline_policy"`
			DeadlineMinutes  int                  `json:"deadline_minutes"`
			ManualGate       bool                 `json:"manual_gate"`
			ConnectivityLost int                  `json:"connectivity_lost_absolute"`
		} `json:"rollout"`
	}{Version: CampaignVersion, Action: spec.ActionType, Payload: payload, Targets: hosts,
		Expression: expression, Excluded: excluded, Reason: spec.Selector.ExcludeReason,
		Compensates: spec.CompensatesCampaignID, Retries: spec.RetriesCampaignID}
	content.Rollout.Canary = spec.CanarySize
	content.Rollout.Wave = spec.WaveSize
	content.Rollout.Concurrent = spec.MaxConcurrent
	content.Rollout.ThresholdPercent = spec.FailureThresholdPercent
	content.Rollout.ThresholdCount = spec.FailureThresholdAbsolute
	content.Rollout.Reboot = spec.RebootPolicy
	content.Rollout.Units = spec.HealthCheckUnits
	content.Rollout.Timeout = spec.JobTimeoutSeconds
	// Recorded resolved, like the deadline: how long a rebooted host is
	// waited for is part of what the approver read, default or not.
	content.Rollout.RebootTimeout = int(spec.RebootTimeout() / time.Second)
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
func FingerprintWithPlans(campaign Campaign, planSetHash string) (string, error) {
	if campaign.ApprovalFingerprint == "" {
		return "", fmt.Errorf("the campaign %s has no request fingerprint", campaign.ID)
	}
	// The request fingerprint came into being when the campaign was created and
	// covers the operation, the payload, the list of hosts and the rollout
	// policy.
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
	// RebootTimeoutSeconds is how long the campaign waits for a host to
	// come back after the reboot it ordered, before the host is failed.
	RebootTimeoutSeconds int  `json:"reboot_timeout_seconds"`
	RequiresApproval     bool `json:"requires_approval"`
	// OfflinePolicy is what the campaign does with a host that is not connected
	// when its turn comes; DeadlineAt is how long it waits for such a host under
	// a waiting policy.
	OfflinePolicy opspec.OfflinePolicy `json:"offline_policy"`
	DeadlineAt    *time.Time           `json:"deadline_at,omitempty"`
	// ManualGate stops the campaign after the canary; the gate fields say
	// who let it into the waves and when.
	ManualGate     bool       `json:"manual_gate"`
	GateAdvancedBy string     `json:"gate_advanced_by,omitempty"`
	GateAdvancedAt *time.Time `json:"gate_advanced_at,omitempty"`
	// ConnectivityLostAbsolute is the number of hosts that may lose their session
	// mid-task before the campaign pauses; zero means no such check.
	ConnectivityLostAbsolute int `json:"connectivity_lost_absolute"`
	// ApprovalFingerprint is the fingerprint of what the approver sees. A consent
	// given against a different fingerprint concerns a different campaign.
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
	// CompensatesCampaignID and CompensatesCampaignName name the campaign this
	// one undoes; both empty for a campaign that is not a compensation.
	CompensatesCampaignID   string `json:"compensates_campaign_id,omitempty"`
	CompensatesCampaignName string `json:"compensates_campaign_name,omitempty"`
	// CompensatedBy lists the campaigns ordered to undo this one, oldest first.
	CompensatedBy []CampaignLink `json:"compensated_by,omitempty"`
	// RetriesCampaignID and RetriesCampaignName name the campaign whose failed
	// hosts this one runs again; both empty for a campaign that is not a retry.
	RetriesCampaignID   string         `json:"retries_campaign_id,omitempty"`
	RetriesCampaignName string         `json:"retries_campaign_name,omitempty"`
	RetriedBy           []CampaignLink `json:"retried_by,omitempty"`
	// Progress counts the hosts of the campaign by how they stand, for a list
	// that shows many campaigns at once.
	Progress *Progress `json:"progress,omitempty"`
	// ChangedHosts counts the hosts the campaign changed, by the rule
	// ChangedTargets reads them: the change landed, whatever came after.
	ChangedHosts int `json:"changed_hosts"`
	// PolicyID and PolicyVersion link a remediation campaign back to the
	// desired-state policy that ordered it; both empty for a campaign an operator
	// ordered.
	PolicyID      string `json:"policy_id,omitempty"`
	PolicyVersion int    `json:"policy_version,omitempty"`
	// Revision grows with every change of the record.
	Revision int64 `json:"revision"`
	// The runner lease: which orchestrator drives the campaign, under which
	// token, until when.
	RunnerID    string     `json:"-"`
	RunnerToken int64      `json:"-"`
	RunnerUntil *time.Time `json:"-"`
}

// CampaignLink names another campaign the way a screen links to it.
type CampaignLink struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State State  `json:"state"`
}

// Progress is the tally of a campaign's hosts as a list row shows it.
type Progress struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Unknown   int `json:"unknown"`
	Skipped   int `json:"skipped"`
	Pending   int `json:"pending"`
}

// Add counts one host in the state given.
func (p *Progress) Add(state TargetState, count int) {
	p.Total += count
	switch state {
	case TargetSucceeded, TargetNoChange:
		p.Succeeded += count
	case TargetFailed:
		p.Failed += count
	case TargetUnknown:
		p.Unknown += count
	case TargetSkipped, TargetCanceled, TargetIneligible, TargetExcluded:
		p.Skipped += count
	default:
		p.Pending += count
	}
}

// RebootTimeout returns the wait for a rebooted host as a duration.
func (c Campaign) RebootTimeout() time.Duration {
	return rebootTimeoutOf(c.RebootTimeoutSeconds)
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
	// StateSince is when the target entered its current state.
	StateSince *time.Time `json:"state_since,omitempty"`
	// Blocker says what the host's task waits on while it has not started: the
	// resource lock and the task holding it, as the agent named them.
	Blocker string `json:"blocker,omitempty"`
	// Revision grows with every change of the row; a state is written
	// only against the revision the writer read.
	Revision int64 `json:"revision"`
	// ClaimedBy and ClaimToken say which runner holds the target and under which
	// token.
	ClaimedBy  string `json:"-"`
	ClaimToken int64  `json:"-"`
	// CancelRequestedAt is when a cancel found the host carrying its task.
	// The task stays with the host; the campaign waits for it to settle.
	CancelRequestedAt *time.Time `json:"cancel_requested_at,omitempty"`
	// CancelOutcome and CancelPhase are the agent's answer to the cancel of the
	// host's task, read off the job: what the request found on the host and what
	// the host was doing.
	CancelOutcome string `json:"cancel_outcome,omitempty"`
	CancelPhase   string `json:"cancel_phase,omitempty"`
}

// Report summarises the course of a campaign.
type Report struct {
	CampaignID string `json:"campaign_id"`
	State      State  `json:"state"`
	// Totals counts the hosts per target state - succeeded, no_change, failed,
	// unknown, skipped, canceled, and the rest - the way the document's terminal
	// report does: a host in the desired state without a mutation and one that
	Totals map[string]int `json:"totals"`
	Waves  []WaveSummary  `json:"waves"`
	// Failures lists the hosts the operator has to look at: the ones that
	// failed and the ones that ended unknown, each with its state.
	Failures []Target `json:"failures"`
	// RebootPending are the hosts that still wait for a reboot after the change.
	RebootPending []string `json:"reboot_pending,omitempty"`
	// PlanChanged are the hosts that came back from being offline with a state
	// that gives a different plan than the approved one.
	PlanChanged []Target `json:"plan_changed,omitempty"`
	// OfflineQueued are the hosts still waiting for their connection.
	OfflineQueued []string `json:"offline_queued,omitempty"`
}

// ConnectivityLostCode is the error code of a host whose session broke while
// its task ran.
const ConnectivityLostCode = "lease_expired"

// OutcomeUnknownCode is the error code the agent answers with when it comes
// back from a restart to find an operation it started and did not live to see
// the end of.
const OutcomeUnknownCode = "outcome_unknown"

// CancelAckTimeoutCode is the error code of a host whose cancel request got no
// answer within the operation's timeout (jobs.
const CancelAckTimeoutCode = "cancel_ack_timeout"

// SkippedByOperatorCode is the error code of a host an operator skipped by
// name: an offline canary the campaign was waiting for, let go with a reason
// so that the barrier opens.
const SkippedByOperatorCode = "skipped_by_operator"

// ConnectivityLost says whether the host ended because its session broke while
// its task ran rather than because the change failed.
func (t Target) ConnectivityLost() bool {
	return t.State == TargetUnknown && t.ErrorCode == ConnectivityLostCode
}

// targetTally is what the stop rules and the final verdict read off the
// targets: how many are settled, how many of those ended well, how many failed
// - the unknown ones among them, because unknown is not a success - how many
type targetTally struct {
	Total     int
	Finished  int
	Succeeded int
	// Failed counts the hosts that failed and the hosts that ended unknown: the
	// threshold is a bound on hosts that did not reach the desired state, and an
	// unknown host did not, as far as anyone knows.
	Failed  int
	Unknown int
	// Skipped counts the hosts left out by a deadline, a window or a
	// policy - not the ones ineligible or excluded, which never took part.
	Skipped int
	Lost    int
}

// tallyTargets counts the targets the way the stop rules read them.
func tallyTargets(targets []Target) targetTally {
	counts := targetTally{Total: len(targets)}
	for _, target := range targets {
		if target.State.Finished() {
			counts.Finished++
		}
		switch target.State {
		case TargetSucceeded, TargetNoChange:
			counts.Succeeded++
		case TargetFailed:
			counts.Failed++
		case TargetUnknown:
			counts.Failed++
			counts.Unknown++
		case TargetSkipped:
			counts.Skipped++
		}
		if target.ConnectivityLost() {
			counts.Lost++
		}
	}
	return counts
}

// settleCampaignState is the verdict on a campaign whose hosts have all
// settled: the state it ends in, read off the tally alone.
func settleCampaignState(counts targetTally) State {
	switch {
	case counts.Failed > 0 && counts.Succeeded == 0:
		return StateFailed
	case counts.Failed > 0:
		return StateCompletedWithIssues
	default:
		return StateCompleted
	}
}

// cancelSettled says whether a canceled campaign may end: no host is
// carrying a task any more. Until then the campaign is canceling.
func cancelSettled(targets []Target) bool {
	for _, target := range targets {
		if target.State.UnderWay() {
			return false
		}
	}
	return true
}

// pauseState is the state a pause puts the campaign in: pausing while any host
// carries a task, paused once none does.
func pauseState(targets []Target) State {
	if cancelSettled(targets) {
		return StatePaused
	}
	return StatePausing
}

// plansExpired says whether the campaign's plans passed their time limit
// before any host started.
func plansExpired(oldestPlan time.Time, started *time.Time, now time.Time) bool {
	if started != nil || oldestPlan.IsZero() {
		return false
	}
	return now.Sub(oldestPlan) > PlanTTL
}

// RebootWindowClosedCode is the error code of a host that was still rebooting
// when the campaign's maintenance window closed.
const RebootWindowClosedCode = "reboot_window_closed"

// PauseWindowClosedMidReboot is the reason a campaign is paused with when a
// host did not come back from its reboot inside the maintenance window.
const PauseWindowClosedMidReboot = "maintenance_window_closed_mid_reboot"

// RebootWindowClosed says whether the host ended because the maintenance
// window closed while it was rebooting.
func (t Target) RebootWindowClosed() bool {
	return t.State == TargetFailed && t.ErrorCode == RebootWindowClosedCode
}

// WaveSummary describes one wave.
type WaveSummary struct {
	Wave      int            `json:"wave"`
	IsCanary  bool           `json:"is_canary"`
	Totals    map[string]int `json:"totals"`
	Completed bool           `json:"completed"`
}

// ThresholdExceeded checks whether the number of failures has crossed the
// campaign's threshold.
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
