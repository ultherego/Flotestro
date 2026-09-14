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
	"github.com/ultherego/flotestro/internal/selector"
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
	// TargetExcluded marks a host the operator left out by name when the
	// campaign was ordered. It stays in the snapshot with the reason and
	// the author: an exclusion is a decision, and a decision nobody can
	// read afterwards is a hole in the audit trail. Not a failure.
	TargetExcluded TargetState = "excluded"
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
	case TargetSucceeded, TargetFailed, TargetSkipped, TargetCanceled, TargetIneligible, TargetExcluded:
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
//
// Two generations live side by side. The flat fields and the host list are
// the first one and stay for the orders that use them. Expression is the
// second: a typed selector over tags, groups and the host facts, compiled
// into the same query the host list runs. When it is present it decides
// alone and the flat fields are ignored.
type Selector struct {
	Site        string   `json:"site,omitempty"`
	Environment string   `json:"environment,omitempty"`
	OSFamily    string   `json:"os_family,omitempty"`
	HostIDs     []string `json:"host_ids,omitempty"`
	// Expression is the typed selector; see the selector package for its
	// grammar.
	Expression *selector.Expression `json:"expression,omitempty"`
	// Exclude names hosts the selector matches that are to stay out, with
	// the reason the operator gave. Such a host enters the snapshot as an
	// excluded target rather than vanishing: the approver is to see what
	// was left out and why.
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
	// RebootTimeoutSeconds bounds the wait for a host to come back after
	// the reboot the campaign ordered. Zero means DefaultRebootTimeout; a
	// given value has to lie between MinRebootTimeout and MaxRebootTimeout.
	RebootTimeoutSeconds int
	RequiresApproval     bool
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
	// CompensatesCampaignID names the campaign this one undoes: the
	// reverse operation on the hosts that campaign changed. Empty for a
	// campaign that is not a compensation. The handler checks the rules
	// (CheckCompensation) before the order reaches the store.
	CompensatesCampaignID string
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

// The bounds of the wait for a rebooted host. Without a bound the campaign
// would wait forever for a machine that never came up; a bound under a
// minute would fail hosts that merely take their time through the BIOS,
// and one over two hours is no longer a wait but a forgotten host.
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
	// Zero is "the default"; anything else has to be a wait the bounds
	// allow, a negative number included - it is not an absence, it is a
	// mistake.
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
	// The exclusions are part of the consent too: a campaign that leaves
	// the database master out is a different campaign from one that does
	// not, even when the rest of the snapshot is the same. The expression
	// is recorded in the shape it was ordered in, so a change to a group's
	// definition after the order does not move the fingerprint - the
	// snapshot already holds what the group resolved to.
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
		// What the campaign undoes is part of what the approver consents
		// to: "the rollback of last night's rollout" is a different
		// decision from the same file write ordered on its own. Absent
		// from the digest of every other campaign, so theirs stay.
		Compensates string `json:"compensates_campaign_id,omitempty"`
		Rollout     struct {
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
			// What happens to an offline host, how long the campaign waits
			// for it, whether it stops after the canary and when a loss of
			// connectivity halts it are decisions the approver read too.
			Offline          opspec.OfflinePolicy `json:"offline_policy"`
			DeadlineMinutes  int                  `json:"deadline_minutes"`
			ManualGate       bool                 `json:"manual_gate"`
			ConnectivityLost int                  `json:"connectivity_lost_absolute"`
		} `json:"rollout"`
	}{Version: CampaignVersion, Action: spec.ActionType, Payload: payload, Targets: hosts,
		Expression: expression, Excluded: excluded, Reason: spec.Selector.ExcludeReason,
		Compensates: spec.CompensatesCampaignID}
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
	// RebootTimeoutSeconds is how long the campaign waits for a host to
	// come back after the reboot it ordered, before the host is failed.
	RebootTimeoutSeconds int  `json:"reboot_timeout_seconds"`
	RequiresApproval     bool `json:"requires_approval"`
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
	// CompensatesCampaignID and CompensatesCampaignName name the campaign
	// this one undoes; both empty for a campaign that is not a
	// compensation. The name travels with the identifier so a screen can
	// link the original without a second read.
	CompensatesCampaignID   string `json:"compensates_campaign_id,omitempty"`
	CompensatesCampaignName string `json:"compensates_campaign_name,omitempty"`
	// CompensatedBy lists the campaigns ordered to undo this one, oldest
	// first. It is read from the compensating campaigns' link, so the
	// record of the original never changes when a rollback is ordered.
	CompensatedBy []CampaignLink `json:"compensated_by,omitempty"`
	// ChangedHosts counts the hosts the campaign changed, by the rule
	// ChangedTargets reads them: the change landed, whatever came after.
	// It is the number a compensation would run on. Zero until the
	// campaign settles: a count of a campaign still changing hosts would
	// invite a rollback of a moving target, which the server refuses.
	ChangedHosts int `json:"changed_hosts"`
}

// CampaignLink names another campaign the way a screen links to it.
type CampaignLink struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State State  `json:"state"`
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
	// StateSince is when the target entered its current state. StartedAt
	// says when the host began the change; only the last transition says
	// when its reboot began, and the wait for the host is counted from
	// there. Absent from reads that do not need it.
	StateSince *time.Time `json:"state_since,omitempty"`
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

// RebootWindowClosedCode is the error code of a host that was still
// rebooting when the campaign's maintenance window closed. The change on
// it is done; what is unknown is whether it will come back, and the window
// the operator promised the fleet in has ended.
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
