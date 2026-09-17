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
	// StatePausing is a pause ordered while hosts are still carrying their
	// tasks. Nothing new starts and no target is claimed; the hosts under
	// way settle, their budget leases are renewed meanwhile, and the
	// campaign is paused once none is in flight. A campaign that said
	// "paused" with hosts still running would have their leases expire
	// under them and their results unread until the resume.
	StatePausing State = "pausing"
	StatePaused  State = "paused"
	// StateCanceling is a cancel ordered while hosts are still carrying
	// their tasks. Nothing new starts; the hosts under way settle on their
	// own - a campaign stop never interrupts work on a host - and the
	// campaign ends canceled once the last of them has. A terminal state
	// written while hosts still run would have the report written from a
	// moving picture.
	StateCanceling State = "canceling"
	StateCompleted State = "completed"
	// StateCompletedWithIssues is a campaign that finished under its
	// threshold but not cleanly: hosts failed or ended unknown along the
	// way. The document tells it from completed so a clean rollout and one
	// that left a third of the fleet behind do not read the same on the
	// list. A host skipped by a policy, a window or a deadline is not an
	// issue: it was left out on purpose, with its reason, and the campaign
	// has always closed as completed over it.
	StateCompletedWithIssues State = "completed_with_issues"
	StateFailed              State = "failed"
	// StatePlanFailed is a planning phase that ended with no host to run
	// on: every plan was refused, failed or never computed. There is
	// nothing to approve and nothing a resume could start, so the campaign
	// ends here rather than standing paused with a reason.
	StatePlanFailed State = "plan_failed"
	// StateExpired is a campaign whose plans passed their time limit before
	// any host started - waiting for an approval or for its window. The
	// consent, given or not, concerned a diff a day old; the campaign is
	// ordered again rather than run on it.
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

// Launching says whether the campaign may start a host now: a campaign in
// its planning phase, its canary or its waves hands tasks to hosts, and so
// does a planned one - approved, or in need of no approval - whose first
// pass is about to name the phase; a host that came back from being
// offline may be planned again on that pass. The launch of a target checks
// this on the campaign row, under a lock, in the same transaction that
// creates the task: a pause or a cancel committed a moment earlier is
// seen, and the task is never created.
func (s State) Launching() bool {
	return s == StatePlanning || s == StatePlanned || s == StateCanary || s == StateRunning
}

// mayBecome says whether the orchestrator may move a campaign from this
// state to the given one. It is the state machine the orchestrator's
// writes are checked against after a lost race: a write that found the
// campaign moved re-reads it and asks this question again rather than
// repeating the old decision. A terminal state never moves; the operator's
// own transitions - approve, pause, resume, advance, cancel - have their
// own conditions in the store.
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
	// TargetDispatched marks a host whose task exists and has not started
	// on the agent's word: queued, leased, or handed over and not yet
	// acknowledged as started. It takes its slot and its tokens - the task
	// is in flight - but the host has changed nothing yet, and a host
	// standing in "running" for a minute with nothing running is what the
	// document calls a lost host.
	TargetDispatched TargetState = "dispatched"
	// TargetAwaitingLock marks a host whose agent holds the task and waits
	// for a resource of the host - another task's package transaction, a
	// unit restart under way. The blocker names what it waits on. Like a
	// dispatched host it holds its slot: the wait is on the host, not in
	// the queue.
	TargetAwaitingLock TargetState = "awaiting_lock"
	TargetRunning      TargetState = "running"
	TargetRebooting    TargetState = "rebooting"
	TargetVerifying    TargetState = "verifying"
	TargetSucceeded    TargetState = "succeeded"
	// TargetNoChange marks a host that already had the desired state: its
	// plan found nothing to do, or the host reported that it changed
	// nothing. A terminal success without a mutation - counted as a success
	// by the threshold and told apart in the report, because "the file was
	// written on forty hosts" and "the file was already there on forty
	// hosts" are two different nights.
	TargetNoChange TargetState = "no_change"
	TargetFailed   TargetState = "failed"
	// TargetUnknown marks a host whose task ended without a result: the
	// session broke while it ran, or the agent came back from a restart
	// with the operation half done. Unknown is not a success - the
	// threshold counts it as a failure - and it is not a failure of the
	// change either: what the host holds is a question to read off the
	// host, not to answer by running the change again.
	TargetUnknown  TargetState = "unknown"
	TargetSkipped  TargetState = "skipped"
	TargetCanceled TargetState = "canceled"
)

// Waiting says whether the host is ready to start but has not started yet.
//
// Waiting for a budget is the same place in the queue as pending: the host
// takes no slot and asks for capacity again on every pass. A host queued
// offline waits in the same place - for its connection rather than for a
// token. A host waiting for a lock is not here: its task is on the agent
// and holds the slot.
func (t TargetState) Waiting() bool {
	return t == TargetPending || t == TargetAwaitingBudget || t == TargetQueuedOffline
}

// UnderWay says whether the host is carrying a task of the change: from
// the dispatch of its task to the end of its verification. A planning host
// carries a task too, but a plan is a read, and a cancel closes it at once
// rather than waiting for it; the cancel waits for these.
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

// HoldsWave says whether the host keeps its wave open.
//
// A settled host does not. A host queued offline in a wave does not
// either: the wave's verdict comes from the hosts that ran, and the
// offline one gets its turn when it comes back - otherwise a single
// unplugged machine would hold the whole fleet until the deadline. The
// canary is the exception the document makes: an offline canary holds
// the barrier. The canary exists to say whether the change is safe, and
// a canary that never ran has said nothing; opening the waves over it
// would run the change on the fleet on the word of nobody. The barrier
// opens when the host comes back and runs, when the deadline closes the
// queue, or when an operator skips the host by name with a reason.
func (t Target) HoldsWave() bool {
	if t.State.Finished() {
		return false
	}
	return t.State != TargetQueuedOffline || t.Wave == 0
}

// mayBecome says whether a target may move from this state to the given
// one. A settled host never moves again - a late result is an observation,
// not a transition - and the transitions among the open states follow the
// course of a host: the queue, the task, the reboot, the verification. The
// list is the one the compare-and-swap write is checked against, so a
// concurrent writer that saw an older state cannot push the host where its
// course does not lead.
func (t TargetState) mayBecome(to TargetState) bool {
	if t.Finished() {
		return false
	}
	// The same state written again carries a new reason or message - a
	// host waiting for another budget than a moment ago - and is a change
	// of the row, not of the course.
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
	// RetriesCampaignID names the finished campaign whose failed hosts
	// this one runs again with the same order. Empty for a campaign that
	// is not a retry. The handler picks the hosts (RetryTargets) before
	// the order reaches the store.
	RetriesCampaignID string
	// PolicyID and PolicyVersion name the desired-state policy that
	// ordered the campaign as its remediation, and the version of the
	// document that judged the drift. Empty for a campaign an operator
	// ordered.
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
		// A retry is a decision about a campaign that went wrong, not the
		// same order twice: "the second go at last night's rollout" is
		// consented to as that. Absent from every other digest, so theirs
		// stay.
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
	// RetriesCampaignID and RetriesCampaignName name the campaign whose
	// failed hosts this one runs again; both empty for a campaign that is
	// not a retry. RetriedBy lists the campaigns ordered to retry this
	// one, oldest first, read from their link so this record never
	// changes when a retry is ordered.
	RetriesCampaignID   string         `json:"retries_campaign_id,omitempty"`
	RetriesCampaignName string         `json:"retries_campaign_name,omitempty"`
	RetriedBy           []CampaignLink `json:"retried_by,omitempty"`
	// Progress counts the hosts of the campaign by how they stand, for a
	// list that shows many campaigns at once. Absent from the single
	// record: the report carries the totals per state there.
	Progress *Progress `json:"progress,omitempty"`
	// ChangedHosts counts the hosts the campaign changed, by the rule
	// ChangedTargets reads them: the change landed, whatever came after.
	// It is the number a compensation would run on. Zero until the
	// campaign settles: a count of a campaign still changing hosts would
	// invite a rollback of a moving target, which the server refuses.
	ChangedHosts int `json:"changed_hosts"`
	// PolicyID and PolicyVersion link a remediation campaign back to the
	// desired-state policy that ordered it; both empty for a campaign an
	// operator ordered.
	PolicyID      string `json:"policy_id,omitempty"`
	PolicyVersion int    `json:"policy_version,omitempty"`
	// Revision grows with every change of the record. A write names the
	// revision it read, and a write against an older one fails: the
	// orchestrator reads the campaign again rather than acting on a stale
	// picture, and a client may send it back as If-Match.
	Revision int64 `json:"revision"`
	// The runner lease: which orchestrator drives the campaign, under
	// which token, until when. Read for the fencing of the orchestrator's
	// writes; not part of the record a client reads.
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
// Unknown is its own number and never folded into failed or succeeded: a
// host that ended without a result did not reach the desired state, as
// far as anyone knows, and did not fail the change either. Skipped covers
// every host that took no part - skipped, canceled, ineligible, excluded -
// and pending is every host not settled yet, under way included.
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
	// StateSince is when the target entered its current state. StartedAt
	// says when the host began the change; only the last transition says
	// when its reboot began, and the wait for the host is counted from
	// there. Absent from reads that do not need it.
	StateSince *time.Time `json:"state_since,omitempty"`
	// Blocker says what the host's task waits on while it has not started:
	// the resource lock and the task holding it, as the agent named them.
	// It follows the wait reason of the job (jobs.LockBlocker) and is
	// empty once the operation starts, or when the host waits on nothing
	// the panel knows of.
	Blocker string `json:"blocker,omitempty"`
	// Revision grows with every change of the row; a state is written
	// only against the revision the writer read.
	Revision int64 `json:"revision"`
	// ClaimedBy and ClaimToken say which runner holds the target and under
	// which token. The token fences every write to the row and the
	// target's budget lease: a runner that lost the target carries an old
	// token, and its writes touch nothing.
	ClaimedBy  string `json:"-"`
	ClaimToken int64  `json:"-"`
	// CancelRequestedAt is when a cancel found the host carrying its task.
	// The task stays with the host; the campaign waits for it to settle.
	CancelRequestedAt *time.Time `json:"cancel_requested_at,omitempty"`
	// CancelOutcome and CancelPhase are the agent's answer to the cancel
	// of the host's task, read off the job: what the request found on
	// the host and what the host was doing. Empty until the host answers.
	CancelOutcome string `json:"cancel_outcome,omitempty"`
	CancelPhase   string `json:"cancel_phase,omitempty"`
}

// Report summarises the course of a campaign.
type Report struct {
	CampaignID string `json:"campaign_id"`
	State      State  `json:"state"`
	// Totals counts the hosts per target state - succeeded, no_change,
	// failed, unknown, skipped, canceled, and the rest - the way the
	// document's terminal report does: a host in the desired state
	// without a mutation and one that ended with no result are each their
	// own number, never folded into a neighbour.
	Totals map[string]int `json:"totals"`
	Waves  []WaveSummary  `json:"waves"`
	// Failures lists the hosts the operator has to look at: the ones that
	// failed and the ones that ended unknown, each with its state.
	Failures []Target `json:"failures"`
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

// OutcomeUnknownCode is the error code the agent answers with when it comes
// back from a restart to find an operation it started and did not live to
// see the end of. The helper may have finished it; the agent neither
// repeats nor invents, and the host ends unknown.
const OutcomeUnknownCode = "outcome_unknown"

// CancelAckTimeoutCode is the error code of a host whose cancel request
// got no answer within the operation's timeout (jobs.CancelAckTimeoutCode).
// The host may have run the change to its end, cut it short or never
// started it; the panel does not know, and the host ends unknown - the
// document's unknown_needs_reconciliation - rather than failed, because
// nothing says the change failed.
const CancelAckTimeoutCode = "cancel_ack_timeout"

// SkippedByOperatorCode is the error code of a host an operator skipped
// by name: an offline canary the campaign was waiting for, let go with a
// reason so that the barrier opens. The host took no part; not a failure.
const SkippedByOperatorCode = "skipped_by_operator"

// ConnectivityLost says whether the host ended because its session broke
// while its task ran rather than because the change failed. Such a host
// ends unknown; the code is what tells it from an agent restart.
func (t Target) ConnectivityLost() bool {
	return t.State == TargetUnknown && t.ErrorCode == ConnectivityLostCode
}

// targetTally is what the stop rules and the final verdict read off the
// targets: how many are settled, how many of those ended well, how many
// failed - the unknown ones among them, because unknown is not a success -
// how many were left out, and how many failed because their session broke.
type targetTally struct {
	Total     int
	Finished  int
	Succeeded int
	// Failed counts the hosts that failed and the hosts that ended
	// unknown: the threshold is a bound on hosts that did not reach the
	// desired state, and an unknown host did not, as far as anyone knows.
	Failed  int
	Unknown int
	// Skipped counts the hosts left out by a deadline, a window or a
	// policy - not the ones ineligible or excluded, which never took part.
	Skipped int
	Lost    int
}

// tallyTargets counts the targets the way the stop rules read them. A
// host is a failure whatever step failed it: a canary whose units did not
// come up after the change is as much a failure as one whose change did
// not run, and the threshold that keeps the next wave from starting reads
// both the same way. A host that ended unknown is a failure to the
// threshold too - the document says unknown is not a success, and a
// threshold that ignored it would let a campaign roll on while every host
// stopped answering.
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
//
// Failed is a campaign in which nothing reached the desired state and
// something tried: every host that ran failed or ended unknown. Completed
// with issues is a campaign that got through - the threshold never fired -
// but not cleanly: hosts failed or ended unknown on the way, and the
// operator has hosts to look at. Completed is the rest, hosts skipped,
// ineligible or excluded included: those never took part - a skip is a
// decision with a reason, not a failure - and a campaign is not blemished
// by a host it did not run on.
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

// pauseState is the state a pause puts the campaign in: pausing while any
// host carries a task, paused once none does. The same rule the operator's
// pause and the machinery's pauses follow, and the rule the settling pass
// applies when the last host of a pausing campaign ends.
func pauseState(targets []Target) State {
	if cancelSettled(targets) {
		return StatePaused
	}
	return StatePausing
}

// plansExpired says whether the campaign's plans passed their time limit
// before any host started. A campaign that has started keeps going on the
// plans it has - every host still checks its own plan's age at dispatch
// and ends plan_stale on its own - because a campaign halfway through the
// fleet is not expired, it is late. One that has not started has nothing
// to be late for: the consent, given or not, concerns a diff a day old.
func plansExpired(oldestPlan time.Time, started *time.Time, now time.Time) bool {
	if started != nil || oldestPlan.IsZero() {
		return false
	}
	return now.Sub(oldestPlan) > PlanTTL
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
