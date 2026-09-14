package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// A diagnostic read fan-out.
//
// A fan-out is the same read the operator orders on one host, ordered on a
// handful at once: the process list of the web tier, the journal of every
// host in a site, a security scan of the environment. It is not a campaign
// - it changes nothing, needs no approval and has no waves - and it is not
// a new kind of job either: one ordinary job per host carries the result,
// and the fan-out is a row that groups them and a view that merges what
// they brought back.
//
// What bounds it is the control plane, not the hosts: every host answers
// with its own output, and the panel holds and merges all of them at once.
// Hence the ceilings - per operation, from the registry; per operator and
// in total, for the fan-outs in flight; and the fleet's read budget, when
// the installation describes one.

// createReadRequest is a fan-out order.
type createReadRequest struct {
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
	// Selector names the hosts the way a campaign does: the flat filters,
	// an explicit list, or the typed expression, which decides alone when
	// present. An empty selector is refused: a read of the whole fleet is
	// never the intent, and the document says as much.
	Selector campaigns.Selector `json:"selector"`
	// Reason goes to the audit log next to the order.
	Reason string `json:"reason,omitempty"`
}

// The ceilings of fan-outs in flight. A fan-out is in flight while any of
// its jobs has not finished; the per-operator ceiling keeps one screen from
// taking the whole allowance, the total keeps the panel from merging more
// output than it should hold at once.
const (
	maxFanOutsPerOperator = 5
	maxFanOutsInFlight    = 20
	// fanOutTTL bounds how long a fan-out job waits for its host. A read
	// is asked for now: a host that comes back in a quarter of an hour
	// answers a question nobody is looking at any more.
	fanOutTTL = 5 * time.Minute
	// maxReadsListed is the page of the operator's fan-out list.
	maxReadsListed = 50
)

// readFanOut is the stored row of a fan-out.
type readFanOut struct {
	ID        string          `json:"id"`
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload"`
	CreatedBy string          `json:"created_by"`
	Reason    string          `json:"reason,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	HostCount int             `json:"host_count"`
	// Counts is the picture of the hosts by state, for the list. The
	// states are the job states folded into four: what waits, what runs,
	// what came back and what did not.
	Counts fanOutCounts `json:"counts"`
}

// fanOutCounts folds the job states into the four the status bar shows.
type fanOutCounts struct {
	Queued    int `json:"queued"`
	Running   int `json:"running"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

// add counts one job under the fold its state belongs to.
func (c *fanOutCounts) add(state jobs.State) {
	switch state {
	case jobs.StateSucceeded:
		c.Succeeded++
	case jobs.StateFailed, jobs.StateTimedOut, jobs.StateCanceled, jobs.StateExpired:
		c.Failed++
	case jobs.StateLeased, jobs.StateDispatched, jobs.StateRunning:
		c.Running++
	default:
		c.Queued++
	}
}

// fanOutHost is one host of the fan-out: its job, and what the job brought
// back.
type fanOutHost struct {
	JobID    string `json:"job_id"`
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	State    string `json:"state"`
	// ErrorCode and Message are the result of a job that did not succeed:
	// a host that refused the read says why, next to the ones that
	// answered.
	ErrorCode  string     `json:"error_code,omitempty"`
	Message    string     `json:"message,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	// Truncated says the host cut its output to the limit of the job.
	Truncated bool `json:"truncated,omitempty"`
	// Lines is the output of a line read, as the host gave it; the merged
	// timeline is built from these.
	Lines []string `json:"lines,omitempty"`
	// Detail is the typed result of a structured read, as the job stored
	// it; Snapshot is the state the read refreshed in the inventory, for
	// the reads whose answer lands there rather than in the job - a
	// process snapshot, a security scan, a unit list.
	Detail   json.RawMessage `json:"detail,omitempty"`
	Snapshot json.RawMessage `json:"snapshot,omitempty"`
}

// timelineLine is one line of the merged timeline: what a host said and,
// when the line carries one, at what moment.
type timelineLine struct {
	HostID   string     `json:"host_id"`
	Hostname string     `json:"hostname"`
	At       *time.Time `json:"at,omitempty"`
	Line     string     `json:"line"`
}

// untimedLines are the lines of one host that carry no timestamp. They
// cannot be placed on the merged timeline, so they stand grouped by host
// under it rather than vanish.
type untimedLines struct {
	HostID   string   `json:"host_id"`
	Hostname string   `json:"hostname"`
	Lines    []string `json:"lines"`
}

// fanOutView is the fan-out with its hosts and the merged result.
type fanOutView struct {
	readFanOut
	// Kind says how the result merges: "timeline" for line reads, whose
	// lines are sorted into one sequence by their timestamps, and
	// "structured" for reads that answer with a typed result per host.
	Kind  string       `json:"kind"`
	Hosts []fanOutHost `json:"hosts"`
	// Timeline and Untimed are set for a line read: the lines with a
	// timestamp in one order, and those without, grouped by host.
	Timeline []timelineLine `json:"timeline,omitempty"`
	Untimed  []untimedLines `json:"untimed,omitempty"`
	// Skipped names the matched hosts that got no job, with the reason:
	// a quarantined host, a host without the adapter. Filled on creation
	// only - the row does not keep them, and the operator reads them from
	// the answer to the order.
	Skipped []skippedHost `json:"skipped,omitempty"`
}

// skippedHost is a matched host the fan-out did not reach.
type skippedHost struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Reason   string `json:"reason"`
	Message  string `json:"message"`
}

// handleCreateRead orders a diagnostic read on many hosts at once.
func (s *Server) handleCreateRead(w http.ResponseWriter, r *http.Request) {
	// Whoever asks must be somebody who may order operations somewhere,
	// before the selector is read: what the selector matches is a fact
	// about the fleet. Every host is checked again below, in its own
	// scope.
	principal, ok := s.authorizeCollection(w, r, authz.PermJobCreate, "read")
	if !ok {
		return
	}
	var request createReadRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}

	action := opspec.ActionType(request.Action)
	if !action.Known() {
		problem(w, http.StatusBadRequest, "unknown_action",
			"unknown operation type; allowed: "+joinFanOutActions())
		return
	}
	// A fan-out is for reads, and for the reads the registry opens to it.
	// A mutation on many hosts is a campaign, with the approval and the
	// waves a campaign has; a refusal here names that.
	if reason := opspec.FanOutRefusal(action); reason != "" {
		problem(w, http.StatusBadRequest, "not_a_fanout_action", reason)
		return
	}
	limit := action.FanOutLimit()

	// The ceiling is checked on the order before any host is resolved: a
	// list of a hundred identifiers is refused as a list, without a
	// hundred host reads to find out.
	if len(request.Selector.HostIDs) > limit {
		problem(w, http.StatusBadRequest, "fanout_too_broad",
			fmt.Sprintf("%s fans out to at most %d hosts; the order names %d",
				action, limit, len(request.Selector.HostIDs)))
		return
	}
	// A read of the whole fleet is never the intent: the filters and the
	// query are explicit, or there is no order.
	if request.Selector.Empty() {
		problem(w, http.StatusBadRequest, "selector_required",
			"a fan-out needs a selector: a site, an environment, a host list or an expression")
		return
	}

	var payload opspec.Payload
	if len(request.Payload) > 0 {
		if err := json.Unmarshal(request.Payload, &payload); err != nil {
			problem(w, http.StatusBadRequest, "invalid_payload", "the payload is not valid JSON")
			return
		}
	}
	if err := opspec.Validate(action, payload); err != nil {
		problem(w, http.StatusBadRequest, "invalid_payload", err.Error())
		return
	}

	chosen, ok := s.checkSelector(w, request.Selector)
	if !ok {
		return
	}
	candidates, ok := s.materialize(w, r, chosen)
	if !ok {
		return
	}
	if len(candidates) == 0 {
		problem(w, http.StatusBadRequest, "no_targets", "the selector matched no hosts")
		return
	}
	if len(candidates) > limit {
		problem(w, http.StatusBadRequest, "fanout_too_broad",
			fmt.Sprintf("%s fans out to at most %d hosts; the selector matched %d - narrow it",
				action, limit, len(candidates)))
		return
	}

	// The permission is checked for every matched host. A fan-out covering
	// one host outside the scope must not pass because the rest is inside.
	for _, host := range candidates {
		scope := authz.Scope{Site: host.Site, Environment: host.Environment}
		if _, ok := s.authorize(w, r, authz.PermJobCreate, scope, "host", host.ID); !ok {
			return
		}
		if _, ok := s.authorize(w, r, authz.Permission(action.Permission()), scope, "host", host.ID); !ok {
			return
		}
	}

	// The same qualification a campaign runs, minus the conflicts: a read
	// takes no lock, so another operation under way on the host is not an
	// obstacle. A quarantined host and a host without the adapter get no
	// job and are named in the answer; an offline host gets one and the
	// time limit settles it.
	kept, excluded := excludeHosts(candidates, chosen, principal.Subject)
	assessment := assessCandidates(kept, action, nil, time.Now().UTC())
	assessment.Closed = append(assessment.Closed, excluded...)
	if len(assessment.Ready) == 0 {
		problem(w, http.StatusBadRequest, "no_eligible_targets",
			"no matched host can run this read: "+describeExclusions(assessment.Exclusions()))
		return
	}
	skipped := make([]skippedHost, 0, len(assessment.Closed))
	for _, closed := range assessment.Closed {
		skipped = append(skipped, skippedHost{
			HostID: closed.Host.ID, Hostname: closed.Host.Hostname,
			Reason: closed.Reason, Message: closed.Message,
		})
	}

	// The fan-outs in flight: per operator, then in total. Refused with
	// the code the panel reads as "wait", not as "wrong".
	mine, total, err := s.fanOutsInFlight(r.Context(), principal.Subject)
	if err != nil {
		s.fail(w, err)
		return
	}
	if mine >= maxFanOutsPerOperator {
		problem(w, http.StatusTooManyRequests, "fanout_busy",
			fmt.Sprintf("you have %d fan-outs in flight, the most one operator runs at once; wait for one to finish", mine))
		return
	}
	if total >= maxFanOutsInFlight {
		problem(w, http.StatusTooManyRequests, "fanout_busy",
			fmt.Sprintf("%d fan-outs are in flight across the panel, the most it merges at once; wait for one to finish", total))
		return
	}

	fanOutID := uuid.NewString()
	owner := fanOutOwner(fanOutID)

	// The fleet's read budget, when the installation describes one: a
	// fan-out of twenty hosts is twenty reads at once, and it asks for
	// them the way one interactive operator does. A refusal is the same
	// answer as a full allowance - wait - with the budget named.
	if s.budgets != nil {
		refusal, err := s.budgets.Acquire(r.Context(), owner, "reads:"+principal.Subject,
			budgets.ClassInteractive, []budgets.Need{{Key: budgets.KeyGlobalReads, Weight: len(assessment.Ready)}})
		if err != nil {
			s.fail(w, err)
			return
		}
		if !refusal.Empty() {
			problem(w, http.StatusTooManyRequests, "fanout_busy",
				"the fleet's read budget has no room for this fan-out; "+refusal.Describe())
			return
		}
	}

	tx, err := s.jobs.Pool().Begin(r.Context())
	if err != nil {
		s.releaseFanOut(r.Context(), owner)
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	stored := readFanOut{
		ID: fanOutID, Action: string(action), Payload: payloadJSON(request.Payload),
		CreatedBy: principal.Subject, Reason: strings.TrimSpace(request.Reason),
		HostCount: len(assessment.Ready),
	}
	if err := tx.QueryRow(r.Context(), `
		insert into read_fanouts (id, action, payload, created_by, reason, host_count)
		values ($1, $2, $3, $4, $5, $6)
		returning created_at`,
		stored.ID, stored.Action, []byte(stored.Payload), stored.CreatedBy, stored.Reason,
		stored.HostCount).Scan(&stored.CreatedAt); err != nil {
		s.releaseFanOut(r.Context(), owner)
		s.fail(w, err)
		return
	}

	// One ordinary job per host. A read needs no approval, so every job
	// starts queued; the precondition binds it to the host's family and
	// adapter the way a single order does.
	created := make([]jobs.Job, 0, len(assessment.Ready))
	for _, host := range assessment.Ready {
		job, err := s.jobs.Create(r.Context(), tx, jobs.Spec{
			HostID:    host.ID,
			Action:    action,
			Payload:   payload,
			TTL:       fanOutTTL,
			CreatedBy: principal.Subject,
			RequestID: requestIDOf(r),
			FanoutID:  fanOutID,
			Preconditions: jobs.Preconditions{
				OSFamily:             host.OSFamily,
				RequiredCapabilities: []string{action.RequiredCapability()},
			},
		})
		if err != nil {
			s.releaseFanOut(r.Context(), owner)
			problem(w, http.StatusBadRequest, "invalid_operation", err.Error())
			return
		}
		created = append(created, *job)
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "read.fanout", TargetType: "read", TargetID: fanOutID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"action_type": string(action), "reason": stored.Reason,
			"hosts": len(created), "matched": len(candidates),
			"skipped":  assessment.Exclusions(),
			"selector": describeSelector(chosen),
		},
	}); err != nil {
		s.releaseFanOut(r.Context(), owner)
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.releaseFanOut(r.Context(), owner)
		s.fail(w, err)
		return
	}

	view := s.projectFanOut(r.Context(), stored, created)
	view.Skipped = skipped
	writeJSON(w, http.StatusCreated, view)
}

// handleListReads lists the operator's own fan-outs, newest first, with
// the picture of their hosts by state.
func (s *Server) handleListReads(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermJobRead, "read")
	if !ok {
		return
	}
	rows, err := s.pool.Query(r.Context(), `
		select f.id::text, f.action, f.payload, f.created_by, f.reason, f.created_at, f.host_count,
		       coalesce(array_agg(j.state) filter (where j.id is not null), '{}'::text[])
		  from read_fanouts f
		  left join jobs j on j.fanout_id = f.id
		 where f.created_by = $1
		 group by f.id
		 order by f.created_at desc, f.id desc
		 limit $2`, principal.Subject, maxReadsListed)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer rows.Close()
	items := make([]readFanOut, 0)
	for rows.Next() {
		var item readFanOut
		var states []string
		if err := rows.Scan(&item.ID, &item.Action, &item.Payload, &item.CreatedBy, &item.Reason,
			&item.CreatedAt, &item.HostCount, &states); err != nil {
			s.fail(w, err)
			return
		}
		for _, state := range states {
			item.Counts.add(jobs.State(state))
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// handleGetRead returns a fan-out with its hosts and the merged result.
//
// The hosts shown are the ones in the scopes the caller may read jobs in:
// a fan-out is a group of jobs, and it inherits their visibility rather
// than granting its own.
func (s *Server) handleGetRead(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermJobRead, "read")
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		problem(w, http.StatusNotFound, "read_not_found", "no such fan-out")
		return
	}
	var stored readFanOut
	err := s.pool.QueryRow(r.Context(), `
		select id::text, action, payload, created_by, reason, created_at, host_count
		  from read_fanouts where id = $1`, id).Scan(&stored.ID, &stored.Action, &stored.Payload,
		&stored.CreatedBy, &stored.Reason, &stored.CreatedAt, &stored.HostCount)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "read_not_found", "no such fan-out")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	filter := jobs.ListFilter{FanoutID: stored.ID, Limit: 500}
	for _, scope := range principal.ScopesFor(authz.PermJobRead) {
		filter.Scopes = append(filter.Scopes, jobs.Scope{Site: scope.Site, Environment: scope.Environment})
	}
	listed, err := s.jobs.List(r.Context(), filter)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.projectFanOut(r.Context(), stored, listed))
}

// projectFanOut projects the fan-out from its jobs: the state of every host,
// what each brought back, and the merge.
//
// The result is a projection, never state of its own: the jobs and their
// attempts are the record, and the screen does not reconstruct anything
// the database does not hold.
func (s *Server) projectFanOut(ctx context.Context, stored readFanOut, listed []jobs.Job) fanOutView {
	action := opspec.ActionType(stored.Action)
	view := fanOutView{readFanOut: stored, Kind: fanOutKind(action), Hosts: make([]fanOutHost, 0, len(listed))}
	// The hosts stand in name order: the list comes newest first, which
	// for jobs created in one transaction is no order at all.
	sort.SliceStable(listed, func(i, j int) bool {
		if listed[i].Hostname != listed[j].Hostname {
			return listed[i].Hostname < listed[j].Hostname
		}
		return listed[i].HostID < listed[j].HostID
	})

	// The reads whose answer lands in the inventory rather than in the job
	// are read from there, once for all hosts.
	module := resultModule(action)
	var fragments map[string][]inventoryFragment
	if module != "" {
		fragments = s.moduleFragments(ctx, listed, module)
	}
	// A package list lands in its own table, and is thousands of rows per
	// host: the fan-out carries its summary - how many packages, the
	// digest, when - and the vulnerability page reads the rows.
	if action == opspec.ActionPackageList {
		fragments = s.packageStates(ctx, listed)
	}

	finished := true
	for _, job := range listed {
		host := fanOutHost{
			JobID: job.ID, HostID: job.HostID, Hostname: job.Hostname, State: string(job.State),
			ErrorCode: job.ResultErrorCode, Message: job.ResultMessage, FinishedAt: job.FinishedAt,
		}
		view.Counts.add(job.State)
		if !job.State.Terminal() {
			finished = false
		}
		if job.State == jobs.StateSucceeded {
			if attempt := s.lastAttempt(ctx, job.ID); attempt != nil {
				host.Truncated = attempt.OutputTruncated
				host.Detail = attempt.Detail
				if view.Kind == "timeline" {
					host.Lines = resultLines(action, attempt)
				}
			}
			if fragment := fragments[job.HostID]; len(fragment) > 0 {
				// A snapshot older than the job is the last cycle's, not
				// this read's answer: it stays out rather than pass for one.
				if latest := fragment[0]; !latest.ObservedAt.Before(job.CreatedAt) {
					host.Snapshot = latest.Payload
				}
			}
		}
		view.Hosts = append(view.Hosts, host)
	}
	if view.Kind == "timeline" {
		view.Timeline, view.Untimed = mergeTimeline(view.Hosts, stored.CreatedAt)
	}
	// A finished fan-out gives its read tokens back. The lease would
	// expire on its own; giving it back at once is what keeps the next
	// fan-out from waiting for capacity nobody uses.
	if finished && len(listed) > 0 {
		s.releaseFanOut(ctx, fanOutOwner(stored.ID))
	}
	return view
}

// inventoryFragment is the part of an inventory module the merge reads.
type inventoryFragment struct {
	Payload    json.RawMessage
	ObservedAt time.Time
}

// moduleFragments reads one inventory module of every host of the fan-out.
func (s *Server) moduleFragments(ctx context.Context, listed []jobs.Job, module string) map[string][]inventoryFragment {
	result := map[string][]inventoryFragment{}
	if s.inventory == nil {
		return result
	}
	hostIDs := make([]string, 0, len(listed))
	for _, job := range listed {
		hostIDs = append(hostIDs, job.HostID)
	}
	fragments, err := s.inventory.HostFragments(ctx, hostIDs)
	if err != nil {
		s.log.Debug("the inventory of a fan-out was not read", "module", module, "err", err)
		return result
	}
	for hostID, list := range fragments {
		for _, fragment := range list {
			if fragment.Module == module {
				result[hostID] = append(result[hostID],
					inventoryFragment{Payload: fragment.Payload, ObservedAt: fragment.ObservedAt})
			}
		}
	}
	return result
}

// packageStates reads the state of the package list of every host, shaped
// like an inventory fragment so the merge reads it the same way.
func (s *Server) packageStates(ctx context.Context, listed []jobs.Job) map[string][]inventoryFragment {
	result := map[string][]inventoryFragment{}
	if s.hostPackages == nil {
		return result
	}
	hostIDs := make([]string, 0, len(listed))
	for _, job := range listed {
		hostIDs = append(hostIDs, job.HostID)
	}
	states, err := s.hostPackages.States(ctx, hostIDs)
	if err != nil {
		s.log.Debug("the package lists of a fan-out were not read", "err", err)
		return result
	}
	for hostID, state := range states {
		if state.CollectedAt == nil {
			continue
		}
		encoded, err := json.Marshal(state)
		if err != nil {
			continue
		}
		result[hostID] = append(result[hostID],
			inventoryFragment{Payload: encoded, ObservedAt: *state.CollectedAt})
	}
	return result
}

// lastAttempt returns the newest attempt of a job, or nil when there is
// none or it could not be read - a host without an answer is shown as one.
func (s *Server) lastAttempt(ctx context.Context, jobID string) *jobs.Attempt {
	attempts, err := s.jobs.Attempts(ctx, jobID)
	if err != nil || len(attempts) == 0 {
		return nil
	}
	return &attempts[len(attempts)-1]
}

// fanOutsInFlight counts the fan-outs with a job that has not finished:
// the operator's own, and everybody's.
func (s *Server) fanOutsInFlight(ctx context.Context, subject string) (mine, total int, err error) {
	err = s.pool.QueryRow(ctx, `
		select count(distinct f.id) filter (where f.created_by = $1), count(distinct f.id)
		  from read_fanouts f
		  join jobs j on j.fanout_id = f.id
		 where j.state in ('planned', 'awaiting_approval', 'queued', 'leased', 'dispatched', 'running')`,
		subject).Scan(&mine, &total)
	return mine, total, err
}

// fanOutOwner is the budget owner of a fan-out.
func fanOutOwner(id string) string { return "fanout:" + id }

// releaseFanOut gives the fan-out's read tokens back. A failure to release
// is logged and not answered: the lease expires by itself anyway.
func (s *Server) releaseFanOut(ctx context.Context, owner string) {
	if s.budgets == nil {
		return
	}
	if err := s.budgets.Release(ctx, owner); err != nil {
		s.log.Error("the read budget of a fan-out was not released", "owner", owner, "err", err)
	}
}

// fanOutKind says how the result of an operation merges: line reads into
// one timeline, everything else side by side.
func fanOutKind(action opspec.ActionType) string {
	switch action {
	case opspec.ActionReadJournal, opspec.ActionReadLogFile, opspec.ActionDockerLogs, opspec.ActionFileRead:
		return "timeline"
	}
	return "structured"
}

// resultModule names the inventory module a read refreshes, for the reads
// whose answer lands there rather than in the job. Empty means the job
// carries the answer.
func resultModule(action opspec.ActionType) string {
	switch action {
	case opspec.ActionProcessList:
		return "processes"
	case opspec.ActionSecurityScan:
		return "security"
	case opspec.ActionUnitStatus:
		return "services.full"
	case opspec.ActionDockerRead:
		return "containers.full"
	}
	return ""
}

// resultLines takes the lines of a line read out of its attempt: the
// journal comes back as text on the standard output, a log file and a
// container log as a list in the typed result, a file as its content.
func resultLines(action opspec.ActionType, attempt *jobs.Attempt) []string {
	if action == opspec.ActionReadJournal {
		return splitLines(attempt.Stdout)
	}
	var detail struct {
		Lines   []string `json:"lines"`
		Content string   `json:"content"`
	}
	if len(attempt.Detail) > 0 {
		_ = json.Unmarshal(attempt.Detail, &detail)
	}
	if detail.Lines != nil {
		return detail.Lines
	}
	if detail.Content != "" {
		return splitLines(detail.Content)
	}
	return splitLines(attempt.Stdout)
}

// splitLines cuts text into lines, without the empty last one a trailing
// newline would make.
func splitLines(text string) []string {
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// mergeTimeline sorts the lines of every host into one sequence by their
// timestamps. The order between hosts is best-effort - clocks differ - and
// the order within a host is kept as the host gave it. A line without a
// timestamp cannot be placed and stays with its host, under the timeline.
func mergeTimeline(hosts []fanOutHost, ordered time.Time) ([]timelineLine, []untimedLines) {
	type placed struct {
		line     timelineLine
		host     int
		sequence int
	}
	var timed []placed
	var untimed []untimedLines
	for index, host := range hosts {
		var loose []string
		for sequence, line := range host.Lines {
			at, ok := lineTimestamp(line, ordered)
			if !ok {
				loose = append(loose, line)
				continue
			}
			moment := at
			timed = append(timed, placed{
				line: timelineLine{HostID: host.HostID, Hostname: host.Hostname, At: &moment, Line: line},
				host: index, sequence: sequence,
			})
		}
		if len(loose) > 0 {
			untimed = append(untimed, untimedLines{HostID: host.HostID, Hostname: host.Hostname, Lines: loose})
		}
	}
	sort.SliceStable(timed, func(i, j int) bool {
		if !timed[i].line.At.Equal(*timed[j].line.At) {
			return timed[i].line.At.Before(*timed[j].line.At)
		}
		if timed[i].host != timed[j].host {
			return timed[i].host < timed[j].host
		}
		return timed[i].sequence < timed[j].sequence
	})
	timeline := make([]timelineLine, 0, len(timed))
	for _, entry := range timed {
		timeline = append(timeline, entry.line)
	}
	return timeline, untimed
}

// The timestamp layouts a log line may start with: journalctl's short-iso,
// RFC 3339 with or without fractions, a plain date and time, and the
// classic syslog stamp, which carries no year.
var isoLayouts = []string{
	"2006-01-02T15:04:05-0700",
	"2006-01-02T15:04:05.000000-0700",
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
}

var dateTimeLayouts = []string{
	"2006-01-02 15:04:05.000000",
	"2006-01-02 15:04:05",
}

// lineTimestamp reads the moment a log line starts with. A line that
// starts with anything else carries no timestamp the merge can use.
func lineTimestamp(line string, ordered time.Time) (time.Time, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return time.Time{}, false
	}
	for _, layout := range isoLayouts {
		if at, err := time.Parse(layout, fields[0]); err == nil {
			return at, true
		}
	}
	if len(fields) >= 2 {
		for _, layout := range dateTimeLayouts {
			if at, err := time.Parse(layout, fields[0]+" "+fields[1]); err == nil {
				return at, true
			}
		}
	}
	// The classic syslog stamp names no year; the year of the order is
	// the only one a read of the last lines can mean.
	if len(fields) >= 3 {
		stamp := fields[0] + " " + fields[1] + " " + fields[2]
		if at, err := time.Parse("Jan 2 15:04:05", stamp); err == nil {
			return at.AddDate(ordered.Year(), 0, 0), true
		}
	}
	return time.Time{}, false
}

// payloadJSON keeps the payload as given, or an empty object for an order
// without one: the column holds an object, and the screen re-reads it to
// order the same again.
func payloadJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	return raw
}

// describeSelector renders the selector for the audit trail.
func describeSelector(chosen campaigns.Selector) map[string]any {
	described := map[string]any{}
	if chosen.Site != "" {
		described["site"] = chosen.Site
	}
	if chosen.Environment != "" {
		described["environment"] = chosen.Environment
	}
	if chosen.OSFamily != "" {
		described["os_family"] = chosen.OSFamily
	}
	if len(chosen.HostIDs) > 0 {
		described["host_ids"] = chosen.HostIDs
	}
	if chosen.Expression != nil {
		described["expression"] = chosen.Expression.Describe()
	}
	if len(chosen.Exclude) > 0 {
		described["exclude"] = chosen.Exclude
	}
	return described
}

// joinFanOutActions lists the operations that fan out, for a refusal.
func joinFanOutActions() string {
	names := make([]string, 0)
	for _, action := range opspec.AllActions() {
		if action.FanOutLimit() > 0 {
			names = append(names, string(action))
		}
	}
	return strings.Join(names, ", ")
}
