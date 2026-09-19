package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Scheduled and recurring campaigns.

// handleListCampaignSchedules lists every schedule, the next to fire
// first.
func (s *Server) handleListCampaignSchedules(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign_schedule"); !ok {
		return
	}
	schedules, err := s.campaigns.ListSchedules(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": schedules, "count": len(schedules)})
}

// readScheduleSpec decodes and checks a schedule.
func (s *Server) readScheduleSpec(w http.ResponseWriter, r *http.Request) (*campaigns.CheckedSchedule, bool) {
	var spec campaigns.ScheduleSpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&spec); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return nil, false
	}
	spec.Reason = strings.TrimSpace(spec.Reason)
	if len([]rune(spec.Reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"a schedule needs a reason (field reason, min. 8 characters); it is carried into every order it places")
		return nil, false
	}
	checked, err := campaigns.CheckSchedule(spec, time.Now().UTC())
	var refusal campaigns.ScheduleError
	if errors.As(err, &refusal) {
		problem(w, http.StatusBadRequest, refusal.Code, refusal.Message)
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	var order createCampaignRequest
	if err := json.Unmarshal(checked.Spec.Order, &order); err != nil {
		problem(w, http.StatusBadRequest, "invalid_order", "the order does not read as a campaign order: "+err.Error())
		return nil, false
	}
	action := opspec.ActionType(order.Action)
	switch {
	case !action.Known() || !action.Mutating():
		problem(w, http.StatusBadRequest, "unknown_action", "a campaign requires an operation that changes host state")
		return nil, false
	case action.RequiresTargetConfirmation() && !opspec.PanelPlanned(action):
		problem(w, http.StatusBadRequest, "not_a_campaign_action",
			"this operation is irreversible and needs its target named; run it host by host")
		return nil, false
	case opspec.CampaignExclusionReason(action) != "":
		problem(w, http.StatusBadRequest, "not_a_campaign_action", opspec.CampaignExclusionReason(action))
		return nil, false
	case !opspec.ExecutableMode(action):
		problem(w, http.StatusBadRequest, "campaign_mode_unsupported", campaignModeRefusal(action))
		return nil, false
	}
	if strings.TrimSpace(order.Name) == "" {
		problem(w, http.StatusBadRequest, "invalid_order", "the order names no campaign (field name)")
		return nil, false
	}
	if _, ok := s.checkSelector(w, order.Selector); !ok {
		return nil, false
	}
	return checked, true
}

// scheduleDetail is what the trail keeps about a schedule on every write.
func scheduleDetail(schedule campaigns.Schedule) map[string]any {
	var order struct {
		Action string `json:"action"`
		Name   string `json:"name"`
	}
	_ = json.Unmarshal(schedule.Order, &order)
	return map[string]any{
		"name": schedule.Name, "action": order.Action, "campaign_name": order.Name,
		"start_at": schedule.StartAt, "recurrence": schedule.Recurrence, "timezone": schedule.Timezone,
		"next_run_at": schedule.NextRunAt, "enabled": schedule.Enabled, "reason": schedule.Reason,
	}
}

// handleCreateCampaignSchedule records a schedule under the caller's
// rights.
func (s *Server) handleCreateCampaignSchedule(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCampaignCreate, "campaign_schedule")
	if !ok {
		return
	}
	checked, ok := s.readScheduleSpec(w, r)
	if !ok {
		return
	}
	created, err := s.campaigns.CreateSchedule(r.Context(), *checked, principal.Subject)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign_schedule.create", TargetType: "campaign_schedule", TargetID: created.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: scheduleDetail(*created), After: scheduleDetail(*created),
	})
	writeJSON(w, http.StatusCreated, created)
}

// scheduleFor reads the schedule of the request under the permission.
// The answer has been written when the second result is false.
func (s *Server) scheduleFor(w http.ResponseWriter, r *http.Request, permission authz.Permission) (*campaigns.Schedule, authz.Principal, bool) {
	principal, ok := s.authorizeCollection(w, r, permission, "campaign_schedule")
	if !ok {
		return nil, principal, false
	}
	found, err := s.campaigns.GetSchedule(r.Context(), r.PathValue("id"))
	if errors.Is(err, campaigns.ErrScheduleNotFound) {
		problem(w, http.StatusNotFound, "schedule_not_found", "no such schedule")
		return nil, principal, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, principal, false
	}
	return found, principal, true
}

func (s *Server) handleGetCampaignSchedule(w http.ResponseWriter, r *http.Request) {
	found, _, ok := s.scheduleFor(w, r, authz.PermCampaignRead)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, found)
}

// handleUpdateCampaignSchedule rewrites a schedule.
func (s *Server) handleUpdateCampaignSchedule(w http.ResponseWriter, r *http.Request) {
	found, principal, ok := s.scheduleFor(w, r, authz.PermCampaignCreate)
	if !ok {
		return
	}
	checked, ok := s.readScheduleSpec(w, r)
	if !ok {
		return
	}
	updated, err := s.campaigns.UpdateSchedule(r.Context(), found.ID, *checked, principal.Subject)
	if errors.Is(err, campaigns.ErrScheduleNotFound) {
		problem(w, http.StatusNotFound, "schedule_not_found", "no such schedule")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign_schedule.update", TargetType: "campaign_schedule", TargetID: updated.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: scheduleDetail(*updated), Before: scheduleDetail(*found), After: scheduleDetail(*updated),
	})
	writeJSON(w, http.StatusOK, updated)
}

// handleDeleteCampaignSchedule removes a schedule; the campaigns it
// placed stay. The reason travels in the body or the query.
func (s *Server) handleDeleteCampaignSchedule(w http.ResponseWriter, r *http.Request) {
	found, principal, ok := s.scheduleFor(w, r, authz.PermCampaignCreate)
	if !ok {
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"removing a schedule needs a reason (field reason, min. 8 characters)")
		return
	}
	if err := s.campaigns.DeleteSchedule(r.Context(), found.ID); err != nil && !errors.Is(err, campaigns.ErrScheduleNotFound) {
		s.fail(w, err)
		return
	}
	detail := scheduleDetail(*found)
	detail["delete_reason"] = reason
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign_schedule.delete", TargetType: "campaign_schedule", TargetID: found.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: detail, Before: scheduleDetail(*found),
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleRunCampaignScheduleNow places the schedule's order at once, without
// moving its next moment: a rehearsal of the monthly window, or the window
// brought forward.
func (s *Server) handleRunCampaignScheduleNow(w http.ResponseWriter, r *http.Request) {
	found, principal, ok := s.scheduleFor(w, r, authz.PermCampaignCreate)
	if !ok {
		return
	}
	reason, ok := requestReason(w, r, nil)
	if !ok {
		return
	}
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) < minimalStepUpReason {
		problem(w, http.StatusBadRequest, "reason_required",
			"running a schedule now needs a reason (field reason, min. 8 characters)")
		return
	}
	campaign, err := s.OrderFromSchedule(r.Context(), *found, time.Now().UTC())
	var refusal campaigns.ScheduleRefusal
	if errors.As(err, &refusal) {
		_ = s.campaigns.RecordScheduleRun(r.Context(), found.ID, "", refusal.Error())
		problem(w, http.StatusConflict, refusal.Code, refusal.Detail)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.campaigns.RecordScheduleRun(r.Context(), found.ID, campaign.ID, ""); err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "campaign_schedule.run", TargetType: "campaign_schedule", TargetID: found.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": found.Name, "campaign_id": campaign.ID, "reason": reason, "on_demand": true},
	})
	writeJSON(w, http.StatusCreated, campaign)
}

// OrderFromSchedule places the order of a schedule through the door of the
// campaign API.
func (s *Server) OrderFromSchedule(ctx context.Context, schedule campaigns.Schedule, runAt time.Time) (*campaigns.Campaign, error) {
	if s.authz == nil {
		return nil, errors.New("no authorization store is configured")
	}
	author, err := s.authz.PrincipalBySubject(ctx, schedule.CreatedBy)
	if errors.Is(err, authz.ErrUnauthenticated) {
		s.recordScheduleRefusal(ctx, schedule, "author_unavailable", schedule.CreatedBy)
		return nil, campaigns.ScheduleRefusal{Code: "author_unavailable",
			Detail: "the schedule's author " + schedule.CreatedBy + " is disabled or gone; nothing is placed under their name"}
	}
	if err != nil {
		return nil, err
	}
	var request createCampaignRequest
	if err := json.Unmarshal(schedule.Order, &request); err != nil {
		s.recordScheduleRefusal(ctx, schedule, "invalid_order", err.Error())
		return nil, campaigns.ScheduleRefusal{Code: "invalid_order", Detail: "the stored order does not read: " + err.Error()}
	}
	// A recurring order names the moment in the campaign's name, so the list
	// tells October's window from November's; a single moment keeps the name as
	// written.
	if schedule.Recurrence != "" {
		request.Name = strings.TrimSpace(request.Name) + " " + runAt.In(schedule.Location()).Format("2006-01-02")
	}
	if strings.TrimSpace(request.Reason) == "" {
		request.Reason = schedule.Reason
	}
	// One moment places one order: a second pass over the same moment -
	// two panels, a retried tick - gets the campaign already placed.
	request.IdempotencyKey = fmt.Sprintf("schedule:%s:%d", schedule.ID, runAt.Unix())
	// A schedule places its order at a moment nobody is watching, so there is no
	// preview behind it.
	request.PreviewID, request.PreviewDigest = "", ""

	actor := *author
	actor.Subject = "schedule:" + schedule.ID
	actor.DisplayName = schedule.Name
	inner, err := http.NewRequestWithContext(authz.ContextWithPrincipal(ctx, actor),
		http.MethodPost, "/api/v1/campaigns", nil)
	if err != nil {
		return nil, err
	}
	inner.Header.Set("X-Request-Id", request.IdempotencyKey)

	answer := &caughtAnswer{header: http.Header{}}
	if _, ok := s.authorizeCollection(answer, inner, authz.PermCampaignCreate, "campaign"); ok {
		s.orderCampaign(answer, inner, request, "", true)
	}
	if answer.status >= http.StatusBadRequest {
		refusal := answer.refusal()
		s.recordScheduleRefusal(ctx, schedule, refusal.Code, refusal.Detail)
		return nil, refusal
	}
	var campaign campaigns.Campaign
	if err := json.Unmarshal(answer.body.Bytes(), &campaign); err != nil {
		return nil, fmt.Errorf("the door's answer does not read as a campaign: %w", err)
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "schedule:" + schedule.ID,
		Action: "campaign_schedule.run", TargetType: "campaign", TargetID: campaign.ID,
		RequestID: request.IdempotencyKey, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"schedule_name": schedule.Name, "author": schedule.CreatedBy, "run_at": runAt,
			"campaign_name": campaign.Name, "state": string(campaign.State), "recurrence": schedule.Recurrence,
		},
	})
	return &campaign, nil
}

// recordScheduleRefusal writes a refused moment on the trail: a schedule that
// places nothing is a change that did not happen, and the trail is to say why
// as much as it says what happened.
func (s *Server) recordScheduleRefusal(ctx context.Context, schedule campaigns.Schedule, code, detail string) {
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "schedule:" + schedule.ID,
		Action: "campaign_schedule.run", TargetType: "campaign_schedule", TargetID: schedule.ID,
		Outcome: audit.OutcomeDenied,
		Detail: map[string]any{
			"schedule_name": schedule.Name, "author": schedule.CreatedBy,
			"reason": code, "detail": detail,
		},
	})
}

// caughtAnswer is the door's answer caught in memory: the status, the headers
// it set and the body it wrote, so the same handler serves a request and a
// schedule.
type caughtAnswer struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (a *caughtAnswer) Header() http.Header { return a.header }

func (a *caughtAnswer) Write(data []byte) (int, error) {
	if a.status == 0 {
		a.status = http.StatusOK
	}
	return a.body.Write(data)
}

func (a *caughtAnswer) WriteHeader(status int) {
	if a.status == 0 {
		a.status = status
	}
}

// refusal reads the problem the door wrote. An answer that is not a
// problem document is still a refusal, named by its status.
func (a *caughtAnswer) refusal() campaigns.ScheduleRefusal {
	var document struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(a.body.Bytes(), &document); err != nil || document.Code == "" {
		return campaigns.ScheduleRefusal{Code: "refused", Detail: http.StatusText(a.status)}
	}
	return campaigns.ScheduleRefusal{Code: document.Code, Detail: document.Detail}
}

// The maintenance calendar.

// calendarEntry is one moment or window of the calendar, whatever its source:
// a host in maintenance, a campaign's window, a schedule's next moments.
type calendarEntry struct {
	// Kind is host_window, campaign_window or schedule.
	Kind string `json:"kind"`
	// ID names the host, the campaign or the schedule.
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	Start *time.Time `json:"start,omitempty"`
	End   *time.Time `json:"end,omitempty"`
	// State is the campaign's state; empty for the other kinds.
	State string `json:"state,omitempty"`
	// Reason is the host window's reason, or the schedule's.
	Reason string `json:"reason,omitempty"`
	// SetBy names who opened the host window.
	SetBy string `json:"set_by,omitempty"`
}

// The bounds of a calendar read: a year at most, so a range typed wrong does
// not draw every window ever recorded; and at most this many moments of one
// schedule, however dense its rule.
const (
	maxCalendarRange       = 366 * 24 * time.Hour
	maxScheduleOccurrences = 100
)

// handleMaintenanceCalendar lists, for a range, the maintenance windows of the
// hosts, the windows of the campaigns and the next moments of the schedules,
// in one list ordered by start.
func (s *Server) handleMaintenanceCalendar(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign_schedule")
	if !ok {
		return
	}
	query := r.URL.Query()
	from, err := time.Parse(time.RFC3339, strings.TrimSpace(query.Get("from")))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_range", "from must be an RFC 3339 timestamp")
		return
	}
	to, err := time.Parse(time.RFC3339, strings.TrimSpace(query.Get("to")))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_range", "to must be an RFC 3339 timestamp")
		return
	}
	if !to.After(from) || to.Sub(from) > maxCalendarRange {
		problem(w, http.StatusBadRequest, "invalid_range", "the range must end after it starts and span a year at most")
		return
	}
	from, to = from.UTC(), to.UTC()
	entries := []calendarEntry{}

	// The host windows: a window is drawn from the moment it was opened
	// to its end.
	rows, err := s.pool.Query(r.Context(), `
		select id, hostname, site, environment, maintenance_until, coalesce(maintenance_reason, ''),
		       coalesce(maintenance_by, ''), maintenance_at
		  from hosts
		 where maintenance_until is not null and maintenance_until >= $1
		   and coalesce(maintenance_at, maintenance_until) < $2
		 order by coalesce(maintenance_at, maintenance_until)`, from, to)
	if err != nil {
		s.fail(w, err)
		return
	}
	for rows.Next() {
		var entry calendarEntry
		var site, environment string
		var until time.Time
		var openedAt *time.Time
		if err := rows.Scan(&entry.ID, &entry.Name, &site, &environment, &until, &entry.Reason, &entry.SetBy, &openedAt); err != nil {
			rows.Close()
			s.fail(w, err)
			return
		}
		if !principal.Can(authz.PermHostRead, authz.Scope{Site: site, Environment: environment}) {
			continue
		}
		entry.Kind = "host_window"
		entry.Start = openedAt
		entry.End = &until
		entries = append(entries, entry)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fail(w, err)
		return
	}

	windows, err := s.campaigns.CampaignWindows(r.Context(), from, to, campaignScopes(principal))
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, window := range windows {
		entries = append(entries, calendarEntry{
			Kind: "campaign_window", ID: window.ID, Name: window.Name,
			Start: window.Start, End: window.End, State: string(window.State),
		})
	}

	schedules, err := s.campaigns.ListSchedules(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, schedule := range schedules {
		for _, moment := range schedule.Occurrences(from, to, maxScheduleOccurrences) {
			at := moment
			entries = append(entries, calendarEntry{
				Kind: "schedule", ID: schedule.ID, Name: schedule.Name, Start: &at, Reason: schedule.Reason,
			})
		}
	}
	sortCalendar(entries)
	writeJSON(w, http.StatusOK, map[string]any{
		"items": entries, "count": len(entries), "from": from, "to": to,
	})
}

// sortCalendar orders the entries by start, an entry without a start by its
// end; a stable order so two windows opening together keep the order their
// sources gave.
func sortCalendar(entries []calendarEntry) {
	moment := func(entry calendarEntry) time.Time {
		if entry.Start != nil {
			return *entry.Start
		}
		if entry.End != nil {
			return *entry.End
		}
		return time.Time{}
	}
	sort.SliceStable(entries, func(i, j int) bool { return moment(entries[i]).Before(moment(entries[j])) })
}
