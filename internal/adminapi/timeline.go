package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
)

// The host timeline: what happened to one host, newest first, from every
// record the panel keeps about it.
//
// The tasks, the audit trail, the sessions, the campaigns and the alerts
// each have their own screen, and an operator looking at a host that
// misbehaves since Tuesday has to open five of them and line the times up
// by hand. The timeline lines them up in the database: one query over the
// sources, each row cut to the same shape, ordered by time. Nothing here
// is derived or guessed - every row is one record of one table, and its
// reference points back at it.

// TimelineItem is one event in the history of a host.
type TimelineItem struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
	// ID tells two rows of the same kind and the same moment apart; it is
	// part of the page key and carries no other meaning.
	ID    string `json:"id"`
	Title string `json:"title"`
	// Event is the moment of the record the row stands for: a task is
	// created and finished, a session opened and ended, an alert fired
	// and resolved. Empty for records that are one moment.
	Event     string `json:"event,omitempty"`
	Detail    string `json:"detail,omitempty"`
	State     string `json:"state,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Ref       Ref    `json:"ref"`
}

// Ref names the record a timeline row comes from.
type Ref struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// timelineSource is one table folded into the timeline. Every source
// selects the same columns in the same order, so the union needs no
// per-source handling: at, kind, id, title, event, detail, state,
// error_code, actor, ref_type, ref_id. The host is $1 in every query,
// always read as a uuid: the trail keys its target by text, and a
// parameter read as two types in one statement is a parse error.
type timelineSource struct {
	kind string
	// permission is what the caller needs in the host's scope to see the
	// rows of this source; the timeline is honest about what it left out.
	permission authz.Permission
	query      string
}

// lifecycleActions are the audit actions that change what the host is to
// the fleet. They come from the trail like every other audit event, but
// the timeline shows them as their own kind: a quarantine is not one more
// line among the tag edits.
const lifecycleActions = "('host.quarantine', 'host.quarantine.release', 'host.decommission')"

var timelineSources = []timelineSource{
	{kind: "job", permission: authz.PermJobRead, query: `
		select j.created_at as at, 'job'::text as kind, j.id::text || ':created' as id,
		       j.action_type as title, 'created'::text as event, ''::text as detail,
		       case when j.finished_at is null then j.state else ''::text end as state,
		       ''::text as error_code, j.created_by as actor,
		       'job'::text as ref_type, j.id::text as ref_id
		from jobs j where j.host_id = $1::uuid
		union all
		select j.finished_at, 'job', j.id::text || ':finished',
		       j.action_type, 'finished', coalesce(j.result_message, ''),
		       j.state, coalesce(j.result_error_code, ''), j.created_by,
		       'job', j.id::text
		from jobs j where j.host_id = $1::uuid and j.finished_at is not null`},
	{kind: "audit", permission: authz.PermAuditRead, query: `
		select a.occurred_at, 'audit', a.id::text,
		       a.action, '', coalesce(a.detail->>'reason', ''),
		       a.outcome, '', a.actor_id,
		       'audit', a.id::text
		from audit_events a
		where a.target_type = 'host' and a.target_id = $1::uuid::text
		  and a.action not in ` + lifecycleActions},
	{kind: "lifecycle", permission: authz.PermAuditRead, query: `
		select a.occurred_at, 'lifecycle', a.id::text,
		       a.action, '', coalesce(a.detail->>'reason', ''),
		       case when a.outcome = 'success' then coalesce(a.detail->>'state', '') else a.outcome end,
		       '', a.actor_id,
		       'audit', a.id::text
		from audit_events a
		where a.target_type = 'host' and a.target_id = $1::uuid::text
		  and a.action in ` + lifecycleActions},
	{kind: "session", permission: authz.PermHostRead, query: `
		select s.started_at, 'session', s.id::text || ':opened',
		       coalesce(s.agent_version, ''), 'opened', coalesce(s.remote_addr, ''),
		       case when s.ended_at is null then 'open' else 'ended' end, '', s.gateway_id,
		       'session', s.id::text
		from agent_sessions s where s.host_id = $1::uuid
		union all
		select s.ended_at, 'session', s.id::text || ':ended',
		       coalesce(s.agent_version, ''), 'ended', coalesce(s.end_reason, ''),
		       'ended', '', s.gateway_id,
		       'session', s.id::text
		from agent_sessions s where s.host_id = $1::uuid and s.ended_at is not null`},
	{kind: "campaign", permission: authz.PermCampaignRead, query: `
		select coalesce(t.finished_at, t.started_at, t.created_at), 'campaign', t.id::text,
		       c.name,
		       case when t.finished_at is not null then 'finished'
		            when t.started_at is not null then 'started'
		            else 'selected' end,
		       coalesce(t.message, ''), t.state, coalesce(t.error_code, ''), c.created_by,
		       'campaign', c.id::text
		from campaign_targets t join campaigns c on c.id = t.campaign_id
		where t.host_id = $1::uuid`},
	{kind: "alert", permission: authz.PermMonitoringRead, query: `
		select a.fired_at, 'alert', a.id::text || ':fired',
		       a.rule_name, 'fired',
		       a.severity || case when a.detail <> '' then ': ' || a.detail else '' end,
		       'firing', '', '',
		       'alert', a.id::text
		from alerts a where a.host_id = $1::uuid and a.fired_at is not null
		union all
		select a.resolved_at, 'alert', a.id::text || ':resolved',
		       a.rule_name, 'resolved',
		       a.severity || case when a.detail <> '' then ': ' || a.detail else '' end,
		       'resolved', '', '',
		       'alert', a.id::text
		from alerts a where a.host_id = $1::uuid and a.fired_at is not null and a.resolved_at is not null`},
}

// The page of the timeline: what the overview shows, and the most a
// caller may ask for at once.
const (
	defaultTimelinePage = 30
	maxTimelinePage     = 200
)

// timelineCursor is the key of the last row of the previous page. The
// order is time, then kind, then identifier - all three fixed once a row
// exists, so the page after a cursor is the same whatever was written in
// the meantime.
type timelineCursor struct {
	At   time.Time
	Kind string
	ID   string
	Set  bool
}

func parseTimelineCursor(value string) (timelineCursor, error) {
	parts, err := paging.Decode(value, 3)
	if err != nil {
		return timelineCursor{}, err
	}
	if parts == nil {
		return timelineCursor{}, nil
	}
	at, err := paging.ParseTime(parts[0])
	if err != nil {
		return timelineCursor{}, err
	}
	if err := validateTimelineKey(parts[1], parts[2]); err != nil {
		return timelineCursor{}, err
	}
	return timelineCursor{At: at, Kind: parts[1], ID: parts[2], Set: true}, nil
}

// validateTimelineKey checks that the kind and the identifier of a cursor
// are ones the timeline issues: the kind is a source, and the identifier
// is the record key of that source - a number for the trail, a UUID with
// an optional event suffix for everything else. A foreign cursor is an
// invalid request, not a query the database gets to fail on.
func validateTimelineKey(kind, id string) error {
	known := false
	for _, source := range timelineSources {
		if source.kind == kind {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("%w: unknown kind %q", paging.ErrInvalidCursor, kind)
	}
	record, _, _ := strings.Cut(id, ":")
	if kind == "audit" || kind == "lifecycle" {
		if _, err := strconv.ParseInt(record, 10, 64); err != nil {
			return fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
		}
		return nil
	}
	if _, err := uuid.Parse(record); err != nil {
		return fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	return nil
}

func (c timelineCursor) String() string {
	return paging.Encode(paging.FormatTime(c.At), c.Kind, c.ID)
}

// handleHostTimeline serves the history of one host, newest first.
//
// Reading the host is the permission of the endpoint; each source then
// asks for its own. A caller without the audit permission gets the
// timeline without the trail, and the answer lists the sources it
// covers, so a screen can say what is missing rather than show a quiet
// history.
func (s *Server) handleHostTimeline(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostRead, scope, "host", hostID)
	if !ok {
		return
	}
	query := r.URL.Query()
	since, err := parseTimeParam(query.Get("since"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_filter", "since must be an RFC 3339 timestamp")
		return
	}
	until, err := parseTimeParam(query.Get("until"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_filter", "until must be an RFC 3339 timestamp")
		return
	}
	cursor, err := parseTimelineCursor(query.Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	limit = paging.Limit(limit, defaultTimelinePage, maxTimelinePage)

	var sources []timelineSource
	kinds := []string{}
	for _, source := range timelineSources {
		if principal.Can(source.permission, scope) {
			sources = append(sources, source)
			kinds = append(kinds, source.kind)
		}
	}
	items, next, err := s.hostTimeline(r.Context(), hostID, sources, since, until, cursor, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "count": len(items), "next_cursor": next, "sources": kinds,
	})
}

// hostTimeline runs the union over the visible sources, keyset-paged.
func (s *Server) hostTimeline(ctx context.Context, hostID string, sources []timelineSource,
	since, until *time.Time, cursor timelineCursor, limit int) ([]TimelineItem, string, error) {
	items := []TimelineItem{}
	if len(sources) == 0 {
		return items, "", nil
	}
	parts := make([]string, 0, len(sources))
	for _, source := range sources {
		parts = append(parts, "("+source.query+")")
	}
	args := []any{hostID}
	conditions := []string{}
	if since != nil {
		args = append(args, *since)
		conditions = append(conditions, fmt.Sprintf("e.at >= $%d", len(args)))
	}
	if until != nil {
		args = append(args, *until)
		conditions = append(conditions, fmt.Sprintf("e.at <= $%d", len(args)))
	}
	if cursor.Set {
		args = append(args, cursor.At, cursor.Kind, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(e.at, e.kind, e.id) < ($%d, $%d, $%d)",
			len(args)-2, len(args)-1, len(args)))
	}
	where := ""
	if len(conditions) > 0 {
		where = " where " + strings.Join(conditions, " and ")
	}
	// One row more than the page says whether there is a next page without
	// a count over every source. The columns are named on the derived
	// table, so the shape does not depend on which source comes first.
	args = append(args, limit+1)
	const columns = "at, kind, id, title, event, detail, state, error_code, actor, ref_type, ref_id"
	query := "select " + columns + " from (" + strings.Join(parts, " union all ") + ") as e (" + columns + ")" +
		where + fmt.Sprintf(" order by e.at desc, e.kind desc, e.id desc limit $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var item TimelineItem
		if err := rows.Scan(&item.At, &item.Kind, &item.ID, &item.Title, &item.Event, &item.Detail,
			&item.State, &item.ErrorCode, &item.Actor, &item.Ref.Type, &item.Ref.ID); err != nil {
			return nil, "", err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[limit-1]
		next = timelineCursor{At: last.At, Kind: last.Kind, ID: last.ID, Set: true}.String()
	}
	return items, next, nil
}
