package adminapi

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
)

// Reading the trail is itself on the trail. Whoever looked at what
// somebody did is part of the story of an incident, and an export is the
// one read that takes the evidence out of the panel - so every read is
// recorded once, with the filter it asked with, before the answer goes out.

// recordAuditRead writes the event of one read of the trail.
func (s *Server) recordAuditRead(r *http.Request, actor authz.Principal, action string,
	targetType, targetID string, filter audit.ListFilter, extra map[string]any) {
	detail := map[string]any{}
	for key, value := range map[string]string{
		"target_id": filter.TargetID, "target_type": filter.TargetType,
		"actor": filter.Actor, "action": filter.Action, "action_prefix": filter.ActionPrefix,
		"outcome": filter.Outcome,
	} {
		if value != "" {
			detail["filter_"+key] = value
		}
	}
	if filter.Since != nil {
		detail["filter_since"] = filter.Since.UTC().Format(time.RFC3339)
	}
	if filter.Until != nil {
		detail["filter_until"] = filter.Until.UTC().Format(time.RFC3339)
	}
	for key, value := range extra {
		detail[key] = value
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: actor.Subject,
		Action: action, TargetType: targetType, TargetID: targetID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess, Detail: detail,
	})
}

func (s *Server) handleHostAudit(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	actor, ok := s.authorize(w, r, authz.PermAuditRead, scope, "host", hostID)
	if !ok {
		return
	}
	// The trail of one host takes the filters of the fleet trail and pages
	// the same way: the host tab asks "the denials on this host since
	// Monday" as the fleet page does, and a host with a long history is
	// browsed rather than cut off at the newest rows. The target is the
	// host of the address, whatever the query says.
	filter, ok := auditFilter(w, r)
	if !ok {
		return
	}
	filter.HostID = hostID
	filter.TargetID = ""
	query := r.URL.Query()
	cursor, err := audit.ParseCursor(query.Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	limit = paging.Limit(limit, defaultListPage, maxListPage)
	extra := map[string]any{"limit": limit}
	if cursor.Set {
		extra["continued"] = true
	}
	s.recordAuditRead(r, actor, "audit.read", "host", hostID, filter, extra)
	page, err := s.audit.ListPaged(r.Context(), filter, cursor, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": page.Items, "count": len(page.Items), "next_cursor": page.NextCursor,
	})
}

// auditFilter reads the filter of a trail read from the query. The time
// bounds are checked here: a value that is not a timestamp is the caller's
// mistake and must not quietly turn into "no bound".
func auditFilter(w http.ResponseWriter, r *http.Request) (audit.ListFilter, bool) {
	query := r.URL.Query()
	filter := audit.ListFilter{
		TargetID:     query.Get("target_id"),
		TargetType:   query.Get("target_type"),
		Actor:        query.Get("actor"),
		Action:       query.Get("action"),
		ActionPrefix: query.Get("action_prefix"),
		Outcome:      query.Get("outcome"),
	}
	var err error
	if filter.Since, err = parseTimeParam(query.Get("since")); err != nil {
		problem(w, http.StatusBadRequest, "invalid_filter", "since must be an RFC 3339 timestamp")
		return filter, false
	}
	if filter.Until, err = parseTimeParam(query.Get("until")); err != nil {
		problem(w, http.StatusBadRequest, "invalid_filter", "until must be an RFC 3339 timestamp")
		return filter, false
	}
	return filter, true
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermAuditRead, authz.GlobalScope, "audit", "")
	if !ok {
		return
	}
	filter, ok := auditFilter(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	cursor, err := audit.ParseCursor(query.Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	limit, _ := strconv.Atoi(query.Get("limit"))
	limit = paging.Limit(limit, defaultListPage, maxListPage)
	// Every request is one read, a further page included: the event says so,
	// and a reviewer sees how far somebody paged as well as what they asked.
	extra := map[string]any{"limit": limit}
	if cursor.Set {
		extra["continued"] = true
	}
	s.recordAuditRead(r, actor, "audit.read", "audit", "", filter, extra)
	page, err := s.audit.ListPaged(r.Context(), filter, cursor, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": page.Items, "count": len(page.Items), "next_cursor": page.NextCursor,
	})
}

// handleAuditExport streams the trail between two moments as JSON lines
// linked by a hash chain, oldest first, with a closing line carrying the
// count and the digest of the last event. A file kept outside the panel
// can then be verified without it - cmd/auditverify does exactly that.
//
// The export is a read of the trail like any other and is recorded as
// one, with its bounds; the event of the export itself is written before
// the read, so an export up to "now" carries its own record.
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorize(w, r, authz.PermAuditRead, authz.GlobalScope, "audit", "")
	if !ok {
		return
	}
	filter, ok := auditFilter(w, r)
	if !ok {
		return
	}
	s.recordAuditRead(r, actor, "audit.export", "audit", "", filter, nil)

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", exportName(filter)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	// A failure midway cannot change the status any more: the answer is
	// then a file without its closing line, which is what the verifier
	// reports as cut short. The log says why.
	writer := audit.NewChainWriter(w)
	err := s.audit.Each(r.Context(), filter, writer.Write)
	if err != nil {
		s.log.Error("the audit export broke off", "err", err)
		return
	}
	if err := writer.Close(); err != nil {
		s.log.Error("the audit export was not closed", "err", err)
	}
}

// exportName names the file after its bounds, so two exports on one desk
// are told apart.
func exportName(filter audit.ListFilter) string {
	name := "audit"
	if filter.Since != nil {
		name += "-from-" + filter.Since.UTC().Format("20060102T150405Z")
	}
	if filter.Until != nil {
		name += "-until-" + filter.Until.UTC().Format("20060102T150405Z")
	}
	return name + ".jsonl"
}
