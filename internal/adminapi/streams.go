package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/campaigns"
	"github.com/ultherego/flotestro/internal/events"
)

// keepaliveInterval keeps the stream alive through proxies that close idle
// connections. An SSE comment is not an event and does not wake the
// interface.
const keepaliveInterval = 25 * time.Second

// handleJobEvents streams the progress of one operation.
//
// The stream carries only the signal "the state changed". The content of
// the result is the database: if the state travelled through the stream,
// the screen after a dropped connection would show something else than
// recorded, and the operator would have no way to notice.
func (s *Server) handleJobEvents(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	job, err := s.jobs.Get(r.Context(), jobID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if job == nil {
		problem(w, http.StatusNotFound, "job_not_found", "no such job")
		return
	}
	host, scope, ok := s.hostScope(w, r, job.HostID)
	if !ok {
		return
	}
	_ = host
	if _, ok := s.authorize(w, r, authz.PermJobRead, scope, "job", jobID); !ok {
		return
	}
	s.stream(w, r, events.ForJob(jobID), nil, nil)
}

// handleCampaignEvents streams a campaign: the transient progress of its
// operations and its durable trail.
//
// The trail events carry an identifier, so the browser sends it back as
// Last-Event-ID after a broken connection and the stream resumes from the
// row after it - nothing that happened while the connection was down is
// lost. The content comes from the table, never from the notification: a
// notification is a wake-up call, and a screen that missed one reads
// everything after the last identifier it has anyway.
func (s *Server) handleCampaignEvents(w http.ResponseWriter, r *http.Request) {
	campaignID := r.PathValue("id")
	if _, ok := s.authorizeCollection(w, r, authz.PermCampaignRead, "campaign"); !ok {
		return
	}
	after := lastEventID(r)
	s.stream(w, r, events.ForCampaign(campaignID), nil, &trail{
		campaignID: campaignID, last: after, read: s.campaigns.CourseAfter,
	})
}

// lastEventID reads the cursor of the trail: the Last-Event-ID header the
// browser sends on reconnection, or the after parameter of a first request
// that wants to skip what it already has.
func lastEventID(r *http.Request) int64 {
	value := r.Header.Get("Last-Event-ID")
	if value == "" {
		value = r.URL.Query().Get("after")
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id < 0 {
		return 0
	}
	return id
}

// trail follows the durable events of one campaign inside a stream.
type trail struct {
	campaignID string
	// last is the identifier of the last event sent; nothing at or before
	// it goes out again, so a replay and a live notification cannot
	// duplicate an event.
	last int64
	read func(ctx context.Context, campaignID string, after int64, limit int) ([]campaigns.Event, error)
}

// emit sends every event after the cursor, page by page.
func (t *trail) emit(ctx context.Context, w http.ResponseWriter, flusher http.Flusher) {
	for {
		batch, err := t.read(ctx, t.campaignID, t.last, trailPage)
		if err != nil || len(batch) == 0 {
			return
		}
		for _, event := range batch {
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "id: %d\nevent: timeline\ndata: %s\n\n", event.ID, data)
			t.last = event.ID
		}
		flusher.Flush()
		if len(batch) < trailPage {
			return
		}
	}
}

// trailPage bounds one read of the trail inside a stream.
const trailPage = 200

// handleFleetEvents streams the events of all the operations the operator
// may see.
//
// A separate stream per operation would be unmaintainable: the panel goes
// over HTTP/1.1, where the browser keeps six connections per domain, and a
// stream takes one permanently. One stream per tab leaves the rest for
// ordinary requests.
func (s *Server) handleFleetEvents(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermJobRead, "job")
	if !ok {
		return
	}
	s.stream(w, r, func(events.Event) bool { return true }, s.scopeGate(principal), nil)
}

// scopeGate lets through only the events of operations from hosts visible
// to this principal. The check runs in the connection goroutine, not in the
// bus: querying the database while broadcasting would stall all receivers.
func (s *Server) scopeGate(principal authz.Principal) func(context.Context, events.Event) bool {
	visible := map[string]bool{}
	return func(ctx context.Context, event events.Event) bool {
		if event.JobID == "" {
			return false
		}
		if allowed, known := visible[event.JobID]; known {
			return allowed
		}
		allowed := false
		if job, err := s.jobs.Get(ctx, event.JobID); err == nil && job != nil {
			if host, err := s.hosts.Get(ctx, job.HostID); err == nil && host != nil {
				allowed = principal.Can(authz.PermJobRead,
					authz.Scope{Site: host.Site, Environment: host.Environment})
			}
		}
		visible[event.JobID] = allowed
		return allowed
	}
}

// stream sends events as Server-Sent Events. With a trail it also replays
// the durable events after the caller's cursor and follows them live.
func (s *Server) stream(w http.ResponseWriter, r *http.Request,
	filter func(events.Event) bool, allowed func(context.Context, events.Event) bool,
	durable *trail) {
	if s.events == nil {
		// No bus is not a client error: the panel works, only without the
		// stream. The answer says so directly instead of hanging in wait.
		problem(w, http.StatusServiceUnavailable, "events_unavailable",
			"the control plane is not streaming progress right now")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		problem(w, http.StatusInternalServerError, "streaming_unsupported",
			"this connection cannot stream events")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	// Proxies buffering the response would turn the stream into one long
	// download that arrives only at the end.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	incoming, unsubscribe := s.events.Subscribe(filter)
	defer unsubscribe()

	// The first event goes at once: a screen that has just connected cannot
	// wait for the next change to refresh its data.
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()

	// The replay comes after the subscription, so an event published in
	// between is seen twice at most - and the cursor drops the repeat.
	if durable != nil {
		durable.emit(r.Context(), w, flusher)
	}

	keepalive := time.NewTicker(keepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case event := <-incoming:
			if event.Outbox != nil {
				// A published row of the trail: read from the cursor on,
				// because the notification is only a signal that there is
				// something to read.
				if durable != nil && event.Outbox.ID > durable.last {
					durable.emit(r.Context(), w, flusher)
				}
				continue
			}
			if allowed != nil && !allowed(r.Context(), event) {
				continue
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			// Progress and a state change are two different events. The
			// screen refreshes its data after a state change, and draws the
			// bar from the progress - merging them into one would make it
			// query the API several times a second.
			name := "job"
			switch {
			case event.Log != nil:
				name = "log"
			case event.Progress != nil:
				name = "progress"
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
			flusher.Flush()
		}
	}
}
