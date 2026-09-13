//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// sessionView describes an agent session row in the database.
type sessionView struct {
	ID     string
	Epoch  int64
	Closed bool
	Reason string
}

// TestNewSessionReplacesTheOldOne guards the property the session epoch
// exists for in the first place: at any moment a host has exactly one
// authoritative session.
//
// Without it two gateways would consider themselves authoritative for the
// same host and the same job would go out twice - and irreversible
// operations would run twice. The test forces a reconnect through
// quarantine, because that is the only way to break a session through the
// API.
func TestNewSessionReplacesTheOldOne(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	ctx := context.Background()
	h.database(ctx)

	before := h.hostSessions(t, host.ID)
	if len(before) == 0 {
		t.Fatal("the host has no session at all")
	}
	open := 0
	for _, session := range before {
		if !session.Closed {
			open++
		}
	}
	if open != 1 {
		t.Fatalf("the host has %d open sessions; exactly one is authoritative", open)
	}
	highest := before[0].Epoch

	// The cleanup lifts the quarantine only when the test did not manage to
	// lift it itself: releasing a host that is already active is a state
	// conflict and would mask the real cause of the failure.
	t.Cleanup(func() {
		var state struct {
			LifecycleState string `json:"lifecycle_state"`
		}
		h.get("/api/v1/hosts/"+host.ID, &state)
		if state.LifecycleState == "quarantined" {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
				map[string]any{"reason": "end of the test"}, nil, http.StatusOK)
		}
		h.awaitConnection(host.ID, 2*time.Minute)
	})
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{"reason": "session epoch test"}, nil, http.StatusOK)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
		map[string]any{"reason": "session epoch test"}, nil, http.StatusOK)
	h.awaitConnection(host.ID, 2*time.Minute)

	after := h.hostSessions(t, host.ID)
	if after[0].Epoch <= highest {
		t.Fatalf("epoch after the reconnect = %d, before = %d", after[0].Epoch, highest)
	}
	if after[0].Closed {
		t.Fatal("the newest session is closed")
	}
	for _, session := range after[1:] {
		if !session.Closed {
			t.Fatalf("the older session %s (epoch %d) was left open", session.ID, session.Epoch)
		}
	}
}

// hostSessions returns the host sessions from the newest epoch down.
func (h *harness) hostSessions(t *testing.T, hostID string) []sessionView {
	t.Helper()
	ctx := context.Background()
	rows, err := h.database(ctx).Query(ctx, `
		select id::text, epoch, ended_at is not null, coalesce(end_reason, '')
		from agent_sessions where host_id = $1::uuid
		order by epoch desc limit 20`, hostID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var sessions []sessionView
	for rows.Next() {
		var session sessionView
		if err := rows.Scan(&session.ID, &session.Epoch, &session.Closed, &session.Reason); err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return sessions
}
