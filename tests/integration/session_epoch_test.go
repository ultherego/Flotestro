//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// sessionView describes an agent session row in the database.
type sessionView struct {
	ID     string
	Epoch  int64
	Closed bool
	Reason string
}

// TestNewSessionReplacesTheOldOne guards the property the session epoch exists
// for in the first place: at any moment a host has exactly one authoritative
// session.
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

	// The cleanup lifts the quarantine only when the test did not manage to lift
	// it itself: releasing a host that is already active is a state conflict and
	// would mask the real cause of the failure.
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

// TestACloneOfTheIdentityIsReported guards the detection of a copied identity
// and the packaged reaction to it: the same certificate alive on two boots at
// the same time quarantines the host and ends both sessions with that reason.
func TestACloneOfTheIdentityIsReported(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	ctx := context.Background()
	pool := h.database(ctx)

	var fingerprint []byte
	if err := pool.QueryRow(ctx, `
		select cert_fingerprint from agent_sessions
		where host_id = $1::uuid and ended_at is null order by epoch desc limit 1`,
		host.ID).Scan(&fingerprint); err != nil {
		t.Fatalf("the host has no open session: %v", err)
	}
	cloneID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		insert into agent_sessions
			(id, host_id, gateway_id, cert_fingerprint, remote_addr, agent_version, boot_id, epoch, last_heartbeat_at)
		values ($1::uuid, $2::uuid, 'clone-test', $3, '203.0.113.7', 'test', 'cloned-boot',
			(select coalesce(max(epoch), 0) + 1 from agent_sessions where host_id = $2::uuid),
			now() + interval '10 minutes')`,
		cloneID, host.ID, fingerprint); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `delete from agent_sessions where id = $1::uuid`, cloneID)
	})

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
	// The reconnect of the real agent is forced the only way the API allows.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{"reason": "duplicate identity test"}, nil, http.StatusOK)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
		map[string]any{"reason": "duplicate identity test"}, nil, http.StatusOK)
	var state struct {
		LifecycleState  string `json:"lifecycle_state"`
		LifecycleReason string `json:"lifecycle_reason"`
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		h.get("/api/v1/hosts/"+host.ID, &state)
		if state.LifecycleState == "quarantined" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the host was not quarantined for the clone within two minutes: state %q", state.LifecycleState)
		}
		time.Sleep(2 * time.Second)
	}
	if !strings.Contains(state.LifecycleReason, "duplicate identity") {
		t.Errorf("the quarantine does not name the clone as its reason: %q", state.LifecycleReason)
	}

	// Both sessions of the identity end with the same reason: the staged clone,
	// and the real agent's session that met it.
	if reason := sessionEnd(ctx, pool, cloneID); reason != "duplicate_identity" {
		t.Errorf("the clone's session ended with %q, want duplicate_identity", reason)
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		sessions := h.hostSessions(t, host.ID)
		if len(sessions) > 0 && sessions[0].ID != cloneID && sessions[0].Closed {
			if sessions[0].Reason != "duplicate_identity" {
				t.Errorf("the real agent's session ended with %q, want duplicate_identity", sessions[0].Reason)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the real agent's session was not closed for the clone: %+v", sessions)
		}
		time.Sleep(time.Second)
	}

	var audit struct {
		Items []struct {
			Action string         `json:"action"`
			Detail map[string]any `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/hosts/"+host.ID+"/audit?limit=50", &audit)
	for _, event := range audit.Items {
		if event.Action == "security.duplicate_identity" && event.Detail["previous_session"] == cloneID {
			if event.Detail["previous_boot_id"] != "cloned-boot" || event.Detail["previous_addr"] != "203.0.113.7" {
				t.Errorf("the incident does not describe the clone: %+v", event.Detail)
			}
			// The incident carries the policy applied and what it did, so the operator
			// reading the trail knows whether the host is waiting for them or still in
			// the fleet.
			if event.Detail["policy"] != "quarantine" || event.Detail["quarantined"] != true {
				t.Errorf("the incident does not say the host was quarantined by policy: %+v", event.Detail)
			}
			return
		}
	}
	t.Fatal("no security.duplicate_identity event was recorded for the clone")
}
