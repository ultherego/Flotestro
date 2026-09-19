//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// Chapter 10.3 of the security remediation: a silence decides what the queue
// never sees, so the two properties of a silence that the queue already reads

// scopedSilenceView is a silence with the two properties of its policy.
type scopedSilenceView struct {
	ID          string     `json:"id"`
	HostID      string     `json:"host_id"`
	RuleID      string     `json:"rule_id"`
	Until       time.Time  `json:"until"`
	Reason      string     `json:"reason"`
	Global      bool       `json:"global"`
	SendSummary bool       `json:"send_summary"`
	CreatedBy   string     `json:"created_by"`
	ExpiredAt   *time.Time `json:"expired_at"`
}

const silenceReason = "integration test of the silence scope"

// recordTrailEvent writes one event of a host straight into the trail, which is
// what the notification router consumes. A security alert of the installation
func recordTrailEvent(h *harness, hostID, eventType string, payload map[string]any) {
	h.t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		h.t.Fatalf("encoding the payload of %s: %v", eventType, err)
	}
	ctx := context.Background()
	if _, err := h.database(ctx).Exec(ctx, `
		insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
		values ('host', $1::uuid, $2, $3::jsonb)`, hostID, eventType, string(encoded)); err != nil {
		h.t.Fatalf("writing %s to the trail: %v", eventType, err)
	}
}

// forgetSilence removes a silence when the test is done: a silence left behind
// would keep the lab's own alerts back.
func forgetSilence(h *harness, id string) {
	h.t.Cleanup(func() {
		ctx := context.Background()
		if _, err := h.database(ctx).Exec(ctx, `delete from silences where id = $1::uuid`, id); err != nil {
			h.t.Logf("the silence %s was not cleaned up: %v", id, err)
		}
	})
}

// TestAGlobalSilenceIsTheOnlyOneThatKeepsSecurityAlertsBack walks the whole
// rule: who may write a global silence, what a scoped one does to a security
func TestAGlobalSilenceIsTheOnlyOneThatKeepsSecurityAlertsBack(t *testing.T) {
	h := newHarness(t)
	// The pool before anything registers a cleanup that reads through it: the
	// cleanups run in reverse, so the pool opened last would close first.
	h.database(context.Background())
	host := h.enrollSyntheticHost(t)
	if host.ID == "" {
		t.Fatal("the synthetic host was not enrolled")
	}

	// The channel hears the security alerts of the installation, the hosts
	// that go quiet, and nothing is narrowed: a scoped channel would refuse
	receiver := newRecipient(t, http.StatusOK)
	channel := createChannel(h, map[string]any{
		"name": fmt.Sprintf("integration-silence-%d", time.Now().UnixNano()), "kind": "webhook",
		"config": map[string]any{"url": receiver.server.URL},
		"events": []string{"security.alert", "host.offline"},
		"reason": notificationReason,
	})

	// An operator of this host's site may silence the host. That is not a
	// permission to blind the installation, and the refusal says so by code.
	scoped := h.withToken(h.createPrincipal(uniqueSubject("scoped-oncall"), []map[string]string{
		{"role": "platform_admin", "site": host.Site, "environment": host.Environment},
	}))
	var refusal struct {
		Code string `json:"code"`
	}
	scoped.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences", map[string]any{
		"reason": silenceReason, "minutes": 30, "global": true,
	}, &refusal, http.StatusForbidden)
	if refusal.Code != "global_silence_denied" {
		t.Fatalf("a scoped operator was refused a global silence as %q", refusal.Code)
	}
	refusal.Code = ""
	scoped.do(http.MethodPost, "/api/v1/monitoring/silences", map[string]any{
		"reason": silenceReason, "minutes": 30, "global": true,
	}, &refusal, http.StatusForbidden)
	if refusal.Code == "" {
		t.Fatal("a scoped operator wrote a global silence of the whole fleet")
	}

	// A global silence covers the installation, so it names neither a host nor
	// a rule; asking for both at once is a contradiction with a code.
	refusal.Code = ""
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences", map[string]any{
		"reason": silenceReason, "minutes": 30, "global": true,
	}, &refusal, http.StatusBadRequest)
	if refusal.Code != "silence_scope_conflict" {
		t.Fatalf("a global silence naming a host was refused as %q", refusal.Code)
	}

	// A silence of this host, written the ordinary way. It keeps the host's own
	// alerts back and must not touch a security alert of the installation.
	var ofTheHost scopedSilenceView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/monitoring/silences", map[string]any{
		"reason": silenceReason, "minutes": 60, "send_summary": true,
	}, &ofTheHost, http.StatusCreated)
	if ofTheHost.ID == "" || ofTheHost.Global || !ofTheHost.SendSummary {
		t.Fatalf("the silence of the host came back as %+v", ofTheHost)
	}
	forgetSilence(h, ofTheHost.ID)

	recordTrailEvent(h, host.ID, "security.duplicate_identity", map[string]any{
		"host_id": host.ID, "detail": "two identities claim the same machine",
		"site": host.Site, "environment": host.Environment,
	})
	kept := awaitQueueRow(h, channel.ID, "security.duplicate_identity", 90*time.Second,
		"reaching the queue", func(row queueRowView) bool { return row.State != "" })
	if kept.State == "suppressed" {
		t.Fatalf("a silence of one host kept back a security alert of the installation: %+v", kept)
	}

	// The same alert under a global silence: kept back, and the row names the
	// silence that did it.
	var global scopedSilenceView
	h.do(http.MethodPost, "/api/v1/monitoring/silences", map[string]any{
		"reason": silenceReason, "minutes": 60, "global": true,
	}, &global, http.StatusCreated)
	if global.ID == "" || !global.Global || global.HostID != "" || global.RuleID != "" {
		t.Fatalf("the global silence came back as %+v", global)
	}
	forgetSilence(h, global.ID)

	recordTrailEvent(h, host.ID, "security.attempt_mismatch", map[string]any{
		"host_id": host.ID, "detail": "the answer named an attempt nobody ordered",
		"site": host.Site, "environment": host.Environment,
	})
	blinded := awaitQueueRow(h, channel.ID, "security.attempt_mismatch", 90*time.Second,
		"kept back by the global silence", func(row queueRowView) bool { return row.State == "suppressed" })
	if blinded.DeliveredAt != nil {
		t.Errorf("a kept-back security alert counts as delivered: %+v", blinded)
	}

	// The summary: an ordinary event of the host is kept back by the silence
	// with the flag, and ending that silence sends one message per channel.
	recordTrailEvent(h, host.ID, "host.offline", map[string]any{
		"host_id": host.ID, "connection_state": "offline",
		"site": host.Site, "environment": host.Environment,
	})
	awaitQueueRow(h, channel.ID, "host.offline", 90*time.Second,
		"kept back by the silence of the host", func(row queueRowView) bool { return row.State == "suppressed" })

	h.do(http.MethodDelete, "/api/v1/hosts/"+host.ID+"/monitoring/silences/"+ofTheHost.ID,
		nil, nil, http.StatusNoContent)
	summary := awaitQueueRow(h, channel.ID, "alert.summary", 120*time.Second,
		"summarising what the silence kept back", func(row queueRowView) bool {
			return row.State == "delivered" || row.Status == "sent"
		})
	if summary.ID == "" {
		t.Fatal("no summary was sent for a silence that asked for one")
	}

	// Once, not once per round: the rows it names are marked as summarised.
	time.Sleep(15 * time.Second)
	summaries := 0
	for _, row := range rowsOf(h, channel.ID).Items {
		if row.EventType == "alert.summary" {
			summaries++
		}
	}
	if summaries != 1 {
		t.Fatalf("the ended silence produced %d summaries on one channel, expected one", summaries)
	}

	// The global silence is ended through the fleet path; a host path does not
	// know it, because it belongs to no host.
	h.do(http.MethodDelete, "/api/v1/monitoring/silences/"+global.ID, nil, nil, http.StatusNoContent)
}
