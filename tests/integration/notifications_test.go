//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

const notificationReason = "integration test of the notification channels"

type channelView struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Kind    string          `json:"kind"`
	Config  json.RawMessage `json:"config"`
	Events  []string        `json:"events"`
	Enabled bool            `json:"enabled"`
	Filter  struct {
		SeverityMin string `json:"severity_min"`
		Site        string `json:"site"`
	} `json:"filter"`
	CreatedBy string `json:"created_by"`
	Reason    string `json:"reason"`
	// The newest row of the queue for this channel: the queue's own state
	// (delivered, retry_wait, dead_letter) and the reason of the last attempt,
	// not the status of a single send.
	LastDelivery *struct {
		ID        string `json:"id"`
		State     string `json:"state"`
		ErrorCode string `json:"error_code"`
	} `json:"last_delivery"`
}

type deliveryView struct {
	// The identifier of a row of the queue is a UUID: a delivery is a durable row
	// an operator can point at and send again, not the sequence number the log of
	// the previous release had.
	ID          string    `json:"id"`
	ChannelID   string    `json:"channel_id"`
	ChannelName string    `json:"channel_name"`
	EventID     int64     `json:"event_id"`
	EventType   string    `json:"event_type"`
	Attempt     int       `json:"attempt"`
	Status      string    `json:"status"`
	ErrorCode   string    `json:"error_code"`
	Error       string    `json:"error"`
	SentAt      time.Time `json:"sent_at"`
}

// webhookConfigView is the configuration of a webhook as the API shows
// it: the secret is never in it, only the fact that one is set.
type webhookConfigView struct {
	URL       string  `json:"url"`
	Secret    *string `json:"secret"`
	SecretSet bool    `json:"secret_set"`
}

// connectionFailure says whether a code names a receiver that could not be
// reached at all - the answer a closed port or an unknown name gets, whichever
// the lab's resolver gives first.
func connectionFailure(code string) bool {
	switch code {
	case "connection_refused", "dns_failure", "timeout", "unreachable":
		return true
	}
	return false
}

// createChannel records a channel and removes it when the test ends.
func createChannel(h *harness, body map[string]any) channelView {
	h.t.Helper()
	var channel channelView
	h.do(http.MethodPost, "/api/v1/notifications/channels", body, &channel, http.StatusCreated)
	if channel.ID == "" {
		h.t.Fatalf("the channel came back without an identifier: %+v", channel)
	}
	h.t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/notifications/channels/"+channel.ID,
			map[string]any{"reason": notificationReason}, nil, 0)
	})
	return channel
}

// TestNotificationChannelKeepsItsSecretAndLogsTypedFailures guards what a
// channel promises: a reason on every write, a secret that goes in and is
// never shown again, and a receiver that cannot be reached recorded in the log
func TestNotificationChannelKeepsItsSecretAndLogsTypedFailures(t *testing.T) {
	h := newHarness(t)
	name := fmt.Sprintf("integration-webhook-%d", time.Now().UnixNano())

	// No reason, no channel; a kind nobody knows, no channel either.
	h.do(http.MethodPost, "/api/v1/notifications/channels", map[string]any{
		"name": name, "kind": "webhook", "config": map[string]any{"url": "http://127.0.0.1:1/"},
		"events": []string{"alert.fired"},
	}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/notifications/channels", map[string]any{
		"name": name, "kind": "pigeon", "config": map[string]any{}, "reason": notificationReason,
	}, nil, http.StatusBadRequest)

	webhook := createChannel(h, map[string]any{
		"name": name, "kind": "webhook",
		"config": map[string]any{"url": "http://127.0.0.1:1/", "secret": "integration-secret"},
		"events": []string{"alert.fired", "alert.fired", "campaign.finished"},
		"filter": map[string]any{"severity_min": "warning"},
		"reason": notificationReason,
	})
	if webhook.Kind != "webhook" || !webhook.Enabled || webhook.CreatedBy == "" ||
		len(webhook.Events) != 2 || webhook.Filter.SeverityMin != "warning" {
		t.Fatalf("the channel came back as %+v", webhook)
	}
	var config webhookConfigView
	if err := json.Unmarshal(webhook.Config, &config); err != nil {
		t.Fatalf("the configuration does not read: %v", err)
	}
	if config.Secret != nil || !config.SecretSet {
		t.Fatalf("the secret is shown, or its presence is not: %s", webhook.Config)
	}

	// The list carries the vocabulary of the form and the channel.
	var list struct {
		Items    []channelView `json:"items"`
		Kinds    []string      `json:"kinds"`
		Subjects []struct {
			Name string `json:"name"`
		} `json:"subjects"`
	}
	h.get("/api/v1/notifications/channels", &list)
	if len(list.Kinds) != 3 || len(list.Subjects) < 8 {
		t.Errorf("the vocabulary is missing: kinds %v, subjects %d", list.Kinds, len(list.Subjects))
	}
	listed := false
	for _, item := range list.Items {
		if item.ID == webhook.ID {
			listed = true
		}
	}
	if !listed {
		t.Errorf("the list does not carry the channel")
	}

	// The test message goes to a closed port: the answer is a failed
	// delivery with the typed reason, and the log keeps the same row.
	var outcome deliveryView
	h.do(http.MethodPost, "/api/v1/notifications/channels/"+webhook.ID+"/test", nil, &outcome, http.StatusOK)
	if outcome.Status != "failed" || !connectionFailure(outcome.ErrorCode) || outcome.Error == "" ||
		outcome.EventType != "test" || outcome.Attempt != 1 {
		t.Fatalf("the test of a closed port came back as %+v", outcome)
	}
	var log struct {
		Items []deliveryView `json:"items"`
	}
	h.get("/api/v1/notifications/deliveries?channel_id="+webhook.ID+"&status=failed", &log)
	if len(log.Items) == 0 || log.Items[0].ChannelID != webhook.ID || log.Items[0].ErrorCode != outcome.ErrorCode {
		t.Errorf("the log does not carry the failed test: %+v", log.Items)
	}
	h.get("/api/v1/notifications/deliveries?channel_id="+webhook.ID+"&status=sent", &log)
	if len(log.Items) != 0 {
		t.Errorf("the log lists a sent delivery of a channel nothing answers at: %+v", log.Items)
	}
	h.do(http.MethodGet, "/api/v1/notifications/deliveries?status=lost", nil, nil, http.StatusBadRequest)
	var fetched channelView
	h.get("/api/v1/notifications/channels/"+webhook.ID, &fetched)
	// Nothing answered at that port, so the queue gave up on the row: the state
	// says so and the code is the transport's own reason, which is what an
	// operator acts on.
	if fetched.LastDelivery == nil || fetched.LastDelivery.State != "dead_letter" ||
		!connectionFailure(fetched.LastDelivery.ErrorCode) {
		t.Errorf("the channel does not carry its last delivery: %+v", fetched.LastDelivery)
	}

	// An edit that does not retype the secret keeps it; one that says the
	// secret is not set clears it. The secret itself never comes back.
	var edited channelView
	h.do(http.MethodPut, "/api/v1/notifications/channels/"+webhook.ID, map[string]any{
		"name": name, "kind": "webhook",
		"config": map[string]any{"url": "http://127.0.0.1:1/hooks", "secret_set": true},
		"events": []string{"alert.fired"}, "reason": notificationReason,
	}, &edited, http.StatusOK)
	config = webhookConfigView{}
	_ = json.Unmarshal(edited.Config, &config)
	if !config.SecretSet || config.URL != "http://127.0.0.1:1/hooks" || config.Secret != nil {
		t.Errorf("the edit lost the secret or the address: %s", edited.Config)
	}
	h.do(http.MethodPut, "/api/v1/notifications/channels/"+webhook.ID, map[string]any{
		"name": name, "kind": "webhook",
		"config": map[string]any{"url": "http://127.0.0.1:1/hooks"},
		"events": []string{"alert.fired"}, "enabled": false, "reason": notificationReason,
	}, &edited, http.StatusOK)
	config = webhookConfigView{}
	_ = json.Unmarshal(edited.Config, &config)
	if config.SecretSet || edited.Enabled {
		t.Errorf("the edit did not clear the secret or disable the channel: %+v %s", edited, edited.Config)
	}

	// A mailbox behind a name that never resolves fails the same typed way; a
	// mailbox whose password names a secret nobody created is refused before it
	// is written.
	email := createChannel(h, map[string]any{
		"name": name + "-mail", "kind": "email",
		"config": map[string]any{
			"host": "mail.invalid", "port": 25, "starttls": false,
			"from": "flotestro@example.com", "to": []string{"oncall@example.com"},
		},
		"events": []string{"host.offline"}, "reason": notificationReason,
	})
	h.do(http.MethodPost, "/api/v1/notifications/channels/"+email.ID+"/test", nil, &outcome, http.StatusOK)
	if outcome.Status != "failed" || !connectionFailure(outcome.ErrorCode) {
		t.Errorf("the test of an unresolvable relay came back as %+v", outcome)
	}
	var refusal struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/notifications/channels", map[string]any{
		"name": name + "-secret", "kind": "email",
		"config": map[string]any{
			"host": "mail.invalid", "starttls": true, "from": "flotestro@example.com",
			"to": []string{"oncall@example.com"}, "username": "flotestro",
			"password_secret": "no-such-secret-" + fmt.Sprint(time.Now().UnixNano()),
		},
		"events": []string{"host.offline"}, "reason": notificationReason,
	}, &refusal, http.StatusBadRequest)
	if refusal.Code != "secret_not_found" {
		t.Errorf("a password naming no secret was refused as %q", refusal.Code)
	}

	// Removing a channel wants a reason; afterwards the channel and its
	// log are gone.
	h.do(http.MethodDelete, "/api/v1/notifications/channels/"+email.ID, nil, nil, http.StatusBadRequest)
	h.do(http.MethodDelete, "/api/v1/notifications/channels/"+email.ID,
		map[string]any{"reason": notificationReason}, nil, http.StatusNoContent)
	h.do(http.MethodGet, "/api/v1/notifications/channels/"+email.ID, nil, nil, http.StatusNotFound)
	h.get("/api/v1/notifications/deliveries?channel_id="+email.ID, &log)
	if len(log.Items) != 0 {
		t.Errorf("the log of a removed channel is still there: %+v", log.Items)
	}

	// The channels are the platform administrator's: a viewer reads
	// nothing here, an operator reads the channels and writes none.
	viewer := h.withToken(h.createPrincipal(uniqueSubject("notify-viewer"), []map[string]string{{"role": "viewer"}}))
	viewer.do(http.MethodGet, "/api/v1/notifications/channels", nil, nil, http.StatusForbidden)
	operator := h.withToken(h.createPrincipal(uniqueSubject("notify-operator"), []map[string]string{{"role": "operator"}}))
	operator.do(http.MethodGet, "/api/v1/notifications/channels", nil, nil, http.StatusOK)
	operator.do(http.MethodPost, "/api/v1/notifications/channels/"+webhook.ID+"/test", nil, nil, http.StatusForbidden)
}

// TestAcknowledgedAlertLeavesTheWaitingCounts guards the meaning of an
// acknowledgement: the alert keeps firing, but it no longer counts among what
// waits for a person - on the dashboard and in the fleet view - and the row
func TestAcknowledgedAlertLeavesTheWaitingCounts(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	awaitSample(h, host.ID, 2*time.Minute)

	var rule alertRuleView
	h.do(http.MethodPost, "/api/v1/monitoring/rules", map[string]any{
		"name": "integration: acknowledged cpu", "metric": "cpu_percent", "operator": "gt",
		"threshold": -1, "for_minutes": 0, "severity": "warning",
		"selector": map[string]any{"host_ids": []string{host.ID}},
	}, &rule, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/monitoring/rules/"+rule.ID, nil, nil, 0)
	})
	fired := awaitAlert(h, host.ID, rule.ID, "firing", 3*time.Minute)

	type summaryView struct {
		AlertsFiring int `json:"alerts_firing"`
	}
	var before summaryView
	h.get("/api/v1/fleet/summary", &before)
	if before.AlertsFiring < 1 {
		t.Fatalf("the summary counts %d firing alerts while one fires", before.AlertsFiring)
	}

	// Taking an alert wants a note of the same length a silence's reason
	// has: "on it" is not a record.
	h.do(http.MethodPost, "/api/v1/monitoring/alerts/"+fired.ID+"/acknowledge",
		map[string]any{"note": "on it"}, nil, http.StatusBadRequest)
	type acknowledgedView struct {
		alertView
		AcknowledgedBy string     `json:"acknowledged_by"`
		AcknowledgedAt *time.Time `json:"acknowledged_at"`
		Note           string     `json:"note"`
	}
	var taken acknowledgedView
	h.do(http.MethodPost, "/api/v1/monitoring/alerts/"+fired.ID+"/acknowledge",
		map[string]any{"note": "looking at the load on this host"}, &taken, http.StatusOK)
	if taken.State != "firing" || taken.AcknowledgedBy == "" || taken.AcknowledgedAt == nil ||
		taken.Note != "looking at the load on this host" {
		t.Fatalf("the acknowledgement came back as %+v", taken)
	}

	var after summaryView
	h.get("/api/v1/fleet/summary", &after)
	if after.AlertsFiring != before.AlertsFiring-1 {
		t.Errorf("alerts_firing went from %d to %d; a taken alert is to leave the count",
			before.AlertsFiring, after.AlertsFiring)
	}
	var fleet struct {
		Firing []acknowledgedView `json:"firing"`
		Counts struct {
			Warning      int `json:"warning"`
			Acknowledged int `json:"acknowledged"`
		} `json:"counts"`
	}
	h.get("/api/v1/monitoring", &fleet)
	inFleet := false
	for _, alert := range fleet.Firing {
		if alert.ID == fired.ID && alert.AcknowledgedAt != nil {
			inFleet = true
		}
	}
	if !inFleet || fleet.Counts.Acknowledged < 1 {
		t.Errorf("the fleet view does not show the alert as taken: %+v", fleet)
	}
	var history struct {
		Items []acknowledgedView `json:"items"`
	}
	h.get("/api/v1/monitoring/alerts?host_id="+host.ID+"&acknowledged=true", &history)
	if len(history.Items) == 0 || history.Items[0].AcknowledgedBy == "" {
		t.Errorf("the history filter on acknowledged alerts finds nothing: %+v", history.Items)
	}

	// A note can be rewritten, and emptied, at any time.
	var noted acknowledgedView
	h.do(http.MethodPost, "/api/v1/monitoring/alerts/"+fired.ID+"/annotate",
		map[string]any{"note": "the load comes from the nightly index rebuild"}, &noted, http.StatusOK)
	if noted.Note != "the load comes from the nightly index rebuild" || noted.AcknowledgedBy != taken.AcknowledgedBy {
		t.Errorf("the note was not written, or the acknowledgement was lost: %+v", noted)
	}

	// Once the rule is gone the alert resolves, and a resolved alert
	// cannot be taken any more - it is history.
	h.do(http.MethodDelete, "/api/v1/monitoring/rules/"+rule.ID, nil, nil, http.StatusNoContent)
	deadline := time.Now().Add(time.Minute)
	for resolved := false; !resolved; {
		h.get("/api/v1/monitoring/alerts?host_id="+host.ID+"&state=resolved&limit=50", &history)
		for _, alert := range history.Items {
			if alert.ID == fired.ID {
				resolved = true
			}
		}
		if !resolved && time.Now().After(deadline) {
			t.Fatalf("the alert did not resolve after its rule was deleted")
		}
		if !resolved {
			time.Sleep(2 * time.Second)
		}
	}
	var refusal struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/monitoring/alerts/"+fired.ID+"/acknowledge",
		map[string]any{"note": "too late to take this one"}, &refusal, http.StatusConflict)
	if refusal.Code != "alert_not_firing" {
		t.Errorf("taking a resolved alert was refused as %q", refusal.Code)
	}
}
