//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// relayBufferPoint is one point of the buffer history as the panel answers
// it.
type relayBufferPoint struct {
	At             string `json:"at"`
	InstanceID     string `json:"instance_id"`
	BytesUsed      int64  `json:"bytes_used"`
	BytesUsedMax   int64  `json:"bytes_used_max"`
	BytesLimit     int64  `json:"bytes_limit"`
	ItemCount      int    `json:"item_count"`
	DroppedTotal   int64  `json:"dropped_total"`
	DroppedDelta   *int64 `json:"dropped_delta"`
	ActiveSessions int    `json:"active_sessions"`
	UpstreamState  string `json:"upstream_state"`
	Disconnected   bool   `json:"disconnected"`
	Restarted      bool   `json:"restarted"`
	Version        string `json:"version"`
	Samples        int    `json:"samples"`
}

type relayBufferHistory struct {
	RelayID     string             `json:"relay_id"`
	Range       string             `json:"range"`
	StepSeconds int                `json:"step_seconds"`
	Rollup      bool               `json:"rollup"`
	Points      []relayBufferPoint `json:"points"`
	Latest      *relayBufferPoint  `json:"latest"`
	Alerts      []struct {
		RuleName string `json:"rule_name"`
		Metric   string `json:"metric"`
		Severity string `json:"severity"`
	} `json:"alerts"`
	RawRetentionHours   int `json:"raw_retention_hours"`
	RollupRetentionDays int `json:"rollup_retention_days"`
}

// relayHeartbeat is what a relay reports about itself.
type relayHeartbeat struct {
	BufferBytes        uint64
	BufferedItems      uint32
	BufferMaxBytes     uint64
	BufferDroppedTotal uint64
	Sessions           uint32
	InstanceID         string
	UpstreamState      string
	SpoolBytesLimit    uint64
}

// pingRelay sends one heartbeat over the relay's own mTLS channel, the way
// the relay process does every minute.
func (h *harness) pingRelay(t *testing.T, relay testRelay, beat relayHeartbeat) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"build":              map[string]any{"agentVersion": "test"},
		"bufferBytes":        beat.BufferBytes,
		"bufferedItems":      beat.BufferedItems,
		"bufferMaxBytes":     beat.BufferMaxBytes,
		"bufferDroppedTotal": beat.BufferDroppedTotal,
		"sessions":           beat.Sessions,
		"instanceId":         beat.InstanceID,
		"upstreamState":      beat.UpstreamState,
		"spoolBytesLimit":    beat.SpoolBytesLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{relay.Cert},
			RootCAs:      testTrustPool(),
			MinVersion:   tls.VersionTLS13,
		}},
	}
	address := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway) +
		"/flotestro.agent.v1.RelayService/Ping"
	request, err := http.NewRequest(http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("the relay heartbeat did not reach the centre: %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("relay heartbeat rejected: %d %s", response.StatusCode, truncate(raw, 300))
	}
}

// TestTheBufferHistoryAnswersWhatTheRelayReported guards the gap this endpoint
// exists for.
func TestTheBufferHistoryAnswersWhatTheRelayReported(t *testing.T) {
	h := newHarness(t)
	relay := h.enrollRelay(t, []string{"history-relay.flotestro.test"})
	ctx := context.Background()
	// The heartbeats are cleaned up with the relay: the rows reference it.
	h.database(ctx)

	const limit = 64 << 20
	h.pingRelay(t, relay, relayHeartbeat{
		BufferBytes: 1 << 20, BufferedItems: 12, BufferMaxBytes: limit,
		SpoolBytesLimit: limit, Sessions: 2, InstanceID: "instance-one",
		UpstreamState: "connected",
	})
	// The link went down: the spool takes the results and the relay says so.
	h.pingRelay(t, relay, relayHeartbeat{
		BufferBytes: 48 << 20, BufferedItems: 900, BufferMaxBytes: limit,
		SpoolBytesLimit: limit, BufferDroppedTotal: 7, Sessions: 2,
		InstanceID: "instance-one", UpstreamState: "buffering",
	})
	// The relay was restarted: a fresh process and counters from zero.
	h.pingRelay(t, relay, relayHeartbeat{
		BufferBytes: 0, BufferedItems: 0, BufferMaxBytes: limit,
		SpoolBytesLimit: limit, BufferDroppedTotal: 0, Sessions: 1,
		InstanceID: "instance-two", UpstreamState: "connected",
	})

	var history relayBufferHistory
	h.get("/api/v1/relays/"+relay.ID+"/buffer-history?range=3h", &history)
	if history.RelayID != relay.ID || history.Range != "3h" || history.Rollup {
		t.Fatalf("the history answered for the wrong relay or window: %+v", history)
	}
	if len(history.Points) < 3 {
		t.Fatalf("the history keeps %d points; three heartbeats were sent: %+v",
			len(history.Points), history.Points)
	}
	if history.RawRetentionHours <= 0 || history.RollupRetentionDays <= 0 {
		t.Fatalf("the history does not say how far back it reaches: %+v", history)
	}

	points := history.Points[len(history.Points)-3:]
	if points[0].BytesUsed != 1<<20 || points[0].BytesLimit != limit || points[0].ItemCount != 12 {
		t.Fatalf("the first report was not kept as sent: %+v", points[0])
	}
	if points[0].Disconnected {
		t.Fatalf("a connected relay was recorded as cut off: %+v", points[0])
	}
	if !points[1].Disconnected || points[1].UpstreamState != "buffering" {
		t.Fatalf("the stretch without an upstream is not in the history: %+v", points[1])
	}
	// The drops are a difference within one process. Seven results were
	// lost between the first two reports, and the history says so.
	if points[1].DroppedDelta == nil || *points[1].DroppedDelta != 7 {
		t.Fatalf("dropped_delta = %v, expected 7: %+v", points[1].DroppedDelta, points[1])
	}
	// The third report comes from a new process. A difference taken across
	// that would be a negative number of dropped results, so there is none.
	if !points[2].Restarted {
		t.Fatalf("the restart of the relay is not marked: %+v", points[2])
	}
	if points[2].DroppedDelta != nil {
		t.Fatalf("a difference was taken across a restart: %v", *points[2].DroppedDelta)
	}
	if points[2].InstanceID == points[1].InstanceID {
		t.Fatalf("the two processes of the relay are not told apart: %+v", points[2])
	}
	if history.Latest == nil || history.Latest.InstanceID != "instance-two" {
		t.Fatalf("the head of the page does not carry the newest report: %+v", history.Latest)
	}

	// The same rows are in the database: the history is durable, not a map
	// in the memory of one panel process.
	var stored int
	if err := h.database(ctx).QueryRow(ctx,
		`select count(*) from relay_buffer_samples where relay_id = $1::uuid`, relay.ID).
		Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored < 3 {
		t.Fatalf("the database holds %d buffer reports of the relay, expected at least 3", stored)
	}

	// A window the retention cannot answer is refused rather than quietly
	// turned into another one.
	h.do(http.MethodGet, "/api/v1/relays/"+relay.ID+"/buffer-history?range=1y",
		nil, nil, http.StatusBadRequest)
}

// TestTheBufferHistoryIsRefusedToACallerWhoMayNotReadTheRelay guards the
// boundary the relay list already keeps: the buffer of a site is not public
// inside the installation.
func TestTheBufferHistoryIsRefusedToACallerWhoMayNotReadTheRelay(t *testing.T) {
	h := newHarness(t)
	relay := h.enrollRelay(t, []string{"history-scope-relay.flotestro.test"})
	h.pingRelay(t, relay, relayHeartbeat{
		BufferBytes: 1024, BufferMaxBytes: 4096, SpoolBytesLimit: 4096,
		InstanceID: "instance-one", UpstreamState: "connected",
	})

	// A viewer sees hosts and nothing of the enrollment machinery: the relay list
	// asks for the right to prepare an installation, and so does its history.
	viewer := h.createPrincipal(uniqueSubject("relay-history-viewer"),
		[]map[string]string{{"role": "viewer", "site": "*", "environment": "*"}})
	h.withToken(viewer).do(http.MethodGet,
		"/api/v1/relays/"+relay.ID+"/buffer-history", nil, nil, http.StatusForbidden)

	// A relay that does not exist answers the same way to a caller who may
	// read relays: a narrowed scope is not to learn which sites have one.
	h.do(http.MethodGet, "/api/v1/relays/00000000-0000-0000-0000-000000000000/buffer-history",
		nil, nil, http.StatusNotFound)
}
