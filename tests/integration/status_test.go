//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// TestStatusJudgesEveryPartOfThePanel checks that the status screen names the
// database as reachable, the schema at its level, the build by its version and
// the durable trail by its queue - and that a block the panel cannot judge is
func TestStatusJudgesEveryPartOfThePanel(t *testing.T) {
	h := newHarness(t)
	var status struct {
		OK      bool `json:"ok"`
		Unknown int  `json:"unknown"`
		Blocks  map[string]struct {
			OK     *bool          `json:"ok"`
			Reason string         `json:"reason"`
			Facts  map[string]any `json:"facts"`
		} `json:"blocks"`
		Links map[string]string `json:"links"`
	}
	h.get("/api/v1/status", &status)

	database, ok := status.Blocks["database"]
	if !ok {
		t.Fatal("the status lacks the database block")
	}
	if database.OK == nil || !*database.OK {
		t.Errorf("the database is not fine: %q", database.Reason)
	}
	if reachable, _ := database.Facts["reachable"].(bool); !reachable {
		t.Error("the database block does not say the database is reachable")
	}
	if _, ok := database.Facts["latency_ms"].(float64); !ok {
		t.Error("the database block lacks the round trip")
	}

	migrations, ok := status.Blocks["migrations"]
	if !ok {
		t.Fatal("the status lacks the migrations block")
	}
	if level, _ := migrations.Facts["level"].(float64); level <= 0 {
		t.Errorf("the migration level is %v; the schema has been migrated", migrations.Facts["level"])
	}

	build, ok := status.Blocks["build"]
	if !ok {
		t.Fatal("the status lacks the build block")
	}
	if version, _ := build.Facts["version"].(string); version == "" {
		t.Error("the build block does not name the version")
	}
	if goVersion, _ := build.Facts["go_version"].(string); goVersion == "" {
		t.Error("the build block does not name the Go version")
	}

	outbox, ok := status.Blocks["outbox"]
	if !ok {
		t.Fatal("the status lacks the outbox block")
	}
	if _, ok := outbox.Facts["pending"].(float64); !ok {
		t.Error("the outbox block does not count the waiting events")
	}
	if _, ok := outbox.Facts["consumers"].([]any); !ok {
		t.Error("the outbox block does not list the consumers")
	}

	// Every block says whether it could be judged; a block without the
	// field would read as fine to a screen that treats absence as false.
	for name, block := range status.Blocks {
		if block.OK == nil && block.Reason == "" {
			t.Errorf("the block %s is unknown without a reason", name)
		}
	}
	for _, name := range []string{"scheduler", "sessions", "certificates", "housekeeping"} {
		if _, ok := status.Blocks[name]; !ok {
			t.Errorf("the status lacks the %s block", name)
		}
	}
	if status.Links["openapi"] == "" || status.Links["metrics"] == "" {
		t.Error("the status does not link the OpenAPI document and the metrics")
	}

	// The screen is for whoever administers the panel, like the settings.
	viewer := h.withToken(h.createPrincipal(uniqueSubject("status-viewer"), []map[string]string{
		{"role": "viewer"},
	}))
	viewer.do(http.MethodGet, "/api/v1/status", nil, nil, http.StatusForbidden)
}

// TestSettingsShowTheRetentionsAndTheSwitches checks that the settings screen
// shows the retentions of the working record next to the trail's and the
// switches the gateway and the scheduler run with.
func TestSettingsShowTheRetentionsAndTheSwitches(t *testing.T) {
	h := newHarness(t)
	var settings struct {
		Areas []struct {
			Key   string `json:"key"`
			Facts []struct {
				Key   string `json:"key"`
				Value any    `json:"value"`
			} `json:"facts"`
		} `json:"areas"`
	}
	h.get("/api/v1/settings", &settings)
	facts := map[string]any{}
	for _, area := range settings.Areas {
		for _, fact := range area.Facts {
			facts[area.Key+"."+fact.Key] = fact.Value
		}
	}
	for _, key := range []string{"retention.jobs", "retention.campaigns", "retention.outbox_events"} {
		if value, _ := facts[key].(string); value == "" {
			t.Errorf("the settings lack %s or show it empty; the working record always has a retention", key)
		}
	}
	if policy, _ := facts["agents.clone_policy"].(string); policy != "report" && policy != "quarantine" {
		t.Errorf("the clone policy is %v; expected report or quarantine", facts["agents.clone_policy"])
	}
	if _, ok := facts["agents.dispatch_rate"].(float64); !ok {
		t.Error("the settings lack the dispatch rate")
	}
	if _, ok := facts["identity.session_group_refresh"].(string); !ok {
		t.Error("the settings lack the session group refresh")
	}
	if _, ok := facts["identity.oidc_admin_logout"].(bool); !ok {
		t.Error("the settings lack the logout switch")
	}
}
