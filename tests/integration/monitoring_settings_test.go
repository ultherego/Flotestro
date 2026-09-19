//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"
)

// The monitoring retentions as a setting of the installation: stored in the
// panel, in force without a restart, and refused before they are stored when
// they would delete readings that are still arriving.

// monitoringSettingsView mirrors GET /api/v1/settings/monitoring.
type monitoringSettingsView struct {
	Effective   monitoringValues `json:"effective"`
	Environment monitoringValues `json:"environment"`
	Stored      struct {
		Present   bool           `json:"present"`
		UpdatedBy string         `json:"updated_by"`
		Revision  int64          `json:"revision"`
		Values    map[string]any `json:"values"`
	} `json:"stored"`
}

type monitoringValues struct {
	RawRetention    string `json:"raw_retention"`
	RollupRetention string `json:"rollup_retention"`
	MaxLateness     string `json:"max_lateness"`
	RawQueryWindow  string `json:"raw_query_window"`
	ClockSkewLimit  string `json:"clock_skew_limit"`
	PartitionsAhead int    `json:"partitions_ahead"`
}

// monitoringWriteResult is the answer of the write and of the dry run.
type monitoringWriteResult struct {
	Valid     *bool            `json:"valid"`
	Code      string           `json:"code"`
	Effective monitoringValues `json:"effective"`
	Impact    struct {
		DroppedPartitions  []string `json:"dropped_raw_partitions"`
		RawSamplesEstimate int64    `json:"raw_samples_estimate"`
		RollupRows         int64    `json:"rollup_rows"`
		Destructive        bool     `json:"destructive"`
	} `json:"impact"`
}

// problemBody is the typed refusal of the API.
type problemBody struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// TestAStoredRetentionIsTheOneTheRunningPanelUses is the gap: the retentions
// used to be flags read once, so changing one meant restarting the control
// plane - a rolling restart on two replicas to change a number. The test
// stores a retention through the panel and reads the status of the same
// running process back until it reports it.
func TestAStoredRetentionIsTheOneTheRunningPanelUses(t *testing.T) {
	h := newHarness(t)

	var before monitoringSettingsView
	h.get("/api/v1/settings/monitoring", &before)
	if before.Effective.RawRetention == "" {
		t.Fatal("the panel reports no raw retention in force")
	}
	original := before.Stored.Values

	// Whatever this fleet was left on is put back, so the next run of the
	// suite starts where this one did.
	t.Cleanup(func() {
		h.do(http.MethodPut, "/api/v1/settings/monitoring",
			restoreBody(original), nil, http.StatusOK)
	})

	inForce, err := time.ParseDuration(before.Effective.RawRetention)
	if err != nil {
		t.Fatalf("the raw retention in force is not a duration: %q", before.Effective.RawRetention)
	}
	// A longer window throws nothing away, so it needs no acknowledgement and
	// leaves the fleet's own samples alone.
	longer := (inForce + 24*time.Hour).String()

	var written monitoringWriteResult
	h.do(http.MethodPut, "/api/v1/settings/monitoring", map[string]any{
		"raw_retention": longer,
		"reason":        "integration test: a retention stored rather than restarted into",
	}, &written, http.StatusOK)
	if written.Effective.RawRetention != longer {
		t.Fatalf("the write answered with %q, not the stored %q", written.Effective.RawRetention, longer)
	}
	if written.Impact.Destructive {
		t.Fatalf("lengthening a retention was reported as throwing data away: %+v", written.Impact)
	}

	// The running process, not the answer of the write: the status block is
	// read from the store the sweep and the gateway read.
	waitForRawRetention(t, h, longer)

	// And it is stored, with the identity that stored it.
	var after monitoringSettingsView
	h.get("/api/v1/settings/monitoring", &after)
	if !after.Stored.Present {
		t.Fatal("the panel reports nothing stored after a write")
	}
	if after.Stored.UpdatedBy == "" {
		t.Fatal("the stored settings do not name who stored them")
	}
	if got := after.Stored.Values["raw_retention"]; got != longer {
		t.Fatalf("the stored raw retention is %v, not %q", got, longer)
	}
	if after.Environment.RawRetention != before.Environment.RawRetention {
		t.Fatalf("storing a value rewrote the environment's: %q became %q",
			before.Environment.RawRetention, after.Environment.RawRetention)
	}
}

// TestASettingThatDeletesWhatIsStillArrivingIsRefusedBeforeItIsStored: the
// validation the panel refuses to start on runs on the write too, and the
// values in force do not move.
func TestASettingThatDeletesWhatIsStillArrivingIsRefusedBeforeItIsStored(t *testing.T) {
	h := newHarness(t)

	var before monitoringSettingsView
	h.get("/api/v1/settings/monitoring", &before)

	// Shorter than the window the panel offers plus the lateness it allows,
	// whatever those are on this fleet.
	window := mustDuration(t, before.Effective.RawQueryWindow)
	lateness := mustDuration(t, before.Effective.MaxLateness)
	impossible := (window + lateness - time.Hour).String()

	var refusal problemBody
	h.do(http.MethodPut, "/api/v1/settings/monitoring", map[string]any{
		"raw_retention":         impossible,
		"acknowledge_data_loss": true,
		"reason":                "integration test: a retention that deletes what is still arriving",
	}, &refusal, http.StatusUnprocessableEntity)
	if refusal.Code != "metrics_retention_too_short" {
		t.Fatalf("the refusal carries the code %q", refusal.Code)
	}

	// Nothing was stored and nothing moved.
	var after monitoringSettingsView
	h.get("/api/v1/settings/monitoring", &after)
	if after.Effective.RawRetention != before.Effective.RawRetention {
		t.Fatalf("a refused write changed the retention in force: %q became %q",
			before.Effective.RawRetention, after.Effective.RawRetention)
	}
	if got := after.Stored.Values["raw_retention"]; got != before.Stored.Values["raw_retention"] {
		t.Fatalf("a refused write changed the stored retention: %v became %v",
			before.Stored.Values["raw_retention"], got)
	}
}

// TestShrinkingARetentionSaysWhatGoesBeforeItIsStored: the preview counts
// what the change removes, and a change that removes something is not made by
// leaving a field at its default.
func TestShrinkingARetentionSaysWhatGoesBeforeItIsStored(t *testing.T) {
	h := newHarness(t)

	var before monitoringSettingsView
	h.get("/api/v1/settings/monitoring", &before)
	window := mustDuration(t, before.Effective.RawQueryWindow)
	lateness := mustDuration(t, before.Effective.MaxLateness)
	inForce := mustDuration(t, before.Effective.RawRetention)

	// The shortest retention this fleet may hold: still valid, and shorter
	// than what is in force, so it is the strongest shrink available here.
	shortest := window + lateness
	if shortest >= inForce {
		t.Skip("the retention in force is already the shortest this fleet allows; nothing to shrink")
	}
	proposal := map[string]any{
		"raw_retention": shortest.String(),
		"reason":        "integration test: what a shrink would drop",
	}

	// The dry run stores nothing and answers with what would go.
	var preview monitoringWriteResult
	h.do(http.MethodPut, "/api/v1/settings/monitoring?dry_run=true", proposal, &preview, http.StatusOK)
	if preview.Valid == nil || !*preview.Valid {
		t.Fatalf("the shortest retention this fleet allows was judged invalid: %+v", preview)
	}
	var untouched monitoringSettingsView
	h.get("/api/v1/settings/monitoring", &untouched)
	if untouched.Effective.RawRetention != before.Effective.RawRetention {
		t.Fatalf("a dry run changed the retention in force: %q became %q",
			before.Effective.RawRetention, untouched.Effective.RawRetention)
	}

	if !preview.Impact.Destructive {
		// A fleet with no history older than the proposal loses nothing, and
		// the write is then an ordinary one; there is no refusal to test.
		return
	}
	var refusal problemBody
	h.do(http.MethodPut, "/api/v1/settings/monitoring", proposal, &refusal, http.StatusConflict)
	if refusal.Code != "metrics_retention_shrink_unacknowledged" {
		t.Fatalf("a shrink that drops readings was refused with the code %q", refusal.Code)
	}
}

// waitForRawRetention reads the status block until the running panel reports
// the retention, without anybody restarting it.
func waitForRawRetention(t *testing.T, h *harness, want string) {
	t.Helper()
	// The replicas re-read the stored settings on their own tick; the one that
	// took the write has them already.
	deadline := time.Now().Add(90 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		var status struct {
			Blocks map[string]struct {
				Facts map[string]any `json:"facts"`
			} `json:"blocks"`
		}
		h.get("/api/v1/status", &status)
		if value, ok := status.Blocks["monitoring"].Facts["raw_retention"].(string); ok {
			last = value
			if value == want {
				return
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("the running panel still reports the raw retention %q, not the stored %q; "+
		"a stored retention that needs a restart is the gap this test covers", last, want)
}

// restoreBody turns the stored values read at the start back into a write
// body. A field nobody had stored comes back empty, which clears it.
func restoreBody(stored map[string]any) map[string]any {
	body := map[string]any{
		"raw_retention":         "",
		"rollup_retention":      "",
		"max_lateness":          "",
		"raw_query_window":      "",
		"clock_skew_limit":      "",
		"partitions_ahead":      0,
		"acknowledge_data_loss": true,
		"reason":                "integration test: the fleet is put back as it was found",
	}
	for key, value := range stored {
		body[key] = value
	}
	return body
}

func mustDuration(t *testing.T, value string) time.Duration {
	t.Helper()
	parsed, err := time.ParseDuration(value)
	if err != nil {
		t.Fatalf("the panel reported %q where a duration was expected: %v", value, err)
	}
	return parsed
}
