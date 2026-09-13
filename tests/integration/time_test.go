//go:build integration

package integration

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

type timeSourceView struct {
	Address       string   `json:"address"`
	State         string   `json:"state"`
	Stratum       *uint32  `json:"stratum"`
	OffsetSeconds *float64 `json:"offset_seconds"`
}

type timeServerView struct {
	Address string `json:"address"`
	Source  string `json:"source"`
	Managed bool   `json:"managed"`
}

type timeProbeView struct {
	Server        string   `json:"server"`
	Reachable     bool     `json:"reachable"`
	OffsetSeconds *float64 `json:"offset_seconds"`
	Error         string   `json:"error"`
}

type timeSnapshot struct {
	Timezone          string           `json:"timezone"`
	Service           string           `json:"service"`
	Unit              string           `json:"unit"`
	Synchronized      *bool            `json:"synchronized"`
	OffsetSeconds     *float64         `json:"offset_seconds"`
	Sources           []timeSourceView `json:"sources"`
	Configured        []timeServerView `json:"configured_servers"`
	ManagedPath       string           `json:"managed_path"`
	ConfigPath        string           `json:"config_path"`
	CanAddSourceDir   bool             `json:"can_add_source_dir"`
	WriteReason       string           `json:"write_reason"`
	UnavailableReason string           `json:"unavailable_reason"`
}

type timeResult struct {
	Kind    string          `json:"kind"`
	Message string          `json:"message"`
	Probes  []timeProbeView `json:"probes"`
}

const timeReason = "integration test of the time module"

// TestTimeShowsTheClockStateNotJustTheDaemon checks that the module answers
// the question "is this host's clock good", not only "is the daemon
// running".
func TestTimeShowsTheClockStateNotJustTheDaemon(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostTimeSnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the time state was not read: %s", state.UnavailableReason)
			}
			if state.Timezone == "" {
				t.Error("the host did not report its time zone")
			}
			if state.Service == "" || state.Unit == "" {
				t.Errorf("the host did not name the time daemon: service=%q unit=%q", state.Service, state.Unit)
			}
			// Unknown is not false: the field is to be filled in or empty,
			// not pose as "not synchronised" when there was no read.
			if state.Synchronized == nil {
				t.Error("the synchronisation state is undetermined despite a running daemon")
			}
			if len(state.Sources) == 0 && len(state.Configured) == 0 {
				t.Error("the host reported neither sources nor configuration entries")
			}
		})
	}
}

// TestTimeSourceTestMeasuresFromTheHost checks that the measurement leaves
// from the host and that a server which did not answer carries a reason
// instead of a zero offset.
func TestTimeSourceTestMeasuresFromTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// One unroutable address from the documentation range and the sources
	// the host really uses: the result is to tell these two cases apart.
	state := hostTimeSnapshot(t, h, host.ID)
	probes := []string{"203.0.113.1"}
	if len(state.Configured) > 0 {
		probes = append(probes, state.Configured[0].Address)
	}

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "time.sync.test", "reason": timeReason,
		"payload": map[string]any{"time": map[string]any{"probe": probes}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("source test: state = %s, %s", job.State, lastMessage(attempts))
	}

	result := jobTimeResult(t, h, job.ID)
	if len(result.Probes) != len(probes) {
		t.Fatalf("measurements = %d, questions = %d", len(result.Probes), len(probes))
	}
	for _, probe := range result.Probes {
		switch {
		case probe.Reachable && probe.OffsetSeconds == nil:
			t.Errorf("server %s answered without an offset measurement", probe.Server)
		case !probe.Reachable && probe.Error == "":
			t.Errorf("server %s is silent without a reason", probe.Server)
		case !probe.Reachable && probe.OffsetSeconds != nil:
			t.Errorf("server %s did not answer, yet has the offset %v",
				probe.Server, *probe.OffsetSeconds)
		}
	}
	// An address from the documentation range never answers; if it did,
	// the measurement would measure something other than assumed.
	for _, probe := range result.Probes {
		if probe.Server == "203.0.113.1" && probe.Reachable {
			t.Error("the unroutable address answered - the test measures something other than it assumes")
		}
	}
}

// TestChangingSourcesRequiresAWorkingSource guards the rule from the
// document: the servers are tested before the host gives up a working
// source.
func TestChangingSourcesRequiresAWorkingSource(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	before := hostTimeSnapshot(t, h, host.ID)
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "time.config.apply", "reason": timeReason,
		"payload": map[string]any{"time": map[string]any{
			"servers": []string{"203.0.113.1", "203.0.113.2"}}},
	}, 3*time.Minute)
	if job.State == "succeeded" {
		t.Fatalf("the panel accepted sources that do not answer: %s", lastMessage(attempts))
	}
	if !strings.Contains(lastMessage(attempts), "answered") {
		t.Errorf("refusal without a reason: %q", lastMessage(attempts))
	}

	// The refusal must not leave the host with half of the change.
	after := hostTimeSnapshot(t, h, host.ID)
	if len(after.Configured) != len(before.Configured) {
		t.Errorf("the server list changed despite the refusal: %d -> %d",
			len(before.Configured), len(after.Configured))
	}
}

// TestTimeZoneChangesAfterACheck checks the whole path of a zone change
// together with the refusals for names the host does not know or that are
// not names.
func TestTimeZoneChangesAfterACheck(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	before := hostTimeSnapshot(t, h, host.ID)

	// A relative path does not reach the host: the order validation
	// rejects it.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "time.timezone.set", "reason": timeReason,
			"payload": map[string]any{"time": map[string]any{"timezone": "../../etc/passwd"}}},
		nil, http.StatusBadRequest)

	// A well-formed name unknown to the host ends with a refusal with a
	// reason.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "time.timezone.set", "reason": timeReason,
		"payload": map[string]any{"time": map[string]any{"timezone": "Europe/Atlantis"}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Error("the panel set a zone the host does not know")
	}
	if !strings.Contains(lastMessage(attempts), "does not know the zone") {
		t.Errorf("refusal without a reason: %q", lastMessage(attempts))
	}

	t.Cleanup(func() {
		if before.Timezone == "" {
			return
		}
		h.runOperation(host.ID, map[string]any{
			"action": "time.timezone.set", "reason": timeReason,
			"payload": map[string]any{"time": map[string]any{"timezone": before.Timezone}},
		}, 2*time.Minute)
	})

	target := "Europe/Warsaw"
	if before.Timezone == target {
		target = "Etc/UTC"
	}
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "time.timezone.set", "reason": timeReason,
		"payload": map[string]any{"time": map[string]any{"timezone": target}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("zone change: state = %s, %s", job.State, lastMessage(attempts))
	}

	after := hostTimeSnapshot(t, h, host.ID)
	if after.Timezone != target {
		t.Errorf("zone after the change = %q, expected %q", after.Timezone, target)
	}
	// A zone change must not move the instant the host lives in.
	if before.OffsetSeconds != nil && after.OffsetSeconds != nil &&
		math.Abs(*after.OffsetSeconds-*before.OffsetSeconds) > 1 {
		t.Errorf("the zone change moved the clock: %v -> %v", *before.OffsetSeconds, *after.OffsetSeconds)
	}
}

// TestPanelDoesNotAppendToSomeoneElsesConfigurationWithoutConsent guards
// the boundary: a host that includes no directory stays read-only until the
// operator agrees to append one line.
func TestPanelDoesNotAppendToSomeoneElsesConfigurationWithoutConsent(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	state := hostTimeSnapshot(t, h, host.ID)
	if !state.CanAddSourceDir {
		t.Skipf("this host already has the panel directory (%s), so there is nothing to append", state.ManagedPath)
	}
	if state.WriteReason == "" {
		t.Error("a read-only host gave no reason")
	}
	// The server must be reachable, otherwise the order falls out at an
	// earlier gate and the test would check something other than intended.
	if len(state.Sources) == 0 {
		t.Skip("the host has no working source to place the order against")
	}

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "time.config.apply", "reason": timeReason,
		"payload": map[string]any{"time": map[string]any{
			"servers": []string{state.Sources[0].Address}}},
	}, 3*time.Minute)
	if job.State == "succeeded" {
		t.Fatal("the panel appended itself to someone else's configuration without consent")
	}
	// The refusal is to name the condition the host does not meet, not
	// only state that it cannot be done.
	if !strings.Contains(lastMessage(attempts), "drop-in") {
		t.Errorf("refusal without a reason: %q", lastMessage(attempts))
	}

	after := hostTimeSnapshot(t, h, host.ID)
	if after.ManagedPath != "" {
		t.Errorf("the panel created its file despite the refusal: %q", after.ManagedPath)
	}
}

func hostTimeSnapshot(t *testing.T, h *harness, hostID string) timeSnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/time", nil, &fragment, http.StatusOK)
	var state timeSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("time snapshot: %v", err)
	}
	return state
}

// jobTimeResult reads the measurements from the last attempt. The
// measurement belongs to the attempt, because it is what knows what the
// host measured and when - the host state will not say that any more.
func jobTimeResult(t *testing.T, h *harness, jobID string) timeResult {
	t.Helper()
	var response struct {
		Items []struct {
			Detail timeResult `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+jobID+"/attempts", nil, &response, http.StatusOK)
	if len(response.Items) == 0 {
		t.Fatal("job without attempts")
	}
	return response.Items[len(response.Items)-1].Detail
}
