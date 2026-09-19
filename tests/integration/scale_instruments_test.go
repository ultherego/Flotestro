//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

// The instruments a panel is judged by at fleet scale. Without them nobody can
// say whether ten thousand sessions fit in the budget: the resident set was

// TestTheExpositionCarriesTheProcessInstruments checks that the panel measures
// itself from the host rather than from the Go runtime.
func TestTheExpositionCarriesTheProcessInstruments(t *testing.T) {
	h := newHarness(t)
	text := h.text("/metrics")

	for _, name := range []string{
		"flotestro_process_resident_bytes",
		"flotestro_process_open_fds",
		"flotestro_process_max_fds",
		"flotestro_process_cpu_seconds_total",
		"flotestro_gc_pause_seconds_total",
		"flotestro_gc_cycles_total",
		"flotestro_go_memory_reserved_bytes",
	} {
		if !strings.Contains(text, "# TYPE "+name+" ") {
			t.Errorf("the exposition lacks %s", name)
		}
	}
	// The resident set says where it was measured; a number without a source
	// cannot be compared between a container and a native installation.
	if !strings.Contains(text, `flotestro_process_resident_bytes{source="`) {
		t.Error("the resident set does not name its source")
	}
	// The old name read as the resident set while it carried reserved address
	// space, which is the reading the measurement chapter forbids.
	if strings.Contains(text, "# TYPE flotestro_memory_bytes ") {
		t.Error("the panel still exposes flotestro_memory_bytes")
	}
	for _, name := range []string{
		"flotestro_metric_sample_ack_seconds",
		"flotestro_heartbeat_seconds",
		"flotestro_task_ack_seconds",
	} {
		if !strings.Contains(text, "# TYPE "+name+" histogram") {
			t.Errorf("the gateway latency %s is not a histogram", name)
		}
	}
}

// TestTheStatusCarriesTheDatabaseFactsOfScale checks the numbers beside the
// connection budget: what waits on a lock, where the WAL stands and how many
func TestTheStatusCarriesTheDatabaseFactsOfScale(t *testing.T) {
	h := newHarness(t)
	var status struct {
		Blocks map[string]struct {
			Facts map[string]any `json:"facts"`
		} `json:"blocks"`
	}
	h.get("/api/v1/status", &status)

	database, ok := status.Blocks["database"]
	if !ok {
		t.Fatal("the status lacks the database block")
	}
	for _, fact := range []string{"lock_waiters", "locks_ungranted", "lock_wait_seconds_max"} {
		if _, ok := database.Facts[fact].(float64); !ok {
			t.Errorf("the database block lacks %s", fact)
		}
	}
	if lsn, _ := database.Facts["wal_lsn"].(string); lsn == "" {
		t.Error("the database block does not say where the WAL stands")
	}
	if _, ok := database.Facts["wal_bytes_total"].(float64); !ok {
		t.Error("the database block lacks the bytes behind the WAL")
	}
	if _, ok := database.Facts["inserts_total"].(float64); !ok {
		t.Error("the database block lacks the rows inserted")
	}

	// The rates are the distance between two readings, and a distance shorter
	// than a second is a rounding error rather than a rate.
	time.Sleep(1200 * time.Millisecond)
	h.get("/api/v1/status", &status)
	database = status.Blocks["database"]
	for _, fact := range []string{"wal_bytes_per_second", "inserts_per_second"} {
		if _, ok := database.Facts[fact].(float64); !ok {
			t.Errorf("a second reading still lacks %s", fact)
		}
	}
}
