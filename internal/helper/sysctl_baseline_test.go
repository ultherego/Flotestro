package helper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tomorrow is an expiry far enough ahead that nothing in these tests sweeps
// the record away while they are looking at it.
func tomorrow() time.Time { return time.Now().Add(24 * time.Hour) }

// The record of "what this host held before the change" is what the
// capability binding accepts as the one other value a rollback may set. It is
// written before every execution, and it used to be written over: a second
// execution under the same task identifier wrote down the state the first one
// had left behind, and from then on the original value was no longer a value
// the rollback was allowed to set. The host could not be put back.
//
// The baseline of a task is taken when the task first runs, and never again.
func TestTheSysctlBaselineOfATaskIsWrittenOnce(t *testing.T) {
	sysctlBeforeDir = t.TempDir()

	original := map[string]string{"net.ipv4.ip_forward": "0", "kernel.dmesg_restrict": "0"}
	if err := recordSysctlBefore("task-1", original, tomorrow()); err != nil {
		t.Fatalf("the first baseline was not written: %v", err)
	}

	// The second execution reads the host as the first one left it and offers
	// that as the baseline. It must change nothing.
	afterTheChange := map[string]string{"net.ipv4.ip_forward": "1", "kernel.dmesg_restrict": "1"}
	if err := recordSysctlBefore("task-1", afterTheChange, tomorrow()); err != nil {
		t.Fatalf("a second write was an error, and it should be a no-op: %v", err)
	}

	held := SysctlBefore("task-1")
	for key, want := range original {
		if held[key] != want {
			t.Errorf("the baseline for %s is %q and the host held %q before the change; "+
				"the rollback can no longer put it back", key, held[key], want)
		}
	}

	// A different task keeps its own baseline: this is write-once per task,
	// not write-once for the host.
	other := map[string]string{"net.ipv4.ip_forward": "1"}
	if err := recordSysctlBefore("task-2", other, tomorrow()); err != nil {
		t.Fatalf("another task could not write its own baseline: %v", err)
	}
	if got := SysctlBefore("task-2")["net.ipv4.ip_forward"]; got != "1" {
		t.Errorf("the second task's baseline is %q, want %q", got, "1")
	}
	if got := SysctlBefore("task-1")["net.ipv4.ip_forward"]; got != "0" {
		t.Errorf("the second task overwrote the first task's baseline: %q", got)
	}
}

// TestTheSysctlBaselineOfATaskThatIsOverIsRemoved drives the other half of
// the record's life, which did not exist until 12.10: nothing ever removed
// one.
//
// They accumulated on every host that had ever been given a kernel setting,
// and a record is not inert - the capability binding accepts the values in
// it as the one other set a rollback may write. A record of a task nobody
// can run any more is therefore a standing authorisation with no owner. The
// laboratory had been sweeping the directory before every gate run since
// 11.10, which is exactly why the product's own silence went unnoticed: the
// same four records, three runs in a row, swept and back again.
func TestTheSysctlBaselineOfATaskThatIsOverIsRemoved(t *testing.T) {
	sysctlBeforeDir = t.TempDir()

	// One task still open, one whose moment has passed.
	if err := recordSysctlBefore("open", map[string]string{"kernel.dmesg_restrict": "0"},
		time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("the open task's baseline was not written: %v", err)
	}
	if err := recordSysctlBefore("over", map[string]string{"kernel.dmesg_restrict": "1"},
		time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("the finished task's baseline was not written: %v", err)
	}

	// A record from before the expiry was carried in it, old enough that the
	// only thing to go on is its age.
	ancient := filepath.Join(sysctlBeforeDir, "ancient.json")
	if err := os.WriteFile(ancient, []byte(`{"net.ipv4.ip_forward":"0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-sysctlRecordKeep - time.Hour)
	if err := os.Chtimes(ancient, stale, stale); err != nil {
		t.Fatal(err)
	}

	sweepSysctlBefore(time.Now())

	if got := SysctlBefore("open"); got["kernel.dmesg_restrict"] != "0" {
		t.Errorf("the baseline of a task that can still be rolled back was swept: %+v", got)
	}
	if got := SysctlBefore("over"); got != nil {
		t.Errorf("the baseline of a task nobody can run any more is still there: %+v, "+
			"and the binding would accept those values as a rollback", got)
	}
	if _, err := os.Stat(ancient); !os.IsNotExist(err) {
		t.Error("a record with no expiry, older than the week it is kept for, is still there")
	}

	// The reader understands both shapes: a host upgraded in the middle of a
	// task still has to be able to put that task back.
	old := filepath.Join(sysctlBeforeDir, "oldshape.json")
	if err := os.WriteFile(old, []byte(`{"net.ipv4.ip_forward":"1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := SysctlBefore("oldshape")["net.ipv4.ip_forward"]; got != "1" {
		t.Errorf("a record written before the change reads as %q, want %q", got, "1")
	}

	// And the new shape is the one being written.
	content, err := os.ReadFile(sysctlBeforePath("open"))
	if err != nil {
		t.Fatal(err)
	}
	var record sysctlRecord
	if err := json.Unmarshal(content, &record); err != nil || record.ExpiresAt.IsZero() {
		t.Errorf("the record carries no expiry, so nothing can tell when it stops mattering: %s", content)
	}
}
