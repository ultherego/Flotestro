package helper

import (
	"testing"
)

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
	if err := recordSysctlBefore("task-1", original); err != nil {
		t.Fatalf("the first baseline was not written: %v", err)
	}

	// The second execution reads the host as the first one left it and offers
	// that as the baseline. It must change nothing.
	afterTheChange := map[string]string{"net.ipv4.ip_forward": "1", "kernel.dmesg_restrict": "1"}
	if err := recordSysctlBefore("task-1", afterTheChange); err != nil {
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
	if err := recordSysctlBefore("task-2", other); err != nil {
		t.Fatalf("another task could not write its own baseline: %v", err)
	}
	if got := SysctlBefore("task-2")["net.ipv4.ip_forward"]; got != "1" {
		t.Errorf("the second task's baseline is %q, want %q", got, "1")
	}
	if got := SysctlBefore("task-1")["net.ipv4.ip_forward"]; got != "0" {
		t.Errorf("the second task overwrote the first task's baseline: %q", got)
	}
}
