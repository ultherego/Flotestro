package vuln

import "testing"

// The lease keeps two instances apart and cannot keep two goroutines of one
// instance apart: Take renews a lease the same instance already holds rather
// than refusing it. So the event-driven recomputation took the lease of the
// cycle running beside it and released it on the way out, and that cycle went
// on without a lease - or stopped. The mutex is what decides inside the
// process (audit of 6c38561, OBS-01, and the regression of its fix).
func TestOnePassOfThisInstanceAtATime(t *testing.T) {
	scheduler := &Scheduler{}
	scheduler.pass.Lock()
	if scheduler.pass.TryLock() {
		t.Fatal("two passes of one instance may run at once")
	}
	scheduler.pass.Unlock()
	if !scheduler.pass.TryLock() {
		t.Fatal("a pass cannot start after the previous one finished")
	}
	scheduler.pass.Unlock()
}
