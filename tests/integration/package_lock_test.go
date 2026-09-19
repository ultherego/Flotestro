//go:build integration

package integration

import "testing"

// TestALocalLockRefusesThePackageChangeWithoutHanging is the scenario of
// chapter 23 in which a local administrator is in the middle of an apt
// transaction when the panel orders one: the job is refused with
func TestALocalLockRefusesThePackageChangeWithoutHanging(t *testing.T) {
	t.Skip("the harness cannot hold the dpkg lock on a lab host; the refusal is checked by the unit test TestLockHeldSeesTheFrontendLock")
}
