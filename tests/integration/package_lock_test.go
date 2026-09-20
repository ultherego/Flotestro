//go:build integration

package integration

import "testing"

// TestALocalLockRefusesThePackageChangeWithoutHanging is the scenario of
// chapter 23: the panel orders a change while the local lock is held.
func TestALocalLockRefusesThePackageChangeWithoutHanging(t *testing.T) {
	t.Skip("the harness cannot hold the dpkg lock on a lab host; the refusal is checked by the unit test TestLockHeldSeesTheFrontendLock")
}
