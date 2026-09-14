//go:build integration

package integration

import "testing"

// TestALocalLockRefusesThePackageChangeWithoutHanging is the scenario of
// chapter 23 in which a local administrator is in the middle of an apt
// transaction when the panel orders one: the job is refused with
// package_manager_locked, names the lock, and does not queue behind it.
//
// The harness reaches the lab hosts through the panel only: it has no shell
// or SSH helper, and the operation catalogue - by design - has nothing that
// would hold /var/lib/dpkg/lock-frontend for it. A second panel operation
// on the same host is refused by the helper's own guard before dpkg is ever
// asked, so it does not stand in for a lock held outside the panel either.
// The refusal itself is checked with a real flock in the adapter's unit
// tests (TestLockHeldSeesTheFrontendLock in internal/packages), where the
// lock can be held by the test.
func TestALocalLockRefusesThePackageChangeWithoutHanging(t *testing.T) {
	t.Skip("the harness cannot hold the dpkg lock on a lab host; the refusal is checked by the unit test TestLockHeldSeesTheFrontendLock")
}
