//go:build integration

package integration

import "testing"

// TestALocalLockRefusesThePackageChangeWithoutHanging is the scenario of
// chapter 23: the panel orders a change while the local lock is held.
func TestALocalLockRefusesThePackageChangeWithoutHanging(t *testing.T) {
	// A waiver would fit this better than absent: the substitute evidence
	// already exists and is named below. It stays absent, and the gate stays
	// red on it, until the owner issues the waiver identifier and its expiry.
	absent(t, "the harness cannot hold the dpkg lock on a lab host; "+
		"the refusal is checked by the unit test TestLockHeldSeesTheFrontendLock")
}
