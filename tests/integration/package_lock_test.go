//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

// The unit the laboratory installs for this scenario. It holds the POSIX record
// lock on /var/lib/dpkg/lock-frontend - the one APT itself takes - and gives it
// up on its own after five minutes, so a holder can never outlive the run that
// started it. It arrives disabled: a lock held outside this test would stop every
// other package scenario on the host.
const dpkgLockUnit = "flotestro-lab-dpkg-lock.service"

// TestALocalLockRefusesThePackageChangeWithoutHanging is the scenario of
// chapter 23: the panel orders a change while the local lock is held.
//
// It was a stub until 02.10, classified absent, on the grounds that the harness
// has no shell on a fleet host. It has something better: the host runs units, and
// starting one is an operation the panel offers. So the lock is taken through the
// product, the refusal is read through the product, and nothing here needs a way
// in that the product does not give an operator.
//
// The unit test beside it is not a substitute and was never evidence for this:
// the checker used flock while APT uses fcntl, and on Linux neither sees the
// other. Measured on agent-debian the same day: with the POSIX lock held by
// another process, flock acquired the file. The scenario is what caught it.
func TestALocalLockRefusesThePackageChangeWithoutHanging(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !capabilityAvailable(host, "packages.apt") {
		absent(t, "the host %s has no apt adapter", host.Hostname)
	}
	if !unitKnownToHost(t, h, host, dpkgLockUnit) {
		absent(t, "the host %s does not have %s; it is installed by provision/fleet-host.sh",
			host.Hostname, dpkgLockUnit)
	}

	// The package goes, so that installing it is a real change. A scenario that
	// planned an installation of something already installed would prove nothing
	// on either side of the lock.
	//
	// Through both approvals: a removal is destructive and one approval leaves it
	// waiting for the second until the wait runs out, which is how this step first
	// failed rather than the thing it prepares for.
	if installedVersionOf(t, h, host.ID, testPackage) != "" {
		removal := h.createOperation(host.ID, map[string]any{
			"action": "packages.remove", "reason": "a clean start for the lock scenario",
			"target_confirmation": host.Hostname,
			"payload": map[string]any{"package_change": map[string]any{
				"packages": []string{testPackage}, "expected_removals": []string{testPackage},
			}},
		})
		if state := h.approve(removal.ID, removal.PayloadHash); state.State == "awaiting_approval" {
			second := h.withToken(h.createPrincipal(uniqueSubject("second-person-lock-scenario"),
				[]map[string]string{{"role": "approver", "site": host.Site, "environment": host.Environment}}))
			second.approve(removal.ID, removal.PayloadHash)
		}
		if gone := h.awaitTerminal(removal.ID, 10*time.Minute); gone.State != "succeeded" {
			t.Fatalf("clearing %s before the scenario ended %s: %s",
				testPackage, gone.State, gone.ResultMessage)
		}
	}

	before := installedVersionOf(t, h, host.ID, testPackage)
	if before != "" {
		t.Fatalf("%s is still installed as %q, so installing it is no change", testPackage, before)
	}

	// The plan comes before the lock, not after. A change is bound to the plan it
	// was approved from, and planning is a read that needs no lock - so taking the
	// lock first would stop the scenario at the step before the one it is about.
	planJob, planAttempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.plan", "reason": "the plan the locked change will be bound to",
		"payload": map[string]any{"package_plan": map[string]any{
			"mode": "install", "only_packages": []string{testPackage}, "refresh_metadata": true,
		}},
	}, 5*time.Minute)
	if planJob.State != "succeeded" {
		t.Fatalf("the plan ended in state %s: %s", planJob.State, lastMessage(planAttempts))
	}
	plan := removalPlanFromAttempts(t, planAttempts)
	if plan.PlanHash == "" {
		t.Fatalf("the plan carries no hash: %+v", plan)
	}
	// A plan with nothing in it would make the whole scenario vacuous: the refusal
	// below would be a refusal to do nothing, and the positive control after it
	// would succeed at doing nothing. The package is removed first for the same
	// reason - on a host that already has it there is no change to plan.
	if len(plan.Changes) == 0 {
		t.Fatalf("the plan of installing %s carries no change, so nothing below would be "+
			"tested: %+v", testPackage, plan)
	}
	change := map[string]any{"package_change": map[string]any{
		"packages": []string{testPackage}, "plan_hash": plan.PlanHash,
	}}

	// Whatever happens, the lock is given back: every later package scenario on
	// this host reads the same file.
	release := func() {
		h.runOperation(host.ID, map[string]any{
			"action": "unit.stop", "reason": "the laboratory gives the dpkg lock back",
			"payload": unitPayload(dpkgLockUnit),
		}, 2*time.Minute)
	}
	t.Cleanup(release)

	start, startAttempts := h.runOperation(host.ID, map[string]any{
		"action": "unit.start", "reason": "holding the dpkg lock for the refusal scenario",
		"payload": unitPayload(dpkgLockUnit),
	}, 2*time.Minute)
	if start.State != "succeeded" {
		t.Fatalf("the lock holder did not start: %s %s", start.State, lastMessage(startAttempts))
	}

	// Bounded, and the bound is the assertion: the point of the scenario is that
	// the change comes back rather than waiting on a lock it cannot have. A
	// timeout here is a failure and not a skip.
	const bound = 3 * time.Minute
	ordered := time.Now()
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.install", "reason": "a change ordered while the lock is held",
		"payload": change,
	}, bound)
	took := time.Since(ordered)

	if job.State == "succeeded" {
		t.Fatalf("the change went through while the lock was held, in %s: %s",
			took.Round(time.Second), lastMessage(attempts))
	}
	if job.ResultErrorCode != "package_manager_locked" {
		t.Fatalf("the refusal is %q, expected package_manager_locked after %s: %s",
			job.ResultErrorCode, took.Round(time.Second), lastMessage(attempts))
	}
	// The message names the file, because that is what tells an operator which
	// lock and therefore who is holding it.
	if message := lastMessage(attempts); !strings.Contains(message, "/var/lib/dpkg/lock-frontend") {
		t.Errorf("the refusal does not name the lock file: %s", message)
	}
	// Nothing was attempted: the refusal is worth having only if it comes before
	// the transaction rather than after half of one.
	if after := installedVersionOf(t, h, host.ID, testPackage); after != before {
		t.Errorf("the refused change moved %s from %q to %q", testPackage, before, after)
	}

	// The positive control. Without it a product that refuses every change for
	// any reason would pass the assertions above.
	release()
	again, againAttempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.install", "reason": "the same change once the lock is free",
		"payload": change,
	}, 10*time.Minute)
	// The whole order has to go through, not merely stop being refused for the
	// lock: accepting any other ending would let a transaction that broke for its
	// own reasons stand in for the proof that the lock was the only obstacle.
	if again.State != "succeeded" {
		t.Fatalf("with the lock free the same change ended %s/%s: %s",
			again.State, again.ResultErrorCode, lastMessage(againAttempts))
	}
	// And the host has to show it. A job that reports success over a package that
	// is not there would be the defect this scenario is placed to catch.
	installed := installedVersionOf(t, h, host.ID, testPackage)
	if installed == "" {
		t.Fatalf("the change succeeded with the lock free and %s is not installed", testPackage)
	}
	t.Logf("refused in %s while held; once free the same order installed %s %s",
		took.Round(time.Second), testPackage, installed)
}

// unitKnownToHost asks the host about the unit rather than assuming the laboratory
// put it there: a scenario that silently tested nothing is worse than one that
// says the state is missing.
func unitKnownToHost(t *testing.T, h *harness, host hostView, unit string) bool {
	t.Helper()
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "unit.status", "reason": "does the host know the laboratory's lock holder",
		"payload": map[string]any{"unit_status": map[string]any{"units": []string{unit}}},
	}, 2*time.Minute)
	message := lastMessage(attempts)
	// systemd says "not-found" of a unit it does not have. A unit it has and is
	// not running is unit_unhealthy, which is the state this one is meant to be in
	// until the scenario starts it - reading that as "missing" skipped the
	// scenario on a host that had everything it needed.
	if strings.Contains(message, "not-found") {
		return false
	}
	if job.State == "succeeded" || job.ResultErrorCode == "unit_unhealthy" {
		return true
	}
	t.Logf("asking %s about %s ended %s/%s: %s", host.Hostname, unit, job.State,
		job.ResultErrorCode, message)
	return false
}

// installedVersionOf reads what the host has installed of one package, through
// the list the panel serves.
func installedVersionOf(t *testing.T, h *harness, hostID, name string) string {
	t.Helper()
	if job, attempts := h.runOperation(hostID, map[string]any{
		"action": "packages.list", "reason": "what the host has installed of one package",
	}, 5*time.Minute); job.State != "succeeded" {
		t.Fatalf("reading the package list: %s %s", job.State, lastMessage(attempts))
	}
	var list struct {
		Items []listedPackage `json:"items"`
	}
	h.get("/api/v1/hosts/"+hostID+"/packages", &list)
	for _, pkg := range list.Items {
		if pkg.Name == name {
			return pkg.Version
		}
	}
	return ""
}
