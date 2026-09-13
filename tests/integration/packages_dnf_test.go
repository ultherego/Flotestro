//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

const lifecycleReason = "integration test of the package lifecycle"

// testPackage is small, has no dependencies beyond the base system and does
// not belong to anything the host runs. The choice matters: the test
// installs and removes it on a live machine.
const testPackage = "tree"

// TestPackageLifecycleOnDNF guards that installation, the removal plan,
// removal and hold also work where the manager is dnf.
//
// The packages chapter promises APT and DNF adapters; for a long time only
// apt had the full cycle, and Fedora got the refusal "supported only for
// apt".
func TestPackageLifecycleOnDNF(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	// Installation.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.install", "reason": lifecycleReason,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{testPackage},
		}},
	}, 10*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the installation ended in state %s: %+v", job.State, attempts)
	}
	t.Cleanup(func() {
		// The cleanup goes the same way as the rest of the test; when the
		// removal in the test succeeds, this call simply changes nothing.
		h.createOperation(host.ID, map[string]any{
			"action": "packages.remove", "reason": lifecycleReason,
			"target_confirmation": host.Hostname,
			"payload": map[string]any{"package_change": map[string]any{
				"packages": []string{testPackage}, "expected_removals": []string{testPackage},
			}},
		})
	})

	// The removal plan: it is what shows what goes away together with the
	// package.
	plan := dnfRemovalPlan(t, h, host.ID, testPackage)
	if len(plan.Removals) == 0 {
		t.Fatalf("the removal plan is empty: %+v", plan)
	}
	found := false
	for _, name := range plan.Removals {
		if name == testPackage {
			found = true
		}
	}
	if !found {
		t.Fatalf("the plan does not cover the package asked about: %+v", plan.Removals)
	}

	// Removal requires a second person's approval in a production
	// environment and typing in the target name: it is an irreversible
	// operation.
	removal := h.createOperation(host.ID, map[string]any{
		"action": "packages.remove", "reason": lifecycleReason,
		"target_confirmation": host.Hostname,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{testPackage}, "expected_removals": plan.Removals,
		}},
	})
	state := h.approve(removal.ID, removal.PayloadHash)
	if state.State == "awaiting_approval" {
		second := h.withToken(h.createPrincipal(uniqueSubject("second-person-dnf"),
			[]map[string]string{{"role": "approver", "site": host.Site, "environment": host.Environment}}))
		state = second.approve(removal.ID, removal.PayloadHash)
	}
	final := h.awaitTerminal(removal.ID, 10*time.Minute)
	if final.State != "succeeded" {
		t.Fatalf("the removal ended in state %s: %+v", final.State, h.attempts(removal.ID))
	}

	// After the removal the plan has nothing left to remove - and that is an
	// answer, not an error.
	after := dnfRemovalPlan(t, h, host.ID, testPackage)
	if len(after.Removals) != 0 {
		t.Fatalf("after the removal the plan still lists %v", after.Removals)
	}
}

// TestPackageHoldOnDNF guards that a hold also works on dnf - or refuses
// outright when the host has nothing to do it with.
func TestPackageHoldOnDNF(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	hold, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.hold.set", "reason": lifecycleReason,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{"restic"}, "hold": true,
		}},
	}, 5*time.Minute)
	if hold.State != "succeeded" {
		// A host without the versionlock plugin must refuse with an
		// explanation, not silently consider the package held.
		if len(attempts) == 0 || !strings.Contains(attempts[len(attempts)-1].Message, "versionlock") {
			t.Fatalf("the hold ended in state %s without an explanation: %+v",
				hold.State, attempts)
		}
		t.Skip("this host has no versionlock plugin")
	}

	release, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.hold.set", "reason": lifecycleReason,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{"restic"}, "hold": false,
		}},
	}, 5*time.Minute)
	if release.State != "succeeded" {
		t.Fatalf("the release ended in state %s: %+v", release.State, attempts)
	}
}

// TestRemovalPlanDoesNotStayQuietAboutARefusal guards the most dangerous
// mistake this module could make: an empty plan reads as "nothing goes
// away", while a refusal from the manager means something entirely
// different.
func TestRemovalPlanDoesNotStayQuietAboutARefusal(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.plan", "reason": lifecycleReason,
		"payload": map[string]any{"package_plan": map[string]any{
			"mode": "remove", "only_packages": []string{"systemd"},
		}},
	}, 5*time.Minute)

	if job.State == "succeeded" {
		detail := removalPlanFromAttempts(t, attempts)
		// If the manager composed a plan, systemd must be on the protected
		// list.
		if len(detail.Protected) == 0 {
			t.Fatalf("the removal plan for systemd names no protected packages: %+v", detail)
		}
		return
	}
	if len(attempts) == 0 || attempts[len(attempts)-1].Message == "" {
		t.Fatal("the plan was refused without an explanation")
	}
}

func dnfRemovalPlan(t *testing.T, h *harness, hostID, pkg string) packageDetail {
	t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "packages.plan", "reason": lifecycleReason,
		"payload": map[string]any{"package_plan": map[string]any{
			"mode": "remove", "only_packages": []string{pkg},
		}},
	}, 5*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the removal plan ended in state %s: %+v", job.State, attempts)
	}
	return removalPlanFromAttempts(t, attempts)
}

func removalPlanFromAttempts(t *testing.T, attempts []attemptView) packageDetail {
	t.Helper()
	if len(attempts) == 0 || attempts[len(attempts)-1].Detail == nil {
		t.Fatal("the plan job has no result")
	}
	return *attempts[len(attempts)-1].Detail
}
