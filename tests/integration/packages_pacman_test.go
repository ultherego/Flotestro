//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

const pacmanReason = "integration test of the pacman adapter"

// pacmanHoldPackage is small, present on every Arch installation and of no
// consequence when held for a minute.
const pacmanHoldPackage = "which"

// TestPackageListOnPacman guards that the Arch host answers the package
// read with the pacman adapter: the list is read, its manager is named and
// the inventory carries the same name.
func TestPackageListOnPacman(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("arch")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.list", "reason": pacmanReason,
	}, 5*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the read ended in state %s: %s", job.State, lastMessage(attempts))
	}
	last := attempts[len(attempts)-1]
	if !strings.HasPrefix(last.Message, "read ") || strings.HasPrefix(last.Message, "read 0 packages") {
		// A list that was not read must not look like a host without
		// packages.
		t.Fatalf("the read did not return packages: %q", last.Message)
	}

	fragment := hostSources(h, host.ID)
	if fragment.Manager != "pacman" {
		t.Fatalf("the inventory names the manager %q, expected pacman", fragment.Manager)
	}
	report := hostVulnerabilities(h, host.ID)
	if report.PackageState.PackageCount == 0 {
		t.Fatalf("the panel holds no packages of the host: %+v", report.PackageState)
	}
	// Arch has no vulnerability feed; the assessment says so rather than
	// showing a clean host. The correlator gathers recomputation requests
	// for a dozen seconds, so the answer is awaited rather than read once.
	deadline := time.Now().Add(90 * time.Second)
	for report.State.CoverageReason != "family_unsupported" && time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		report = hostVulnerabilities(h, host.ID)
	}
	if report.State.CoverageReason != "family_unsupported" {
		t.Errorf("coverage reason = %q, expected family_unsupported", report.State.CoverageReason)
	}
}

// TestUpdatePlanOnPacman guards that the plan either comes from checkupdates
// or refuses with the code that names the missing tool - never an empty
// plan pretending there is nothing to do.
func TestUpdatePlanOnPacman(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("arch")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.plan", "reason": pacmanReason,
		"payload": planPayload(false),
	}, 10*time.Minute)
	last := attempts[len(attempts)-1]
	switch job.State {
	case "succeeded":
		if last.Detail == nil || last.Detail.Manager != "pacman" {
			t.Fatalf("the plan does not name pacman: %+v", last.Detail)
		}
		for _, change := range last.Detail.Changes {
			if change.Security {
				t.Errorf("%s is marked as a security update on a host without security metadata",
					change.Name)
			}
		}
	default:
		if last.ErrorCode != "checkupdates_missing" {
			t.Fatalf("the plan ended in state %s with the code %q: %s",
				job.State, last.ErrorCode, last.Message)
		}
		if !capabilityFeature(host, "packages.pacman", "plan") {
			return
		}
		t.Fatal("the host reports the plan feature and refuses to plan")
	}

	// A partial upgrade is a refusal by policy: the whole system upgrades.
	partial, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.plan", "reason": pacmanReason,
		"payload": planPayload(false, pacmanHoldPackage),
	}, 5*time.Minute)
	if partial.State == "succeeded" {
		t.Fatal("a plan narrowed to one package was accepted on Arch")
	}
	if code := attempts[len(attempts)-1].ErrorCode; code != "partial_upgrade_unsupported" {
		t.Fatalf("the partial plan ended with the code %q", code)
	}
}

// TestPackageHoldOnPacman guards that a hold lands in IgnorePkg and comes
// back out.
func TestPackageHoldOnPacman(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("arch")

	hold, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.hold.set", "reason": pacmanReason,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{pacmanHoldPackage}, "hold": true,
		}},
	}, 5*time.Minute)
	if hold.State != "succeeded" {
		t.Fatalf("the hold ended in state %s: %s", hold.State, lastMessage(attempts))
	}
	t.Cleanup(func() {
		h.createOperation(host.ID, map[string]any{
			"action": "packages.hold.set", "reason": pacmanReason,
			"payload": map[string]any{"package_change": map[string]any{
				"packages": []string{pacmanHoldPackage}, "hold": false,
			}},
		})
	})

	release, attempts := h.runOperation(host.ID, map[string]any{
		"action": "packages.hold.set", "reason": pacmanReason,
		"payload": map[string]any{"package_change": map[string]any{
			"packages": []string{pacmanHoldPackage}, "hold": false,
		}},
	}, 5*time.Minute)
	if release.State != "succeeded" {
		t.Fatalf("the release ended in state %s: %s", release.State, lastMessage(attempts))
	}
}

// TestRepositoriesOnPacman guards that the sections of pacman.conf are read
// as sources: core and extra with their mirrors, signatures checked.
func TestRepositoriesOnPacman(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("arch")

	fragment := hostSources(h, host.ID)
	if !fragment.Repositories.Known {
		t.Fatalf("the sources were not read: %s", fragment.Repositories.Reason)
	}
	for _, id := range []string{"core", "extra"} {
		source := findSource(fragment.Repositories.Repositories, id)
		if source == nil {
			t.Fatalf("the source %s is missing: %+v", id, fragment.Repositories.Repositories)
		}
		if source.URL == "" {
			t.Errorf("the source %s has no server from its mirror list", id)
		}
		if !source.Enabled || !source.Signed || source.Managed {
			t.Errorf("the source %s was read as %+v", id, *source)
		}
	}
}

// capabilityFeature reads one feature of one adapter from the host view.
func capabilityFeature(host hostView, name, feature string) bool {
	for _, capability := range host.Capabilities {
		if capability.Name == name {
			return capability.Available && capability.Features[feature]
		}
	}
	return false
}
