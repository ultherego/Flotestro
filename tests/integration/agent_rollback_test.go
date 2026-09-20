//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

// keptArtefactDir is where the helper holds the package file of the version a
// host can go back to.
const keptArtefactDir = "/var/lib/flotestro-helper/agent-upgrade/rollback"

// TestGoingBackReadsTheKeptArtefactAndNotTheRepository is the negative side of
// chapter 14.5: the refusal names the artefact the host kept, not a download.
func TestGoingBackReadsTheKeptArtefactAndNotTheRepository(t *testing.T) {
	h := newHarness(t)
	// A Debian-family host: its manager can fetch the file of a version it
	// already holds, which is what makes both steps reachable here.
	host := h.hostByFamily("debian")

	var before agentHostView
	h.get("/api/v1/hosts/"+host.ID, &before)
	if before.AgentVersion == "" {
		t.Skip("the host does not report the version of its agent")
	}

	// The host is made to keep a way back to the version it runs: the target of
	// this order is a release that exists nowhere, so the order is refused.
	prepare, _ := h.runOperation(host.ID, map[string]any{
		"action": "agent.upgrade",
		"payload": map[string]any{
			"agent_upgrade": map[string]any{
				"target_version":   "99.0.0",
				"package_sha256":   strings.Repeat("9f", 32),
				"rollback_version": before.AgentVersion,
			},
		},
	}, 6*time.Minute)
	if prepare.State == "succeeded" {
		t.Fatalf("a release that exists nowhere was installed: %s", prepare.ResultMessage)
	}
	if prepare.ResultErrorCode == "agent_rollback_unavailable" {
		t.Skipf("the host could not keep the artefact of %s, so there is no kept copy to read: %s",
			before.AgentVersion, prepare.ResultMessage)
	}

	// Going back to the version the host kept, under a digest that matches
	// nothing: the refusal names the kept artefact, not a fresh download.
	wrongDigest := strings.Repeat("9f", 32)
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "agent.upgrade",
		"payload": map[string]any{
			"agent_upgrade": map[string]any{
				"target_version": before.AgentVersion,
				"package_sha256": wrongDigest,
			},
		},
	}, 6*time.Minute)

	if job.State == "succeeded" {
		t.Fatalf("the return succeeded on a wrong digest: %s", job.ResultMessage)
	}
	if job.ResultErrorCode != "agent_kept_artefact_invalid" {
		t.Fatalf("the return was refused as %q (%s), expected agent_kept_artefact_invalid: "+
			"the host went to the repository instead of reading the artefact it kept",
			job.ResultErrorCode, job.ResultMessage)
	}
	// The refusal names the file the host would not install, and it is the kept
	// copy rather than a fresh download.
	if !strings.Contains(job.ResultMessage, keptArtefactDir) {
		t.Errorf("the refusal %q does not name the artefact the host kept under %s",
			job.ResultMessage, keptArtefactDir)
	}
	if !strings.Contains(job.ResultMessage, wrongDigest) {
		t.Errorf("the refusal %q does not name the digest the order carried", job.ResultMessage)
	}
	for _, attempt := range attempts {
		if attempt.Status == "succeeded" {
			t.Errorf("attempt %d succeeded although the kept artefact was refused", attempt.Number)
		}
	}

	// The host is still there, running the version it ran before: a refused
	// return must not cost the fleet its agent.
	h.awaitConnection(host.ID, 2*time.Minute)
	var after agentHostView
	h.get("/api/v1/hosts/"+host.ID, &after)
	if after.AgentVersion != before.AgentVersion {
		t.Fatalf("the host runs the agent %s after a refused return, it ran %s",
			after.AgentVersion, before.AgentVersion)
	}
	if after.ConnectionState != "online" {
		t.Fatalf("the host is %s after a refused return", after.ConnectionState)
	}

	// The host takes work again: the refusal left neither the package manager
	// nor the helper in a state that blocks the next operation.
	follow, _ := h.runOperation(host.ID, map[string]any{
		"action": "inventory.refresh", "payload": map[string]any{
			"inventory": map[string]any{"modules": []string{"packages"}},
		},
	}, 3*time.Minute)
	if follow.State != "succeeded" {
		t.Errorf("the host refused the next operation after a refused return: %s (%s)",
			follow.State, follow.ResultMessage)
	}

	// The artefact the host kept is released once the panel confirms the
	// replacement, and an order that releases it installs nothing.
	release, _ := h.runOperation(host.ID, map[string]any{
		"action": "agent.upgrade",
		"payload": map[string]any{
			"agent_upgrade": map[string]any{
				"target_version":   before.AgentVersion,
				"release_rollback": true,
			},
		},
	}, 3*time.Minute)
	if release.State != "succeeded" {
		t.Fatalf("the host did not release what it kept: %s (%s)",
			release.State, release.ResultMessage)
	}

	// With nothing kept, the same order reaches the repository again and is
	// refused on the digest of the file it downloaded.
	repeated, _ := h.runOperation(host.ID, map[string]any{
		"action": "agent.upgrade",
		"payload": map[string]any{
			"agent_upgrade": map[string]any{
				"target_version": before.AgentVersion,
				"package_sha256": wrongDigest,
			},
		},
	}, 6*time.Minute)
	if !refusedOnTheArtefact(repeated.ResultErrorCode) {
		t.Fatalf("after the release the order was refused as %q (%s), expected one of %v: "+
			"the host still holds an artefact it was told to drop",
			repeated.ResultErrorCode, repeated.ResultMessage, artefactRefusals)
	}
}
