//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

// agentHostView is the part of a host this test reads: which version of the
// agent the host reports and whether it is still there afterwards.
type agentHostView struct {
	ID              string `json:"id"`
	Hostname        string `json:"hostname"`
	AgentVersion    string `json:"agent_version"`
	ConnectionState string `json:"connection_state"`
}

// The artefact refusals of a replacement.
var artefactRefusals = []string{"agent_package_digest_mismatch", "agent_package_unavailable"}

// TestAnAgentUpgradeWithAWrongPackageDigestIsRefusedAndTheAgentKeepsRunning is
// the negative side of chapter 14.
//
// What it measures, and what it cannot: the digest is compared by the agent
// that is being replaced, because an upgrade is always carried out by the old
// one. In the laboratory that agent is deliberately a version behind, so this
// measures the refusal as the previous release wrote it. The version being
// released is measured by the upgrade that succeeds - after which the new
// agent is the one running - and by the unit tests of the helper. The order
// here names the version the repository actually offers rather than the one
// the host already has, so the artefact fetched is the one the release
// publishes; targeting the installed version made the package manager fetch a
// file it already had, which answered a narrower question than anybody
// wanted.
func TestAnAgentUpgradeWithAWrongPackageDigestIsRefusedAndTheAgentKeepsRunning(t *testing.T) {
	defer replacingAgent()()
	h := newHarness(t)
	// A Debian-family host: the digest of a .deb is what its package manager
	// hands the helper, so the comparison is reachable here.
	host := h.hostByFamily("debian")

	var before agentHostView
	h.get("/api/v1/hosts/"+host.ID, &before)
	if before.AgentVersion == "" {
		t.Skip("the host does not report the version of its agent")
	}

	// The version the fleet repository offers. Where that is the version the
	// host already runs - a lab whose candidate has not been published yet -
	// the order names the installed one, and the comparison still happens.
	target, published := h.publishedAgentVersion()
	if !published {
		target = before.AgentVersion
	}
	if target != before.AgentVersion {
		t.Logf("the order targets %s, the host runs %s", target, before.AgentVersion)
	}

	// A digest of the right shape and of nothing the release ever published.
	wrongDigest := strings.Repeat("9f", 32)
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "agent.upgrade",
		"payload": map[string]any{
			"agent_upgrade": map[string]any{
				"target_version": target,
				"package_sha256": wrongDigest,
			},
		},
	}, 6*time.Minute)

	if job.State == "succeeded" {
		t.Fatalf("the upgrade succeeded on a wrong digest: %s", job.ResultMessage)
	}
	if !refusedOnTheArtefact(job.ResultErrorCode) {
		t.Fatalf("the upgrade was refused as %q (%s), expected one of %v",
			job.ResultErrorCode, job.ResultMessage, artefactRefusals)
	}
	// The refusal says what was compared. A digest mismatch an operator
	// cannot read is a release they cannot correct.
	if !strings.Contains(job.ResultMessage, wrongDigest) {
		t.Errorf("the refusal %q does not name the digest the order carried", job.ResultMessage)
	}
	for _, attempt := range attempts {
		if attempt.Status == "succeeded" {
			t.Errorf("attempt %d succeeded although the artefact was refused", attempt.Number)
		}
	}

	// The host is still there, running the version it ran before: a refusal
	// that costs the fleet its agent would be worse than the gap it closes.
	h.awaitConnection(host.ID, 2*time.Minute)
	var after agentHostView
	h.get("/api/v1/hosts/"+host.ID, &after)
	if after.AgentVersion != before.AgentVersion {
		t.Fatalf("the host runs the agent %s after a refused upgrade, it ran %s",
			after.AgentVersion, before.AgentVersion)
	}
	if after.ConnectionState != "online" {
		t.Fatalf("the host is %s after a refused upgrade", after.ConnectionState)
	}

	// The host still takes work: the refusal left neither the package
	// manager nor the helper in a state that blocks the next operation.
	follow, _ := h.runOperation(host.ID, map[string]any{
		"action": "inventory.refresh", "payload": map[string]any{
			"inventory": map[string]any{"modules": []string{"packages"}},
		},
	}, 3*time.Minute)
	if follow.State != "succeeded" {
		t.Errorf("the host refused the next operation after a refused upgrade: %s (%s)",
			follow.State, follow.ResultMessage)
	}
}

// refusedOnTheArtefact says whether the code is one of the refusals that
// leave the host untouched.
func refusedOnTheArtefact(code string) bool {
	for _, refusal := range artefactRefusals {
		if code == refusal {
			return true
		}
	}
	return false
}
