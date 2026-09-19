//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

const firewallProofReason = "integration test of the management channel proof"

// TestAnIdempotentRuleStillProvesTheManagementChannel checks the proof that
// disarms the rescue plan of a firewall change.
func TestAnIdempotentRuleStillProvesTheManagementChannel(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostFirewallSnapshot(t, h, host.ID)
	if !state.Writable {
		t.Skip("the host does not allow changing the firewall")
	}
	const name = "proof-test"

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "firewall.rule.remove", "reason": firewallProofReason,
			"payload": map[string]any{"firewall": map[string]any{
				"rule_id": name, "rollback_seconds": 60}},
		}, 2*time.Minute)
	})

	rule := map[string]any{
		"rule_id": name, "chain": "input", "action": "drop",
		"protocol": "tcp", "ports": []string{"27"},
		"sources": []string{"10.10.0.0/16"}, "comment": "proof",
		"rollback_seconds": 60,
	}
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.ensure", "reason": firewallProofReason,
		"payload": map[string]any{"firewall": rule},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("creating the rule: state = %s, %s", job.State, lastMessage(attempts))
	}
	if message := lastMessage(attempts); !strings.Contains(message, "the management channel was proved") {
		t.Fatalf("the change was accepted without a proof in the result: %q", message)
	}

	// The same rule again: nothing to change, and still a proof.
	job, attempts = h.runOperation(host.ID, map[string]any{
		"action": "firewall.rule.ensure", "reason": firewallProofReason,
		"payload": map[string]any{"firewall": rule},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("repeating the rule: state = %s, %s", job.State, lastMessage(attempts))
	}
	message := lastMessage(attempts)
	if !strings.Contains(message, "the management channel was proved") {
		t.Fatalf("a change that changed nothing carries no proof: %q", message)
	}
	// The proof says who acknowledged it and that the rescue plan was let go
	// afterwards, in that order: an operator reading the result is to see what
	// disarmed the rollback.
	if !strings.Contains(message, "acknowledged a control call over mTLS") ||
		!strings.Contains(message, "the rollback was disarmed") {
		t.Fatalf("the proof does not say what it was: %q", message)
	}
}
