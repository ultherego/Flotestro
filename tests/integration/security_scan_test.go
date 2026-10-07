//go:build integration

package integration

import (
	"testing"
	"time"
)

// Two adapters of the agent had no scenario at all until 06.10: the one behind
// security.scan and the one behind security.audit.reload. The gate's report
// names the adapters a host offered, not the ones anybody wrote a scenario
// against, so an adapter with no test read exactly like an adapter whose tests
// passed. The guard that found it is in internal/release; these are the two
// scenarios it was asking for.

// TestSecurityScanComesFromTheHost orders the scan as an operation - which is
// what the capability "security" is actually for - and asks that the answer be
// about the host rather than a shape with nothing in it. The scan changes
// nothing, so what is checked is the material it brings back.
func TestSecurityScanComesFromTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	if !hasCapability(host, "security") {
		notApplicable(t, "agent-debian", "%s does not offer the security adapter", host.Hostname)
	}

	// The field is "action". It was "action_type" here on the first run, which
	// is the name the *response* carries, so the panel read an empty action and
	// refused with unknown_action and the whole list of the ones it knows. The
	// refusal said exactly what was wrong; the scenario had never run to read
	// it.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action":  "security.scan",
		"payload": map[string]any{},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the scan ended in state %s: %s", job.State, job.ResultMessage)
	}
	if len(attempts) == 0 {
		t.Fatal("the scan succeeded with no attempt recorded, so nothing says a host answered")
	}

	// The panel keeps what the scan found, and what it keeps is the thing an
	// operator reads. A snapshot whose listening set is unknown and whose
	// reason is empty would be the "unknown is not zero" failure in its
	// quietest form: a screen that looks like a host exposing nothing.
	snapshot := hostSecuritySnapshot(t, h, host.ID)
	if !snapshot.ListeningKnown && snapshot.UnavailableReason == "" &&
		len(snapshot.Missing) == 0 {
		t.Error("the scan left the listening set unknown and said nothing about why")
	}
	if snapshot.ListeningKnown && len(snapshot.Listening) == 0 {
		t.Error("a host running sshd and the agent reports nothing listening")
	}
	for _, listener := range snapshot.Listening {
		if listener.Port <= 0 || listener.Protocol == "" {
			t.Errorf("a listener came back without a port or a protocol: %+v", listener)
		}
	}
}

// TestAuditRulesReloadIsOrderedAndRead orders the reload on a host that offers
// the audit adapter. It is a mutation of what the host records, so the point is
// that it is carried out and that the state afterwards is read from the host
// and not assumed - the verifier of this action is VerifierAuditRules, and a
// reload nobody read back is a change nobody saw.
func TestAuditRulesReloadIsOrderedAndRead(t *testing.T) {
	h := newHarness(t)
	var target *hostView
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		if hasCapability(host, "security.audit") {
			candidate := host
			target = &candidate
			break
		}
	}
	if target == nil {
		notApplicable(t, "agent-fedora", "no online host of this run offers the security.audit adapter")
	}

	before := hostSecuritySnapshot(t, h, target.ID)
	if !before.Audit.Present {
		notApplicable(t, "agent-fedora", "%s offers the adapter and reports no audit daemon", target.Hostname)
	}

	job, attempts := h.runOperation(target.ID, map[string]any{
		"action":  "security.audit.reload",
		"payload": map[string]any{},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the reload on %s ended in state %s: %s", target.Hostname, job.State, job.ResultMessage)
	}
	if len(attempts) == 0 {
		t.Fatal("the reload succeeded with no attempt recorded")
	}

	// Read back, from the host. A count that is simply absent after a reload
	// is the state nobody looked at being presented as a state.
	after := hostSecuritySnapshot(t, h, target.ID)
	if !after.Audit.Present {
		t.Fatalf("%s reported an audit daemon before the reload and none after", target.Hostname)
	}
	if after.Audit.RulesLoaded == nil {
		t.Error("after a reload the host reports no number of loaded rules")
	}
	if after.Audit.Active == nil {
		t.Error("after a reload the host does not say whether the daemon is active")
	}
}
