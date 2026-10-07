//go:build integration

package integration

import (
	"strings"
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
	// A host where the reload has something to load. Offering the adapter is
	// not enough and asking only that was the first version's mistake: it took
	// the first host that offers it, which was agent-arch, where the daemon is
	// not running and /etc/audit/rules.d is empty. The reload there did exactly
	// what it could - nothing - and the panel refused to call that verified,
	// correctly. Measured across the fleet on 07.10: fedora active with one
	// rule in the kernel, ubuntu active with none, arch inactive with none,
	// debian without the daemon at all.
	var target *hostView
	var before securitySnapshot
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" || !hasCapability(host, "security.audit") {
			continue
		}
		snapshot := hostSecuritySnapshot(t, h, host.ID)
		if !snapshot.Audit.Present || snapshot.Audit.Active == nil || !*snapshot.Audit.Active {
			continue
		}
		if snapshot.Audit.RulesLoaded == nil || *snapshot.Audit.RulesLoaded == 0 {
			continue
		}
		candidate := host
		target, before = &candidate, snapshot
		break
	}
	if target == nil {
		absent(t, "no online host runs an audit daemon with a rule in the kernel, so a reload has nothing to load")
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
	} else if before.Audit.RulesLoaded != nil && *after.Audit.RulesLoaded < *before.Audit.RulesLoaded {
		// A reload that ends with fewer rules than it began with has taken
		// protection off the host, which is the direction that matters.
		t.Errorf("%s knew %d audit rules and knows %d after the reload",
			target.Hostname, *before.Audit.RulesLoaded, *after.Audit.RulesLoaded)
	}
	if after.Audit.Active == nil {
		t.Error("after a reload the host does not say whether the daemon is active")
	}
}

// TestAReloadThatLoadsNothingIsNotCalledVerified is the other side, and it is
// the one the fleet actually offers: a host whose audit daemon knows no rule.
// The reload runs - there is nothing wrong with the host - and the panel
// refuses to call the result verified, because "the kernel knows no audit rule
// after the reload" is not the state an operator asked for when they ordered
// the rules reloaded.
//
// Written on 07.10 after the positive case was pointed at agent-arch by
// mistake and this is what came back. A behaviour measured and then left
// undescribed is a behaviour nobody is holding to.
func TestAReloadThatLoadsNothingIsNotCalledVerified(t *testing.T) {
	h := newHarness(t)
	var target *hostView
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" || !hasCapability(host, "security.audit") {
			continue
		}
		snapshot := hostSecuritySnapshot(t, h, host.ID)
		if !snapshot.Audit.Present {
			continue
		}
		if snapshot.Audit.RulesLoaded != nil && *snapshot.Audit.RulesLoaded > 0 {
			continue
		}
		candidate := host
		target = &candidate
		break
	}
	if target == nil {
		absent(t, "every online host with an audit daemon already knows a rule, so none can show an empty reload")
	}

	job, _ := h.runOperation(target.ID, map[string]any{
		"action":  "security.audit.reload",
		"payload": map[string]any{},
	}, 3*time.Minute)
	if job.State == "succeeded" {
		t.Fatalf("the reload on %s loaded no rule and the panel called it succeeded", target.Hostname)
	}
	// And the refusal says what is missing rather than failing blankly: the
	// difference between "it did not work" and "the host now knows no rule" is
	// the whole value of the verifier.
	if !strings.Contains(job.ResultMessage, "audit rule") {
		t.Errorf("the result of an empty reload on %s says %q, which does not name the rules",
			target.Hostname, job.ResultMessage)
	}
}
