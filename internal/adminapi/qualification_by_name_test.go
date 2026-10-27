package adminapi

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/opspec"
)

func dockerHost(id string, features map[string]bool) hosts.Host {
	return hosts.Host{
		ID: id, Hostname: id, LifecycleState: "active", ConnectionState: "online",
		Capabilities: hosts.Capabilities{{Name: hosts.CapDocker, Version: 1, Available: true, Features: features}},
	}
}

// An order that names its container reaches only the agents that resolve names: one that reported
// the docker adapter without the feature is closed out with its own reason, one that reported
// nothing is noted as unknown (not as too old), and an order by identifier needs no feature.
func TestAnOrderByNameLeavesOutTheAgentsThatCannotResolveIt(t *testing.T) {
	candidates := []hosts.Host{
		dockerHost("new", map[string]bool{"read": true, "write": true, "name_addressing": true}),
		dockerHost("old", map[string]bool{"read": true, "write": true}),
		{ID: "silent", Hostname: "silent", LifecycleState: "active", ConnectionState: "online"},
	}
	now := time.Now().UTC()

	named := assessCandidatesFor(candidates, opspec.ActionDockerRestart, true, nil, now)
	ready := map[string]bool{}
	for _, host := range named.Ready {
		ready[host.ID] = true
	}
	if !ready["new"] || ready["old"] {
		t.Fatalf("by name the new agent is ready and the old one is not: %v", ready)
	}
	var tooOld []string
	for _, group := range named.Exclusions() {
		if group.Reason == ReasonAgentTooOld {
			tooOld = group.Sample
		}
	}
	if len(tooOld) != 1 || tooOld[0] != "old" {
		t.Fatalf("the old agent is closed out as too old: %v", tooOld)
	}
	for _, note := range named.Notes {
		if note.Reason == ReasonCapabilityUnknown && ready["silent"] {
			return
		}
	}
	t.Fatal("a host that reported no adapter at all is kept and noted as unknown, not closed as too old")
}

func TestAnOrderByIdentifierNeedsNoFeature(t *testing.T) {
	old := dockerHost("old", map[string]bool{"read": true, "write": true})
	got := assessCandidatesFor([]hosts.Host{old}, opspec.ActionDockerRestart, false, nil, time.Now().UTC())
	if len(got.Ready) != 1 {
		t.Fatalf("an order by identifier closed out the old agent: %+v", got.Closed)
	}
	if got := assessCandidates([]hosts.Host{old}, opspec.ActionDockerRestart, nil, time.Now().UTC()); len(got.Ready) != 1 {
		t.Fatal("the plain qualification changed for orders that do not name a container")
	}
}
