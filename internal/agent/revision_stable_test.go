package agent

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/modules/power"
)

func revisionOf(t *testing.T, facts Facts) string {
	t.Helper()
	revision, _, err := facts.Revision()
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	return revision
}

// A host that stands still reports free space, an uptime and a boot time that differ at every
// report; none of that is a change of the host.
func TestWhatMovesByItselfDoesNotMoveTheRevision(t *testing.T) {
	uptime := func(v float64) *float64 { return &v }
	base := Facts{
		Hostname: "agent-debian",
		Hardware: Hardware{CPUCores: 2, RootFSBytes: 100 << 30, RootFSFreeByte: 50 << 30},
		Power:    &power.Snapshot{BootID: "b1", UptimeSeconds: uptime(100), BootedAt: time.Unix(1000, 1)},
	}
	later := base
	later.Hardware.RootFSFreeByte = 50<<30 - 4096
	later.Power = &power.Snapshot{BootID: "b1", UptimeSeconds: uptime(9000), BootedAt: time.Unix(1000, 999)}
	later.CollectedAt = time.Now()
	if revisionOf(t, base) != revisionOf(t, later) {
		t.Fatal("free space, uptime and the moment of the boot moved the revision")
	}
}

func TestWhatIsAChangeOfTheHostStillMovesTheRevision(t *testing.T) {
	base := Facts{Hostname: "agent-debian", Hardware: Hardware{CPUCores: 2, RootFSBytes: 100 << 30}}
	for name, change := range map[string]func(*Facts){
		"a disk that grew":      func(f *Facts) { f.Hardware.RootFSBytes = 200 << 30 },
		"another core count":    func(f *Facts) { f.Hardware.CPUCores = 4 },
		"another boot":          func(f *Facts) { f.BootID = "other" },
		"another host name":     func(f *Facts) { f.Hostname = "renamed" },
		"another power boot id": func(f *Facts) { f.Power = &power.Snapshot{BootID: "b2"} },
	} {
		changed := base
		change(&changed)
		if revisionOf(t, base) == revisionOf(t, changed) {
			t.Errorf("%s left the revision as it was", name)
		}
	}
}

// The counters a firewall rule prints in its own text move with every packet.
func TestTheCountersInTheTextOfARuleDoNotMoveTheRevision(t *testing.T) {
	a := stableForm(map[string]any{"text": "tcp dport 22 counter packets 10 bytes 900 accept"})
	b := stableForm(map[string]any{"text": "tcp dport 22 counter packets 99 bytes 7000 accept"})
	c := stableForm(map[string]any{"text": "tcp dport 23 counter packets 10 bytes 900 accept"})
	if a.(map[string]any)["text"] != b.(map[string]any)["text"] {
		t.Fatal("the counters of a rule moved its text")
	}
	if a.(map[string]any)["text"] == c.(map[string]any)["text"] {
		t.Fatal("another port left the text of the rule as it was")
	}
}
