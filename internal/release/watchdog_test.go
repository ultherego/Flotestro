package release

import (
	"strings"
	"testing"
)

// The line the watchdog really wrote on 08.10, in the bundle that was accepted
// as a pass. It is kept verbatim: a guard written against a shape I invented
// would pass over the shape the lab produces.
const watchdogOn0810 = `== watching agent-debian agent-ubuntu agent-fedora agent-arch every 60s while the suite runs
15:38:33 agent-debian has not answered 3 checks; reloading it once
15:39:41 agent-debian answers again
`

func TestAReloadDuringTheSuiteEndsTheVerdict(t *testing.T) {
	reasons := RepairsDuringTheSuite([]byte(watchdogOn0810))
	if len(reasons) != 1 {
		t.Fatalf("the log of 08.10 names one reload; the reader found %d reasons: %v", len(reasons), reasons)
	}
	for _, want := range []string{"agent-debian", "15:38:33", "repaired fleet"} {
		if !strings.Contains(reasons[0], want) {
			t.Errorf("the reason does not say %q: %s", want, reasons[0])
		}
	}
}

// A watch that saw nothing is the normal case and may not cost a run its
// verdict: the header alone is not an intervention.
func TestAWatchThatTouchedNothingCostsNothing(t *testing.T) {
	quiet := "== watching agent-debian agent-ubuntu every 60s while the suite runs\n"
	if reasons := RepairsDuringTheSuite([]byte(quiet)); len(reasons) != 0 {
		t.Errorf("a quiet watch produced %d reasons: %v", len(reasons), reasons)
	}
	if reasons := RepairsDuringTheSuite(nil); len(reasons) != 0 {
		t.Errorf("no log at all produced %d reasons: %v", len(reasons), reasons)
	}
}

// A machine that stayed dead after the reload is worse than one that came
// back, and the lab writes it in two shapes depending on where it noticed.
func TestAMachineThatStayedDownIsNamedToo(t *testing.T) {
	for _, line := range []string{
		"16:02:11 agent-arch still does not answer after the reload; it needs a person",
		"16:02:11 agent-arch does not answer after the reload either",
	} {
		reasons := RepairsDuringTheSuite([]byte(line + "\n"))
		if len(reasons) != 1 {
			t.Fatalf("%q produced %d reasons", line, len(reasons))
		}
		if !strings.Contains(reasons[0], "agent-arch") ||
			!strings.Contains(reasons[0], "incomplete fleet") {
			t.Errorf("the reason for %q reads: %s", line, reasons[0])
		}
	}
}
