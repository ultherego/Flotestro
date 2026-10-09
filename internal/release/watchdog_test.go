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

// And the log of 09.10, where the reload the watchdog asked for did not
// happen: vagrant refuses while the suite holds the machine's lock, and the
// boot time of the machine proved it had never restarted. The first reader
// called this "the watchdog reloaded agent-debian", which was not true.
const watchdogOn0910 = `== watching agent-debian agent-ubuntu agent-fedora agent-arch every 60s while the suite runs
12:03:26 agent-debian has not answered 3 checks; reloading it once
12:03:40 agent-debian could not be reloaded: An action 'reload' was attempted on the machine 'agent-debian', but another process is already executing an action on the machine.
12:04:33 agent-debian answers again
`

func TestAReloadDuringTheSuiteEndsTheVerdict(t *testing.T) {
	reasons := RepairsDuringTheSuite([]byte(watchdogOn0810))
	if len(reasons) != 1 {
		t.Fatalf("the log of 08.10 names one reload; the reader found %d reasons: %v", len(reasons), reasons)
	}
	for _, want := range []string{"agent-debian", "15:38:33", "faltered"} {
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

// A reload that did not happen is named as that, and the machine that stopped
// answering still ends the verdict: the suite ran over a fleet that faltered
// whether or not the repair worked.
func TestAReloadThatDidNotHappenIsNotCalledOne(t *testing.T) {
	reasons := RepairsDuringTheSuite([]byte(watchdogOn0910))
	if len(reasons) != 2 {
		t.Fatalf("the log of 09.10 names a machine that stopped answering and a reload that "+
			"failed; the reader found %d reasons: %v", len(reasons), reasons)
	}
	joined := strings.Join(reasons, " | ")
	for _, want := range []string{"stopped answering at 12:03:26", "could not reload agent-debian"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the reasons do not say %q: %s", want, joined)
		}
	}
	// And they must not claim the reload happened.
	for _, wrong := range []string{"was reloaded", "repaired fleet"} {
		if strings.Contains(joined, wrong) {
			t.Errorf("the reasons say %q over a reload that was refused: %s", wrong, joined)
		}
	}
}

// A reload that did happen says so, and the machine that needed it is still
// the reason the run is not a pass.
func TestAReloadThatHappenedIsNamedOnce(t *testing.T) {
	log := `12:03:26 agent-debian has not answered 3 checks; reloading it once
12:04:10 agent-debian was reloaded
12:04:33 agent-debian answers again
`
	reasons := RepairsDuringTheSuite([]byte(log))
	if len(reasons) != 1 {
		t.Fatalf("a reload that worked gives one reason; got %d: %v", len(reasons), reasons)
	}
	if !strings.Contains(reasons[0], "stopped answering") {
		t.Errorf("the reason does not name what happened: %s", reasons[0])
	}
}
