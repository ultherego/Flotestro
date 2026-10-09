package release

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// watchdogLog is the artefact the fleet watchdog writes while the suite runs.
const watchdogLog = "watchdog.log"

// RepairsDuringTheSuite reads the watchdog's log and returns one reason per
// machine it had to touch.
//
// The watchdog reloads a fleet host that stops answering, so that one hung
// machine does not fail every later test for a reason that has nothing to do
// with the commit. That is worth doing, and it was worth printing - but the
// verdict never read it, so a run in which a host was reloaded was recorded as
// a pass. On 08.10 the reload landed inside the scenario that claims a host
// comes back on its own: the test passed because the watchdog brought the host
// back, and the bundle carrying that log was accepted as evidence of a pass.
//
// A repair is not an approved limitation either - nobody signed it, it has no
// expiry - so it is not what "limited" is for. The measurement was helped, and
// a helped measurement measures the help: the run has to be repeated.
//
// What the reasons say is what the log says happened, and no more. The first
// version of this read "reloading it once" as a reload - and on 09.10 the gate
// recorded that over a machine whose boot time proved it had never restarted,
// because vagrant refuses a reload while the suite holds the machine's lock.
// The watchdog now writes whether the reload happened, and a machine that
// stopped answering ends the verdict either way: that is the fact the suite
// ran over, and it is the one worth naming.
func RepairsDuringTheSuite(log []byte) []string {
	var reasons []string
	scanner := bufio.NewScanner(bytes.NewReader(log))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "==") {
			// The header names the machines it watches and the interval; it
			// says nothing was done.
			continue
		}
		when, machine := timeAndMachine(line)
		switch {
		case strings.Contains(line, "has not answered"):
			// The watchdog saw a machine of the fleet stop answering and set
			// about repairing it. Whether the repair worked is the next line's
			// business; either way the suite was running over a fleet that
			// faltered, which is what ends the verdict here.
			reasons = append(reasons, fmt.Sprintf(
				"%s stopped answering at %s while the suite was running, and the watchdog "+
					"stepped in: the tests of this run were measured over a fleet that faltered",
				machine, when))
		case strings.Contains(line, "could not be reloaded"):
			reasons = append(reasons, fmt.Sprintf(
				"the watchdog could not reload %s at %s, so the machine recovered on its own "+
					"or did not recover at all; the run says which only by what its tests did",
				machine, when))
		case strings.Contains(line, "needs a person"),
			strings.Contains(line, "after the reload either"):
			reasons = append(reasons, fmt.Sprintf(
				"%s did not answer after the watchdog reloaded it at %s, so the suite ran "+
					"against an incomplete fleet", machine, when))
		}
	}
	return reasons
}

// timeAndMachine takes the two leading fields the watchdog writes. A line in
// another shape still ends the verdict; it is only named less precisely.
func timeAndMachine(line string) (when, machine string) {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		return fields[0], fields[1]
	}
	return "an unnamed time", "a machine the log does not name"
}
