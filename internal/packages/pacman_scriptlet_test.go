package packages

import (
	"slices"
	"testing"
)

// The output is what pacman printed on agent-arch on 02.10, installing a package
// whose post_install returns 1. The exit code was zero.
const pacmanBrokenInstall = `resolving dependencies...
looking for conflicting packages...

Packages (1) flotestro-lab-broken-1.0.0-1

:: Processing package changes...
installing flotestro-lab-broken...
flotestro-lab-broken: the maintainer script of this package fails by design; it exists so the fleet can be tested against a broken transaction
error: command failed to execute correctly
:: Running post-transaction hooks...
(1/1) Arming ConditionNeedsUpdate...
`

func TestTheFailedScriptletIsAttributedToThePackageBeingInstalled(t *testing.T) {
	got := PacmanScriptletFailures(pacmanBrokenInstall)
	if want := []string{"flotestro-lab-broken"}; !slices.Equal(got, want) {
		t.Errorf("scriptlet failures = %v, want %v", got, want)
	}
}

func TestAnInstallationWithoutAFailedScriptletNamesNobody(t *testing.T) {
	clean := `:: Processing package changes...
installing flotestro-lab-broken...
:: Running post-transaction hooks...
(1/1) Arming ConditionNeedsUpdate...
`
	if got := PacmanScriptletFailures(clean); len(got) != 0 {
		t.Errorf("scriptlet failures = %v over a transaction that printed no failure", got)
	}
}

// A hook that fails prints the same line, after a marker of its own. Blaming the
// last package pacman happened to touch would name an innocent one.
func TestAFailedHookIsNotBlamedOnTheLastPackage(t *testing.T) {
	hook := `:: Processing package changes...
installing flotestro-lab-broken...
:: Running post-transaction hooks...
(1/2) Arming ConditionNeedsUpdate...
error: command failed to execute correctly
`
	if got := PacmanScriptletFailures(hook); len(got) != 0 {
		t.Errorf("scriptlet failures = %v for a hook's failure", got)
	}
}

func TestEveryOperationPacmanNamesCanCarryAFailure(t *testing.T) {
	for _, verb := range []string{"installing", "upgrading", "downgrading",
		"reinstalling", "removing"} {
		output := verb + " somepkg...\nerror: command failed to execute correctly\n"
		got := PacmanScriptletFailures(output)
		if want := []string{"somepkg"}; !slices.Equal(got, want) {
			t.Errorf("%s: scriptlet failures = %v, want %v", verb, got, want)
		}
	}
}

// Prose that happens to begin with one of the verbs is not a progress line.
func TestASentenceIsNotAProgressLine(t *testing.T) {
	output := "installing packages takes a while\nerror: command failed to execute correctly\n"
	if got := PacmanScriptletFailures(output); len(got) != 0 {
		t.Errorf("scriptlet failures = %v from prose", got)
	}
}

// Why the adapter reads the combined output and not the two streams joined.
//
// pacman prints its progress on stdout and the failure on stderr. Joined stream
// by stream, every operation line comes first and every error after, so the
// error of a package arrives when the parser has already passed ":: Running
// post-transaction hooks..." and holds nobody - and the report then said a
// transaction had gone through over a package left half configured. 02.10: the
// arch scenario failed with "scriptlet errors = []" against a host that had just
// printed the failure.
func TestTheTwoStreamsJoinedApartLoseThePackage(t *testing.T) {
	stdout := `:: Processing package changes...
installing flotestro-lab-broken...
:: Running post-transaction hooks...
(1/1) Arming ConditionNeedsUpdate...
`
	stderr := `flotestro-lab-broken: the maintainer script fails by design
error: command failed to execute correctly
`
	if got := PacmanScriptletFailures(stdout + "\n" + stderr); len(got) != 0 {
		t.Errorf("joined apart the parser named %v; the test below is what the "+
			"adapter must rely on instead", got)
	}
	// The same lines in the order they were written.
	combined := `:: Processing package changes...
installing flotestro-lab-broken...
flotestro-lab-broken: the maintainer script fails by design
error: command failed to execute correctly
:: Running post-transaction hooks...
(1/1) Arming ConditionNeedsUpdate...
`
	got := PacmanScriptletFailures(combined)
	if want := []string{"flotestro-lab-broken"}; !slices.Equal(got, want) {
		t.Errorf("from the combined output: %v, want %v", got, want)
	}
}
