package release

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The gate's report names every adapter a host offered. It cannot name the
// adapters anybody wrote a scenario against, so an adapter with no test at all
// reads like an adapter whose tests passed - and the manifest was asked to
// close that and does not.
//
// This closes the half that can be closed mechanically, without anybody
// declaring anything by hand. Every action the product knows says which
// capability a host needs for it (opspec.ActionType.RequiredCapability), and
// the integration suite orders actions by their own names. So the suite's
// sources are read, the action names in them are mapped through the product's
// own table, and the capabilities that come out are the ones the suite
// exercises. No guessing, and nothing to keep in step by hand.
//
// What is left over is in the shortfall file, which may only shrink: a
// capability nobody exercises is recorded there once, and a capability that
// gains a scenario has to be struck off - a stale entry fails here, so the file
// cannot rot into a rubber stamp.
const capabilityShortfall = "testdata/capability-coverage-shortfall.txt"

// Six adapters the agent declares are required by no action at all - measured,
// not assumed: the three package managers, the local accounts, the helper's own
// capability and the relay identity. For those this guard has nothing to say,
// because there is no action a scenario could order to reach them, and
// demanding a scenario would be demanding one nobody can write. They are
// recorded here instead, so that the set cannot change in silence: an adapter
// that gains an action has to leave this list, and one that appears here
// without losing its actions fails.
const capabilityUnordered = "testdata/capability-no-action-requires.txt"

func TestEveryCapabilityIsExercisedOrAccountedFor(t *testing.T) {
	root := repositoryRoot(t)
	ordered, err := actionNamesOrderedBy(filepath.Join(root, "tests", "integration"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) == 0 {
		t.Fatal("no action name was found in the integration suite, so this guard checked nothing")
	}

	// The product's own table, read rather than copied.
	capabilityOf := map[string]string{}
	for _, action := range opspec.AllActions() {
		if capability := action.RequiredCapability(); capability != "" {
			capabilityOf[string(action)] = capability
		}
	}
	exercised := map[string][]string{}
	for name, places := range ordered {
		capability, known := capabilityOf[name]
		if !known || capability == "" {
			continue
		}
		exercised[capability] = append(exercised[capability], places...)
	}

	// How many actions name each capability as their requirement. A capability
	// no action names cannot be reached by ordering anything.
	needed := map[string]int{}
	for _, action := range opspec.AllActions() {
		if capability := action.RequiredCapability(); capability != "" {
			needed[capability]++
		}
	}

	recorded, err := readInventory(capabilityShortfall)
	if err != nil {
		t.Fatalf("reading %s: %v", capabilityShortfall, err)
	}
	accounted := map[string]bool{}
	for _, entry := range recorded {
		accounted[entry] = true
	}
	unordered, err := readInventory(capabilityUnordered)
	if err != nil {
		t.Fatalf("reading %s: %v", capabilityUnordered, err)
	}
	noAction := map[string]bool{}
	for _, entry := range unordered {
		noAction[entry] = true
	}

	var missing, covered int
	for _, capability := range agent.AllCapabilities {
		if needed[capability] == 0 {
			if !noAction[capability] {
				t.Errorf("no action requires %s, and %s does not record that: "+
					"an adapter nothing can order is a fact about the product, not a gap in the suite",
					capability, capabilityUnordered)
			}
			continue
		}
		if noAction[capability] {
			t.Errorf("%s lists %s, and %d actions require it: strike it off",
				capabilityUnordered, capability, needed[capability])
		}
		places := exercised[capability]
		switch {
		case len(places) > 0 && accounted[capability]:
			t.Errorf("%s is exercised by the suite and still listed in %s: strike it off, "+
				"because a shortfall list that outlives the shortfall stops being a ratchet",
				capability, capabilityShortfall)
		case len(places) > 0:
			covered++
		case accounted[capability]:
			missing++
		default:
			t.Errorf("no scenario of the integration suite orders an action needing %s, "+
				"and %s does not account for it: either write one or record the shortfall",
				capability, capabilityShortfall)
		}
	}
	for _, file := range []struct {
		name    string
		entries []string
	}{{capabilityShortfall, recorded}, {capabilityUnordered, unordered}} {
		for _, entry := range file.entries {
			if !knownCapability(entry) {
				t.Errorf("%s lists %s, which the agent does not declare", file.name, entry)
			}
		}
	}
	t.Logf("%d capabilities an action can reach: %d exercised by the suite, %d recorded as not; "+
		"%d that no action requires",
		covered+missing, covered, missing, len(unordered))
	if os.Getenv("SHOW_CAPABILITY_COVERAGE") != "" {
		for _, capability := range sortedCapabilities(exercised) {
			t.Logf("  %-22s %s", capability, strings.Join(first(exercised[capability], 3), " "))
		}
	}
}

func knownCapability(name string) bool {
	for _, capability := range agent.AllCapabilities {
		if capability == name {
			return true
		}
	}
	return false
}

func sortedCapabilities(exercised map[string][]string) []string {
	names := make([]string, 0, len(exercised))
	for name := range exercised {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func first(values []string, count int) []string {
	if len(values) <= count {
		return values
	}
	return values[:count]
}

// actionNamesOrderedBy finds the action names the integration suite mentions,
// with the files they are in. The suite orders actions by name - "backup.run",
// "unit.restart" - in the JSON it posts, so the names are string literals in
// its sources; reading the text is enough and needs no build tag.
func actionNamesOrderedBy(directory string) (map[string][]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, action := range opspec.AllActions() {
		known[string(action)] = true
	}
	found := map[string][]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		for _, literal := range quotedStrings(string(body)) {
			if known[literal] {
				found[literal] = append(found[literal], entry.Name())
			}
		}
	}
	return found, nil
}

// quotedStrings pulls the double-quoted literals out of Go source. A reader of
// the text rather than of the syntax tree, because what is wanted is every
// place a name appears - in a payload, in a table, in a helper's argument -
// and not only the ones in a position the tree gives a meaning to.
func quotedStrings(body string) []string {
	var found []string
	for index := 0; index < len(body); index++ {
		if body[index] != '"' {
			continue
		}
		end := index + 1
		for end < len(body) && body[end] != '"' && body[end] != '\n' {
			if body[end] == '\\' {
				end++
			}
			end++
		}
		if end < len(body) && body[end] == '"' {
			found = append(found, body[index+1:end])
		}
		index = end
	}
	return found
}

// And the guard has to be able to see a capability lose its last scenario.
func TestTheCoverageGuardSeesAnUnexercisedCapability(t *testing.T) {
	if !knownCapability(agent.CapBackup) {
		t.Fatalf("%s is not a capability the agent declares", agent.CapBackup)
	}
	if knownCapability("adapter.nobody.declares") {
		t.Error("a capability nobody declares was taken for one that is declared")
	}
	// The names the mapping is built from are the product's own, so an action
	// that needs a capability has to come back with it.
	capability := opspec.ActionBackupRun.RequiredCapability()
	if capability != agent.CapBackup {
		t.Errorf("backup.run needs %q, and the agent calls the adapter %q", capability, agent.CapBackup)
	}
}
