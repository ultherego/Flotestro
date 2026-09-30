package campaigns

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestAllStatesCoversEveryDeclaredState is the drift guard. It reads the state
// constants out of the package's own source rather than comparing SQL strings,
// so a new state that nobody classified fails here instead of being quietly
// absent from the queries that drive campaigns.
func TestAllStatesCoversEveryDeclaredState(t *testing.T) {
	declared := declaredStates(t)
	for _, name := range []string{"State", "TargetState"} {
		if len(declared[name]) == 0 {
			t.Fatalf("no %s constants were found; the drift guard reads nothing", name)
		}
	}

	var listed []string
	for _, state := range AllStates {
		listed = append(listed, string(state))
	}
	assertSameSet(t, "AllStates", declared["State"], listed)

	// Every target state a query names has to be a declared one; the settled
	// states belong to no set here, so the target sets are checked the other way.
	for _, set := range [][]TargetState{InFlightTargetStates, UnstartedTargetStates,
		OpenTargetStates, ClaimedTargetStates} {
		for _, state := range set {
			if !slices.Contains(declared["TargetState"], string(state)) {
				t.Errorf("the target state %q is in a query set but is not declared", state)
			}
		}
	}
}

// TestStateSetsStayDerivedFromOneAnother pins the relations between the sets,
// so a state added to one of them cannot be forgotten in the others.
func TestStateSetsStayDerivedFromOneAnother(t *testing.T) {
	for _, state := range AllStates {
		open := slices.Contains(UnfinishedStates, state)
		if open == state.Terminal() {
			t.Errorf("the state %q is terminal=%v and unfinished=%v", state, state.Terminal(), open)
		}
	}
	// The one deliberate difference between the two campaign sets.
	if diff := missing(UnfinishedStates, DrivenStates); !slices.Equal(diff, []State{StatePaused}) {
		t.Errorf("DrivenStates differs from UnfinishedStates by %v, want only the paused state", diff)
	}
	// Every state an operator may pause from is a state the campaign can be in
	// while it is not over.
	for _, state := range PausableStates {
		if !slices.Contains(UnfinishedStates, state) {
			t.Errorf("a campaign can be paused from %q, which is not an unfinished state", state)
		}
		if !state.mayBecome(StatePausing) || !state.mayBecome(StatePaused) {
			t.Errorf("Store.Pause takes %q but the transition table refuses it", state)
		}
	}
	if !slices.Equal(OpenTargetStates, slices.Concat(UnstartedTargetStates, InFlightTargetStates)) {
		t.Error("OpenTargetStates is no longer the unstarted hosts plus the ones in flight")
	}
	for _, state := range InFlightTargetStates {
		if !state.UnderWay() {
			t.Errorf("the target state %q is listed as in flight but UnderWay says otherwise", state)
		}
	}
}

// TestTheOrchestratorDrivesACampaignAtTheManualGate is the defect itself: the
// query that decides what the orchestrator handles left the gate out, so a
// campaign waiting for a decision had no deadline and no plan age checked.
func TestTheOrchestratorDrivesACampaignAtTheManualGate(t *testing.T) {
	if !slices.Contains(DrivenStates, StateManualGate) {
		t.Error("the orchestrator does not drive a campaign standing at the manual gate")
	}
	gate := SQLList([]State{StateManualGate})
	if !strings.Contains(activeCampaigns, strings.Trim(gate, "()")) {
		t.Errorf("the active campaigns query does not name the manual gate: %s", activeCampaigns)
	}
}

// TestSQLListRendersAnInList keeps the renderer honest: the queries paste its
// output straight after an "in".
func TestSQLListRendersAnInList(t *testing.T) {
	if got := SQLList([]State{StateRunning, StatePaused}); got != "('running', 'paused')" {
		t.Errorf("SQLList = %s", got)
	}
}

// declaredStates reads the string constants of the named types out of the
// package's source, keyed by type name.
func declaredStates(t *testing.T) map[string][]string {
	t.Helper()
	fileSet := token.NewFileSet()
	packages, err := parser.ParseDir(fileSet, ".", nil, 0)
	if err != nil {
		t.Fatalf("the package source was not parsed: %v", err)
	}
	found := map[string][]string{}
	for _, parsed := range packages {
		for _, file := range parsed.Files {
			for _, decl := range file.Decls {
				general, ok := decl.(*ast.GenDecl)
				if !ok || general.Tok != token.CONST {
					continue
				}
				for _, spec := range general.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					typeName, ok := value.Type.(*ast.Ident)
					if !ok || len(value.Values) != 1 {
						continue
					}
					literal, ok := value.Values[0].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						continue
					}
					text, err := strconv.Unquote(literal.Value)
					if err != nil {
						t.Fatalf("the constant %s does not hold a plain string: %v", value.Names[0], err)
					}
					found[typeName.Name] = append(found[typeName.Name], text)
				}
			}
		}
	}
	return found
}

// assertSameSet reports what each side holds and the other does not.
func assertSameSet(t *testing.T, name string, declared, listed []string) {
	t.Helper()
	for _, state := range declared {
		if !slices.Contains(listed, state) {
			t.Errorf("the state %q is declared but missing from %s", state, name)
		}
	}
	for _, state := range listed {
		if !slices.Contains(declared, state) {
			t.Errorf("%s names %q, which no constant declares", name, state)
		}
	}
}

// missing returns the states of the first set that the second does not hold.
func missing(all, subset []State) []State {
	var gone []State
	for _, state := range all {
		if !slices.Contains(subset, state) {
			gone = append(gone, state)
		}
	}
	return gone
}
