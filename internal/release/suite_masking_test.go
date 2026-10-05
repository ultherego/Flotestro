package release

import "testing"

// One suite cannot stand in for the other. A passing Go suite made an absent
// browser run look like a complete one, and a passing browser run did the same
// for an empty Go log: the totals are what the two came to together, so the
// gap never showed in them.
func TestOneSuiteDoesNotCoverForTheOther(t *testing.T) {
	goLog := goSuiteLog(3, 0)
	browser := []byte(`{"suites":[{"title":"panel","specs":[{"title":"opens","tests":[{"status":"expected"}]}]}]}`)

	// Both declared, both there: nothing to say.
	both, err := countFromLogs(goLog, browser, declaredSuites{goSuite: true, playwright: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(both.Problems) != 0 {
		t.Fatalf("a complete run reported %v", both.Problems)
	}
	if both.Counts.Discovered != 4 {
		t.Fatalf("the two suites came to %d scenarios", both.Counts.Discovered)
	}

	// The browser suite declared and missing, behind a Go suite that passed.
	missingBrowser, err := countFromLogs(goLog, nil, declaredSuites{goSuite: true, playwright: true})
	if err != nil {
		t.Fatal(err)
	}
	if !problemSays(missingBrowser.Problems, "names a browser suite log and the bundle carries nothing") {
		t.Fatalf("a missing browser log behind a passing Go suite reported %v", missingBrowser.Problems)
	}

	// And the other way round.
	missingGo, err := countFromLogs(nil, browser, declaredSuites{goSuite: true, playwright: true})
	if err != nil {
		t.Fatal(err)
	}
	if !problemSays(missingGo.Problems, "names a Go suite log and the bundle carries nothing") {
		t.Fatalf("a missing Go log behind a passing browser run reported %v", missingGo.Problems)
	}

	// A browser log that parses and names nothing, behind a passing Go suite.
	emptyBrowser, err := countFromLogs(goLog, []byte(`{"suites":[]}`),
		declaredSuites{goSuite: true, playwright: true})
	if err != nil {
		t.Fatal(err)
	}
	if !problemSays(emptyBrowser.Problems, "the browser suite log names no scenario") {
		t.Fatalf("an empty browser report reported %v", emptyBrowser.Problems)
	}
}
