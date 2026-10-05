package release

import (
	"strings"
	"testing"
)

// Three more ways a run proved less than its arithmetic says, each measured by
// the reviewer against the pushed tree.
func TestARunCutShortOrFailedOutsideItsTestsEndsTheVerdict(t *testing.T) {
	// A Go process killed after a passing test and before the package's
	// verdict: the package started and never ended.
	cut := []byte(`{"Action":"start","Package":"p"}` + "\n" +
		`{"Action":"run","Package":"p","Test":"TestOne"}` + "\n" +
		`{"Action":"pass","Package":"p","Test":"TestOne"}` + "\n")
	outcome, err := countFromLogs(suiteBytes(cut, nil), requireSuites("go_test_json"))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Counts.Failed != 0 || outcome.Counts.Passed != 1 {
		t.Fatalf("the arithmetic is %+v; the point is that it looks clean", outcome.Counts)
	}
	if !problemSays(outcome.Problems, "the package p started and never reached a verdict") {
		t.Fatalf("the log problems are %v", outcome.Problems)
	}

	// A browser run whose globalTeardown threw: every spec is "expected" and
	// the runner exits 1, with the failure outside any test.
	teardown := []byte(`{"suites":[{"title":"panel","specs":[{"title":"opens","tests":[{"status":"expected"}]}]}],` +
		`"errors":[{"message":"teardown failed","location":{"file":"e2e/global.ts"}}]}`)
	browser, err := countFromLogs(suiteBytes(nil, teardown), requireSuites("playwright_json"))
	if err != nil {
		t.Fatal(err)
	}
	if browser.Counts.Failed != 0 || browser.Counts.Passed != 1 {
		t.Fatalf("the arithmetic of the browser run is %+v", browser.Counts)
	}
	if !problemSays(browser.Problems, "failed outside any test, in e2e/global.ts") {
		t.Fatalf("the log problems are %v", browser.Problems)
	}

	// A browser run with no such errors says nothing extra.
	clean := []byte(`{"suites":[{"title":"panel","specs":[{"title":"opens","tests":[{"status":"expected"}]}]}]}`)
	quiet, err := countFromLogs(suiteBytes(nil, clean), requireSuites("playwright_json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(quiet.Problems) != 0 {
		t.Fatalf("a clean browser run reported %v", quiet.Problems)
	}
}

func problemSays(problems []string, text string) bool {
	for _, problem := range problems {
		if strings.Contains(problem, text) {
			return true
		}
	}
	return false
}
