package release

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The counter-test of the second review, with a real `go test -json` log: every
// test passed and the package failed, so `go test` exited 1 while the
// arithmetic came out spotless. The checker counted scenarios and skipped every
// event with no Test field, which is exactly the shape a package verdict has.
func TestAPackageThatFailedAfterItsTestsPassedEndsTheVerdict(t *testing.T) {
	log, err := os.ReadFile("testdata/package_failure.json")
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := countFromLogs(log, nil, declaredSuites{goSuite: true})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Counts.Failed != 0 || outcome.Counts.Passed != 1 {
		t.Fatalf("the arithmetic of the log is %+v; the point is that it looks clean", outcome.Counts)
	}
	if len(outcome.Problems) != 1 || !strings.Contains(outcome.Problems[0], "the package pkgfail failed") {
		t.Fatalf("the log problems are %v", outcome.Problems)
	}

	// And through the whole checker: a report that matches those counts, over
	// that log, is refused rather than recorded as a pass.
	report := goodReport()
	report["logs"] = map[string]string{"go_test_json": digestOf(log)}
	report["artifacts"] = map[string]string{"integration.log": digestOf([]byte("x"))}
	report["counts"] = map[string]int{
		"discovered": 1, "passed": 1, "failed": 0,
		"skipped": 0, "absent": 0, "not_applicable": 0, "waived": 0,
	}
	bundle := bundleOf(t, map[string][]byte{
		"result.json":               encode(t, report),
		"logs/go_test_json":         log,
		"artifacts/integration.log": []byte("x"),
	})
	_, verdict, reasons, err := CheckGateEvidence(bytes.NewReader(bundle),
		report["sha"].(string), report["tree_hash"].(string))
	if err == nil && verdict == VerdictPass {
		t.Fatal("a run whose package failed came out pass")
	}
	if !containsText(reasons, "the package pkgfail failed") {
		t.Fatalf("the reasons do not name the package: %v (%v)", reasons, err)
	}
}

// A scenario that started and never ended is a suite that was cut off. The
// counts are of what finished, so such a run also comes out looking complete.
func TestAScenarioThatStartedAndNeverEndedEndsTheVerdict(t *testing.T) {
	log := []byte(`{"Action":"run","Package":"p","Test":"TestOne"}` + "\n" +
		`{"Action":"pass","Package":"p","Test":"TestOne"}` + "\n" +
		`{"Action":"run","Package":"p","Test":"TestCutOff"}` + "\n")
	outcome, err := countFromLogs(log, nil, declaredSuites{goSuite: true})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Counts.Discovered != 1 || outcome.Counts.Failed != 0 {
		t.Fatalf("the arithmetic is %+v; the cut-off scenario is not in it", outcome.Counts)
	}
	if len(outcome.Problems) != 1 || !strings.Contains(outcome.Problems[0], "p.TestCutOff started and never ended") {
		t.Fatalf("the log problems are %v", outcome.Problems)
	}
}

// A log with nothing in it is not a run with nothing to report.
func TestALogThatNamesNoScenarioEndsTheVerdict(t *testing.T) {
	outcome, err := countFromLogs([]byte("\n\n"), nil, declaredSuites{goSuite: true})
	if err != nil {
		t.Fatal(err)
	}
	if !problemSays(outcome.Problems, "the Go suite log names no scenario") {
		t.Fatalf("the log problems are %v", outcome.Problems)
	}
	// A log the report names and did not write: zero bytes, and the checker
	// used to read it exactly as it reads a run that carries no log at all.
	zero, err := countFromLogs([]byte{}, nil, declaredSuites{goSuite: true})
	if err != nil {
		t.Fatal(err)
	}
	if !problemSays(zero.Problems, "carries nothing in it") {
		t.Fatalf("a zero-byte log the report names reported %v", zero.Problems)
	}

	// And no logs at all is a different matter: a quick run carries none, and
	// its verdict already says why.
	empty, err := countFromLogs(nil, nil, declaredSuites{})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Problems) != 0 {
		t.Fatalf("a run with no logs reported %v", empty.Problems)
	}
}
