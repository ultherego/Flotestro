package release

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// The hole these measure: the suites to be counted were derived from the
// report's own log map, so a report that simply omitted a key declared no such
// suite, the absent log was therefore nothing to answer for, and a bundle whose
// stage list said playwright=pass was accepted with no browser evidence in it
// at all. The counts are left agreeing with the logs that remain, which is what
// made it invisible - the arithmetic of a Go-only run is spotless.

// browserSuiteLog is a browser run of one passing spec, in the shape the
// runner's JSON reporter writes it.
var browserSuiteLog = []byte(`{"suites":[{"title":"panel","specs":` +
	`[{"title":"opens","tests":[{"status":"expected"}]}]}]}`)

// runOfBothSuites is the bundle of a full run of both suites: 309 Go scenarios
// and one browser one, which is the 310 the report's counts claim. Each test
// below spoils exactly one piece of one suite's evidence.
func runOfBothSuites(t *testing.T) (map[string]any, map[string][]byte) {
	t.Helper()
	goLog := goSuiteLog(309, 0)
	screenshot := []byte("\x89PNG\r\n\x1a\nthe panel, as the run left it")
	report := goodReport()
	report["logs"] = map[string]string{
		"go_test_json":    digestOf(goLog),
		"playwright_json": digestOf(browserSuiteLog),
	}
	report["artifacts"] = map[string]string{"panel.png": digestOf(screenshot)}
	files := map[string][]byte{
		"logs/go_test_json":    goLog,
		"logs/playwright_json": browserSuiteLog,
		"artifacts/panel.png":  screenshot,
	}
	return report, files
}

// goOnlyCounts is the arithmetic of the Go suite alone: what a report says once
// the browser suite has been dropped from it.
func goOnlyCounts() map[string]int {
	return map[string]int{
		"discovered": 309, "passed": 309, "failed": 0,
		"skipped": 0, "absent": 0, "not_applicable": 0, "waived": 0,
	}
}

// browserOnlyCounts is the same for the browser suite alone.
func browserOnlyCounts() map[string]int {
	return map[string]int{
		"discovered": 1, "passed": 1, "failed": 0,
		"skipped": 0, "absent": 0, "not_applicable": 0, "waived": 0,
	}
}

// judge is what the checker made of this bundle: the verdict it computed and
// every reason it gave, with a refusal read as a reason of its own so one
// assertion covers both ways a bundle can be turned down.
func judge(t *testing.T, report map[string]any, files map[string][]byte) (string, []string) {
	t.Helper()
	files[evidenceReport] = encode(t, report)
	bundle := bundleOf(t, files)
	_, verdict, reasons, err := CheckGateEvidence(bytes.NewReader(bundle),
		report["sha"].(string), report["tree_hash"].(string))
	if err != nil {
		reasons = append(reasons, err.Error())
	}
	return verdict, reasons
}

// The fixture itself, so the counter-tests below prove what they say: a bundle
// that does back both suites is accepted.
func TestABundleThatBacksBothSuitesIsAccepted(t *testing.T) {
	report, files := runOfBothSuites(t)
	verdict, reasons := judge(t, report, files)
	if verdict != VerdictPass {
		t.Fatalf("the bundle of a complete run reached %q: %v", verdict, reasons)
	}
}

// 1. The stage ran and the report does not name the log at all.
func TestAStageThatRanAndDeclaresNoLogIsRefused(t *testing.T) {
	report, files := runOfBothSuites(t)
	delete(report["logs"].(map[string]string), "playwright_json")
	delete(files, evidenceLogs+"playwright_json")
	report["counts"] = goOnlyCounts()
	verdict, reasons := judge(t, report, files)
	if verdict == VerdictPass {
		t.Fatalf("a run whose report omitted the browser log reached pass: %v", reasons)
	}
	if !containsText(reasons, "declares no playwright_json") {
		t.Fatalf("the reasons do not say the log was never declared: %v", reasons)
	}
}

// 2. The log is declared and the bundle does not carry it.
func TestAStageWhoseLogIsNotInTheBundleIsRefused(t *testing.T) {
	report, files := runOfBothSuites(t)
	delete(files, evidenceLogs+"playwright_json")
	report["counts"] = goOnlyCounts()
	verdict, reasons := judge(t, report, files)
	if verdict == VerdictPass {
		t.Fatalf("a run whose browser log was dropped from the bundle reached pass: %v", reasons)
	}
	if !containsText(reasons, "playwright_json") {
		t.Fatalf("the reasons do not name the missing log: %v", reasons)
	}
}

// 3. The log is declared, carried, and empty.
func TestAStageWhoseLogIsEmptyIsRefused(t *testing.T) {
	report, files := runOfBothSuites(t)
	report["logs"].(map[string]string)["playwright_json"] = digestOf([]byte{})
	files[evidenceLogs+"playwright_json"] = []byte{}
	report["counts"] = goOnlyCounts()
	verdict, reasons := judge(t, report, files)
	if verdict == VerdictPass {
		t.Fatalf("a run whose browser log was empty reached pass: %v", reasons)
	}
	if !containsText(reasons, "carries nothing in it") {
		t.Fatalf("the reasons do not say the log was empty: %v", reasons)
	}
}

// 4. The same three for the Go suite, which had the hole closed for it by a
// rule of its own - one stage, named in one place, which is how the browser
// suite came to be left out.
func TestTheSuiteStageThatRanAndDeclaresNoLogIsRefused(t *testing.T) {
	report, files := runOfBothSuites(t)
	delete(report["logs"].(map[string]string), "go_test_json")
	delete(files, evidenceLogs+"go_test_json")
	report["counts"] = browserOnlyCounts()
	verdict, reasons := judge(t, report, files)
	if verdict == VerdictPass {
		t.Fatalf("a run whose report omitted the Go log reached pass: %v", reasons)
	}
	if !containsText(reasons, "declares no go_test_json") {
		t.Fatalf("the reasons do not say the log was never declared: %v", reasons)
	}
}

// 5.
func TestTheSuiteStageWhoseLogIsNotInTheBundleIsRefused(t *testing.T) {
	report, files := runOfBothSuites(t)
	delete(files, evidenceLogs+"go_test_json")
	report["counts"] = browserOnlyCounts()
	verdict, reasons := judge(t, report, files)
	if verdict == VerdictPass {
		t.Fatalf("a run whose Go log was dropped from the bundle reached pass: %v", reasons)
	}
	if !containsText(reasons, "go_test_json") {
		t.Fatalf("the reasons do not name the missing log: %v", reasons)
	}
}

// 6.
func TestTheSuiteStageWhoseLogIsEmptyIsRefused(t *testing.T) {
	report, files := runOfBothSuites(t)
	report["logs"].(map[string]string)["go_test_json"] = digestOf([]byte{})
	files[evidenceLogs+"go_test_json"] = []byte{}
	report["counts"] = browserOnlyCounts()
	verdict, reasons := judge(t, report, files)
	if verdict == VerdictPass {
		t.Fatalf("a run whose Go log was empty reached pass: %v", reasons)
	}
	if !containsText(reasons, "carries nothing in it") {
		t.Fatalf("the reasons do not say the log was empty: %v", reasons)
	}
}

// The table is what makes the rule a rule, and a stage name misspelled in it
// is the rule switched off: nothing would ever match, and the suite would be
// owed no log again - silently, which is the failure this whole mechanism is
// about.
func TestEverySuiteLogNamesAStageOfAFullRun(t *testing.T) {
	for _, suite := range suiteLogs {
		if !slices.Contains(fullRunStages, suite.Stage) {
			t.Errorf("the suite log %s names the stage %q, which no full run accounts for",
				suite.Key, suite.Stage)
		}
		if suite.Key == "" || suite.Name == "" || suite.Read == nil {
			t.Errorf("the suite log of the stage %s is incomplete: %+v", suite.Stage, suite)
		}
		// And the fixture declares one log per suite, so a suite added to the
		// table is noticed here rather than over a real bundle.
		if _, declared := goodReport()["logs"].(map[string]string)[suite.Key]; !declared {
			t.Errorf("the good report declares no %s, so no test here covers that suite", suite.Key)
		}
	}
}

// 7. And the behaviour that has to survive the rule: a suite that genuinely did
// not run is not asked for a log. Such a run is still a fail - the browser
// suite is one of the stages a full run accounts for - but it is a fail for the
// stage it never reached and not for evidence of a suite nobody ran.
func TestASuiteThatDidNotRunIsNotAskedForItsLog(t *testing.T) {
	report, files := runOfBothSuites(t)
	delete(report["stages"].(map[string]any), "playwright")
	delete(report["logs"].(map[string]string), "playwright_json")
	delete(files, evidenceLogs+"playwright_json")
	report["counts"] = goOnlyCounts()
	report["verdict"] = VerdictFail
	verdict, reasons := judge(t, report, files)
	if verdict != VerdictFail {
		t.Fatalf("a run that never reached the browser suite reached %q: %v", verdict, reasons)
	}
	for _, reason := range reasons {
		if strings.Contains(reason, "declares no playwright_json") ||
			strings.Contains(reason, "browser suite log") {
			t.Fatalf("a suite that did not run was asked for its log: %v", reasons)
		}
	}
	if !containsText(reasons, "never reached the stage playwright") {
		t.Fatalf("the reasons do not name the stage that did not run: %v", reasons)
	}
}
