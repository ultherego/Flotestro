package release

import (
	"encoding/json"
	"strings"
	"testing"
)

// A report of a run that proves what it says it proves. The tests below take
// this and spoil one thing at a time.
func goodReport() map[string]any {
	return map[string]any{
		"schema_version":    GateSchemaVersion,
		"sha":               "0123456789abcdef0123456789abcdef01234567",
		"tree_hash":         "89abcdef0123456789abcdef0123456789abcdef",
		"tree_clean":        true,
		"quick":             false,
		"harness_digest":    "sha256:" + strings.Repeat("a", 64),
		"lab_config_digest": "sha256:" + strings.Repeat("b", 64),
		"started_at":        "2026-09-29T08:00:00+02:00",
		"finished_at":       "2026-09-29T09:12:00+02:00",
		"commands":          []string{"go test -json -count=1 ./tests/integration/"},
		"hosts": []map[string]string{
			{"name": "agent-debian", "distribution": "debian", "version": "13"},
			{"name": "agent-fedora", "distribution": "fedora", "version": "42"},
		},
		"agents": []map[string]string{
			{"host": "agent-debian", "version_before": "0.61.0", "version_after": "0.62.0"},
		},
		// Every stage a full run accounts for: a report that names only some of
		// them is a run that stopped, and the verdict has to say so.
		"stages": map[string]any{
			"tree":        map[string]any{"result": "pass", "seconds": 1},
			"gofmt":       map[string]any{"result": "pass", "seconds": 3},
			"panel":       map[string]any{"result": "pass", "seconds": 97},
			"web":         map[string]any{"result": "pass", "seconds": 24},
			"vitest":      map[string]any{"result": "pass", "seconds": 70},
			"agents":      map[string]any{"result": "pass", "seconds": 60},
			"relay":       map[string]any{"result": "pass", "seconds": 2},
			"preflight":   map[string]any{"result": "pass", "seconds": 57},
			"integration": map[string]any{"result": "pass", "seconds": 2100},
			"playwright":  map[string]any{"result": "pass", "seconds": 110},
		},
		"counts": map[string]int{
			"discovered": 310, "passed": 310, "failed": 0,
			"skipped": 0, "absent": 0, "not_applicable": 0, "waived": 0,
		},
		"skips":   []map[string]string{},
		"logs":    map[string]string{"go_test_json": "sha256:" + strings.Repeat("c", 64)},
		"verdict": "pass",
	}
}

func encode(t *testing.T, report map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The bug this schema exists for: a report with no "quick" field used to be
// read as a full run, so the absence of the evidence was the evidence.
func TestAReportThatIsSilentAboutQuickIsRefused(t *testing.T) {
	report := goodReport()
	delete(report, "quick")
	_, err := ParseGateReport(encode(t, report))
	if err == nil {
		t.Fatal("a report with no quick field was accepted")
	}
	if !strings.Contains(err.Error(), "quick") {
		t.Fatalf("the refusal does not name the missing field: %v", err)
	}
}

// Every field the verdict leans on has to be present as a field.
func TestEveryRequiredFieldIsRequiredByItsPresence(t *testing.T) {
	for _, key := range gateRequiredKeys {
		report := goodReport()
		delete(report, key)
		if _, err := ParseGateReport(encode(t, report)); err == nil {
			t.Errorf("a report with no %q was accepted", key)
		}
	}
}

func TestAGoodReportPasses(t *testing.T) {
	_, verdict, reasons, err := CheckGateReport(encode(t, goodReport()), "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	if verdict != VerdictPass {
		t.Fatalf("verdict %q, reasons %v", verdict, reasons)
	}
}

func TestAQuickRunIsNeverAPass(t *testing.T) {
	report := goodReport()
	report["quick"] = true
	report["verdict"] = "fail"
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatal(err)
	}
	verdict, reasons := parsed.ComputeVerdict()
	if verdict != VerdictFail {
		t.Fatalf("a quick run reached %q", verdict)
	}
	if len(reasons) == 0 || !strings.Contains(reasons[0], "quick") {
		t.Fatalf("the reasons do not name the quick run: %v", reasons)
	}
}

func TestASkipWithoutAClassIsAFailure(t *testing.T) {
	report := goodReport()
	report["skips"] = []map[string]string{{"test": "TestDnfUpgrade", "reason": "no dnf here"}}
	report["counts"] = map[string]int{
		"discovered": 310, "passed": 309, "failed": 0,
		"skipped": 1, "absent": 0, "not_applicable": 0, "waived": 0,
	}
	report["verdict"] = "fail"
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatal(err)
	}
	verdict, reasons := parsed.ComputeVerdict()
	if verdict != VerdictFail {
		t.Fatalf("an unclassified skip reached %q", verdict)
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "which kind of skip") {
		t.Fatalf("unexpected reasons: %v", reasons)
	}
}

func TestAnAbsentConditionIsAFailure(t *testing.T) {
	report := goodReport()
	report["skips"] = []map[string]string{
		{"test": "TestRelayCarriesAJob", "class": SkipAbsent, "reason": "no relay answered"},
	}
	report["counts"] = map[string]int{
		"discovered": 310, "passed": 309, "failed": 0,
		"skipped": 1, "absent": 1, "not_applicable": 0, "waived": 0,
	}
	report["verdict"] = "fail"
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatal(err)
	}
	if verdict, _ := parsed.ComputeVerdict(); verdict != VerdictFail {
		t.Fatalf("an absent condition reached %q", verdict)
	}
}

func TestNotApplicableHasToNameAHostThatRunsIt(t *testing.T) {
	base := goodReport()
	base["counts"] = map[string]int{
		"discovered": 310, "passed": 309, "failed": 0,
		"skipped": 1, "absent": 0, "not_applicable": 1, "waived": 0,
	}
	for _, kind := range []struct {
		name    string
		skip    map[string]string
		verdict string
	}{
		{"with no host at all", map[string]string{
			"test": "TestDnfUpgrade", "class": SkipNotApplicable, "reason": "dnf is not this host's package manager",
		}, VerdictFail},
		{"naming a host outside the matrix", map[string]string{
			"test": "TestDnfUpgrade", "class": SkipNotApplicable,
			"reason": "dnf is not this host's package manager", "runs_on": "agent-suse",
		}, VerdictFail},
		{"naming a host of the matrix", map[string]string{
			"test": "TestDnfUpgrade", "class": SkipNotApplicable,
			"reason": "dnf is not this host's package manager", "runs_on": "agent-fedora",
		}, VerdictPass},
	} {
		t.Run(kind.name, func(t *testing.T) {
			report := goodReport()
			report["counts"] = base["counts"]
			report["skips"] = []map[string]string{kind.skip}
			report["verdict"] = kind.verdict
			parsed, err := ParseGateReport(encode(t, report))
			if err != nil {
				t.Fatal(err)
			}
			verdict, reasons := parsed.ComputeVerdict()
			if verdict != kind.verdict {
				t.Fatalf("verdict %q, wanted %q; reasons %v", verdict, kind.verdict, reasons)
			}
		})
	}
}

func TestAWaiverMakesTheRunLimitedAndAnExpiredOneFails(t *testing.T) {
	counts := map[string]int{
		"discovered": 310, "passed": 309, "failed": 0,
		"skipped": 1, "absent": 0, "not_applicable": 0, "waived": 1,
	}
	for _, kind := range []struct {
		name    string
		skip    map[string]string
		verdict string
	}{
		{"in date", map[string]string{
			"test": "TestTPMSealing", "class": SkipWaived, "reason": "no TPM in the laboratory",
			"waiver": "WV-2026-004", "until": "2026-12-31", "evidence": "docs/waivers/WV-2026-004.md",
		}, VerdictLimited},
		{"expired", map[string]string{
			"test": "TestTPMSealing", "class": SkipWaived, "reason": "no TPM in the laboratory",
			"waiver": "WV-2026-004", "until": "2026-08-31", "evidence": "docs/waivers/WV-2026-004.md",
		}, VerdictFail},
		{"without substitute evidence", map[string]string{
			"test": "TestTPMSealing", "class": SkipWaived, "reason": "no TPM in the laboratory",
			"waiver": "WV-2026-004", "until": "2026-12-31",
		}, VerdictFail},
		{"without an expiry", map[string]string{
			"test": "TestTPMSealing", "class": SkipWaived, "reason": "no TPM in the laboratory",
			"waiver": "WV-2026-004", "evidence": "docs/waivers/WV-2026-004.md",
		}, VerdictFail},
	} {
		t.Run(kind.name, func(t *testing.T) {
			report := goodReport()
			report["counts"] = counts
			report["skips"] = []map[string]string{kind.skip}
			report["verdict"] = kind.verdict
			parsed, err := ParseGateReport(encode(t, report))
			if err != nil {
				t.Fatal(err)
			}
			verdict, reasons := parsed.ComputeVerdict()
			if verdict != kind.verdict {
				t.Fatalf("verdict %q, wanted %q; reasons %v", verdict, kind.verdict, reasons)
			}
		})
	}
}

func TestCountsHaveToMatchTheSkipsThemselves(t *testing.T) {
	report := goodReport()
	report["skips"] = []map[string]string{
		{"test": "TestDnfUpgrade", "class": SkipNotApplicable, "reason": "no dnf", "runs_on": "agent-fedora"},
	}
	report["verdict"] = "fail"
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatal(err)
	}
	verdict, reasons := parsed.ComputeVerdict()
	if verdict != VerdictFail {
		t.Fatalf("counts that name no skip reached %q", verdict)
	}
	if len(reasons) == 0 {
		t.Fatal("no reason was given")
	}
}

// The verdict in the file is not the verdict: it is checked against the one
// the evidence reaches, so a report edited on its way to the workflow is
// refused rather than recorded.
func TestAClaimedVerdictThatTheEvidenceDeniesIsRefused(t *testing.T) {
	report := goodReport()
	report["stages"] = map[string]any{
		"integration": map[string]any{"result": "fail", "seconds": 2100},
	}
	_, _, _, err := CheckGateReport(encode(t, report), "")
	if err == nil {
		t.Fatal("a report that claims a pass over a failed stage was accepted")
	}
	if !strings.Contains(err.Error(), "the evidence in it says") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

func TestAReportAboutAnotherCommitIsRefused(t *testing.T) {
	_, _, _, err := CheckGateReport(encode(t, goodReport()), strings.Repeat("f", 40))
	if err == nil || !strings.Contains(err.Error(), "the same commit") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

func TestATimestampWithoutATimezoneIsRefused(t *testing.T) {
	report := goodReport()
	report["started_at"] = "2026-09-29 08:00:00"
	if _, err := ParseGateReport(encode(t, report)); err == nil {
		t.Fatal("a naive timestamp was accepted")
	}
}

// A field this checker does not know is a report from another schema, and
// reading the fields it does recognise out of one is how a rule gets lost.
func TestAFieldThisCheckerDoesNotKnowIsRefused(t *testing.T) {
	report := goodReport()
	report["result"] = "pass"
	if _, err := ParseGateReport(encode(t, report)); err == nil {
		t.Fatal("an unknown field was accepted")
	}
}

func TestTheSummaryBeginsWithTheVerdict(t *testing.T) {
	parsed, err := ParseGateReport(encode(t, goodReport()))
	if err != nil {
		t.Fatal(err)
	}
	summary := parsed.Summary(VerdictPass)
	if !strings.HasPrefix(summary, "verdict=pass ") {
		t.Fatalf("the summary does not begin with the verdict: %q", summary)
	}
	if len(summary) > 120 {
		t.Fatalf("the summary is %d characters; a status takes 140", len(summary))
	}
}

// A quick run is refused by the verdict, not by the schema: it has no suite
// log because it never ran the suite, and the report still has to be readable.
func TestAQuickReportWithoutASuiteLogIsStillReadable(t *testing.T) {
	report := goodReport()
	report["quick"] = true
	report["logs"] = map[string]string{}
	report["hosts"] = []map[string]string{}
	report["agents"] = []map[string]string{}
	report["counts"] = map[string]int{
		"discovered": 40, "passed": 40, "failed": 0,
		"skipped": 0, "absent": 0, "not_applicable": 0, "waived": 0,
	}
	report["verdict"] = "fail"
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatal(err)
	}
	if verdict, _ := parsed.ComputeVerdict(); verdict != VerdictFail {
		t.Fatalf("a quick run reached %q", verdict)
	}
}

// A run the preflight stopped has no suite log because the suite never ran.
// That is a fail with a reason somebody can read, not a report the checker
// refuses: refusing it would leave a legitimately red run with no verdict.
func TestARunStoppedBeforeTheSuiteIsAFailAndNotARefusal(t *testing.T) {
	report := goodReport()
	stages := report["stages"].(map[string]any)
	stages["preflight"] = map[string]any{"result": "fail", "seconds": 57}
	delete(stages, "integration")
	delete(stages, "playwright")
	report["logs"] = map[string]string{}
	report["counts"] = map[string]int{
		"discovered": 0, "passed": 0, "failed": 0,
		"skipped": 0, "absent": 0, "not_applicable": 0, "waived": 0,
	}
	report["verdict"] = "fail"
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatalf("the checker refused a report of a run that stopped early: %v", err)
	}
	verdict, reasons := parsed.ComputeVerdict()
	if verdict != VerdictFail {
		t.Fatalf("a run stopped at the preflight reached %q", verdict)
	}
	var named bool
	for _, reason := range reasons {
		if strings.Contains(reason, "preflight") {
			named = true
		}
	}
	if !named {
		t.Errorf("the reasons do not name the stage that stopped the run: %v", reasons)
	}
}

// Leaving a stage out of the report must not be the way past the gate: the
// verdict is computed over the stages a report names, so an unnamed one has to
// be fatal rather than simply absent from the arithmetic.
func TestAReportThatOmitsTheSuiteCannotPass(t *testing.T) {
	report := goodReport()
	stages := report["stages"].(map[string]any)
	delete(stages, "integration")
	report["logs"] = map[string]string{}
	report["verdict"] = "pass"
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatalf("the report did not parse: %v", err)
	}
	if verdict, reasons := parsed.ComputeVerdict(); verdict == VerdictPass {
		t.Fatalf("a report with no suite stage reached pass; reasons %v", reasons)
	}
}
