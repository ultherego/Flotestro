package release

import "testing"

// The report records the commit's tree, so it cannot show that the working tree
// was still that tree when the artefacts were built from it. The stage that asks
// afterwards is therefore required, the same way identity is.
func TestAReportWithoutTheUnchangedStageIsNotAFullRun(t *testing.T) {
	report := goodReport()
	stages := report["stages"].(map[string]any)
	delete(stages, "unchanged")
	report["verdict"] = "fail"
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatal(err)
	}
	verdict, reasons := parsed.ComputeVerdict()
	if verdict == VerdictPass {
		t.Fatalf("a run that never checked the tree after building from it passed: %v", reasons)
	}
}
