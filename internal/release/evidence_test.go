package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The bundle of a run that backs its own report: the report as the laboratory
// wrote it, and the bytes of everything it claims a digest of. Every test below
// spoils exactly one thing about it.
func goodBundle(t *testing.T) (bundle []byte, sha, tree string) {
	t.Helper()
	suiteLog := []byte(`{"Action":"pass","Test":"TestTheFleetAnswers"}` + "\n")
	screenshot := []byte("\x89PNG\r\n\x1a\nthe panel, as the run left it")

	report := goodReport()
	report["logs"] = map[string]string{"go_test_json": digestOf(suiteLog)}
	report["artifacts"] = map[string]string{"panel.png": digestOf(screenshot)}
	raw := encode(t, report)

	return bundleOf(t, map[string][]byte{
		"result.json":         raw,
		"logs/go_test_json":   suiteLog,
		"artifacts/panel.png": screenshot,
	}), report["sha"].(string), report["tree_hash"].(string)
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func bundleOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	for name, content := range files {
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// rewrite returns the bundle again with one file replaced or, with nil, removed.
func rewrite(t *testing.T, original []byte, path string, content []byte) []byte {
	t.Helper()
	files := unpack(t, original)
	if content == nil {
		delete(files, path)
	} else {
		files[path] = content
	}
	return bundleOf(t, files)
}

func unpack(t *testing.T, bundle []byte) map[string][]byte {
	t.Helper()
	stream, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	reader := tar.NewReader(stream)
	for {
		header, err := reader.Next()
		if err != nil {
			break
		}
		var content bytes.Buffer
		if _, err := content.ReadFrom(reader); err != nil {
			t.Fatal(err)
		}
		files[header.Name] = content.Bytes()
	}
	return files
}

// tar -czf ... -C dir . is how the gate writes the bundle, and it names every
// entry with a leading "./" plus a directory entry per folder. A checker that
// only accepted the bare names would refuse every real bundle while every test
// passed, so this is the shape the laboratory actually produces.
func TestTheBundleTheLaboratoryWritesIsAccepted(t *testing.T) {
	bundle, sha, tree := goodBundle(t)
	files := unpack(t, bundle)
	asTarWritesIt := map[string][]byte{}
	for name, content := range files {
		asTarWritesIt["./"+name] = content
	}
	evidence, err := VerifyEvidence(bytes.NewReader(bundleOf(t, asTarWritesIt)), sha, tree)
	if err != nil {
		t.Fatalf("the bundle as tar writes it was refused: %v", err)
	}
	if evidence.Verified != 2 {
		t.Fatalf("%d files were verified, expected 2", evidence.Verified)
	}
}

func TestABundleThatBacksItsReportIsAccepted(t *testing.T) {
	bundle, sha, tree := goodBundle(t)
	evidence, err := VerifyEvidence(bytes.NewReader(bundle), sha, tree)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Verified != 2 {
		t.Fatalf("%d files were verified against their digests, expected 2", evidence.Verified)
	}
	if evidence.Digest != digestOf(bundle) {
		t.Fatalf("the bundle digest is %s, the bundle hashes to %s", evidence.Digest, digestOf(bundle))
	}
	if verdict, reasons := evidence.Report.ComputeVerdict(); verdict != VerdictPass {
		t.Fatalf("the verdict over verified evidence is %q: %v", verdict, reasons)
	}
}

// The case this mechanism exists for: the report is the one the laboratory
// wrote and a log was replaced afterwards.
func TestALogReplacedAfterTheRunIsRefused(t *testing.T) {
	bundle, sha, tree := goodBundle(t)
	spoiled := rewrite(t, bundle, "logs/go_test_json",
		[]byte(`{"Action":"pass","Test":"TestTheFleetAnswers"}`+"\n"+`{"Action":"pass","Test":"TestNobodyRan"}`+"\n"))
	assertRefusal(t, spoiled, sha, tree, "the log go_test_json in the bundle is")
}

func TestAnArtefactReplacedAfterTheRunIsRefused(t *testing.T) {
	bundle, sha, tree := goodBundle(t)
	spoiled := rewrite(t, bundle, "artifacts/panel.png", []byte("another screenshot entirely"))
	assertRefusal(t, spoiled, sha, tree, "the artefact panel.png in the bundle is")
}

func TestADigestWithoutItsBytesIsRefused(t *testing.T) {
	bundle, sha, tree := goodBundle(t)
	assertRefusal(t, rewrite(t, bundle, "logs/go_test_json", nil), sha, tree,
		"a digest without its bytes is a claim, not evidence")
}

// A file the report does not stand behind: the next reader cannot tell which of
// the two the run produced.
func TestAFileTheReportDoesNotAccountForIsRefused(t *testing.T) {
	bundle, sha, tree := goodBundle(t)
	spoiled := rewrite(t, bundle, "artifacts/extra.png", []byte("an artefact nobody claimed"))
	assertRefusal(t, spoiled, sha, tree, "which the report does not account for")
}

// git holds the tree of a commit; the report only claims one. A run of the
// right commit over the wrong tree is what a pasted report cannot rule out.
func TestATreeGitDoesNotHoldIsRefused(t *testing.T) {
	bundle, sha, _ := goodBundle(t)
	assertRefusal(t, bundle, sha, strings.Repeat("f", 40), "git holds")
}

func TestABundleAboutAnotherCommitIsRefused(t *testing.T) {
	bundle, _, tree := goodBundle(t)
	assertRefusal(t, bundle, strings.Repeat("1", 40), tree, "the verdict was asked for")
}

func TestABundleWithoutTheReportIsRefused(t *testing.T) {
	bundle, sha, tree := goodBundle(t)
	assertRefusal(t, rewrite(t, bundle, "result.json", nil), sha, tree,
		"the report has to come from the bundle")
}

// A capability the manifest leaves out would narrow the accounting silently.
func TestAManifestMissingACapabilityIsAFail(t *testing.T) {
	report := goodReport()
	manifest := report["capability_manifest"].(map[string]any)
	delete(manifest, "backup")
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatal(err)
	}
	verdict, reasons := parsed.ComputeVerdict()
	if verdict != VerdictFail {
		t.Fatalf("a manifest without backup reached %q", verdict)
	}
	if !containsText(reasons, "says nothing about backup") {
		t.Fatalf("the reasons do not name the missing capability: %v", reasons)
	}
}

func TestAnEmptyFleetIsAFailAndNotAnExemption(t *testing.T) {
	report := goodReport()
	report["hosts"] = []map[string]string{}
	report["agents"] = []map[string]string{}
	report["capability_manifest"] = manifestWithoutAFleet()
	// The skip that an empty fleet used to excuse: it claims another host runs
	// the scenario, and there is no other host.
	report["skips"] = []map[string]string{
		{"test": "TestTheFirewallRuleLifecycle", "suite": "integration",
			"class": SkipNotApplicable, "runs_on": "agent-ubuntu", "reason": "no ufw here"},
	}
	report["counts"] = map[string]int{
		"discovered": 310, "passed": 309, "failed": 0,
		"skipped": 1, "absent": 0, "not_applicable": 1, "waived": 0,
	}
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatal(err)
	}
	verdict, reasons := parsed.ComputeVerdict()
	if verdict != VerdictFail {
		t.Fatalf("a run against no fleet reached %q", verdict)
	}
	if !containsText(reasons, "a suite that ran against nothing attests nothing") {
		t.Fatalf("the reasons do not say the fleet was empty: %v", reasons)
	}
	if !containsText(reasons, "which is not a host of this run") {
		t.Fatalf("the empty fleet still excuses the skip: %v", reasons)
	}
}

func assertRefusal(t *testing.T, bundle []byte, sha, tree, expected string) {
	t.Helper()
	_, err := VerifyEvidence(bytes.NewReader(bundle), sha, tree)
	if err == nil {
		t.Fatal("the bundle was accepted")
	}
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("the refusal is %q, expected it to say %q", err.Error(), expected)
	}
}

func containsText(reasons []string, text string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, text) {
			return true
		}
	}
	return false
}

// The first real bundle the laboratory produced was refused, and the refusal
// was wrong. agents-after.tsv names every host the panel knows an agent on -
// including the synthetic hosts the suite enrols for its own scenarios, which
// have no distribution to read over ssh and so never reach hosts.tsv. A fleet
// that gains hosts during a run is not a malformed report.
//
// The direction that does matter is the other one: a host the report lists and
// no agent version for it.
func TestAFleetThatGainedHostsDuringTheRunIsNotMalformed(t *testing.T) {
	report := goodReport()
	agents := report["agents"].([]map[string]string)
	report["agents"] = append(agents,
		map[string]string{"host": "clone-a-1791139767261194926",
			"version_before": "test", "version_after": "test"})
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatalf("a report naming an agent of an enrolled host was refused: %v", err)
	}
	if verdict, reasons := parsed.ComputeVerdict(); verdict != VerdictPass {
		t.Fatalf("the verdict is %q: %v", verdict, reasons)
	}
}

func TestAHostWithNoAgentVersionIsAFail(t *testing.T) {
	report := goodReport()
	report["agents"] = []map[string]string{
		{"host": "agent-debian", "version_before": "0.61.0", "version_after": "0.62.0"},
	}
	parsed, err := ParseGateReport(encode(t, report))
	if err != nil {
		t.Fatal(err)
	}
	verdict, reasons := parsed.ComputeVerdict()
	if verdict != VerdictFail {
		t.Fatalf("a host with no recorded agent version reached %q", verdict)
	}
	if !containsText(reasons, "no agent version is reported for agent-fedora") {
		t.Fatalf("the reasons do not name the host: %v", reasons)
	}
}
