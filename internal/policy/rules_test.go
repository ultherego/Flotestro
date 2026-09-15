package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
)

var now = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

// fixture builds the facts of one host from the fragments a test names,
// each observed a minute ago unless the test says otherwise.
func fixture(fragments map[string]string) Facts {
	facts := Facts{
		Host: hosts.Host{ID: "h1", Hostname: "web-1", Capabilities: hosts.Capabilities{
			{Name: hosts.CapSystemd, Available: true},
			{Name: hosts.CapAPT, Available: true},
			{Name: hosts.CapKernel, Available: true},
			{Name: hosts.CapFiles, Available: true},
		}},
		Fragments: map[string]inventory.Fragment{},
		Now:       now,
	}
	for module, payload := range fragments {
		facts.Fragments[module] = inventory.Fragment{
			Module: module, Revision: "rev-" + module, Payload: json.RawMessage(payload),
			ObservedAt: now.Add(-time.Minute),
		}
	}
	return facts
}

func withPackages(facts Facts, digest string, names ...string) Facts {
	facts.Packages = PackageFacts{Loaded: true, Digest: digest, Installed: map[string]bool{}}
	for _, name := range names {
		facts.Packages.Installed[name] = true
	}
	return facts
}

func expectVerdict(t *testing.T, judgement Judgement, verdict string) {
	t.Helper()
	if judgement.Verdict != verdict {
		t.Fatalf("verdict = %s (%s), want %s", judgement.Verdict, judgement.Reason, verdict)
	}
}

func TestPackageInstalledJudgesThePanelCopyAgainstTheReportedDigest(t *testing.T) {
	facts := withPackages(fixture(map[string]string{
		modulePackages: `{"manager":"apt","installed_digest":"d1"}`,
	}), "d1", "cron", "openssh-server")

	judgement := Judge(Rule{Kind: KindPackageInstalled, Name: "cron"}, facts)
	expectVerdict(t, judgement, VerdictCompliant)
	if judgement.Revision != "rev-packages" {
		t.Fatalf("revision = %q", judgement.Revision)
	}

	judgement = Judge(Rule{Kind: KindPackageInstalled, Name: "nonexistent-pkg-xyz"}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation == nil || judgement.Remediation.Action != "packages.install" {
		t.Fatalf("remediation = %+v", judgement.Remediation)
	}
	if !strings.Contains(string(judgement.Remediation.Payload), `"nonexistent-pkg-xyz"`) {
		t.Fatalf("payload = %s", judgement.Remediation.Payload)
	}
}

func TestAStalePackageCopyIsAnErrorNotAPass(t *testing.T) {
	facts := withPackages(fixture(map[string]string{
		modulePackages: `{"manager":"apt","installed_digest":"d2"}`,
	}), "d1", "cron")
	judgement := Judge(Rule{Kind: KindPackageInstalled, Name: "cron"}, facts)
	expectVerdict(t, judgement, VerdictError)
	if reasonCode(judgement.Reason) != ReasonListStale {
		t.Fatalf("reason = %s", judgement.Reason)
	}

	// No copy at all is the same answer with a different reason.
	missing := fixture(map[string]string{modulePackages: `{"manager":"apt","installed_digest":"d1"}`})
	missing.Packages = PackageFacts{Loaded: true, UnavailableReason: "nobody asked"}
	judgement = Judge(Rule{Kind: KindPackageInstalled, Name: "cron"}, missing)
	expectVerdict(t, judgement, VerdictError)
}

func TestPackageAbsentFixesWithARemovalThatNamesTheSet(t *testing.T) {
	facts := withPackages(fixture(map[string]string{
		modulePackages: `{"manager":"apt","installed_digest":"d1"}`,
	}), "d1", "telnetd")
	judgement := Judge(Rule{Kind: KindPackageAbsent, Name: "telnetd"}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation == nil || judgement.Remediation.Action != "packages.remove" {
		t.Fatalf("remediation = %+v", judgement.Remediation)
	}
	if !strings.Contains(string(judgement.Remediation.Payload), `"expected_removals":["telnetd"]`) {
		t.Fatalf("payload = %s", judgement.Remediation.Payload)
	}
	expectVerdict(t, Judge(Rule{Kind: KindPackageAbsent, Name: "cron"}, facts), VerdictCompliant)
}

func TestAHostWithoutAPackageManagerIsNotApplicable(t *testing.T) {
	facts := fixture(nil)
	facts.Host.Capabilities = hosts.Capabilities{{Name: hosts.CapSystemd, Available: true}}
	expectVerdict(t, Judge(Rule{Kind: KindPackageInstalled, Name: "cron"}, facts), VerdictNotApplicable)
	// A host that reported no registry at all is unknown, not exempt.
	facts.Host.Capabilities = nil
	expectVerdict(t, Judge(Rule{Kind: KindPackageInstalled, Name: "cron"}, facts), VerdictError)
}

const unitListingFixture = `{"units":[
	{"name":"cron.service","active_state":"active","unit_file_state":"enabled","load_state":"loaded"},
	{"name":"telnet.socket","active_state":"inactive","unit_file_state":"disabled","load_state":"loaded"},
	{"name":"nginx.service","active_state":"failed","unit_file_state":"enabled","load_state":"loaded"}
]}`

func TestUnitStateJudgesTheListingAndTheFailedUnits(t *testing.T) {
	facts := fixture(map[string]string{
		moduleUnitListing: unitListingFixture,
		moduleServices:    `{"failed_units":["nginx.service"],"failed_units_known":true}`,
	})
	enabledActive := Rule{Kind: KindUnitState, Unit: "cron.service", Enabled: boolPtr(true), Active: boolPtr(true)}
	expectVerdict(t, Judge(enabledActive, facts), VerdictCompliant)

	judgement := Judge(Rule{Kind: KindUnitState, Unit: "telnet.socket", Enabled: boolPtr(true), Active: boolPtr(true)}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation == nil || judgement.Remediation.Action != "unit.enable.set" {
		t.Fatalf("the first step is %+v, want unit.enable.set", judgement.Remediation)
	}

	judgement = Judge(Rule{Kind: KindUnitState, Unit: "nginx.service", Active: boolPtr(true)}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation == nil || judgement.Remediation.Action != "unit.start" {
		t.Fatalf("remediation = %+v, want unit.start", judgement.Remediation)
	}

	judgement = Judge(Rule{Kind: KindUnitState, Unit: "telnet.socket", Active: boolPtr(false)}, facts)
	expectVerdict(t, judgement, VerdictCompliant)
}

func TestUnitStateWithoutTheListingIsAnErrorThatNamesTheRead(t *testing.T) {
	facts := fixture(map[string]string{moduleServices: `{"failed_units":[],"failed_units_known":true}`})
	judgement := Judge(Rule{Kind: KindUnitState, Unit: "cron.service", Active: boolPtr(true)}, facts)
	expectVerdict(t, judgement, VerdictError)
	if !strings.Contains(judgement.Reason, "unit.status") {
		t.Fatalf("reason = %s", judgement.Reason)
	}
}

func TestAnUnknownUnitIsADriftWithoutAFix(t *testing.T) {
	facts := fixture(map[string]string{moduleUnitListing: unitListingFixture})
	judgement := Judge(Rule{Kind: KindUnitState, Unit: "ghost.service", Active: boolPtr(true)}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation != nil || reasonCode(judgement.Reason) != ReasonNoRemediation {
		t.Fatalf("judgement = %+v", judgement)
	}
}

func TestAFactOlderThanTwiceItsPaceIsAnError(t *testing.T) {
	facts := fixture(map[string]string{moduleServices: `{"failed_units":[],"failed_units_known":true}`, moduleUnitListing: unitListingFixture})
	stale := facts.Fragments[moduleUnitListing]
	stale.ObservedAt = now.Add(-3 * 24 * time.Hour)
	facts.Fragments[moduleUnitListing] = stale
	judgement := Judge(Rule{Kind: KindUnitState, Unit: "cron.service", Active: boolPtr(true)}, facts)
	expectVerdict(t, judgement, VerdictError)
	if reasonCode(judgement.Reason) != ReasonStale {
		t.Fatalf("reason = %s", judgement.Reason)
	}
}

func TestAModuleTheHostFailedToReadIsNotAnEmptyModule(t *testing.T) {
	facts := fixture(map[string]string{moduleKernel: `{}`})
	failed := facts.Fragments[moduleKernel]
	failed.UnavailableReason = "sysctl is missing"
	facts.Fragments[moduleKernel] = failed
	judgement := Judge(Rule{Kind: KindSysctl, Key: "net.ipv4.ip_forward", Value: "0"}, facts)
	expectVerdict(t, judgement, VerdictError)
	if reasonCode(judgement.Reason) != ReasonReadFailed {
		t.Fatalf("reason = %s", judgement.Reason)
	}
}

func TestSysctlJudgesTheCurrentValue(t *testing.T) {
	facts := fixture(map[string]string{moduleKernel: `{"settings":[
		{"key":"net.ipv4.ip_forward","current":"1","source":"/etc/sysctl.d/99-forward.conf"},
		{"key":"kernel.kptr_restrict","current":""}
	]}`})
	judgement := Judge(Rule{Kind: KindSysctl, Key: "net.ipv4.ip_forward", Value: "0"}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation == nil || judgement.Remediation.Action != "sysctl.ensure" ||
		!strings.Contains(string(judgement.Remediation.Payload), `"net.ipv4.ip_forward":"0"`) {
		t.Fatalf("remediation = %+v", judgement.Remediation)
	}
	expectVerdict(t, Judge(Rule{Kind: KindSysctl, Key: "net.ipv4.ip_forward", Value: "1"}, facts), VerdictCompliant)
	expectVerdict(t, Judge(Rule{Kind: KindSysctl, Key: "kernel.kptr_restrict", Value: "1"}, facts), VerdictError)
	expectVerdict(t, Judge(Rule{Kind: KindSysctl, Key: "vm.swappiness", Value: "1"}, facts), VerdictError)
}

const digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestFileContentJudgesTheReportedDigestAndFixesFromTheStore(t *testing.T) {
	facts := fixture(map[string]string{moduleFiles: `{"files":[
		{"path":"/etc/motd","sha256":"` + digestB + `","managed":true,"exists":true,"mode":"0644","owner":"root","group":"root"}
	]}`})
	facts.FileContent = func(digest string) ([]byte, bool) {
		if digest == digestA {
			return []byte("welcome\n"), true
		}
		return nil, false
	}
	judgement := Judge(Rule{Kind: KindFileContent, Path: "/etc/motd", SHA256: digestA}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation == nil || judgement.Remediation.Action != "file.ensure" {
		t.Fatalf("remediation = %+v", judgement.Remediation)
	}
	payload := string(judgement.Remediation.Payload)
	if !strings.Contains(payload, `"content":"welcome\n"`) || !strings.Contains(payload, `"expected_sha256":"`+digestB+`"`) {
		t.Fatalf("payload = %s", payload)
	}
	expectVerdict(t, Judge(Rule{Kind: KindFileContent, Path: "/etc/motd", SHA256: digestB}, facts), VerdictCompliant)

	// A version the panel does not hold is a drift nothing can fix.
	judgement = Judge(Rule{Kind: KindFileContent, Path: "/etc/motd", SHA256: strings.Repeat("c", 64)}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation != nil || reasonCode(judgement.Reason) != ReasonNoRemediation {
		t.Fatalf("judgement = %+v", judgement)
	}
}

func TestAFileTheHostDoesNotReportIsADriftTheStoreCanFix(t *testing.T) {
	facts := fixture(map[string]string{moduleFiles: `{"files":[]}`})
	facts.FileContent = func(string) ([]byte, bool) { return []byte("x"), true }
	judgement := Judge(Rule{Kind: KindFileContent, Path: "/etc/motd", SHA256: digestA}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation == nil || strings.Contains(string(judgement.Remediation.Payload), "expected_sha256") {
		t.Fatalf("remediation = %+v", judgement.Remediation)
	}
}

const accountsFixture = `{"accounts":[
	{"name":"deploy","ssh_keys":[{"fingerprint":"SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"ssh-ed25519"}]},
	{"name":"fresh","ssh_keys":[]},
	{"name":"broken","ssh_keys":[],"unavailable_reason":"home is not readable"}
]}`

func TestSSHKeyPresentJudgesFingerprintsAndFixesOnlyAnEmptyAccount(t *testing.T) {
	facts := fixture(map[string]string{moduleAccounts: accountsFixture})
	present := "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	other := "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	material := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample deploy@panel"

	expectVerdict(t, Judge(Rule{Kind: KindSSHKeyPresent, User: "deploy", Fingerprint: present}, facts), VerdictCompliant)

	// The account holds another key: the panel has no material for it,
	// so it reports and does not replace.
	judgement := Judge(Rule{Kind: KindSSHKeyPresent, User: "deploy", Fingerprint: other, PublicKey: material}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation != nil || reasonCode(judgement.Reason) != ReasonNoRemediation {
		t.Fatalf("judgement = %+v", judgement)
	}

	// An empty account gets the key.
	judgement = Judge(Rule{Kind: KindSSHKeyPresent, User: "fresh", Fingerprint: other, PublicKey: material}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation == nil || judgement.Remediation.Action != "localuser.sshkeys.set" {
		t.Fatalf("remediation = %+v", judgement.Remediation)
	}

	// Without material there is nothing to set.
	judgement = Judge(Rule{Kind: KindSSHKeyPresent, User: "fresh", Fingerprint: other}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation != nil {
		t.Fatalf("remediation = %+v", judgement.Remediation)
	}

	expectVerdict(t, Judge(Rule{Kind: KindSSHKeyPresent, User: "broken", Fingerprint: other}, facts), VerdictError)
	judgement = Judge(Rule{Kind: KindSSHKeyPresent, User: "nobody", Fingerprint: other}, facts)
	expectVerdict(t, judgement, VerdictDrift)
	if judgement.Remediation != nil {
		t.Fatalf("a missing account got a fix: %+v", judgement.Remediation)
	}
}

func TestAMissingModuleIsAnErrorForEveryKind(t *testing.T) {
	facts := fixture(nil)
	rules := []Rule{
		{Kind: KindUnitState, Unit: "cron.service", Active: boolPtr(true)},
		{Kind: KindFileContent, Path: "/etc/motd", SHA256: digestA},
		{Kind: KindSysctl, Key: "a", Value: "1"},
		{Kind: KindSSHKeyPresent, User: "deploy", Fingerprint: "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for _, rule := range rules {
		judgement := Judge(rule, facts)
		if judgement.Verdict != VerdictError || reasonCode(judgement.Reason) != ReasonFactMissing {
			t.Errorf("%s: judgement = %+v", rule.Kind, judgement)
		}
	}
}

func TestFindingCarriesTheVerdictIntoTheRemediationBuilder(t *testing.T) {
	rule := Rule{Kind: KindSysctl, Key: "k", Value: "1"}
	drift := Finding(0, rule, 2, Judgement{Verdict: VerdictDrift, Reason: "k = 0", Revision: "r1",
		Remediation: nil})
	if !drift.Applicable || drift.Passed || drift.Unknown || drift.CheckID != "rule:0:sysctl:k" || drift.CheckVersion != 2 {
		t.Fatalf("drift = %+v", drift)
	}
	unknown := Finding(0, rule, 2, Judgement{Verdict: VerdictError, Reason: ReasonStale + ": old"})
	if !unknown.Unknown || unknown.ReasonCode != ReasonStale || unknown.NeedsAction() {
		t.Fatalf("unknown = %+v", unknown)
	}
	exempt := Finding(0, rule, 2, Judgement{Verdict: VerdictNotApplicable})
	if exempt.Applicable || exempt.NeedsAction() {
		t.Fatalf("exempt = %+v", exempt)
	}
	passed := Finding(0, rule, 2, Judgement{Verdict: VerdictCompliant})
	if !passed.Passed || passed.NeedsAction() {
		t.Fatalf("passed = %+v", passed)
	}
}
