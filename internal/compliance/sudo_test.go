package compliance

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/modules/sudoers"
)

// The sudo check judges what the helper parsed: the default grant passes
// because it asks for a password, and a policy nobody could read is unknown.
func TestRootWithoutPasswordIsJudgedFromTheParsedPolicy(t *testing.T) {
	group := sudoers.Rule{
		Users: []string{"%sudo"}, Hosts: []string{"ALL"}, RunAs: []string{"ALL"}, Commands: []string{"ALL"},
		AllHosts: true, AllCommands: true, RunAsAnyUser: true, RootEquivalent: true, Critical: true,
		Source: "/etc/sudoers", Line: 24,
	}
	cloud := group
	cloud.Users, cloud.NoPasswd = []string{"ubuntu"}, true
	cloud.Source, cloud.Line = "/etc/sudoers.d/90-cloud-init-users", 2

	clean := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSudoers: fragmentOf(t, moduleSudoers, sudoers.Snapshot{Rules: []sudoers.Rule{group}}),
	}}, testNow)
	if result := finding(clean, "sudo.root_nopasswd"); !result.Passed || result.Remediation != nil {
		t.Fatalf("the default grant with a password did not pass: %+v", result)
	}

	leaky := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSudoers: fragmentOf(t, moduleSudoers, sudoers.Snapshot{Rules: []sudoers.Rule{group, cloud}}),
	}}, testNow)
	result := finding(leaky, "sudo.root_nopasswd")
	if result.Passed || result.Unknown {
		t.Fatalf("a passwordless root grant passed: %+v", result)
	}
	if !strings.Contains(result.Evidence, "/etc/sudoers.d/90-cloud-init-users:2") || !strings.Contains(result.Evidence, "ubuntu") {
		t.Errorf("the evidence does not name the file and the grantee: %q", result.Evidence)
	}
	// The panel writes no sudoers file, so the remediation is a note and
	// not an operation.
	if result.Remediation == nil || result.Remediation.Action != "" || result.Remediation.Note == "" {
		t.Errorf("remediation = %+v", result.Remediation)
	}

	// A global "!authenticate" makes the default grant passwordless too.
	global := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSudoers: fragmentOf(t, moduleSudoers, sudoers.Snapshot{
			Rules:    []sudoers.Rule{group},
			Defaults: []sudoers.Default{{Params: []string{"!authenticate"}, DisablesAuthentication: true}},
		}),
	}}, testNow)
	if result := finding(global, "sudo.root_nopasswd"); result.Passed || !strings.Contains(result.Observed, "authentication off") {
		t.Errorf("a global !authenticate was not judged: %+v", result)
	}

	// A policy the helper could not open is unknown with the reason, and a
	// refused read is a permission problem rather than a read failure.
	refused := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSudoers: fragmentOf(t, moduleSudoers, sudoers.Snapshot{
			UnavailableReason: "permission denied reading /etc/sudoers",
		}),
	}}, testNow)
	if result := finding(refused, "sudo.root_nopasswd"); !result.Unknown || result.ReasonCode != ReasonPermissionDenied {
		t.Errorf("a refused policy was judged: %+v", result)
	}
	absent := Evaluate("host", Input{}, testNow)
	if result := finding(absent, "sudo.root_nopasswd"); !result.Unknown || result.ReasonCode != ReasonFactMissing {
		t.Errorf("a missing policy was judged: %+v", result)
	}
}

// A policy the parser did not fully understand cannot pass: a skipped line or
// an unreadable drop-in may hold the very grant the check looks for.
func TestAParserProblemNeverPassesTheSudoCheck(t *testing.T) {
	group := sudoers.Rule{
		Users: []string{"%sudo"}, Hosts: []string{"ALL"}, RunAs: []string{"ALL"}, Commands: []string{"ALL"},
		AllHosts: true, AllCommands: true, RunAsAnyUser: true, RootEquivalent: true, Critical: true,
		Source: "/etc/sudoers", Line: 24,
	}
	skipped := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSudoers: fragmentOf(t, moduleSudoers, sudoers.Snapshot{
			Rules: []sudoers.Rule{group},
			Files: []sudoers.File{{Path: "/etc/sudoers", Lines: 30}},
			Problems: []sudoers.Problem{{
				Source: "/etc/sudoers.d/ops", Line: 3, Text: "Defaults:ops !authenticate, something",
				Reason: "unknown directive",
			}},
		}),
	}}, testNow)
	result := finding(skipped, "sudo.root_nopasswd")
	if result.Passed || !result.Unknown || result.ReasonCode != ReasonParseError {
		t.Fatalf("a policy with a skipped line was judged clean: %+v", result)
	}
	if !strings.Contains(result.Observed, "/etc/sudoers.d/ops:3") || !strings.Contains(result.Observed, "unknown directive") {
		t.Errorf("the note does not name the skipped line: %q", result.Observed)
	}

	unreadable := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSudoers: fragmentOf(t, moduleSudoers, sudoers.Snapshot{
			Rules: []sudoers.Rule{group},
			Files: []sudoers.File{
				{Path: "/etc/sudoers", Lines: 30},
				{Path: "/etc/sudoers.d/90-cloud-init-users", IncludedFrom: "/etc/sudoers", Reason: "permission denied"},
			},
		}),
	}}, testNow)
	result = finding(unreadable, "sudo.root_nopasswd")
	if result.Passed || !result.Unknown || result.ReasonCode != ReasonParseError {
		t.Fatalf("a policy with an unreadable drop-in was judged clean: %+v", result)
	}
	if !strings.Contains(result.Observed, "/etc/sudoers.d/90-cloud-init-users: permission denied") {
		t.Errorf("the note does not name the unreadable file: %q", result.Observed)
	}

	// A grant the parser did read is a finding, problems or not.
	cloud := group
	cloud.Users, cloud.NoPasswd = []string{"ubuntu"}, true
	cloud.Source, cloud.Line = "/etc/sudoers.d/90-cloud-init-users", 2
	found := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSudoers: fragmentOf(t, moduleSudoers, sudoers.Snapshot{
			Rules:    []sudoers.Rule{group, cloud},
			Problems: []sudoers.Problem{{Source: "/etc/sudoers", Line: 40, Text: "?", Reason: "unknown directive"}},
		}),
	}}, testNow)
	if result := finding(found, "sudo.root_nopasswd"); result.Passed || result.Unknown {
		t.Fatalf("a passwordless grant next to a skipped line was not a finding: %+v", result)
	}
}

// The host's own checker is a separate answer from the parse: visudo -c says
// what sudo loads, and a host that cannot say it does not pass by default.
func TestTheCheckerResultIsJudgedOnItsOwn(t *testing.T) {
	group := sudoers.Rule{
		Users: []string{"%sudo"}, Hosts: []string{"ALL"}, RunAs: []string{"ALL"}, Commands: []string{"ALL"},
		AllHosts: true, AllCommands: true, RunAsAnyUser: true, RootEquivalent: true, Critical: true,
		Source: "/etc/sudoers", Line: 24,
	}
	policy := func(check *sudoers.SyntaxCheck) Input {
		return Input{Fragments: map[string]Fragment{
			moduleSudoers: fragmentOf(t, moduleSudoers, sudoers.Snapshot{
				Rules:       []sudoers.Rule{group},
				Files:       []sudoers.File{{Path: "/etc/sudoers", Lines: 30}},
				SyntaxCheck: check,
			}),
		}}
	}

	accepted := Evaluate("host", policy(&sudoers.SyntaxCheck{
		Tool: "/usr/sbin/visudo", Available: true, Ran: true, Output: "/etc/sudoers: parsed OK",
	}), testNow)
	if result := finding(accepted, "sudo.syntax_valid"); !result.Passed || result.Remediation != nil {
		t.Errorf("a file the checker took did not pass: %+v", result)
	}

	// A refused file is a finding of its own, and it also stops the policy
	// check from calling the parsed rules clean: sudo loads none of them.
	refused := Evaluate("host", policy(&sudoers.SyntaxCheck{
		Tool: "/usr/sbin/visudo", Available: true, Ran: true, ExitCode: 1,
		Output: "/etc/sudoers.d/ops:3:10: unknown defaults entry \"authenticat\"",
	}), testNow)
	syntax := finding(refused, "sudo.syntax_valid")
	if syntax.Passed || syntax.Unknown || !syntax.NeedsAction() {
		t.Fatalf("a refused file was not a finding: %+v", syntax)
	}
	if !strings.Contains(syntax.Observed, "exit 1") || !strings.Contains(syntax.Evidence, "/etc/sudoers.d/ops:3") {
		t.Errorf("the finding does not name the status and the file: %+v", syntax)
	}
	if syntax.Remediation == nil || syntax.Remediation.Action != "" || syntax.Remediation.Note == "" {
		t.Errorf("remediation = %+v", syntax.Remediation)
	}
	if result := finding(refused, "sudo.root_nopasswd"); result.Passed || !result.Unknown ||
		result.ReasonCode != ReasonParseError {
		t.Errorf("a refused policy was judged clean: %+v", result)
	}

	// A host without the checker proves nothing, and a checker that returned
	// no status is a third answer again. Neither is a pass.
	missing := Evaluate("host", policy(&sudoers.SyntaxCheck{
		Reason: "visudo was not found on this host",
	}), testNow)
	if result := finding(missing, "sudo.syntax_valid"); result.Passed || !result.Unknown ||
		result.ReasonCode != ReasonCheckerMissing {
		t.Errorf("a host without visudo was judged: %+v", result)
	}
	stuck := Evaluate("host", policy(&sudoers.SyntaxCheck{
		Tool: "/usr/sbin/visudo", Available: true, Reason: "visudo did not finish within 15s",
	}), testNow)
	if result := finding(stuck, "sudo.syntax_valid"); result.Passed || !result.Unknown ||
		result.ReasonCode != ReasonCheckerFailed {
		t.Errorf("a checker without a status was judged: %+v", result)
	}
}

// An agent of the previous release reports no checker result. That is unknown
// with a reason, and it leaves the semantic check exactly where it was.
func TestAnAgentThatReportsNoCheckerResultBreaksNothing(t *testing.T) {
	group := sudoers.Rule{
		Users: []string{"%sudo"}, Hosts: []string{"ALL"}, RunAs: []string{"ALL"}, Commands: []string{"ALL"},
		AllHosts: true, AllCommands: true, RunAsAnyUser: true, RootEquivalent: true, Critical: true,
		Source: "/etc/sudoers", Line: 24,
	}
	report := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSudoers: fragmentOf(t, moduleSudoers, sudoers.Snapshot{
			Rules: []sudoers.Rule{group},
			Files: []sudoers.File{{Path: "/etc/sudoers", Lines: 30}},
		}),
	}}, testNow)

	syntax := finding(report, "sudo.syntax_valid")
	if syntax.Passed || !syntax.Unknown || syntax.ReasonCode != ReasonFactMissing {
		t.Errorf("a silent agent was judged on the checker: %+v", syntax)
	}
	if !strings.Contains(syntax.Observed, "visudo -c") {
		t.Errorf("the observation does not name what was not reported: %q", syntax.Observed)
	}
	// The grant with a password still passes: the new read did not make an
	// installation that was in order look broken.
	if result := finding(report, "sudo.root_nopasswd"); !result.Passed {
		t.Errorf("the policy check changed for an agent that reports no checker result: %+v", result)
	}
}
