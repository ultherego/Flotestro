package compliance

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/modules/sudoers"
)

// The sudo check judges what the helper parsed: the distribution's default
// grant to the sudo group passes because it asks for a password, a
// passwordless drop-in fails with the file named, and a policy the helper
// could not read is undetermined rather than clean.
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

// A policy the parser did not fully understand cannot pass: a skipped line
// or an unreadable drop-in may hold the very grant the check looks for.
// The verdict is undetermined with parse_error and the note says what was
// not read. A grant the parser did find still fails - what was read is a
// finding whatever else was missed.
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
