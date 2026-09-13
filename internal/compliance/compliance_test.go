package compliance

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/modules/security"
	sshmodule "github.com/ultherego/flotestro/internal/modules/ssh"
	hosttime "github.com/ultherego/flotestro/internal/modules/time"
	"github.com/ultherego/flotestro/internal/opspec"
)

// readAt is the moment the host reported its facts, and testNow the moment of
// the assessment. The difference is small on purpose: an assessment computed
// against an old read ends with an undetermined state, and that is a separate
// test.
var readAt = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
var testNow = readAt.Add(time.Minute)

func fragmentOf(t *testing.T, module string, content any) Fragment {
	t.Helper()
	encoded, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("serialising %s: %v", module, err)
	}
	return Fragment{
		Module: module, Revision: "rev-" + module, Payload: encoded,
		ObservedAt: readAt,
	}
}

func finding(report Report, id string) Finding {
	for _, result := range report.Findings {
		if result.CheckID == id {
			return result
		}
	}
	return Finding{}
}

// A host that did not report a module is not a non-conformant host: a missing
// read and a wrong value are two different answers.
func TestAMissingModuleGivesAnUnknownState(t *testing.T) {
	report := Evaluate("host", Input{}, testNow)

	for _, result := range report.Findings {
		if result.Module == "" {
			continue
		}
		if !result.Unknown {
			t.Errorf("%s without a module has a known state: %+v", result.CheckID, result)
		}
		if result.Remediation != nil {
			t.Errorf("%s without a read has a remediation plan", result.CheckID)
		}
	}
	if report.Counts["failed"] != 0 {
		t.Errorf("non-conformances without a read: %d", report.Counts["failed"])
	}
	// A plan without findings that need action is empty but still has a digest.
	if report.PlanHash == "" {
		t.Error("a report without a plan digest")
	}
}

// A module read with an error is not a non-conformance either - it carries a reason.
func TestAModuleThatWasNotReadCarriesAReason(t *testing.T) {
	fragment := fragmentOf(t, moduleSecurity, security.Snapshot{})
	fragment.UnavailableReason = "helper: no answer"
	report := Evaluate("host", Input{Fragments: map[string]Fragment{moduleSecurity: fragment}}, testNow)

	result := finding(report, "mac.enforcing")
	if !result.Unknown {
		t.Fatalf("finding = %+v", result)
	}
	if result.Observed == "" || result.Revision != "rev-security" {
		t.Errorf("a finding without a reason or without a revision: %+v", result)
	}
}

func TestSELinuxInPermissiveHasARemediation(t *testing.T) {
	state := security.Snapshot{
		MAC: security.Mandatory{
			System: security.SystemSELinux, Mode: security.ModePermissive,
			ConfiguredMode: security.ModeEnforcing, Policy: "targeted",
		},
	}
	report := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, state)}}, testNow)

	result := finding(report, "mac.enforcing")
	if result.Passed || result.Unknown {
		t.Fatalf("permissive treated as protection: %+v", result)
	}
	if result.Remediation == nil || result.Remediation.Action != "selinux.mode.set" {
		t.Fatalf("remediation = %+v", result.Remediation)
	}
	// A remediation is an ordinary module operation, so it carries a ready payload.
	var payload struct {
		Security struct {
			Mode string `json:"mode"`
		} `json:"security"`
	}
	if err := json.Unmarshal(result.Remediation.Payload, &payload); err != nil {
		t.Fatalf("remediation payload: %v", err)
	}
	if payload.Security.Mode != security.ModeEnforcing {
		t.Errorf("remediation payload = %+v", payload)
	}
	// A drift between the running and the configured mode is a separate finding.
	trwalosc := finding(report, "mac.persistent")
	if trwalosc.Passed {
		t.Error("a mode drift treated as conformance")
	}
}

// AppArmor with profiles in complain mode alone does not protect, but the
// panel has nothing to fix it with - and it says so instead of proposing an
// operation that does not exist.
func TestAppArmorWithoutEnforcedProfilesHasNoRemediatingOperation(t *testing.T) {
	zero, dwa := 0, 2
	state := security.Snapshot{MAC: security.Mandatory{
		System: security.SystemAppArmor, Mode: security.ModeEnforcing,
		ProfilesEnforcing: &zero, ProfilesComplain: &dwa,
	}}
	report := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, state)}}, testNow)

	result := finding(report, "mac.enforcing")
	if result.Passed {
		t.Fatal("profiles in complain mode treated as protection")
	}
	if result.Remediation == nil || result.Remediation.Action != "" {
		t.Fatalf("remediation = %+v", result.Remediation)
	}
	if result.Remediation.Note == "" {
		t.Error("a missing remediation without an explanation")
	}
}

func TestAPassedFindingCarriesNoRemediation(t *testing.T) {
	state := security.Snapshot{
		MAC: security.Mandatory{System: security.SystemSELinux, Mode: security.ModeEnforcing, ConfiguredMode: security.ModeEnforcing},
		Audit: security.Audit{Present: true, Active: wskaznikPrawdy(),
			RulesLoaded: countPointer(12), RulesConfigured: countPointer(12)},
	}
	report := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, state)}}, testNow)

	for _, id := range []string{"mac.enforcing", "mac.persistent", "audit.running", "audit.rules-loaded"} {
		result := finding(report, id)
		if !result.Passed {
			t.Errorf("%s = %+v", id, result)
		}
		if result.Remediation != nil {
			t.Errorf("%s passed and still carries a remediation", id)
		}
	}
}

// The plan digest binds the approval to the state the operator reviewed.
func TestThePlanDigestDependsOnTheState(t *testing.T) {
	permissive := security.Snapshot{MAC: security.Mandatory{
		System: security.SystemSELinux, Mode: security.ModePermissive, ConfiguredMode: security.ModePermissive}}
	enforcing := security.Snapshot{MAC: security.Mandatory{
		System: security.SystemSELinux, Mode: security.ModeEnforcing, ConfiguredMode: security.ModeEnforcing}}

	first := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, permissive)}}, testNow)
	second := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, permissive)}}, testNow.Add(time.Hour))
	third := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, enforcing)}}, testNow)

	// Ten sam state daje ten sam digest niezaleznie od chwili policzenia.
	if first.PlanHash != second.PlanHash {
		t.Error("the plan digest changed without a change of state")
	}
	if first.PlanHash == third.PlanHash {
		t.Error("a change of state did not change the plan digest")
	}
}

// Security updates are computed from a fact the panel knows by itself.
func TestSecurityUpdatesComeFromThePanelsInventory(t *testing.T) {
	zero, seven := 0, 7
	passed := Evaluate("host", Input{Host: Host{PendingSecurityUpdates: &zero}}, testNow)
	if !finding(passed, "packages.security-updates").Passed {
		t.Error("no pending updates treated as non-conformance")
	}

	pending := Evaluate("host", Input{Host: Host{PendingSecurityUpdates: &seven}}, testNow)
	result := finding(pending, "packages.security-updates")
	if result.Passed || result.Remediation == nil || result.Remediation.Action != "packages.plan" {
		t.Fatalf("finding = %+v", result)
	}

	// An undetermined number is not zero.
	undetermined := Evaluate("host", Input{}, testNow)
	if !finding(undetermined, "packages.security-updates").Unknown {
		t.Error("an undetermined number of updates treated as no updates")
	}
}

// Every remediation has to name an operation the panel knows. A check
// proposing a non-existent operation type would be rejected only at the
// ordering, and the operator would then see an error instead of a plan.
func TestRemediationsPointAtOperationsFromTheCatalogue(t *testing.T) {
	for _, check := range Checks {
		if check.ID == "" || check.Version == 0 || check.Severity == "" {
			t.Errorf("a check without an identity: %+v", check)
		}
		if check.Rationale == "" || check.Expected == "" {
			t.Errorf("%s without a rationale or a target state", check.ID)
		}
	}
	report := Evaluate("host", hostWithEveryNonConformance(t), testNow)
	remediations := 0
	for _, result := range report.Findings {
		if result.Remediation == nil || result.Remediation.Action == "" {
			continue
		}
		remediations++
		action := opspec.ActionType(result.Remediation.Action)
		if !action.Known() {
			t.Errorf("%s proposes the unknown operation %q", result.CheckID, action)
			continue
		}
		// Payload remediations musi przejsc walidacje tej operacji tak samo jak
		// A payload typed by hand: a plan that can only be ordered after a
		// fix is not a plan.
		// An operation without a payload is valid: a scan or a reload of the
		// rules has nothing to carry.
		var payload opspec.Payload
		if len(result.Remediation.Payload) == 0 {
			if err := opspec.Validate(action, payload); err != nil {
				t.Errorf("%s: the operation %s requires a payload the remediation does not carry: %v",
					result.CheckID, action, err)
			}
			continue
		}
		if err := json.Unmarshal(result.Remediation.Payload, &payload); err != nil {
			t.Errorf("%s: the remediation payload is not a payload of the operation: %v", result.CheckID, err)
			continue
		}
		if err := opspec.Validate(action, payload); err != nil {
			t.Errorf("%s: the remediation payload was rejected by %s: %v", result.CheckID, action, err)
		}
	}
	// If the scenario stopped producing non-conformances, the test would pass
	// without checking anything.
	if remediations < 6 {
		t.Fatalf("the scenario produced only %d remediations with an operation", remediations)
	}
}

// hostWithEveryNonConformance builds a state in which every check
// z naprawa ma co naprawiac.
func hostWithEveryNonConformance(t *testing.T) Input {
	t.Helper()
	falsz, seven := false, 7
	ochrona := security.Snapshot{
		MAC: security.Mandatory{
			System: security.SystemSELinux, Mode: security.ModePermissive,
			ConfiguredMode: security.ModeEnforcing, Policy: "targeted",
		},
		Audit:          security.Audit{Present: true, Active: &falsz, RulesLoaded: countPointer(0), RulesConfigured: countPointer(4)},
		SecureBoot:     &falsz,
		ListeningKnown: true,
		OwnersKnown:    true,
		Listening: []security.Listener{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd", Reach: security.ReachAllInterfaces},
		},
	}
	serwer := sshmodule.Snapshot{PermitRootLogin: "yes", PasswordAuthentication: "yes"}
	jadro := kernel.Snapshot{Settings: []kernel.Setting{
		{Key: "net.ipv4.conf.all.rp_filter", Current: "0"},
		{Key: "net.ipv4.tcp_syncookies", Current: "0"},
	}}
	zegar := hosttime.Snapshot{Synchronized: &falsz, Service: hosttime.DaemonChrony}
	prawda := true
	zasilanie := power.Snapshot{RebootRequired: &prawda, RebootReasons: []string{"linux-image-amd64"}}

	return Input{
		Host: Host{PendingSecurityUpdates: &seven},
		Fragments: map[string]Fragment{
			moduleSecurity: fragmentOf(t, moduleSecurity, ochrona),
			moduleSSH:      fragmentOf(t, moduleSSH, serwer),
			moduleKernel:   fragmentOf(t, moduleKernel, jadro),
			moduleTime:     fragmentOf(t, moduleTime, zegar),
			modulePower:    fragmentOf(t, modulePower, zasilanie),
		},
	}
}

func wskaznikPrawdy() *bool       { prawda := true; return &prawda }
func countPointer(value int) *int { return &value }

// A host with AppArmor does not fail a check requiring SELinux. The "not
// applicable" state is a separate answer: it enters neither conformance nor
// non-conformance, and it creates no plan step.
func TestACheckThatDoesNotApplyIsNotAFailure(t *testing.T) {
	three, zero := 3, 0
	state := security.Snapshot{
		MAC: security.Mandatory{
			System: security.SystemAppArmor, Mode: security.ModeEnforcing,
			ProfilesEnforcing: &three, ProfilesComplain: &zero,
		},
	}
	report := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, state)}}, testNow)

	trwalosc := finding(report, "mac.persistent")
	if trwalosc.Applicable {
		t.Fatalf("sprawdzenie SELinuksa dotyczy hosta z AppArmorem: %+v", trwalosc)
	}
	if trwalosc.Passed || trwalosc.Unknown {
		t.Error("the not-applicable state was mixed with conformance or with undetermined")
	}
	if trwalosc.ReasonCode != ReasonUnsupported {
		t.Errorf("reason code = %q", trwalosc.ReasonCode)
	}
	if trwalosc.Remediation != nil {
		t.Error("a check that does not apply carries a remediation")
	}
	if report.Counts["not_applicable"] == 0 {
		t.Errorf("the summary has no not-applicable state: %v", report.Counts)
	}

	// A host without sshd and without an audit daemon does not fail their checks either.
	bezUslug := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, security.Snapshot{MAC: state.MAC}),
		moduleSSH:      fragmentOf(t, moduleSSH, sshmodule.Snapshot{}),
	}}, testNow)
	for _, id := range []string{"ssh.root-login", "ssh.password-auth", "audit.rules-loaded"} {
		if result := finding(bezUslug, id); result.Applicable {
			t.Errorf("%s applies to a host without that service: %+v", id, result)
		}
	}
}

// Every undetermined state carries a reason code: without it the operator
// does not know whether to wait for a read, repair the agent or grant
// permissions.
func TestEveryUndeterminedFindingHasAReasonCode(t *testing.T) {
	cases := map[string]Input{
		"without modules": {},
		"a module with an error": {Fragments: map[string]Fragment{
			moduleSecurity: fragmentZBledem(t, moduleSecurity, "helper: no answer"),
		}},
		"missing facts": {Fragments: map[string]Fragment{
			moduleSecurity: fragmentOf(t, moduleSecurity, security.Snapshot{
				MAC:   security.Mandatory{System: security.SystemAppArmor, Mode: security.ModeEnforcing},
				Audit: security.Audit{Present: true},
				Missing: map[string]string{
					security.FactAppArmorProfiles: "the AppArmor profiles lie in securityfs",
					security.FactAuditRules:       "auditctl: permission denied",
					security.FactSecureBoot:       "the EFI variable was not read: permission denied",
				},
			}),
		}},
	}
	dozwolone := map[string]bool{
		ReasonFactMissing: true, ReasonReadFailed: true,
		ReasonPermissionDenied: true, ReasonStaleInventory: true,
	}
	for nazwa, input := range cases {
		t.Run(nazwa, func(t *testing.T) {
			report := Evaluate("host", input, testNow)
			nieustalone := 0
			for _, result := range report.Findings {
				if !result.Unknown {
					continue
				}
				nieustalone++
				if !dozwolone[result.ReasonCode] {
					t.Errorf("%s: code powodu = %q", result.CheckID, result.ReasonCode)
				}
				if result.Observed == "" {
					t.Errorf("%s: an undetermined state without a description", result.CheckID)
				}
			}
			if nieustalone == 0 {
				t.Fatal("the case produced no undetermined state")
			}
		})
	}
}

// Odmowa dostepu i nieudany odczyt prowadza do dwoch roznych dzialan
// of the operator, so they have two different codes.
func TestTheReasonCodeTellsAPermissionDenialApart(t *testing.T) {
	state := security.Snapshot{
		MAC:   security.Mandatory{System: security.SystemAppArmor, Mode: security.ModeEnforcing},
		Audit: security.Audit{Present: true},
		Missing: map[string]string{
			security.FactAppArmorProfiles: "the AppArmor profiles live in securityfs",
			security.FactAuditRules:       "helper: polaczenie zerwane",
		},
	}
	report := Evaluate("host", Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, state)}}, testNow)

	if code := finding(report, "mac.enforcing").ReasonCode; code != ReasonPermissionDenied {
		t.Errorf("a permission denial was reported as %q", code)
	}
	if code := finding(report, "audit.rules-loaded").ReasonCode; code != ReasonReadFailed {
		t.Errorf("a read failure was reported as %q", code)
	}
}

// A read from a day ago describes the host of a day ago: an assessment
// resting on it would speak about a state that may no longer exist.
func TestAStaleReadIsNotConformance(t *testing.T) {
	state := security.Snapshot{MAC: security.Mandatory{
		System: security.SystemSELinux, Mode: security.ModeEnforcing, ConfiguredMode: security.ModeEnforcing}}
	input := Input{Fragments: map[string]Fragment{
		moduleSecurity: fragmentOf(t, moduleSecurity, state)}}

	fresh := Evaluate("host", input, readAt.Add(MaxReadAge-time.Minute))
	if !finding(fresh, "mac.enforcing").Passed {
		t.Fatal("a fresh read gave no result")
	}

	staleReport := Evaluate("host", input, readAt.Add(MaxReadAge+time.Minute))
	staleFinding := finding(staleReport, "mac.enforcing")
	if !staleFinding.Unknown || staleFinding.ReasonCode != ReasonStaleInventory {
		t.Fatalf("a stale read = %+v", staleFinding)
	}
}

// The plan digest has a fixed canonical form, versioned and bound to the
// host. The vectors are nailed down: a change of the form is to break this
// test rather than silently invalidate approved plans.
func TestPlanDigestVectors(t *testing.T) {
	empty := PlanHash("host-a", nil)
	if empty != "974678b3d16d9c31041a89a484c91bf837cb0921e5584c9a6d634ccc51ad38e8" {
		t.Errorf("the digest of an empty plan = %q", empty)
	}

	step := []Finding{{
		CheckID: "mac.enforcing", CheckVersion: 1, Applicable: true,
		Module: "security", Revision: "rew-1", Observed: "SELinux: permissive",
		Remediation: &Remediation{
			Action:  "selinux.mode.set",
			Payload: json.RawMessage(`{"security":{"mode":"enforcing"}}`),
		},
	}}
	digest := PlanHash("host-a", step)
	if digest != "17c5837bb4b81f944318287154302912f59e00f2294e4c27057fdc1eaab5e77a" {
		t.Errorf("the digest of the step = %q", digest)
	}

	// Ten sam step na innym hoscie to inny plan.
	if PlanHash("host-b", step) == digest {
		t.Error("the digest does not depend on the host")
	}
	// Zmiana wersji sprawdzenia zmienia znaczenie kroku.
	other := append([]Finding(nil), step...)
	other[0].CheckVersion = 2
	if PlanHash("host-a", other) == digest {
		t.Error("the digest does not depend on the check version")
	}
	// Zmiana rewizji odczytu znaczy, ze plan liczono z innych faktow.
	other[0].CheckVersion = 1
	other[0].Revision = "rew-2"
	if PlanHash("host-a", other) == digest {
		t.Error("the digest does not depend on the inventory revision")
	}
	// Zmiana payloadu remediations zmienia to, co zostanie wykonane.
	other[0].Revision = "rew-1"
	other[0].Remediation = &Remediation{
		Action:  "selinux.mode.set",
		Payload: json.RawMessage(`{"security":{"mode":"permissive"}}`),
	}
	if PlanHash("host-a", other) == digest {
		t.Error("the digest does not depend on the remediation payload")
	}
}

func fragmentZBledem(t *testing.T, module, powod string) Fragment {
	t.Helper()
	fragment := fragmentOf(t, module, security.Snapshot{})
	fragment.UnavailableReason = powod
	return fragment
}
