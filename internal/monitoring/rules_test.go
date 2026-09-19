package monitoring

import (
	"errors"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

const (
	testHostID = "2b1f0a4e-2d6a-4a61-8c2f-1a6c9d7b0e11"
	testRuleID = "8f1d2c3b-4a5e-4f60-9d71-0c2b3a4e5f60"
)

func silenceAt(now time.Time) Silence {
	return Silence{Until: now.Add(time.Hour), Reason: "storage maintenance"}
}

// A global silence is the one that may keep back the security alerts of the
// installation, so it covers all of it; naming a host or a rule contradicts
func TestValidateSilenceRefusesAGlobalSilenceThatNarrows(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	narrowed := func(name string, host, rule string) {
		t.Helper()
		silence := silenceAt(now)
		silence.Global, silence.HostID, silence.RuleID = true, host, rule
		err := ValidateSilence(silence, now)
		if err == nil {
			t.Fatalf("a global silence naming %s was accepted", name)
		}
		if code := opspec.RefusalCode(err); code != RefusalSilenceScopeConflict {
			t.Fatalf("a global silence naming %s was refused as %q, expected %s",
				name, code, RefusalSilenceScopeConflict)
		}
	}
	narrowed("a host", testHostID, "")
	narrowed("a rule", "", testRuleID)
	narrowed("a host and a rule", testHostID, testRuleID)
}

// The two shapes that do make sense: a global silence of the installation and
// a fleet-wide silence that is not global.
func TestValidateSilenceAcceptsTheWholeInstallation(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	global := silenceAt(now)
	global.Global, global.SendSummary = true, true
	if err := ValidateSilence(global, now); err != nil {
		t.Fatalf("a global silence of nothing narrower was refused: %v", err)
	}
	if err := ValidateSilence(silenceAt(now), now); err != nil {
		t.Fatalf("a fleet-wide silence that is not global was refused: %v", err)
	}
}

// The bounds that were there before keep their code: a malformed silence is
// invalid_silence at the endpoint, not one of the typed refusals.
func TestValidateSilenceKeepsThePlainRefusals(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	malformed := func(name string, silence Silence) {
		t.Helper()
		err := ValidateSilence(silence, now)
		if err == nil {
			t.Fatalf("a silence with %s was accepted", name)
		}
		var refusal *opspec.RefusalError
		if errors.As(err, &refusal) {
			t.Fatalf("a silence with %s got the typed code %q; it is a malformed request",
				name, refusal.Code)
		}
	}
	short := silenceAt(now)
	short.Reason = "x"
	malformed("a reason nobody can read", short)

	past := silenceAt(now)
	past.Until = now.Add(-time.Minute)
	malformed("a deadline in the past", past)

	long := silenceAt(now)
	long.Until = now.Add(MaxSilence + time.Minute)
	malformed("a deadline further off than a day", long)

	unknown := silenceAt(now)
	unknown.RuleID = "not-a-rule"
	malformed("a rule identifier that is none", unknown)
}

// A rule written before the three settings existed keeps the behaviour it had:
// the sampling interval, two of them, and a gap nobody is told about.
func TestARuleWithoutCadenceSettingsKeepsTodaysBehaviour(t *testing.T) {
	rule := Rule{Name: "disk", Metric: MetricFilesystemUsedPercent, Operator: "gt",
		Threshold: 90, ForMinutes: 10, Severity: "warning"}
	if err := rule.Validate(); err != nil {
		t.Fatalf("a rule that says nothing about its cadence was refused: %v", err)
	}
	if rule.Cadence() != SamplingInterval {
		t.Errorf("the cadence of a rule that does not say is %s, not the sampling interval", rule.Cadence())
	}
	if rule.MaxGap() != DefaultMaxGapFactor*SamplingInterval {
		t.Errorf("the gap of a rule that does not say is %s", rule.MaxGap())
	}
	if rule.Policy() != NoDataIgnore {
		t.Errorf("a rule that does not say has the policy %q; it has to ignore gaps as before", rule.Policy())
	}
	// What is written down says what the evaluator will do, rather than
	// leaving a zero to be read as a default somewhere else.
	settled := rule.settled()
	if settled.ExpectedCadenceSeconds != 60 || settled.MaxGapSeconds != 120 ||
		settled.NoDataPolicy != NoDataIgnore {
		t.Fatalf("the settled rule is %d s / %d s / %q",
			settled.ExpectedCadenceSeconds, settled.MaxGapSeconds, settled.NoDataPolicy)
	}
}

// The settings are checked against each other and against the interval the
// agents sample at, and every refusal carries a code the panel can branch on.
func TestValidateRefusesCadenceSettingsThatContradictTheFleet(t *testing.T) {
	sound := func() Rule {
		return Rule{Name: "disk", Metric: MetricFilesystemUsedPercent, Operator: "gt",
			Threshold: 90, Severity: "warning"}
	}
	refused := func(name string, rule Rule, want string) {
		t.Helper()
		err := rule.Validate()
		if err == nil {
			t.Fatalf("a rule with %s was accepted", name)
		}
		if code := opspec.RefusalCode(err); code != want {
			t.Fatalf("a rule with %s was refused as %q, expected %s", name, code, want)
		}
	}

	faster := sound()
	faster.ExpectedCadenceSeconds = 30
	refused("a cadence faster than the sampling interval", faster, RefusalRuleCadenceTooFast)

	negative := sound()
	negative.ExpectedCadenceSeconds = -60
	refused("a negative cadence", negative, RefusalRuleCadenceTooFast)

	slow := sound()
	slow.ExpectedCadenceSeconds = int(MaxCadence/time.Second) + 60
	refused("a cadence longer than a day", slow, RefusalRuleCadenceTooSlow)

	wide := sound()
	wide.MaxGapSeconds = int(MaxCadence/time.Second) + 60
	refused("a gap longer than a day", wide, RefusalRuleCadenceTooSlow)

	narrow := sound()
	narrow.ExpectedCadenceSeconds, narrow.MaxGapSeconds = 300, 120
	refused("a gap narrower than its cadence", narrow, RefusalRuleGapBelowCadence)

	unknown := sound()
	unknown.NoDataPolicy = "page_me"
	refused("a policy that is none of the three", unknown, RefusalRuleNoDataPolicyUnknown)

	// The gap of a rule that names only a cadence follows it, so naming a
	// slower cadence alone is not a contradiction.
	slower := sound()
	slower.ExpectedCadenceSeconds = 300
	if err := slower.Validate(); err != nil {
		t.Fatalf("a rule with a five-minute cadence and no gap of its own was refused: %v", err)
	}
	if slower.MaxGap() != 10*time.Minute {
		t.Errorf("the gap that follows a five-minute cadence is %s", slower.MaxGap())
	}
	for _, policy := range NoDataPolicies {
		accepted := sound()
		accepted.NoDataPolicy = policy
		if err := accepted.Validate(); err != nil {
			t.Fatalf("the policy %q was refused: %v", policy, err)
		}
	}
}
