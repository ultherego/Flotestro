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
// that, and the refusal carries a code rather than a sentence.
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
