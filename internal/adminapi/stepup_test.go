package adminapi

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
)

func session(auth authz.Authentication) *authz.Session {
	return &authz.Session{ID: "session", PrincipalID: "principal", Auth: auth}
}

func TestStepUpRequiresReason(t *testing.T) {
	policy := stepUpPolicy{MaxAge: 5 * time.Minute}

	for name, reason := range map[string]string{
		"empty":     "",
		"spaces":    "      ",
		"too short": "because",
	} {
		_, denial := policy.evaluate(reason, session(authz.Authentication{At: time.Now()}))
		if denial == nil {
			t.Errorf("%s: the reason %q was accepted", name, reason)
			continue
		}
		if denial.Code != "reason_required" {
			t.Errorf("%s: denial code = %q", name, denial.Code)
		}
	}
}

func TestStepUpRequiresFreshAuthentication(t *testing.T) {
	policy := stepUpPolicy{MaxAge: 5 * time.Minute}
	reason := "granting a role to the new on-call team"

	if _, denial := policy.evaluate(reason, session(authz.Authentication{
		At: time.Now().Add(-time.Minute), ACR: "1",
	})); denial != nil {
		t.Fatalf("fresh authentication rejected: %+v", denial)
	}

	_, denial := policy.evaluate(reason, session(authz.Authentication{
		At: time.Now().Add(-time.Hour),
	}))
	if denial == nil {
		t.Fatal("old authentication was accepted")
	}
	if denial.Code != "reauthentication_required" {
		t.Errorf("denial code = %q", denial.Code)
	}
	if denial.Detail["authentication_age_seconds"] == nil {
		t.Error("the denial does not say how old the authentication is")
	}

	// No auth_time is an undetermined state. Letting such a session through
	// would mean treating an unknown time as "a moment ago".
	if _, denial := policy.evaluate(reason, session(authz.Authentication{})); denial == nil {
		t.Error("a session without an authentication time was accepted")
	}

	// Disabled freshness must not reject a session the provider said
	// nothing about: the installation deliberately gave up this condition.
	noRequirement := stepUpPolicy{}
	if _, denial := noRequirement.evaluate(reason, session(authz.Authentication{})); denial != nil {
		t.Errorf("the disabled freshness requirement still rejects: %+v", denial)
	}
}

func TestStepUpChecksAuthenticationLevel(t *testing.T) {
	policy := stepUpPolicy{MaxAge: time.Hour, ACR: "gold"}
	reason := "changing the group mapping after a reorganisation"

	if _, denial := policy.evaluate(reason, session(authz.Authentication{
		At: time.Now(), ACR: "1",
	})); denial == nil {
		t.Error("a session with a lower level was accepted")
	}

	evidence, denial := policy.evaluate(reason, session(authz.Authentication{
		At: time.Now(), ACR: "gold", AMR: []string{"pwd", "otp"},
	}))
	if denial != nil {
		t.Fatalf("a session with the required level rejected: %+v", denial)
	}
	// The panel records what the provider reported and does not translate
	// it into its own "mfa: yes" - MFA belongs to the identity provider.
	if evidence["acr"] != "gold" {
		t.Errorf("the evidence does not carry the level: %+v", evidence)
	}
	if evidence["purpose"] != reason {
		t.Errorf("the evidence does not carry the reason: %+v", evidence)
	}
	if evidence["reauthenticated"] != true {
		t.Errorf("the evidence does not confirm re-authentication: %+v", evidence)
	}
}

// TestStepUpAutomatedIdentity guards that no authentication that did not
// happen is attributed to an API token.
func TestStepUpAutomatedIdentity(t *testing.T) {
	policy := stepUpPolicy{MaxAge: 5 * time.Minute, ACR: "gold"}

	evidence, denial := policy.evaluate("deploying the test fleet", nil)
	if denial != nil {
		t.Fatalf("the automated identity was blocked: %+v", denial)
	}
	if evidence["authentication"] != "api_token" || evidence["reauthenticated"] != false {
		t.Errorf("the evidence does not tell a token from a session: %+v", evidence)
	}
	if _, present := evidence["acr"]; present {
		t.Errorf("the evidence attributes an authentication level to a token: %+v", evidence)
	}
	// A reason is required from an automaton too: without it the audit
	// trail does not say why an access rule was changed.
	if _, denial := policy.evaluate("", nil); denial == nil {
		t.Error("the automated identity passed without a reason")
	}
}

// A missing reason is a gap in the request, not in the session. Sending the
// client to log in again would make them fix what is not broken.
func TestMissingReasonIsRequestError(t *testing.T) {
	policy := stepUpPolicy{}
	_, denial := policy.evaluate("short", nil)
	if denial == nil {
		t.Fatal("a too short reason was accepted")
	}
	if denial.Code != "reason_required" {
		t.Errorf("code = %q", denial.Code)
	}
	if !denial.RequestError {
		t.Error("the missing reason was marked as missing authentication")
	}
}
