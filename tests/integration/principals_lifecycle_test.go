//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

const identityLifecycleReason = "integration test of the identity lifecycle"

// TestAnIdentityIsDisabledAndEnabledAgain walks an identity through its
// whole life: created without a token, given one with a short life and a
// description, listed with its sessions, disabled with every credential
// ending at once, refused a second disabling, enabled again and issued a
// new token that works. The credentials ended at the disabling stay
// ended; the roles come back with the identity. Every step leaves its own
// event on the trail.
func TestAnIdentityIsDisabledAndEnabledAgain(t *testing.T) {
	h := newHarness(t)
	subject := uniqueSubject("lifecycle")

	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject": subject, "kind": "user", "display_name": "Lifecycle probe",
		"roles":  []map[string]string{{"role": "viewer"}},
		"reason": identityLifecycleReason,
	}, &created, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("the identity was created without an identifier")
	}
	if created.Token != "" {
		t.Error("a token was issued although none was asked for")
	}

	// A token with a life of an hour and a description of its own: the
	// listing shows both, so a reviewer knows what the token is for and
	// when it stops on its own.
	var issued struct {
		ID          string    `json:"id"`
		Token       string    `json:"token"`
		Description string    `json:"description"`
		ExpiresAt   time.Time `json:"token_expires_at"`
	}
	h.do(http.MethodPost, "/api/v1/principals/"+created.ID+"/tokens", map[string]any{
		"description": "lifecycle probe token", "token_ttl_hours": 1, "reason": identityLifecycleReason,
	}, &issued, http.StatusCreated)
	if issued.Token == "" || issued.Description != "lifecycle probe token" {
		t.Fatalf("the token was not issued as asked: %+v", issued)
	}
	if left := time.Until(issued.ExpiresAt); left <= 0 || left > time.Hour+time.Minute {
		t.Errorf("the token expires in %s, expected within an hour", left)
	}
	type listedPrincipal struct {
		ID         string     `json:"id"`
		Subject    string     `json:"subject"`
		DisabledAt *time.Time `json:"disabled_at"`
		Bindings   []struct {
			Role string `json:"role"`
		} `json:"bindings"`
		Tokens []struct {
			ID          string     `json:"id"`
			Description string     `json:"description"`
			ExpiresAt   *time.Time `json:"expires_at"`
		} `json:"tokens"`
	}
	find := func(path string) *listedPrincipal {
		var listing struct {
			Items []listedPrincipal `json:"items"`
		}
		h.get(path, &listing)
		for i := range listing.Items {
			if listing.Items[i].ID == created.ID {
				return &listing.Items[i]
			}
		}
		return nil
	}
	listed := find("/api/v1/principals")
	if listed == nil {
		t.Fatal("the new identity is not listed")
	}
	if len(listed.Tokens) != 1 || listed.Tokens[0].Description != "lifecycle probe token" || listed.Tokens[0].ExpiresAt == nil {
		t.Errorf("the listing does not carry the token with its description and expiry: %+v", listed.Tokens)
	}
	probe := h.withToken(issued.Token)
	probe.get("/api/v1/whoami", nil)

	// A token is not a session: an identity that only ever used tokens has
	// none, and the answer is the shape of the list, not a refusal. A
	// session identifier that is not one of this identity's ends nothing.
	var sessions struct {
		Items       []map[string]any `json:"items"`
		Count       int              `json:"count"`
		PrincipalID string           `json:"principal_id"`
	}
	h.get("/api/v1/principals/"+created.ID+"/sessions", &sessions)
	if sessions.PrincipalID != created.ID || sessions.Items == nil || sessions.Count != len(sessions.Items) {
		t.Errorf("the session list is not shaped as expected: %+v", sessions)
	}
	h.do(http.MethodGet, "/api/v1/principals/"+uuid.NewString()+"/sessions", nil, nil, http.StatusNotFound)
	h.do(http.MethodDelete, "/api/v1/principals/"+created.ID+"/sessions/"+uuid.NewString()+
		"?reason="+url.QueryEscape(identityLifecycleReason), nil, nil, http.StatusNotFound)
	h.do(http.MethodDelete, "/api/v1/principals/"+created.ID+"/sessions/not-a-session"+
		"?reason="+url.QueryEscape(identityLifecycleReason), nil, nil, http.StatusNotFound)

	// Disabling ends the token at once; a second disabling is a conflict,
	// because the caller believed the identity was still enabled.
	h.do(http.MethodDelete, "/api/v1/principals/"+created.ID+"?reason="+url.QueryEscape(identityLifecycleReason),
		nil, nil, http.StatusNoContent)
	probe.do(http.MethodGet, "/api/v1/whoami", nil, nil, http.StatusUnauthorized)
	var conflict struct {
		Code string `json:"code"`
	}
	h.do(http.MethodDelete, "/api/v1/principals/"+created.ID+"?reason="+url.QueryEscape(identityLifecycleReason),
		nil, &conflict, http.StatusConflict)
	if conflict.Code != "principal_disabled" {
		t.Errorf("the second disabling answered %q, expected principal_disabled", conflict.Code)
	}
	if find("/api/v1/principals") != nil {
		t.Error("the disabled identity is still among the enabled ones")
	}
	disabled := find("/api/v1/principals?disabled=true")
	if disabled == nil || disabled.DisabledAt == nil {
		t.Fatalf("the disabled identity is not listed with the moment it was disabled: %+v", disabled)
	}
	if len(disabled.Bindings) != 1 || disabled.Bindings[0].Role != "viewer" {
		t.Errorf("the disabled identity lost its bindings: %+v", disabled.Bindings)
	}

	// Enabling brings the identity back with its roles; the token that
	// ended stays ended, and a new one works. Enabling what is enabled is
	// the same kind of conflict as disabling what is disabled.
	var enabled struct {
		ID       string `json:"id"`
		Subject  string `json:"subject"`
		Bindings []struct {
			Role string `json:"role"`
		} `json:"bindings"`
	}
	h.do(http.MethodPost, "/api/v1/principals/"+created.ID+"/enable",
		map[string]any{"reason": identityLifecycleReason}, &enabled, http.StatusOK)
	if enabled.Subject != subject || len(enabled.Bindings) != 1 {
		t.Errorf("the enabled identity is not the one that was disabled: %+v", enabled)
	}
	h.do(http.MethodPost, "/api/v1/principals/"+created.ID+"/enable",
		map[string]any{"reason": identityLifecycleReason}, &conflict, http.StatusConflict)
	if conflict.Code != "principal_enabled" {
		t.Errorf("the second enabling answered %q, expected principal_enabled", conflict.Code)
	}
	if find("/api/v1/principals") == nil {
		t.Error("the enabled identity is not listed again")
	}
	if find("/api/v1/principals?disabled=true") != nil {
		t.Error("the enabled identity is still among the disabled ones")
	}
	probe.do(http.MethodGet, "/api/v1/whoami", nil, nil, http.StatusUnauthorized)
	var reissued struct {
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/principals/"+created.ID+"/tokens", map[string]any{
		"description": "after the enabling", "token_ttl_hours": 1, "reason": identityLifecycleReason,
	}, &reissued, http.StatusCreated)
	var whoami struct {
		Subject  string `json:"subject"`
		Bindings []struct {
			Role string `json:"role"`
		} `json:"bindings"`
	}
	h.withToken(reissued.Token).get("/api/v1/whoami", &whoami)
	if whoami.Subject != subject || len(whoami.Bindings) != 1 || whoami.Bindings[0].Role != "viewer" {
		t.Errorf("the enabled identity does not act with its roles: %+v", whoami)
	}

	// Every step is on the trail under the identity it changed; an enabling
	// without a reason is refused before anything happens.
	var trail auditPage
	h.get("/api/v1/audit?target_id="+created.ID+"&outcome=success&limit=50", &trail)
	seen := map[string]bool{}
	for _, event := range trail.Items {
		seen[event.Action] = true
	}
	for _, action := range []string{"principal.create", "principal.token.issue", "principal.disable", "principal.enable"} {
		if !seen[action] {
			t.Errorf("the trail of the identity lacks %s: %v", action, seen)
		}
	}
	var refusal struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/principals/"+created.ID+"/enable", map[string]any{"reason": "short"},
		&refusal, http.StatusBadRequest)
	if refusal.Code != "reason_required" {
		t.Errorf("an enabling without a reason answered %q, expected reason_required", refusal.Code)
	}
}

// TestAnIdentityIsCreatedWithinTheBoundsOfTheStore: a kind the table would
// refuse and a token that would outlive a year are the caller's mistakes,
// named as such before anything is written.
func TestAnIdentityIsCreatedWithinTheBoundsOfTheStore(t *testing.T) {
	h := newHarness(t)
	var refusal struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject": uniqueSubject("odd-kind"), "kind": "robot", "reason": identityLifecycleReason,
	}, &refusal, http.StatusBadRequest)
	if refusal.Code != "invalid_kind" {
		t.Errorf("an unknown kind answered %q, expected invalid_kind", refusal.Code)
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject": uniqueSubject("long-token"), "kind": "service",
		"issue_token": true, "token_ttl_hours": 24 * 366, "reason": identityLifecycleReason,
	}, &refusal, http.StatusBadRequest)
	if refusal.Code != "invalid_ttl" {
		t.Errorf("a token of more than a year answered %q, expected invalid_ttl", refusal.Code)
	}

	// A service identity with its first token, listed under its kind.
	subject := uniqueSubject("service")
	var created struct {
		ID             string    `json:"id"`
		Token          string    `json:"token"`
		TokenExpiresAt time.Time `json:"token_expires_at"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject": subject, "kind": "service", "roles": []map[string]string{{"role": "viewer"}},
		"issue_token": true, "token_ttl_hours": 2, "reason": identityLifecycleReason,
	}, &created, http.StatusCreated)
	if created.Token == "" {
		t.Fatal("the first token was not issued")
	}
	if left := time.Until(created.TokenExpiresAt); left <= 0 || left > 2*time.Hour+time.Minute {
		t.Errorf("the first token expires in %s, expected within two hours", left)
	}
	var whoami struct {
		Subject string `json:"subject"`
		Kind    string `json:"kind"`
	}
	h.withToken(created.Token).get("/api/v1/whoami", &whoami)
	if whoami.Subject != subject || whoami.Kind != "service" {
		t.Errorf("the service identity answers as %+v", whoami)
	}
}
