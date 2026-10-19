//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/authz"
)

// The rules of a password session that the sign-in test does not reach: what a
// session may do before its owner has replaced the password, what a password
// can renew, and what a crowd of wrong guesses costs.

// passwordIdentity makes a viewer with a password and returns what signs in.
func passwordIdentity(h *harness, mustChange bool) (id, subject, password string) {
	h.t.Helper()
	subject = "local-" + uuid.NewString()[:8]
	password = "a long enough passphrase"
	var created struct {
		ID string `json:"id"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject": subject,
		"roles": []map[string]any{{
			"role": "viewer", "team_scope": map[string]string{"mode": "any"},
		}},
		"reason": "the integration suite makes a local identity to sign in as",
	}, &created, http.StatusCreated)
	h.do(http.MethodPut, "/api/v1/principals/"+created.ID+"/password", map[string]any{
		"password": password, "must_change": mustChange,
		"reason": "the integration suite sets the first password",
	}, nil, http.StatusOK)
	return created.ID, subject, password
}

// browser is a session by cookie, the way the panel's page talks.
type browser struct {
	h       *harness
	session string
	csrf    string
}

func signInByPassword(h *harness, subject, password string) *browser {
	h.t.Helper()
	encoded, _ := json.Marshal(map[string]any{"subject": subject, "password": password})
	response, err := http.Post(h.api+"/auth/password", "application/json", bytes.NewReader(encoded))
	if err != nil {
		h.t.Fatalf("signing in: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(response.Body)
		h.t.Fatalf("signing in: status %d: %s", response.StatusCode, truncate(raw, 200))
	}
	b := &browser{h: h}
	for _, cookie := range response.Cookies() {
		switch cookie.Name {
		case authz.SessionCookie:
			b.session = cookie.Value
		case authz.CSRFCookie:
			b.csrf = cookie.Value
		}
	}
	if b.session == "" || b.csrf == "" {
		h.t.Fatal("the sign-in did not hand back a session and a CSRF value")
	}
	return b
}

func (b *browser) call(method, path string, body any) (int, string) {
	b.h.t.Helper()
	var payload io.Reader
	if body != nil {
		encoded, _ := json.Marshal(body)
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, b.h.api+path, payload)
	if err != nil {
		b.h.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(authz.CSRFHeader, b.csrf)
	request.AddCookie(&http.Cookie{Name: authz.SessionCookie, Value: b.session})
	request.AddCookie(&http.Cookie{Name: authz.CSRFCookie, Value: b.csrf})
	response, err := b.h.client.Do(request)
	if err != nil {
		b.h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(raw)
}

// A password somebody else chose does not open the rest of the API: the session
// exists so that its owner can replace it, and nothing else, until they have.
func TestASessionOnAPasswordToBeReplacedReachesNothingElse(t *testing.T) {
	h := newHarness(t)
	_, subject, password := passwordIdentity(h, true)
	b := signInByPassword(h, subject, password)

	if status, body := b.call(http.MethodGet, "/api/v1/hosts", nil); status != http.StatusForbidden ||
		!bytes.Contains([]byte(body), []byte("password_change_required")) {
		t.Fatalf("a read before the change: status %d, %s", status, truncate([]byte(body), 200))
	}
	if status, _ := b.call(http.MethodPost, "/api/v1/roles", map[string]any{"name": "x"}); status != http.StatusForbidden {
		t.Fatalf("a write before the change: status %d, expected 403", status)
	}
	if status, _ := b.call(http.MethodGet, "/api/v1/whoami", nil); status != http.StatusOK {
		t.Errorf("whoami before the change: status %d; the page has to know who this is", status)
	}

	if status, body := b.call(http.MethodPost, "/api/v1/profile/password", map[string]any{
		"current": password, "new": "a different long passphrase",
	}); status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("the change: status %d, %s", status, body)
	}
	if status, body := b.call(http.MethodGet, "/api/v1/hosts", nil); status != http.StatusOK {
		t.Errorf("a read after the change: status %d, %s", status, truncate([]byte(body), 200))
	}
}

// A password renews a session the password made, and nothing else: the
// provider's session keeps the authentication it was made by.
func TestAPasswordRenewsOnlyASessionThePasswordMade(t *testing.T) {
	h := newHarness(t)
	_, subject, password := passwordIdentity(h, false)
	b := signInByPassword(h, subject, password)

	if status, body := b.call(http.MethodPost, "/auth/password/reauthenticate",
		map[string]any{"password": password}); status != http.StatusOK {
		t.Fatalf("a password session renewing itself: status %d, %s", status, body)
	}

	// The same session, as the provider would have made it.
	digest := sha256.Sum256([]byte(b.session))
	if _, err := h.database(context.Background()).Exec(context.Background(), `
		update web_sessions set amr = '{mfa}', acr = 'audit:mfa',
		       authenticated_at = now() - interval '1 hour'
		 where token_hash = $1`, digest[:]); err != nil {
		t.Fatalf("making it a provider session: %v", err)
	}
	if status, body := b.call(http.MethodPost, "/auth/password/reauthenticate",
		map[string]any{"password": password}); status != http.StatusConflict {
		t.Fatalf("a password renewing a provider session: status %d, %s", status, body)
	}
	var stale bool
	if err := h.database(context.Background()).QueryRow(context.Background(),
		`select authenticated_at < now() - interval '30 minutes' from web_sessions where token_hash = $1`,
		digest[:]).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if !stale {
		t.Error("the refused renewal moved the authentication time of a provider session")
	}
}

// Wrong guesses made at once count one each. Read, add, write lost all but one
// of them, and ten at a time left the account open.
func TestWrongGuessesMadeAtOnceAllCount(t *testing.T) {
	h := newHarness(t)
	_, subject, password := passwordIdentity(h, false)

	var wg sync.WaitGroup
	for i := 0; i < authz.MaxFailedSignIns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			encoded, _ := json.Marshal(map[string]any{"subject": subject, "password": "not the one at all"})
			response, err := http.Post(h.api+"/auth/password", "application/json", bytes.NewReader(encoded))
			if err == nil {
				_ = response.Body.Close()
			}
		}()
	}
	wg.Wait()

	encoded, _ := json.Marshal(map[string]any{"subject": subject, "password": password})
	response, err := http.Post(h.api+"/auth/password", "application/json", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("ten wrong guesses at once, then the right password: status %d, expected 429 (locked)",
			response.StatusCode)
	}
}
