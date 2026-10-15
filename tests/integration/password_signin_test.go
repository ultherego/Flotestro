//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// Signing in with a password, which is how a person gets into an
// installation that has no identity provider.
//
// It runs here because every part of the answer is in the database and in
// the session the panel hands back: the hash, the counting of wrong
// attempts, the lock, and the cookie that turns into an identity on the next
// request.
func TestAPersonSignsInWithAPassword(t *testing.T) {
	h := newHarness(t)
	subject := "local-" + uuid.NewString()[:8]
	password := "a long enough passphrase"

	// An identity made the ordinary way has no password: it signs in through
	// the provider, or not at all.
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

	h.do(http.MethodPost, "/auth/password", map[string]any{
		"subject": subject, "password": password,
	}, nil, http.StatusUnauthorized)

	// An administrator sets one.
	h.do(http.MethodPut, "/api/v1/principals/"+created.ID+"/password", map[string]any{
		"password": password, "must_change": true,
		"reason": "the integration suite sets the first password",
	}, nil, http.StatusOK)

	// The listing says there is one now, and that its owner has to replace
	// it - without saying anything about what it is.
	var listed struct {
		Items []struct {
			ID       string `json:"id"`
			Subject  string `json:"subject"`
			Password *struct {
				MustChange bool   `json:"must_change"`
				SetBy      string `json:"set_by"`
			} `json:"password"`
		} `json:"items"`
	}
	h.get("/api/v1/principals?q="+subject, &listed)
	if len(listed.Items) != 1 {
		t.Fatalf("the identity is not in the listing: %d rows", len(listed.Items))
	}
	if listed.Items[0].Password == nil {
		t.Fatal("the listing says this identity has no password, and one was just set")
	}
	if !listed.Items[0].Password.MustChange {
		t.Error("a password somebody else chose is not marked for replacement")
	}

	// The right password opens, and the answer says the owner has to replace
	// it rather than letting them forget.
	var signedIn struct {
		Subject    string `json:"subject"`
		MustChange bool   `json:"must_change_password"`
	}
	h.do(http.MethodPost, "/auth/password", map[string]any{
		"subject": subject, "password": password,
	}, &signedIn, http.StatusOK)
	if signedIn.Subject != subject || !signedIn.MustChange {
		t.Errorf("the sign-in answered %+v", signedIn)
	}

	// A wrong password is refused with the same sentence as an unknown name:
	// whoever is typing learns nothing about which names exist.
	h.do(http.MethodPost, "/auth/password", map[string]any{
		"subject": subject, "password": "not the one at all",
	}, nil, http.StatusUnauthorized)
	h.do(http.MethodPost, "/auth/password", map[string]any{
		"subject": "nobody-" + uuid.NewString()[:8], "password": "not the one at all",
	}, nil, http.StatusUnauthorized)

	// Ten wrong ones lock the account, and the lock says so plainly: its
	// owner has to know that waiting is the answer, not retyping.
	//
	// The count is of this identity alone, so the refusal above for a name
	// nobody has does not belong to it: one wrong password so far, eight
	// here, and the tenth is the one that locks. The lock answers on the
	// attempt that reaches the limit, not on the one after it - whoever is
	// typing learns at once that waiting is now the only move.
	for i := 0; i < 8; i++ {
		h.do(http.MethodPost, "/auth/password", map[string]any{
			"subject": subject, "password": fmt.Sprintf("wrong attempt %d", i),
		}, nil, http.StatusUnauthorized)
	}
	h.do(http.MethodPost, "/auth/password", map[string]any{
		"subject": subject, "password": "the tenth wrong one",
	}, nil, http.StatusTooManyRequests)
	// And the right password is refused while the lock holds: a lock that
	// the right password opens is not a lock.
	h.do(http.MethodPost, "/auth/password", map[string]any{
		"subject": subject, "password": password,
	}, nil, http.StatusTooManyRequests)

	// Setting a password again answers the question the lock was asking.
	h.do(http.MethodPut, "/api/v1/principals/"+created.ID+"/password", map[string]any{
		"password": "another long passphrase", "must_change": false,
		"reason": "the integration suite clears the lock by setting a password",
	}, nil, http.StatusOK)
	h.do(http.MethodPost, "/auth/password", map[string]any{
		"subject": subject, "password": "another long passphrase",
	}, nil, http.StatusOK)

	// What the installation will not store.
	for _, weak := range []string{"short", "password is here", subject + "-2026"} {
		h.do(http.MethodPut, "/api/v1/principals/"+created.ID+"/password", map[string]any{
			"password": weak, "reason": "the integration suite checks the password policy",
		}, nil, http.StatusBadRequest)
	}

	// Taking the password away leaves the identity to the provider.
	h.do(http.MethodDelete, "/api/v1/principals/"+created.ID+"/password?reason=the+suite+removes+the+password",
		nil, nil, http.StatusNoContent)
	h.do(http.MethodPost, "/auth/password", map[string]any{
		"subject": subject, "password": "another long passphrase",
	}, nil, http.StatusUnauthorized)
}
