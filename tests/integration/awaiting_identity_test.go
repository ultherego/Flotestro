//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// A role granted to somebody who has never signed in waits for them on a
// record their first sign-in will adopt.
//
// The trap this covers is the one the product had already written down and
// would have walked into: an identity arriving from the provider never takes
// over a principal that exists under the same subject with another origin.
// A record made in advance the ordinary way would therefore have been
// orphaned at the person's first sign-in, and the role granted to them would
// have sat on a record nobody used.
func TestARoleCanWaitForSomebodyWhoHasNotSignedIn(t *testing.T) {
	h := newHarness(t)
	subject := "awaited-" + uuid.NewString()[:8]

	var granted struct {
		PrincipalID      string `json:"principal_id"`
		Subject          string `json:"subject"`
		Role             string `json:"role"`
		WrittenInAdvance bool   `json:"identity_written_in_advance"`
		AwaitingIssuer   string `json:"awaiting_issuer"`
	}
	h.do(http.MethodPost, "/api/v1/access/holders/grant", map[string]any{
		"subject": subject, "display_name": "Awaited Person",
		"role": "viewer", "reason": "the integration suite grants a role before the first sign-in",
	}, &granted, http.StatusCreated)

	if !granted.WrittenInAdvance {
		t.Error("the answer says the identity already existed, and this subject is new")
	}
	if granted.AwaitingIssuer == "" {
		t.Error("the record names no issuer to wait for, so no sign-in could ever adopt it")
	}
	if granted.PrincipalID == "" {
		t.Fatal("no identity came back")
	}

	// It is on the list of who may sign in, with the role, and marked as
	// somebody the panel has not met.
	var holders struct {
		Items []struct {
			Subject  string `json:"subject"`
			SignedIn bool   `json:"signed_in"`
			Roles    []struct {
				Role string `json:"role"`
				From string `json:"from"`
			} `json:"roles"`
		} `json:"items"`
	}
	h.get("/api/v1/access/holders", &holders)
	found := false
	for _, holder := range holders.Items {
		if holder.Subject != subject {
			continue
		}
		found = true
		if holder.SignedIn {
			t.Error("somebody who has never signed in is listed as known to the panel")
		}
		if len(holder.Roles) != 1 || holder.Roles[0].Role != "viewer" || holder.Roles[0].From != "binding" {
			t.Errorf("the roles of the awaited identity are %+v", holder.Roles)
		}
	}
	if !found {
		t.Fatal("the identity granted a role in advance is not on the list of who may sign in")
	}

	// Granting a second role to the same person uses the record that is
	// already there rather than making another.
	var again struct {
		PrincipalID      string `json:"principal_id"`
		WrittenInAdvance bool   `json:"identity_written_in_advance"`
	}
	h.do(http.MethodPost, "/api/v1/access/holders/grant", map[string]any{
		"subject": subject, "role": "auditor",
		"reason": "the integration suite grants a second role to the same person",
	}, &again, http.StatusCreated)
	if again.WrittenInAdvance {
		t.Error("the second grant wrote the person down again")
	}
	if again.PrincipalID != granted.PrincipalID {
		t.Errorf("the second grant made another identity: %s then %s", granted.PrincipalID, again.PrincipalID)
	}

	// A grant naming no role, or a role nobody defined, is refused rather
	// than leaving a record behind that waits for nothing.
	h.do(http.MethodPost, "/api/v1/access/holders/grant", map[string]any{
		"subject": "never-" + uuid.NewString()[:8], "role": "a_role_nobody_defined",
		"reason": "the integration suite checks an unknown role is refused",
	}, nil, http.StatusBadRequest)
}
