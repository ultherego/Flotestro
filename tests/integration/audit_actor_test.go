//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// actorEventView mirrors an audit event with its actor snapshot.
type actorEventView struct {
	ID      int64          `json:"id"`
	ActorID string         `json:"actor_id"`
	Action  string         `json:"action"`
	Detail  map[string]any `json:"detail"`
	Actor   *struct {
		PrincipalID  string `json:"principal_id"`
		Subject      string `json:"subject"`
		DisplayName  string `json:"display_name"`
		Kind         string `json:"kind"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
		CredentialID string `json:"credential_id"`
	} `json:"actor"`
}

type actorPage struct {
	Items []actorEventView `json:"items"`
}

// TestAuditKeepsTheActorsNameAsItWas checks that an event carries the actor as
// it was written: the identifier, the subject, the display name and the kind.
func TestAuditKeepsTheActorsNameAsItWas(t *testing.T) {
	h := newHarness(t)
	subject := uniqueSubject("renamed-auditor")

	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	h.do(http.MethodPost, "/api/v1/principals", map[string]any{
		"subject": subject, "display_name": "Name As Ordered", "kind": "user",
		"roles":       []map[string]string{{"role": "auditor"}},
		"issue_token": true,
		"reason":      "identity prepared for an integration test",
	}, &created, http.StatusCreated)
	if created.ID == "" || created.Token == "" {
		t.Fatal("the identity came without an identifier or a token")
	}
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/principals/"+created.ID,
			map[string]any{"reason": "integration test finished"}, nil, 0)
	})

	// Reading the trail is on the trail: one read under the new identity
	// leaves one event whose actor is that identity.
	auditor := h.withToken(created.Token)
	auditor.do(http.MethodGet, "/api/v1/audit?limit=1", nil, nil, http.StatusOK)

	byPrincipal := "/api/v1/audit?actor_kind=user&actor_principal_id=" + created.ID + "&limit=10"
	var first actorPage
	h.get(byPrincipal, &first)
	if len(first.Items) == 0 {
		t.Fatal("the identity's own read is not on the trail under its identifier")
	}
	event := first.Items[0]
	if event.Actor == nil {
		t.Fatalf("the event carries no actor snapshot: %+v", event)
	}
	if event.Actor.PrincipalID != created.ID || event.Actor.Subject != subject ||
		event.Actor.DisplayName != "Name As Ordered" || event.Actor.Kind != "user" {
		t.Fatalf("the snapshot is not the identity as ordered: %+v", *event.Actor)
	}
	if event.ActorID != subject {
		t.Fatalf("actor_id = %q, expected the subject %q for the readers that know it", event.ActorID, subject)
	}
	for _, item := range first.Items {
		if item.Actor == nil || item.Actor.PrincipalID != created.ID {
			t.Fatalf("the filter by identifier let through another actor: %+v", item)
		}
	}

	// The identity is renamed under the trail.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := h.database(ctx).Exec(ctx,
		`update principals set display_name = $2 where id = $1`, created.ID, "Name After Rename"); err != nil {
		t.Fatalf("renaming the identity: %v", err)
	}
	h.do(http.MethodDelete, "/api/v1/principals/"+created.ID,
		map[string]any{"reason": "integration test of the actor snapshot"}, nil, http.StatusNoContent)

	var second actorPage
	h.get(byPrincipal, &second)
	var again *actorEventView
	for i := range second.Items {
		if second.Items[i].ID == event.ID {
			again = &second.Items[i]
		}
	}
	if again == nil || again.Actor == nil {
		t.Fatal("the event is gone from the trail after the identity was renamed and disabled")
	}
	if again.Actor.DisplayName != "Name As Ordered" || again.Actor.PrincipalID != created.ID ||
		again.Actor.Subject != subject {
		t.Fatalf("the rename rewrote the history: %+v", *again.Actor)
	}
}
