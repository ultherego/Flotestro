//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// The identities a suite makes are not left enabled behind it. By 20.10 the
// laboratory held 2638 of them, two of them people, and every list of identities
// in the panel paged through the rest.
func TestAnIdentityATestMakesIsDisabledWhenThatTestEnds(t *testing.T) {
	h := newHarness(t)
	subject := "cleanup-" + uuid.NewString()[:8]
	var created struct {
		ID string `json:"id"`
	}

	t.Run("the test that makes it", func(t *testing.T) {
		inner := *h
		inner.t = t
		inner.do(http.MethodPost, "/api/v1/principals", map[string]any{
			"subject": subject,
			"roles": []map[string]any{{
				"role": "viewer", "team_scope": map[string]string{"mode": "any"},
			}},
			"reason": "the integration suite makes an identity to see it taken away again",
		}, &created, http.StatusCreated)

		var enabled struct {
			Items []struct {
				Subject string `json:"subject"`
			} `json:"items"`
		}
		inner.get("/api/v1/principals?q="+subject, &enabled)
		if len(enabled.Items) != 1 {
			t.Fatalf("the identity is not enabled while its test runs: %d rows", len(enabled.Items))
		}
	})

	// Its test has ended, and so has the cleanup. Read from the database: the
	// listing of disabled identities does not filter by name.
	var disabled bool
	if err := h.database(context.Background()).QueryRow(context.Background(),
		`select disabled_at is not null from principals where id = $1`, created.ID).Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	if !disabled {
		t.Fatal("the identity a finished test made is still enabled")
	}

	// A fixture that is meant to stay is not taken: no generated suffix.
	if generatedSubject.MatchString("second-person-volume") {
		t.Error("a fixed fixture name reads as a generated one")
	}
}
