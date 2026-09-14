package oidc

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/oauth2"
)

func TestOnlyAnInvalidGrantMeansTheUserIsGone(t *testing.T) {
	// The refresher ends a session on this answer alone: every other failure
	// says something about the provider or the network, not about the user,
	// and a session must not be lost to an outage.
	cases := []struct {
		name string
		err  error
		gone bool
	}{
		{"invalid_grant", &oauth2.RetrieveError{ErrorCode: "invalid_grant"}, true},
		{"invalid_grant wrapped as Refresh wraps it",
			fmt.Errorf("renewing the session: %w", &oauth2.RetrieveError{ErrorCode: "invalid_grant"}), true},
		{"invalid_client", &oauth2.RetrieveError{ErrorCode: "invalid_client"}, false},
		{"a status without a code", &oauth2.RetrieveError{}, false},
		{"a network error", errors.New("dial tcp: connection refused"), false},
		{"no error", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsInvalidGrant(tc.err); got != tc.gone {
				t.Fatalf("IsInvalidGrant = %v, expected %v", got, tc.gone)
			}
		})
	}
}
