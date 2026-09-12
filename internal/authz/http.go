package authz

import (
	"context"
)

type contextKey string

const principalKey contextKey = "flotestro.principal"

// GlobalScope is the target of operations not assigned to any particular
// part of the fleet. Only an assignment with an asterisk matches it, so the
// operator of one environment does not manage the whole system.
var GlobalScope = Scope{Site: Wildcard, Environment: Wildcard}

// Anonymous is an identity without any permissions.
var Anonymous = Principal{Subject: "anonymous", Kind: "user"}

// FromContext returns the identity of the request.
func FromContext(ctx context.Context) Principal {
	principal, ok := ctx.Value(principalKey).(Principal)
	if !ok {
		return Anonymous
	}
	return principal
}

// Authenticated says whether the request has any identity at all.
func (p Principal) Authenticated() bool {
	return p.ID != ""
}
