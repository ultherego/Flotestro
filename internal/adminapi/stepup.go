package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// The highest-impact operations require fresh authentication and a reason.
// These are the changes that move the access rules themselves: mapping
// groups to roles, granting permissions to a principal, global directory
// rules.
//
// The panel does not implement MFA and does not pretend to know it. MFA
// belongs to the identity provider; the panel checks only whether it got
// the declared authentication level (acr) and whether the authentication is
// fresh. When the installation defined no level, freshness alone remains -
// and that is how it is written in the audit log, so nobody reads it as an
// MFA confirmation.
type stepUpPolicy struct {
	// MaxAge is the allowed authentication age. Zero disables the freshness
	// requirement.
	MaxAge time.Duration
	// ACR is the required authentication level. Empty means the
	// installation did not define it.
	ACR string
}

const minimalStepUpReason = 8

// stepUpDenial describes a refusal together with what is missing. The
// client is meant to learn from it that re-authenticating and retrying the
// request is worthwhile.
type stepUpDenial struct {
	Code    string
	Message string
	Detail  map[string]any
	// RequestError means a refusal re-authentication will not fix. A missing
	// reason is a gap in the request, not in the session - sending the
	// client to the login would make them fix what is not broken.
	RequestError bool
}

// evaluate decides whether a highest-impact operation may take place. The
// function has no side effects: the audit record and the HTTP response
// belong to the layer above, so the rule itself can be checked in a test.
func (p stepUpPolicy) evaluate(reason string, session *authz.Session) (map[string]any, *stepUpDenial) {
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) < minimalStepUpReason {
		return nil, &stepUpDenial{
			Code:         "reason_required",
			Message:      "this operation requires a reason (field reason, min. 8 characters)",
			Detail:       map[string]any{},
			RequestError: true,
		}
	}

	if session == nil {
		// An automated identity cannot re-authenticate: there is no human
		// behind it. The operation is allowed, but the audit log records
		// directly that the authentication was not refreshed.
		return map[string]any{
			"high_impact": true, "purpose": reason,
			"authentication": "api_token", "reauthenticated": false,
		}, nil
	}

	if p.MaxAge > 0 {
		if session.Auth.At.IsZero() {
			// The provider did not report auth_time. An undetermined state
			// cannot be read as "a moment ago".
			return nil, &stepUpDenial{
				Code:    "reauthentication_required",
				Message: "the identity provider did not report the authentication time; sign in again",
				Detail:  map[string]any{"required_max_age_seconds": int(p.MaxAge.Seconds())},
			}
		}
		if age := time.Since(session.Auth.At); age > p.MaxAge {
			return nil, &stepUpDenial{
				Code:    "reauthentication_required",
				Message: "this operation requires fresh authentication; sign in again",
				Detail: map[string]any{
					"required_max_age_seconds":   int(p.MaxAge.Seconds()),
					"authentication_age_seconds": int(age.Seconds()),
				},
			}
		}
	}
	if p.ACR != "" && session.Auth.ACR != p.ACR {
		return nil, &stepUpDenial{
			Code:    "reauthentication_required",
			Message: "this operation requires authentication at level " + p.ACR,
			Detail:  map[string]any{"required_acr": p.ACR, "session_acr": session.Auth.ACR},
		}
	}

	return map[string]any{
		"high_impact": true, "purpose": reason,
		"authentication": "session", "reauthenticated": true,
		// The authentication method is recorded as the provider reported it.
		// The panel does not translate it into its own "mfa: yes".
		"acr": session.Auth.ACR, "amr": session.Auth.AMR,
		"authenticated_at": session.Auth.At.UTC().Format(time.RFC3339),
	}, nil
}

// requireStepUp applies the rule and returns the authentication evidence to
// record in the audit entry of the operation itself.
//
// A refusal is audited here, because the operation never takes place. A
// success is audited by the handler together with the change description:
// one operation is meant to leave one entry, not two saying the same.
func (s *Server) requireStepUp(w http.ResponseWriter, r *http.Request,
	principal authz.Principal, reason, action, targetType, targetID string) (map[string]any, bool) {
	session, _ := authz.SessionFromContext(r.Context())

	evidence, denial := s.stepUp.evaluate(reason, session)
	if denial != nil {
		denial.Detail["reason"] = denial.Code
		denial.Detail["action"] = action
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: action, TargetType: targetType, TargetID: targetID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied, Detail: denial.Detail,
		})
		if denial.RequestError {
			problem(w, http.StatusBadRequest, denial.Code, denial.Message)
			return nil, false
		}
		// 401 instead of 403: fresh authentication is missing, not permissions.
		problem(w, http.StatusUnauthorized, denial.Code, denial.Message)
		return nil, false
	}
	return evidence, true
}

// withStepUp attaches the authentication evidence to the change
// description. Thanks to that one audit entry says both what changed and on
// what basis.
func withStepUp(detail, evidence map[string]any) map[string]any {
	for key, value := range evidence {
		detail[key] = value
	}
	return detail
}
