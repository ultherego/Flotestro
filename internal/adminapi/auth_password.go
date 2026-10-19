package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
)

// Signing in with a password, for an installation with no identity provider.
//
// The panel had RBAC, roles and tokens and no door for a person: /auth/login
// answers 501 without a provider, and the bootstrap token is for the first
// group mapping. The owner asked where access comes from in an installation
// with no FreeIPA and no SSO, and the answer was "nowhere" - so here it is.
//
// What the answers say is deliberate. A wrong name and a wrong password are
// the same sentence to whoever is typing, and two different lines in the
// trail: the person at the keyboard learns nothing about which names exist,
// and the administrator reading the audit afterwards learns everything.

type passwordSignInRequest struct {
	Subject  string `json:"subject"`
	Password string `json:"password"`
}

func (s *Server) handlePasswordSignIn(w http.ResponseWriter, r *http.Request) {
	var request passwordSignInRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	subject := strings.TrimSpace(request.Subject)
	if subject == "" || request.Password == "" {
		problem(w, http.StatusBadRequest, "invalid_body", "a sign-in names an identity and a password")
		return
	}

	signIn, err := s.authz.SignInWithPassword(r.Context(), subject, request.Password)
	if err != nil {
		s.refusePasswordSignIn(w, r, subject, err)
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	// A local session carries no provider: no refresh token, no groups, and
	// the authentication time is this moment - which is what a step-up asks
	// about later.
	_, cookieValue, err := s.authz.CreateSession(r.Context(), tx, signIn.Principal.ID,
		nil, authz.SessionTokens{}, authz.Authentication{
			At: time.Now(), AMR: []string{"pwd"},
		}, s.sessionLimits, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: signIn.Principal.Subject,
		Action: "auth.password.signin", TargetType: "principal", TargetID: signIn.Principal.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"must_change_password": signIn.MustChange, "remote_addr": r.RemoteAddr},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	s.setSessionCookies(w, r, cookieValue)
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": signIn.Principal.Subject,
		// The panel sends them to the change form; the session exists either
		// way, because a password somebody else chose is still how they got
		// in and they have to be able to change it.
		"must_change_password": signIn.MustChange,
	})
}

// refusePasswordSignIn answers the one sentence and records the real reason.
func (s *Server) refusePasswordSignIn(w http.ResponseWriter, r *http.Request, subject string, err error) {
	reason := "unknown"
	switch {
	case errors.Is(err, authz.ErrNoSuchLocalIdentity):
		reason = "no_local_identity"
	case errors.Is(err, authz.ErrWrongPassword):
		reason = "wrong_password"
	case errors.Is(err, authz.ErrAccountLocked):
		reason = "locked"
	default:
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: subject,
		Action: "auth.password.signin", TargetType: "principal", TargetID: subject,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
		Detail: map[string]any{"reason": reason, "remote_addr": r.RemoteAddr},
	})
	if reason == "locked" {
		// This one is said plainly: the person is locked out of their own
		// account and has to know that waiting is the answer, not retyping.
		problem(w, http.StatusTooManyRequests, "account_locked", err.Error())
		return
	}
	problem(w, http.StatusUnauthorized, "invalid_credentials",
		"the identity or the password is wrong")
}

// handlePasswordReauthenticate refreshes the authentication time of a local
// session, which is what a step-up asks for.
//
// With a provider, fresh authentication means being sent back to it. A local
// identity has no provider to be sent to, so it is the same password again -
// and the session's authentication time moves only when it matches.
func (s *Server) handlePasswordReauthenticate(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	if !principal.Authenticated() {
		problem(w, http.StatusUnauthorized, "unauthenticated", "re-authentication needs a session to refresh")
		return
	}
	session, hasSession := authz.SessionFromContext(r.Context())
	if !hasSession {
		problem(w, http.StatusBadRequest, "no_session",
			"re-authentication applies to a browser session; a token carries none")
		return
	}
	var request passwordSignInRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if _, err := s.authz.SignInWithPassword(r.Context(), principal.Subject, request.Password); err != nil {
		s.refusePasswordSignIn(w, r, principal.Subject, err)
		return
	}
	refreshed, err := s.authz.RefreshAuthentication(r.Context(), session.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !refreshed {
		problem(w, http.StatusConflict, "reauthentication_not_by_password",
			"this session was made by the identity provider; a password cannot renew it - sign in through the provider again")
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "auth.password.reauthenticate", TargetType: "principal", TargetID: principal.ID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
	})
	writeJSON(w, http.StatusOK, map[string]any{"reauthenticated": true})
}
