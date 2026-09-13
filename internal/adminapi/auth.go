package adminapi

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/oidc"
)

// handleLogin starts the login at the identity provider.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		problem(w, http.StatusNotImplemented, "oidc_disabled",
			"login through an identity provider is not configured")
		return
	}

	// Re-authentication has two reasons and both require the same from the
	// provider: that it asks for credentials instead of handing back the
	// existing session.
	//
	// step_up concerns the highest-impact operations and also demands an
	// authentication level. force changes the account: without it a user
	// with an active SSO session of another user is quietly logged in with
	// the wrong account, and there is no way out of it in the panel.
	query := r.URL.Query()
	stepUp := oidc.StepUp{}
	switch {
	case query.Get("step_up") != "":
		stepUp = oidc.StepUp{Force: true, ACRValues: s.stepUp.ACR}
	case query.Get("force") != "":
		stepUp = oidc.StepUp{Force: true}
	}

	flow, err := s.oidc.BeginAuth(stepUp)
	if err != nil {
		s.fail(w, err)
		return
	}
	// The redirect target must be local, otherwise the login would become an
	// open redirect to any page.
	redirectAfter := localPath(query.Get("redirect"))

	if err := s.authz.SaveAuthFlow(r.Context(), flow.State, flow.CodeVerifier,
		flow.Nonce, redirectAfter, 10*time.Minute); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, flow.AuthURL, http.StatusFound)
}

// handleAuthCallback exchanges the code for tokens and creates a server
// session.
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		problem(w, http.StatusNotImplemented, "oidc_disabled", "login is not configured")
		return
	}
	query := r.URL.Query()

	if providerError := query.Get("error"); providerError != "" {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: "anonymous",
			Action: "auth.login", Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": providerError, "description": query.Get("error_description"),
			},
		})
		problem(w, http.StatusUnauthorized, "login_failed", "the identity provider rejected the login")
		return
	}

	code, state := query.Get("code"), query.Get("state")
	if code == "" || state == "" {
		problem(w, http.StatusBadRequest, "invalid_callback", "missing login code or state")
		return
	}

	// The state is single-use: reading deletes it, so repeating the same
	// redirect logs nobody in a second time.
	verifier, nonce, redirectAfter, err := s.authz.TakeAuthFlow(r.Context(), state)
	if err != nil {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: "anonymous",
			Action: "auth.login", Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": "unknown_state"},
		})
		problem(w, http.StatusBadRequest, "invalid_state",
			"the login state is unknown or expired")
		return
	}

	tokens, claims, err := s.oidc.Exchange(r.Context(), code, verifier, nonce)
	if err != nil {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: "anonymous",
			Action: "auth.login", Outcome: audit.OutcomeFailure,
			Detail: map[string]any{"reason": "token_exchange_failed", "error": err.Error()},
		})
		problem(w, http.StatusUnauthorized, "login_failed", "the code exchange failed")
		return
	}

	tx, err := s.authz.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	principalID, err := s.authz.UpsertExternalPrincipal(r.Context(), tx, s.oidc.Issuer(),
		claims.Subject, claims.PreferredUsername, claims.Name, claims.Email)
	if err != nil {
		s.fail(w, err)
		return
	}

	sessionID, cookieValue, err := s.authz.CreateSession(r.Context(), tx, principalID,
		claims.Groups, authz.SessionTokens{
			RefreshToken:    tokens.RefreshToken,
			IDToken:         tokens.IDToken,
			AccessExpiresAt: tokens.ExpiresAt,
		}, authz.Authentication{
			At:  claims.AuthTime,
			ACR: claims.ACR,
			AMR: claims.AMR,
		}, s.sessionLimits, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		s.fail(w, err)
		return
	}

	// The role follows from the group mapping; the group name from the token
	// alone grants nothing.
	mapped, err := s.authz.MappedBindings(r.Context(), s.oidc.Issuer(), claims.Groups)
	if err != nil {
		s.fail(w, err)
		return
	}
	roles := make([]string, 0, len(mapped))
	for _, binding := range mapped {
		roles = append(roles, string(binding.Role))
	}

	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: firstNonEmpty(claims.PreferredUsername, claims.Subject),
		Action: "auth.login", TargetType: "principal", TargetID: principalID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"issuer": s.oidc.Issuer(), "session_id": sessionID,
			"groups": claims.Groups, "mapped_roles": roles, "remote_addr": r.RemoteAddr,
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	s.setSessionCookies(w, r, cookieValue)
	if redirectAfter == "" {
		redirectAfter = "/"
	}
	http.Redirect(w, r, redirectAfter, http.StatusFound)
}

// handleLogout ends the panel session and directs to the logout at the
// provider. Deleting the cookie alone is not enough: the provider would log
// the user in again without asking for a password.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	session, hasSession := authz.SessionFromContext(r.Context())

	if hasSession {
		if err := s.authz.RevokeSession(r.Context(), session.ID, "logout"); err != nil {
			s.log.Error("the session was not revoked", "session_id", session.ID, "err", err)
		}
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "auth.logout", TargetType: "principal", TargetID: principal.ID,
			Outcome: audit.OutcomeSuccess,
			Detail:  map[string]any{"session_id": session.ID},
		})
	}
	s.clearSessionCookies(w, r)

	target := "/"
	if s.oidc != nil && hasSession && session.IDToken != "" {
		target = s.oidc.LogoutURL(session.IDToken, s.publicURL)
	}
	writeJSON(w, http.StatusOK, map[string]any{"logout_url": target})
}

// setSessionCookies sets the session cookie and the CSRF token.
func (s *Server) setSessionCookies(w http.ResponseWriter, r *http.Request, sessionValue string) {
	secure := s.cookieSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:  authz.SessionCookie,
		Value: sessionValue,
		Path:  "/",
		// The refresh token stays on the server; the browser gets only a
		// reference, inaccessible to scripts.
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.sessionLimits.Absolute / time.Second),
	})

	csrf := make([]byte, 32)
	if _, err := rand.Read(csrf); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  authz.CSRFCookie,
		Value: base64.RawURLEncoding.EncodeToString(csrf),
		Path:  "/",
		// The CSRF token must be readable by the script that sends it back in
		// a header.
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.sessionLimits.Absolute / time.Second),
	})
}

func (s *Server) clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	secure := s.cookieSecure(r)
	for _, name := range []string{authz.SessionCookie, authz.CSRFCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == authz.SessionCookie, Secure: secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

// cookieSecure enables the Secure flag when the panel is exposed over
// HTTPS. In a lab over HTTP the flag would make logging in impossible at
// all.
func (s *Server) cookieSecure(r *http.Request) bool {
	if strings.HasPrefix(strings.ToLower(s.publicURL), "https://") {
		return true
	}
	return r.TLS != nil
}

// localPath rejects redirect targets pointing outside the panel.
func localPath(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") {
		return ""
	}
	return parsed.Path
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
