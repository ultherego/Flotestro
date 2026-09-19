package adminapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
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
	// provider: that it asks for credentials instead of handing back the existing
	// session.
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
	s.setLoginStateCookie(w, r, flow.State)
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
	// The browser has to be the one that started this login.
	if !loginStateMatches(r, state) {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: "anonymous",
			Action: "auth.login", Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": "state_not_bound_to_browser", "remote_addr": r.RemoteAddr},
		})
		problem(w, http.StatusBadRequest, "invalid_state",
			"the login was started in another browser or the login cookie expired; start again")
		return
	}
	s.clearLoginStateCookie(w, r)

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

	// A login replaces the session the browser came with.
	previous, hasPrevious := authz.SessionFromContext(r.Context())

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

	detail := map[string]any{
		"issuer": s.oidc.Issuer(), "session_id": sessionID,
		"groups": claims.Groups, "mapped_roles": roles, "remote_addr": r.RemoteAddr,
	}
	if hasPrevious {
		detail["replaced_session_id"] = previous.ID
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: firstNonEmpty(claims.PreferredUsername, claims.Subject),
		Action: "auth.login", TargetType: "principal", TargetID: principalID,
		Outcome: audit.OutcomeSuccess,
		Detail:  detail,
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	// The old session ends once the new one stands; a failure here leaves a
	// session that expires on its own, not a browser without one.
	if hasPrevious && previous.ID != sessionID {
		if err := s.authz.RevokeSession(r.Context(), previous.ID, "replaced_by_login"); err != nil {
			s.log.Error("the replaced session was not revoked", "session_id", previous.ID, "err", err)
		}
	}

	s.setSessionCookies(w, r, cookieValue)
	if redirectAfter == "" {
		redirectAfter = "/"
	}
	http.Redirect(w, r, redirectAfter, http.StatusFound)
}

// handleLogout ends the panel session and directs to the logout at the
// provider.
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

// cookieSecure enables the Secure flag when the panel is exposed over HTTPS.
// In a lab over HTTP the flag would make logging in impossible at all.
func (s *Server) cookieSecure(r *http.Request) bool {
	if strings.HasPrefix(strings.ToLower(s.publicURL), "https://") {
		return true
	}
	return r.TLS != nil
}

// localPathPattern is what a redirect target inside the panel looks like: an
// absolute path of the characters a route of the panel uses.
var localPathPattern = regexp.MustCompile(`^/[A-Za-z0-9/_.\-?=&%#]*$`)

// localPath rejects redirect targets pointing outside the panel.
func localPath(value string) string {
	if value == "" || strings.Contains(value, `\`) || !localPathPattern.MatchString(value) {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") ||
		strings.HasPrefix(parsed.Path, "//") {
		return ""
	}
	// The decoded path is what the Location header carries, so it has to pass the
	// same test as the raw value: "/%5Cevil.
	if !localPathPattern.MatchString(parsed.Path) || strings.HasPrefix(parsed.Path, "//") {
		return ""
	}
	return parsed.Path
}

// loginStateCookie binds the login to the browser that started it.
const loginStateCookie = "flotestro_login"

// setLoginStateCookie remembers the digest of the state for the length of
// the login flow.
func (s *Server) setLoginStateCookie(w http.ResponseWriter, r *http.Request, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginStateCookie,
		Value:    loginStateDigest(state),
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		// Lax rather than Strict: the callback is a top-level navigation
		// from the provider, which Strict would strip the cookie from.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((10 * time.Minute) / time.Second),
	})
}

// loginStateMatches says whether the state of the callback is the one
// this browser started with.
func loginStateMatches(r *http.Request, state string) bool {
	cookie, err := r.Cookie(loginStateCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(loginStateDigest(state))) == 1
}

// loginStateDigest keeps the state itself out of the cookie: the cookie
// vouches for the state without being a second copy of it.
func loginStateDigest(state string) string {
	sum := sha256.Sum256([]byte(state))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Server) clearLoginStateCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: loginStateCookie, Value: "", Path: "/auth/", MaxAge: -1,
		HttpOnly: true, Secure: s.cookieSecure(r), SameSite: http.SameSiteLaxMode,
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
