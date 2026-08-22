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

// handleLogin rozpoczyna logowanie u dostawcy tozsamosci.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		problem(w, http.StatusNotImplemented, "oidc_disabled",
			"login through an identity provider is not configured")
		return
	}

	// Ponowne uwierzytelnienie ma dwa powody i oba wymagaja tego samego od
	// dostawcy: zeby zapytal o poswiadczenia zamiast odeslac istniejaca sesje.
	//
	// step_up dotyczy operacji o najwiekszym wplywie i zada tez poziomu
	// uwierzytelnienia. force zmienia konto: bez niego uzytkownik z aktywna
	// sesja SSO innego uzytkownika jest logowany po cichu nie tym kontem,
	// co chcial, i nie ma z tego wyjscia w panelu.
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
	// Cel przekierowania musi byc lokalny, inaczej logowanie stalo by sie
	// otwartym przekierowaniem na dowolna strone.
	redirectAfter := localPath(query.Get("redirect"))

	if err := s.authz.SaveAuthFlow(r.Context(), flow.State, flow.CodeVerifier,
		flow.Nonce, redirectAfter, 10*time.Minute); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, flow.AuthURL, http.StatusFound)
}

// handleAuthCallback wymienia kod na tokeny i zaklada sesje serwerowa.
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

	// Stan jest jednorazowy: odczyt kasuje go, wiec powtorzenie tego samego
	// przekierowania nie zaloguje nikogo drugi raz.
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

	// Rola wynika z mapowania grup; sama nazwa grupy z tokenu niczego nie nadaje.
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

// handleLogout konczy sesje panelu i kieruje do wylogowania u dostawcy.
// Samo skasowanie ciasteczka nie wystarcza: dostawca zalogowalby uzytkownika
// ponownie bez pytania o haslo.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	principal := authz.FromContext(r.Context())
	session, hasSession := authz.SessionFromContext(r.Context())

	if hasSession {
		if err := s.authz.RevokeSession(r.Context(), session.ID, "wylogowanie"); err != nil {
			s.log.Error("nie uniewazniono sesji", "session_id", session.ID, "err", err)
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

// setSessionCookies ustawia ciasteczko sesji oraz token CSRF.
func (s *Server) setSessionCookies(w http.ResponseWriter, r *http.Request, sessionValue string) {
	secure := s.cookieSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:  authz.SessionCookie,
		Value: sessionValue,
		Path:  "/",
		// Refresh token zostaje na serwerze; przegladarka dostaje wylacznie
		// referencje, niedostepna dla skryptu.
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
		// Token CSRF musi byc czytelny dla skryptu, ktory odsyla go w naglowku.
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

// cookieSecure wlacza flage Secure, gdy panel jest wystawiony po HTTPS.
// W laboratorium po HTTP flaga uniemozliwilaby zalogowanie sie w ogole.
func (s *Server) cookieSecure(r *http.Request) bool {
	if strings.HasPrefix(strings.ToLower(s.publicURL), "https://") {
		return true
	}
	return r.TLS != nil
}

// localPath odrzuca cele przekierowania wskazujace poza panel.
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
