package authz

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

const (
	// SessionCookie carries a reference to the server-side session. It is
	// HttpOnly, so a script in the browser cannot read it.
	SessionCookie = "flotestro_session"
	// CSRFCookie is readable by a script and has to be sent back in a header.
	// The cookie by itself authorises nothing.
	CSRFCookie = "flotestro_csrf"
	// CSRFHeader is the header carrying the value of CSRFCookie.
	CSRFHeader = "X-Flotestro-CSRF"
)

// SessionAuthenticator turns a cookie into an identity.
type SessionAuthenticator interface {
	AuthenticateSession(ctx context.Context, cookieValue string) (*Principal, *Session, error)
}

type sessionContextKey struct{}

// Authenticator joins two ways of authenticating: a browser session from the
// identity provider and an API token for automation.
type Authenticator struct {
	Tokens interface {
		Authenticate(ctx context.Context, token string) (*Principal, error)
	}
	Sessions SessionAuthenticator
}

// Middleware establishes the identity of the request. Authentication by
// itself authorises nothing: the handlers make the decisions, because only
// they know the target's scope.
func (a Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		principal := Anonymous

		// The browser session takes precedence; the API token serves automation.
		if cookie, err := r.Cookie(SessionCookie); err == nil && a.Sessions != nil {
			if authenticated, session, err := a.Sessions.AuthenticateSession(ctx, cookie.Value); err == nil {
				// A state-changing request with a cookie requires CSRF
				// confirmation: the browser attaches the cookie
				// automatically, so having it does not prove the user's
				// intent.
				if !safeMethod(r.Method) && !csrfValid(r) {
					writeCSRFError(w)
					return
				}
				principal = *authenticated
				ctx = ContextWithSession(ctx, session)
			}
		}

		if !principal.Authenticated() && a.Tokens != nil {
			if token := bearerToken(r); token != "" {
				if authenticated, err := a.Tokens.Authenticate(ctx, token); err == nil {
					principal = *authenticated
				}
			}
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, principalKey, principal)))
	})
}

// ContextWithSession attaches the session to the context. Outside the
// middleware it serves tests that check behaviour depending on the way of
// authenticating.
func ContextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, session)
}

// SessionFromContext returns the browser session if the request uses one.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(sessionContextKey{}).(*Session)
	return session, ok
}

func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// csrfValid checks the double submit scheme: the value from the cookie has
// to be repeated in a header, which a foreign site cannot do.
func csrfValid(r *http.Request) bool {
	cookie, err := r.Cookie(CSRFCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get(CSRFHeader)
	if header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) == 1
}

func writeCSRFError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"type":"about:blank","title":"Forbidden","status":403,` +
		`"code":"csrf_required","detail":"the ` + CSRFHeader + ` header is missing or invalid"}`))
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
