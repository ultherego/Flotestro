package authz

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

const (
	// SessionCookie niesie referencje do sesji serwerowej. Jest HttpOnly, wiec
	// skrypt w przegladarce jej nie odczyta.
	SessionCookie = "flotestro_session"
	// CSRFCookie jest czytelny dla skryptu i musi zostac odeslany w naglowku.
	// Ciasteczko samo w sobie nie autoryzuje niczego.
	CSRFCookie = "flotestro_csrf"
	// CSRFHeader jest naglowkiem z wartoscia CSRFCookie.
	CSRFHeader = "X-Flotestro-CSRF"
)

// SessionAuthenticator zamienia ciasteczko na tozsamosc.
type SessionAuthenticator interface {
	AuthenticateSession(ctx context.Context, cookieValue string) (*Principal, *Session, error)
}

type sessionContextKey struct{}

// Authenticator laczy dwie drogi uwierzytelnienia: sesje przegladarki
// z dostawcy tozsamosci oraz token API dla automatyzacji.
type Authenticator struct {
	Tokens interface {
		Authenticate(ctx context.Context, token string) (*Principal, error)
	}
	Sessions SessionAuthenticator
}

// Middleware ustala tozsamosc zadania. Samo uwierzytelnienie niczego nie
// autoryzuje: decyzje podejmuja handlery, bo tylko one znaja zakres celu.
func (a Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		principal := Anonymous

		// Sesja przegladarki ma pierwszenstwo; token API sluzy automatyzacji.
		if cookie, err := r.Cookie(SessionCookie); err == nil && a.Sessions != nil {
			if authenticated, session, err := a.Sessions.AuthenticateSession(ctx, cookie.Value); err == nil {
				// Zadanie zmieniajace stan z ciasteczkiem wymaga potwierdzenia
				// CSRF: przegladarka dolacza ciasteczko automatycznie, wiec
				// samo jego posiadanie nie dowodzi intencji uzytkownika.
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

// ContextWithSession dokleja sesje do kontekstu. Poza middleware sluzy
// testom, ktore sprawdzaja zachowanie zalezne od sposobu uwierzytelnienia.
func ContextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, session)
}

// SessionFromContext zwraca sesje przegladarki, jesli zadanie z niej korzysta.
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

// csrfValid sprawdza schemat double submit: wartosc z ciasteczka musi zostac
// powtorzona w naglowku, czego obca strona nie potrafi zrobic.
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
		`"code":"csrf_required","detail":"brak lub nieprawidlowy naglowek ` + CSRFHeader + `"}`))
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
