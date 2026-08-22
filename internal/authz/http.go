package authz

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const principalKey contextKey = "flotestro.principal"

// GlobalScope jest celem operacji nieprzypisanych do konkretnej czesci floty.
// Dopasuje sie do niego wylacznie przypisanie z gwiazdka, wiec operator
// jednego srodowiska nie zarzadza calym systemem.
var GlobalScope = Scope{Site: Wildcard, Environment: Wildcard}

// Anonymous jest tozsamoscia bez zadnych uprawnien.
var Anonymous = Principal{Subject: "anonymous", Kind: "user"}

// Authenticator zamienia token na tozsamosc.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (*Principal, error)
}

// Middleware uwierzytelnia zadanie i wklada tozsamosc do kontekstu.
// Samo uwierzytelnienie niczego nie autoryzuje: decyzje podejmuja handlery,
// bo tylko one znaja zakres celu.
func Middleware(authenticator Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := Anonymous
			if token := bearerToken(r); token != "" {
				if authenticated, err := authenticator.Authenticate(r.Context(), token); err == nil {
					principal = *authenticated
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal)))
		})
	}
}

// FromContext zwraca tozsamosc zadania.
func FromContext(ctx context.Context) Principal {
	principal, ok := ctx.Value(principalKey).(Principal)
	if !ok {
		return Anonymous
	}
	return principal
}

// Authenticated mowi, czy zadanie ma jakakolwiek tozsamosc.
func (p Principal) Authenticated() bool {
	return p.ID != ""
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
