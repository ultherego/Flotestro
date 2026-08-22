package authz

import (
	"context"
)

type contextKey string

const principalKey contextKey = "flotestro.principal"

// GlobalScope jest celem operacji nieprzypisanych do konkretnej czesci floty.
// Dopasuje sie do niego wylacznie przypisanie z gwiazdka, wiec operator
// jednego srodowiska nie zarzadza calym systemem.
var GlobalScope = Scope{Site: Wildcard, Environment: Wildcard}

// Anonymous jest tozsamoscia bez zadnych uprawnien.
var Anonymous = Principal{Subject: "anonymous", Kind: "user"}

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
