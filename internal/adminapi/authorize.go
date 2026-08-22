package adminapi

import (
	"errors"
	"net/http"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
)

// authorize sprawdza uprawnienie w zakresie celu. Kazda odmowa trafia do
// audytu: slad pokazujacy wylacznie udane operacje jest bezuzyteczny przy
// analizie incydentu.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, permission authz.Permission,
	scope authz.Scope, targetType, targetID string) (authz.Principal, bool) {
	principal := authz.FromContext(r.Context())

	if !principal.Authenticated() {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: "anonymous",
			Action: string(permission), TargetType: targetType, TargetID: targetID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": "unauthenticated", "path": r.URL.Path},
		})
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated",
			"a token is required; header Authorization: Bearer <token>")
		return principal, false
	}

	if !principal.Can(permission, scope) {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: string(permission), TargetType: targetType, TargetID: targetID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "permission_denied", "permission": string(permission),
				"scope": scope.String(), "roles": principal.Roles(),
			},
		})
		problem(w, http.StatusForbidden, "permission_denied",
			"missing permission "+string(permission)+" in scope "+scope.String())
		return principal, false
	}
	return principal, true
}

// authorizeCollection autoryzuje odczyt kolekcji, ktora nie ma jednego
// zakresu: listy hostow, zadan, kampanii czy podsumowania floty.
//
// Wystarczy uprawnienie w dowolnym zakresie, a wynik zawezaja handlery do
// tego, co tozsamosc faktycznie moze widziec. Wymaganie zakresu globalnego
// zamienialo zwykle przegladanie panelu w odmowe dla kazdego, kto ma role
// ograniczona do jednego srodowiska - czyli dla typowego operatora.
func (s *Server) authorizeCollection(w http.ResponseWriter, r *http.Request,
	permission authz.Permission, targetType string) (authz.Principal, bool) {
	principal := authz.FromContext(r.Context())

	if !principal.Authenticated() {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: "anonymous",
			Action: string(permission), TargetType: targetType,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{"reason": "unauthenticated", "path": r.URL.Path},
		})
		w.Header().Set("WWW-Authenticate", `Bearer realm="flotestro"`)
		problem(w, http.StatusUnauthorized, "unauthenticated",
			"a token is required; header Authorization: Bearer <token>")
		return principal, false
	}

	if !principal.CanAnywhere(permission) {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: string(permission), TargetType: targetType,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": "permission_denied", "permission": string(permission),
				"roles": principal.Roles(),
			},
		})
		problem(w, http.StatusForbidden, "permission_denied",
			"missing permission "+string(permission)+" in any scope")
		return principal, false
	}
	return principal, true
}

// hostScope zwraca zakres autoryzacji hosta. Host, ktorego nie ma, nie moze
// byc celem zadnej operacji.
func (s *Server) hostScope(w http.ResponseWriter, r *http.Request, hostID string) (*hosts.Host, authz.Scope, bool) {
	host, err := s.hosts.Get(r.Context(), hostID)
	if errors.Is(err, hosts.ErrNotFound) {
		problem(w, http.StatusNotFound, "host_not_found", "no such host")
		return nil, authz.Scope{}, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, authz.Scope{}, false
	}
	return host, authz.Scope{Site: host.Site, Environment: host.Environment}, true
}

// jobScope zwraca zakres autoryzacji zadania, czyli zakres hosta, ktorego
// zadanie dotyczy.
func (s *Server) jobScope(r *http.Request, hostID string) authz.Scope {
	host, err := s.hosts.Get(r.Context(), hostID)
	if err != nil {
		// Nieznany zakres nie moze byc dopasowany przez waskie przypisanie,
		// wiec pusty zakres jest bezpieczna wartoscia domyslna.
		return authz.Scope{}
	}
	return authz.Scope{Site: host.Site, Environment: host.Environment}
}

// scopeFilter buduje klauzule WHERE zawezajaca hosty do zakresow tozsamosci.
// Sama regula zawezania mieszka w pakiecie authz, razem z autoryzacja: dwie
// osobne implementacje tej samej semantyki juz raz sie rozjechaly.
func scopeFilter(scopes []authz.Scope) (string, []any) {
	warunek, args := authz.ScopeSQL(scopes, "site", "environment", 0)
	if warunek == "" {
		return "", nil
	}
	return " where " + warunek, args
}
