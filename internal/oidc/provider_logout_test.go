package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The scenario of the architecture document: a user disabled from the panel
// must not stay logged into the other applications behind Keycloak until
// the provider's own session runs out. The panel ends those sessions
// through the admin API, with its own client credentials. The tests stand
// a fake Keycloak up in the process: a realm under /realms/{name}, a token
// endpoint that honours the client credentials grant, a user lookup and
// the logout of one user.

// fakeKeycloak records what the panel asked of the admin API.
type fakeKeycloak struct {
	server *httptest.Server
	realm  string

	mu         sync.Mutex
	users      map[string]string // username -> id
	tokens     int
	lookups    []string
	loggedOut  []string
	forbidden  bool
	lastBearer string
}

func newFakeKeycloak(t *testing.T) *fakeKeycloak {
	t.Helper()
	keycloak := &fakeKeycloak{realm: "flotestro", users: map[string]string{
		"anna": "6d1c-anna", "annabel": "9f3e-annabel",
	}}
	mux := http.NewServeMux()
	realm := "/realms/" + keycloak.realm
	mux.HandleFunc(realm+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := keycloak.server.URL + realm
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/protocol/openid-connect/auth",
			"token_endpoint":                        issuer + "/protocol/openid-connect/token",
			"jwks_uri":                              issuer + "/protocol/openid-connect/certs",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc(realm+"/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
	})
	mux.HandleFunc(realm+"/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		// The service account answers the client credentials grant alone,
		// and only to the panel's own client.
		if r.PostForm.Get("grant_type") != "client_credentials" ||
			r.PostForm.Get("client_id") != testClientID || r.PostForm.Get("client_secret") != "panel-secret" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized_client"})
			return
		}
		keycloak.mu.Lock()
		keycloak.tokens++
		keycloak.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "service-account-token", "token_type": "Bearer", "expires_in": 60,
		})
	})
	admin := "/admin/realms/" + keycloak.realm
	authorised := func(w http.ResponseWriter, r *http.Request) bool {
		keycloak.mu.Lock()
		defer keycloak.mu.Unlock()
		keycloak.lastBearer = r.Header.Get("Authorization")
		if keycloak.lastBearer != "Bearer service-account-token" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return false
		}
		if keycloak.forbidden {
			// A service account without view-users and manage-users.
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "unknown_error"})
			return false
		}
		return true
	}
	mux.HandleFunc(admin+"/users", func(w http.ResponseWriter, r *http.Request) {
		if !authorised(w, r) {
			return
		}
		name := r.URL.Query().Get("username")
		keycloak.mu.Lock()
		keycloak.lookups = append(keycloak.lookups, r.URL.RawQuery)
		keycloak.mu.Unlock()
		// Keycloak matches by prefix unless asked for the exact name; the
		// fake does the same so a sloppy lookup shows.
		var matched []map[string]string
		for username, id := range keycloak.users {
			if username == name || (r.URL.Query().Get("exact") != "true" && strings.HasPrefix(username, name)) {
				matched = append(matched, map[string]string{"id": id, "username": username})
			}
		}
		if matched == nil {
			matched = []map[string]string{}
		}
		writeJSON(w, http.StatusOK, matched)
	})
	mux.HandleFunc(admin+"/users/", func(w http.ResponseWriter, r *http.Request) {
		if !authorised(w, r) {
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, admin+"/users/")
		id, action, _ := strings.Cut(rest, "/")
		if r.Method != http.MethodPost || action != "logout" {
			http.NotFound(w, r)
			return
		}
		keycloak.mu.Lock()
		keycloak.loggedOut = append(keycloak.loggedOut, id)
		keycloak.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	keycloak.server = httptest.NewServer(mux)
	t.Cleanup(keycloak.server.Close)
	return keycloak
}

func (k *fakeKeycloak) discover(t *testing.T, adminLogout bool) *Provider {
	t.Helper()
	provider, err := Discover(context.Background(), Config{
		IssuerURL:    k.server.URL + "/realms/" + k.realm,
		ClientID:     testClientID,
		ClientSecret: "panel-secret",
		RedirectURL:  testRedirectURL,
		HTTPClient:   k.server.Client(),
		AdminLogout:  adminLogout,
	})
	if err != nil {
		t.Fatalf("discovering the fake Keycloak: %v", err)
	}
	return provider
}

func (k *fakeKeycloak) snapshot() (tokens int, lookups, loggedOut []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.tokens, append([]string(nil), k.lookups...), append([]string(nil), k.loggedOut...)
}

func TestDisablingAUserEndsTheirProviderSessions(t *testing.T) {
	keycloak := newFakeKeycloak(t)
	provider := keycloak.discover(t, true)

	if err := provider.LogoutSubject(context.Background(), "anna"); err != nil {
		t.Fatalf("the logout failed: %v", err)
	}
	tokens, lookups, loggedOut := keycloak.snapshot()
	if tokens != 1 {
		t.Errorf("the panel fetched %d service tokens, expected one per logout", tokens)
	}
	// The lookup asks for the exact name: annabel must not be logged out
	// in anna's place, and anna must be the only one.
	if len(lookups) != 1 || !strings.Contains(lookups[0], "exact=true") || !strings.Contains(lookups[0], "username=anna") {
		t.Errorf("the lookup was %v", lookups)
	}
	if len(loggedOut) != 1 || loggedOut[0] != "6d1c-anna" {
		t.Errorf("the sessions ended were %v, expected anna's alone", loggedOut)
	}
}

func TestTheProviderLogoutIsOffByDefault(t *testing.T) {
	keycloak := newFakeKeycloak(t)
	provider := keycloak.discover(t, false)

	err := provider.LogoutSubject(context.Background(), "anna")
	if !errors.Is(err, ErrAdminLogoutDisabled) {
		t.Fatalf("a disabled logout answered %v", err)
	}
	// Nothing reached the provider: no token, no lookup, no logout. The
	// local denial is the whole of the change then.
	if tokens, lookups, loggedOut := keycloak.snapshot(); tokens != 0 || len(lookups) != 0 || len(loggedOut) != 0 {
		t.Errorf("a disabled logout still called the provider: tokens %d, lookups %v, logouts %v",
			tokens, lookups, loggedOut)
	}
}

func TestAnUnknownUserAndARefusalAreNamedNotHidden(t *testing.T) {
	keycloak := newFakeKeycloak(t)
	provider := keycloak.discover(t, true)

	err := provider.LogoutSubject(context.Background(), "nobody")
	if !errors.Is(err, ErrSubjectNotFound) {
		t.Errorf("an unknown user answered %v", err)
	}
	if _, _, loggedOut := keycloak.snapshot(); len(loggedOut) != 0 {
		t.Errorf("an unknown user ended somebody's sessions: %v", loggedOut)
	}
	// A prefix of a known name is not that name.
	if err := provider.LogoutSubject(context.Background(), "ann"); !errors.Is(err, ErrSubjectNotFound) {
		t.Errorf("a prefix of a name answered %v", err)
	}

	// A service account without the realm management roles: the refusal
	// carries the status, because that status is the whole diagnosis.
	keycloak.mu.Lock()
	keycloak.forbidden = true
	keycloak.mu.Unlock()
	err = provider.LogoutSubject(context.Background(), "anna")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("a refusal by the admin API answered %v", err)
	}
}

func TestOnlyAKeycloakRealmGetsAnAdminLogout(t *testing.T) {
	// The generic issuer of the login tests has no realm in its address:
	// the admin API would be an invented address, so nothing is sent.
	issuer := newFakeIssuer(t)
	provider, err := Discover(context.Background(), Config{
		IssuerURL: issuer.server.URL, ClientID: testClientID, ClientSecret: "panel-secret",
		RedirectURL: testRedirectURL, HTTPClient: issuer.server.Client(), AdminLogout: true,
	})
	if err != nil {
		t.Fatalf("discovering the fake issuer: %v", err)
	}
	if err := provider.LogoutSubject(context.Background(), "anna"); !errors.Is(err, ErrNotKeycloak) {
		t.Errorf("an issuer without a realm answered %v", err)
	}
	if form := issuer.lastTokenRequest(); form != nil {
		t.Errorf("the token endpoint was called for an issuer without a realm: %v", form)
	}

	for issuer, realm := range map[string]string{
		"https://ipa.example.test:8443/realms/flotestro": "flotestro",
		"https://sso.example.test/auth/realms/fleet/":    "fleet",
		"https://sso.example.test/realms/":               "",
		"https://sso.example.test/realms/a/b":            "",
		"https://login.microsoftonline.com/tenant/v2.0":  "",
	} {
		server, got, ok := keycloakRealm(strings.TrimSuffix(issuer, "/"))
		if ok != (realm != "") || got != realm {
			t.Errorf("%s: realm %q ok=%v", issuer, got, ok)
		}
		if ok && strings.Contains(server, "/realms") {
			t.Errorf("%s: the server address %q keeps the realm path", issuer, server)
		}
	}
}
