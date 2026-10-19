package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubTokens and stubSessions allow checking the authentication chain itself
// without a database.
type stubTokens struct{ principal *Principal }

func (s stubTokens) Authenticate(context.Context, string) (*Principal, error) {
	if s.principal == nil {
		return nil, ErrUnauthenticated
	}
	return s.principal, nil
}

type stubSessions struct{ principal *Principal }

func (s stubSessions) AuthenticateSession(context.Context, string) (*Principal, *Session, error) {
	if s.principal == nil {
		return nil, nil, ErrSessionInvalid
	}
	return s.principal, &Session{ID: "session-1", PrincipalID: s.principal.ID}, nil
}

func handlerCapturing(captured *Principal) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*captured = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func TestTheSessionTakesPrecedenceOverTheToken(t *testing.T) {
	sessionPrincipal := &Principal{ID: "from-session", Subject: "operator"}
	tokenPrincipal := &Principal{ID: "from-token", Subject: "automation"}
	authenticator := Authenticator{
		Tokens:   stubTokens{principal: tokenPrincipal},
		Sessions: stubSessions{principal: sessionPrincipal},
	}

	var captured Principal
	request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_anything"})
	request.Header.Set("Authorization", "Bearer flta_something")

	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(httptest.NewRecorder(), request)
	if captured.ID != "from-session" {
		t.Fatalf("identity = %q, expected from-session", captured.ID)
	}
}

func TestATokenWorksWithoutASession(t *testing.T) {
	authenticator := Authenticator{
		Tokens:   stubTokens{principal: &Principal{ID: "from-token", Subject: "automation"}},
		Sessions: stubSessions{},
	}
	var captured Principal
	request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	request.Header.Set("Authorization", "Bearer flta_something")

	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(httptest.NewRecorder(), request)
	if captured.ID != "from-token" {
		t.Fatalf("identity = %q, expected from-token", captured.ID)
	}
}

func TestAStateChangeWithACookieRequiresCSRF(t *testing.T) {
	principal := &Principal{ID: "from-session", Subject: "operator"}
	authenticator := Authenticator{Sessions: stubSessions{principal: principal}}

	// The browser attaches the cookie automatically, so having it does not
	// prove that the request comes from a user of the panel.
	t.Run("without the header", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/x/approve", nil)
		request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_anything"})
		request.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "csrf-value"})

		recorder := httptest.NewRecorder()
		var captured Principal
		authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("code = %d, expected 403", recorder.Code)
		}
	})

	t.Run("header not matching the cookie", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/x/approve", nil)
		request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_anything"})
		request.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "csrf-value"})
		request.Header.Set(CSRFHeader, "another-value")

		recorder := httptest.NewRecorder()
		var captured Principal
		authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("code = %d, expected 403", recorder.Code)
		}
	})

	t.Run("a matching header passes", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/x/approve", nil)
		request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_anything"})
		request.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "csrf-value"})
		request.Header.Set(CSRFHeader, "csrf-value")

		recorder := httptest.NewRecorder()
		var captured Principal
		authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("code = %d, expected 200", recorder.Code)
		}
		if captured.ID != "from-session" {
			t.Fatalf("identity = %q", captured.ID)
		}
	})
}

func TestAReadWithACookieDoesNotRequireCSRF(t *testing.T) {
	// A read-only request does not change state, so requiring CSRF would make
	// the panel harder to use with no gain in security.
	authenticator := Authenticator{
		Sessions: stubSessions{principal: &Principal{ID: "from-session", Subject: "operator"}},
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_anything"})

	recorder := httptest.NewRecorder()
	var captured Principal
	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || captured.ID != "from-session" {
		t.Fatalf("code = %d, identity = %q", recorder.Code, captured.ID)
	}
}

func TestATokenDoesNotRequireCSRF(t *testing.T) {
	// The token is sent explicitly by the client, so it is not open to being
	// attached unintentionally by a browser.
	authenticator := Authenticator{
		Tokens: stubTokens{principal: &Principal{ID: "from-token", Subject: "automation"}},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/campaigns", nil)
	request.Header.Set("Authorization", "Bearer flta_something")

	recorder := httptest.NewRecorder()
	var captured Principal
	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || captured.ID != "from-token" {
		t.Fatalf("code = %d, identity = %q", recorder.Code, captured.ID)
	}
}

func TestNoCredentialsGiveAnAnonymousIdentity(t *testing.T) {
	authenticator := Authenticator{Tokens: stubTokens{}, Sessions: stubSessions{}}
	var captured Principal
	request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(httptest.NewRecorder(), request)

	if captured.Authenticated() {
		t.Fatal("a request without credentials got an identity")
	}
	if captured.Can(PermHostRead, GlobalScope) {
		t.Fatal("the anonymous identity has permissions")
	}
}

func TestAnInvalidAuthorizationSchemeIsIgnored(t *testing.T) {
	authenticator := Authenticator{
		Tokens: stubTokens{principal: &Principal{ID: "from-token"}},
	}
	for _, header := range []string{"Basic dXNlcjpwYXNz", "flta_bare_token", "Bearer", ""} {
		var captured Principal
		request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(httptest.NewRecorder(), request)
		if captured.Authenticated() {
			t.Errorf("the header %q was accepted as a credential", header)
		}
	}
}

func TestMergeBindingsRemovesDuplicates(t *testing.T) {
	manual := []Binding{{Role: RoleOperator, Scope: Scope{Site: "lab", Environment: "test"}}}
	mapped := []Binding{
		{Role: RoleOperator, Scope: Scope{Site: "lab", Environment: "test"}},
		{Role: RoleViewer, Scope: GlobalScope},
	}
	merged := mergeBindings(manual, mapped)
	if len(merged) != 2 {
		t.Fatalf("merged %d assignments, expected 2", len(merged))
	}
}

type stubMustChange struct{}

func (stubMustChange) AuthenticateSession(context.Context, string) (*Principal, *Session, error) {
	return &Principal{ID: "p", Subject: "newcomer"}, &Session{ID: "s", PrincipalID: "p", MustChangePassword: true}, nil
}

// A session whose owner has to replace the password reaches the change, who it
// is and the way out, and nothing else - the rule is the API's, not the page's.
func TestASessionOnAPasswordToBeReplacedReachesOnlyTheChange(t *testing.T) {
	authenticator := Authenticator{Sessions: stubMustChange{}}
	var captured Principal
	handler := authenticator.Middleware(handlerCapturing(&captured))

	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/v1/whoami", http.StatusOK},
		{http.MethodGet, "/api/v1/me/preferences", http.StatusOK},
		{http.MethodPost, "/api/v1/profile/password", http.StatusOK},
		{http.MethodPost, "/auth/logout", http.StatusOK},
		{http.MethodGet, "/api/v1/hosts", http.StatusForbidden},
		{http.MethodPost, "/api/v1/roles", http.StatusForbidden},
		{http.MethodPut, "/api/v1/me/preferences", http.StatusForbidden},
		{http.MethodPost, "/auth/password/reauthenticate", http.StatusForbidden},
	} {
		request := httptest.NewRequest(c.method, c.path, nil)
		request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_x"})
		request.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "t"})
		request.Header.Set(CSRFHeader, "t")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != c.want {
			t.Errorf("%s %s = %d, expected %d", c.method, c.path, recorder.Code, c.want)
		}
	}
}
