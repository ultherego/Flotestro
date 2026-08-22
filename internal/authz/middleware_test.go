package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubTokens i stubSessions pozwalaja sprawdzic sam lancuch uwierzytelnienia
// bez bazy danych.
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
	return s.principal, &Session{ID: "sesja-1", PrincipalID: s.principal.ID}, nil
}

func handlerCapturing(captured *Principal) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*captured = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func TestSesjaMaPierwszenstwoPrzedTokenem(t *testing.T) {
	sessionPrincipal := &Principal{ID: "z-sesji", Subject: "operator"}
	tokenPrincipal := &Principal{ID: "z-tokenu", Subject: "automat"}
	authenticator := Authenticator{
		Tokens:   stubTokens{principal: tokenPrincipal},
		Sessions: stubSessions{principal: sessionPrincipal},
	}

	var captured Principal
	request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_cokolwiek"})
	request.Header.Set("Authorization", "Bearer flta_cos")

	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(httptest.NewRecorder(), request)
	if captured.ID != "z-sesji" {
		t.Fatalf("tozsamosc = %q, oczekiwano z-sesji", captured.ID)
	}
}

func TestTokenDzialaBezSesji(t *testing.T) {
	authenticator := Authenticator{
		Tokens:   stubTokens{principal: &Principal{ID: "z-tokenu", Subject: "automat"}},
		Sessions: stubSessions{},
	}
	var captured Principal
	request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	request.Header.Set("Authorization", "Bearer flta_cos")

	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(httptest.NewRecorder(), request)
	if captured.ID != "z-tokenu" {
		t.Fatalf("tozsamosc = %q, oczekiwano z-tokenu", captured.ID)
	}
}

func TestZmianaStanuZCiasteczkiemWymagaCSRF(t *testing.T) {
	principal := &Principal{ID: "z-sesji", Subject: "operator"}
	authenticator := Authenticator{Sessions: stubSessions{principal: principal}}

	// Przegladarka dolacza ciasteczko automatycznie, wiec samo jego posiadanie
	// nie dowodzi, ze zadanie pochodzi od uzytkownika panelu.
	t.Run("bez naglowka", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/x/approve", nil)
		request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_cokolwiek"})
		request.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "wartosc-csrf"})

		recorder := httptest.NewRecorder()
		var captured Principal
		authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("kod = %d, oczekiwano 403", recorder.Code)
		}
	})

	t.Run("naglowek niezgodny z ciasteczkiem", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/x/approve", nil)
		request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_cokolwiek"})
		request.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "wartosc-csrf"})
		request.Header.Set(CSRFHeader, "inna-wartosc")

		recorder := httptest.NewRecorder()
		var captured Principal
		authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("kod = %d, oczekiwano 403", recorder.Code)
		}
	})

	t.Run("zgodny naglowek przechodzi", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/x/approve", nil)
		request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_cokolwiek"})
		request.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "wartosc-csrf"})
		request.Header.Set(CSRFHeader, "wartosc-csrf")

		recorder := httptest.NewRecorder()
		var captured Principal
		authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("kod = %d, oczekiwano 200", recorder.Code)
		}
		if captured.ID != "z-sesji" {
			t.Fatalf("tozsamosc = %q", captured.ID)
		}
	})
}

func TestOdczytZCiasteczkiemNieWymagaCSRF(t *testing.T) {
	// Zadanie tylko do odczytu nie zmienia stanu, wiec wymog CSRF
	// utrudnialby korzystanie z panelu bez zysku dla bezpieczenstwa.
	authenticator := Authenticator{
		Sessions: stubSessions{principal: &Principal{ID: "z-sesji", Subject: "operator"}},
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: "flts_cokolwiek"})

	recorder := httptest.NewRecorder()
	var captured Principal
	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || captured.ID != "z-sesji" {
		t.Fatalf("kod = %d, tozsamosc = %q", recorder.Code, captured.ID)
	}
}

func TestTokenNieWymagaCSRF(t *testing.T) {
	// Token jest przesylany jawnie przez klienta, wiec nie jest podatny na
	// mimowolne dolaczenie przez przegladarke.
	authenticator := Authenticator{
		Tokens: stubTokens{principal: &Principal{ID: "z-tokenu", Subject: "automat"}},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/campaigns", nil)
	request.Header.Set("Authorization", "Bearer flta_cos")

	recorder := httptest.NewRecorder()
	var captured Principal
	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || captured.ID != "z-tokenu" {
		t.Fatalf("kod = %d, tozsamosc = %q", recorder.Code, captured.ID)
	}
}

func TestBrakPoswiadczenDajeTozsamoscAnonimowa(t *testing.T) {
	authenticator := Authenticator{Tokens: stubTokens{}, Sessions: stubSessions{}}
	var captured Principal
	request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(httptest.NewRecorder(), request)

	if captured.Authenticated() {
		t.Fatal("zadanie bez poswiadczen dostalo tozsamosc")
	}
	if captured.Can(PermHostRead, GlobalScope) {
		t.Fatal("tozsamosc anonimowa ma uprawnienia")
	}
}

func TestNieprawidlowySchematAutoryzacjiJestIgnorowany(t *testing.T) {
	authenticator := Authenticator{
		Tokens: stubTokens{principal: &Principal{ID: "z-tokenu"}},
	}
	for _, header := range []string{"Basic dXNlcjpwYXNz", "flta_goly_token", "Bearer", ""} {
		var captured Principal
		request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		authenticator.Middleware(handlerCapturing(&captured)).ServeHTTP(httptest.NewRecorder(), request)
		if captured.Authenticated() {
			t.Errorf("naglowek %q zostal przyjety jako poswiadczenie", header)
		}
	}
}

func TestMergeBindingsUsuwaDuplikaty(t *testing.T) {
	manual := []Binding{{Role: RoleOperator, Scope: Scope{Site: "lab", Environment: "test"}}}
	mapped := []Binding{
		{Role: RoleOperator, Scope: Scope{Site: "lab", Environment: "test"}},
		{Role: RoleViewer, Scope: GlobalScope},
	}
	merged := mergeBindings(manual, mapped)
	if len(merged) != 2 {
		t.Fatalf("polaczono %d przypisan, oczekiwano 2", len(merged))
	}
}
