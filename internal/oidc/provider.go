// Package oidc obsluguje logowanie operatorow przez zewnetrznego dostawce
// tozsamosci. Panel nigdy nie przyjmuje samej nazwy grupy z requestu: role
// pochodza wylacznie z podpisanego tokenu o zweryfikowanym issuer i audience.
//
// Weryfikacja podpisu i rotacja kluczy sa realizowane przez biblioteke
// go-oidc. Wlasna implementacja walidacji JWT jest czestym zrodlem luk
// (alg=none, pomylenie kid, brak sprawdzenia audience), a to jest kod, od
// ktorego zalezy caly dostep do panelu.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config opisuje polaczenie z dostawca tozsamosci.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// GroupsClaim wskazuje pole tokenu z lista grup uzytkownika.
	GroupsClaim string
	HTTPClient  *http.Client
}

// Enabled mowi, czy logowanie przez dostawce jest skonfigurowane.
func (c Config) Enabled() bool {
	return c.IssuerURL != "" && c.ClientID != ""
}

// Provider realizuje przeplyw Authorization Code z PKCE.
type Provider struct {
	config   Config
	provider *coreoidc.Provider
	verifier *coreoidc.IDTokenVerifier
	oauth    oauth2.Config
	client   *http.Client
}

// Discover pobiera konfiguracje dostawcy wraz z adresem kluczy podpisujacych.
func Discover(ctx context.Context, config Config) (*Provider, error) {
	if !config.Enabled() {
		return nil, fmt.Errorf("dostawca tozsamosci nie jest skonfigurowany")
	}
	if len(config.Scopes) == 0 {
		config.Scopes = []string{coreoidc.ScopeOpenID, "profile", "email"}
	}
	if config.GroupsClaim == "" {
		config.GroupsClaim = "groups"
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	discoveryCtx := coreoidc.ClientContext(ctx, client)
	provider, err := coreoidc.NewProvider(discoveryCtx, strings.TrimSuffix(config.IssuerURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("discovery %s: %w", config.IssuerURL, err)
	}

	return &Provider{
		config:   config,
		provider: provider,
		// Weryfikator sprawdza podpis, issuer, audience i czasy waznosci.
		verifier: provider.Verifier(&coreoidc.Config{ClientID: config.ClientID}),
		oauth: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       config.Scopes,
		},
		client: client,
	}, nil
}

// Issuer zwraca identyfikator dostawcy.
func (p *Provider) Issuer() string { return strings.TrimSuffix(p.config.IssuerURL, "/") }

// AuthFlow to jednorazowy stan rozpoczetego logowania.
type AuthFlow struct {
	State        string
	Nonce        string
	CodeVerifier string
	AuthURL      string
}

// StepUp opisuje zadanie ponownego uwierzytelnienia. Operacje o najwiekszym
// wplywie wymagaja swiezego logowania, a nie samego posiadania sesji.
type StepUp struct {
	// Force wymusza ponowne uwierzytelnienie nawet przy waznej sesji
	// u dostawcy (prompt=login, max_age=0).
	Force bool
	// ACRValues zada konkretnego poziomu uwierzytelnienia. Puste oznacza, ze
	// instalacja nie zdefiniowala poziomu i panel poprzestaje na swiezosci.
	ACRValues string
}

// BeginAuth buduje adres logowania wraz z PKCE. Weryfikator zostaje po stronie
// serwera; do przegladarki trafia wylacznie jego skrot w challenge.
func (p *Provider) BeginAuth(stepUp StepUp) (*AuthFlow, error) {
	state, err := randomString(32)
	if err != nil {
		return nil, err
	}
	nonce, err := randomString(32)
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()

	return &AuthFlow{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		AuthURL:      p.oauth.AuthCodeURL(state, authOptions(nonce, verifier, stepUp)...),
	}, nil
}

// authOptions sklada parametry zadania autoryzacji. Przy step-up dokladamy
// prompt=login i max_age=0: bez nich dostawca odeslalby istniejaca sesje
// i panel uznalby stare uwierzytelnienie za swieze.
func authOptions(nonce, verifier string, stepUp StepUp) []oauth2.AuthCodeOption {
	options := []oauth2.AuthCodeOption{
		coreoidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	}
	if stepUp.Force {
		options = append(options,
			oauth2.SetAuthURLParam("prompt", "login"),
			oauth2.SetAuthURLParam("max_age", "0"))
	}
	if stepUp.ACRValues != "" {
		options = append(options, oauth2.SetAuthURLParam("acr_values", stepUp.ACRValues))
	}
	return options
}

// TokenSet to komplet tokenow zwrocony przez dostawce.
type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresAt    time.Time
}

// Claims to zweryfikowana tozsamosc uzytkownika.
type Claims struct {
	Subject           string
	PreferredUsername string
	Email             string
	Name              string
	Groups            []string

	// AuthTime jest chwila, w ktorej dostawca faktycznie uwierzytelnil
	// uzytkownika. Zerowa wartosc oznacza, ze dostawca jej nie podal, i nie
	// moze byc czytana jako "przed chwila".
	AuthTime time.Time
	// ACR i AMR opisuja sposob uwierzytelnienia. Panel ich nie interpretuje
	// po swojemu: MFA nalezy do dostawcy tozsamosci, a panel jedynie sprawdza,
	// czy dostal zadeklarowany poziom.
	ACR string
	AMR []string
}

// Exchange wymienia kod autoryzacyjny na tokeny i weryfikuje token tozsamosci.
// Nonce jest sprawdzany, bo bez tego token z innej sesji logowania mogłby
// zostac wstrzykniety w trwajacy przeplyw.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier, nonce string) (*TokenSet, *Claims, error) {
	exchangeCtx := coreoidc.ClientContext(ctx, p.client)
	token, err := p.oauth.Exchange(exchangeCtx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return nil, nil, fmt.Errorf("wymiana kodu: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, nil, fmt.Errorf("odpowiedz nie zawiera id_token")
	}
	claims, err := p.verify(ctx, rawIDToken, nonce)
	if err != nil {
		return nil, nil, err
	}

	return &TokenSet{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}, claims, nil
}

// Refresh odnawia sesje. Refresh token nigdy nie opuszcza serwera.
func (p *Provider) Refresh(ctx context.Context, refreshToken string) (*TokenSet, *Claims, error) {
	refreshCtx := coreoidc.ClientContext(ctx, p.client)
	source := p.oauth.TokenSource(refreshCtx, &oauth2.Token{RefreshToken: refreshToken})
	token, err := source.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("odnowienie sesji: %w", err)
	}

	set := &TokenSet{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}
	if set.RefreshToken == "" {
		set.RefreshToken = refreshToken
	}

	// Przy odnowieniu nonce nie obowiazuje: token nie pochodzi z nowego
	// logowania uzytkownika.
	if rawIDToken, ok := token.Extra("id_token").(string); ok && rawIDToken != "" {
		set.IDToken = rawIDToken
		claims, err := p.verify(ctx, rawIDToken, "")
		if err != nil {
			return nil, nil, err
		}
		return set, claims, nil
	}
	return set, nil, nil
}

// verify sprawdza podpis, issuer, audience, czasy waznosci i nonce.
func (p *Provider) verify(ctx context.Context, rawIDToken, expectedNonce string) (*Claims, error) {
	verifyCtx := coreoidc.ClientContext(ctx, p.client)
	idToken, err := p.verifier.Verify(verifyCtx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("weryfikacja tokenu tozsamosci: %w", err)
	}
	if expectedNonce != "" && idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("nonce tokenu nie zgadza sie z rozpoczetym logowaniem")
	}

	raw := map[string]any{}
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("odczyt claims: %w", err)
	}

	claims := &Claims{
		Subject:           idToken.Subject,
		PreferredUsername: stringClaim(raw, "preferred_username"),
		Email:             stringClaim(raw, "email"),
		Name:              stringClaim(raw, "name"),
		Groups:            stringsClaim(raw, p.config.GroupsClaim),
		ACR:               stringClaim(raw, "acr"),
		AMR:               stringsClaim(raw, "amr"),
		AuthTime:          timeClaim(raw, "auth_time"),
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("token nie zawiera identyfikatora podmiotu")
	}
	return claims, nil
}

// LogoutURL buduje adres wylogowania u dostawcy. Uniewaznienie sesji panelu
// nie wystarcza: bez tego dostawca zalogowalby uzytkownika ponownie bez pytania.
func (p *Provider) LogoutURL(idToken, redirectAfter string) string {
	var endpoint struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := p.provider.Claims(&endpoint); err != nil || endpoint.EndSessionEndpoint == "" {
		return redirectAfter
	}
	url := endpoint.EndSessionEndpoint + "?client_id=" + p.config.ClientID
	if idToken != "" {
		url += "&id_token_hint=" + idToken
	}
	if redirectAfter != "" {
		url += "&post_logout_redirect_uri=" + redirectAfter
	}
	return url
}

// timeClaim czyta znacznik czasu wyrazony w sekundach epoki. Brak wartosci
// daje czas zerowy, ktory znaczy "nieustalony": panel nie moze zalozyc, ze
// uwierzytelnienie nastapilo przed chwila, skoro dostawca tego nie powiedzial.
func timeClaim(claims map[string]any, name string) time.Time {
	switch value := claims[name].(type) {
	case float64:
		return time.Unix(int64(value), 0).UTC()
	case json.Number:
		if seconds, err := value.Int64(); err == nil {
			return time.Unix(seconds, 0).UTC()
		}
	case string:
		if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
			return time.Unix(seconds, 0).UTC()
		}
	}
	return time.Time{}
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

// stringsClaim czyta liste grup. Dostawcy zwracaja ja raz jako tablice,
// raz jako pojedynczy ciag, wiec przyjmujemy obie postacie.
func stringsClaim(claims map[string]any, name string) []string {
	switch value := claims[name].(type) {
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok && text != "" {
				result = append(result, strings.TrimPrefix(text, "/"))
			}
		}
		return result
	case string:
		if value == "" {
			return nil
		}
		return []string{strings.TrimPrefix(value, "/")}
	default:
		return nil
	}
}

func randomString(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
