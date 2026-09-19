// Package oidc handles the login of operators through an external identity
// provider.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config describes the connection to an identity provider.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// GroupsClaim names the field of the token with the list of the groups of
	// the user.
	GroupsClaim string
	HTTPClient  *http.Client
	// AdminLogout lets the panel end a user's sessions at the provider when the
	// user is disabled from the panel.
	AdminLogout bool
}

// Enabled says whether the login through a provider is configured.
func (c Config) Enabled() bool {
	return c.IssuerURL != "" && c.ClientID != ""
}

// Provider implements the Authorization Code flow with PKCE.
type Provider struct {
	config   Config
	provider *coreoidc.Provider
	verifier *coreoidc.IDTokenVerifier
	oauth    oauth2.Config
	client   *http.Client
	// probeState remembers the last connection test for the checklist.
	probeState
}

// Discover fetches the configuration of the provider together with the
// address of the signing keys.
func Discover(ctx context.Context, config Config) (*Provider, error) {
	if !config.Enabled() {
		return nil, fmt.Errorf("the identity provider is not configured")
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
		// The verifier checks the signature, the issuer, the audience and the
		// validity times.
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

// Issuer returns the identifier of the provider.
func (p *Provider) Issuer() string { return strings.TrimSuffix(p.config.IssuerURL, "/") }

// AuthFlow is the one-time state of a login that has been started.
type AuthFlow struct {
	State        string
	Nonce        string
	CodeVerifier string
	AuthURL      string
}

// StepUp describes a demand for another authentication. The operations of the
// greatest impact require a fresh login rather than merely holding a session.
type StepUp struct {
	// Force demands another authentication even with a valid session at the
	// provider (prompt=login, max_age=0).
	Force bool
	// ACRValues demand a specific level of authentication. Empty means the
	// installation defined no level and the panel settles for freshness.
	ACRValues string
}

// BeginAuth builds the login address together with PKCE.
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

// authOptions assembles the parameters of the authorisation request.
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

// TokenSet is the set of tokens returned by the provider.
type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresAt    time.Time
}

// Claims are the verified identity of a user.
type Claims struct {
	Subject           string
	PreferredUsername string
	Email             string
	Name              string
	Groups            []string

	// AuthTime is the moment the provider actually authenticated the user.
	AuthTime time.Time
	// ACR and AMR describe the way of the authentication.
	ACR string
	AMR []string
}

// Exchange exchanges the authorisation code for the tokens and verifies the
// identity token.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier, nonce string) (*TokenSet, *Claims, error) {
	exchangeCtx := coreoidc.ClientContext(ctx, p.client)
	token, err := p.oauth.Exchange(exchangeCtx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return nil, nil, fmt.Errorf("exchanging the code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, nil, fmt.Errorf("the answer carries no id_token")
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

// Refresh renews the session. The refresh token never leaves the server.
func (p *Provider) Refresh(ctx context.Context, refreshToken string) (*TokenSet, *Claims, error) {
	refreshCtx := coreoidc.ClientContext(ctx, p.client)
	source := p.oauth.TokenSource(refreshCtx, &oauth2.Token{RefreshToken: refreshToken})
	token, err := source.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("renewing the session: %w", err)
	}

	set := &TokenSet{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}
	if set.RefreshToken == "" {
		set.RefreshToken = refreshToken
	}

	// At a renewal the nonce does not hold: the token does not come from a new
	// login of the user.
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

// IsInvalidGrant says whether a renewal failed because the provider no longer
// honours the refresh token: the user was disabled or deleted, the provider's
// session was logged out, or the token was revoked.
func IsInvalidGrant(err error) bool {
	var retrieve *oauth2.RetrieveError
	return errors.As(err, &retrieve) && retrieve.ErrorCode == "invalid_grant"
}

// verify checks the signature, the issuer, the audience, the validity times
// and the nonce.
func (p *Provider) verify(ctx context.Context, rawIDToken, expectedNonce string) (*Claims, error) {
	verifyCtx := coreoidc.ClientContext(ctx, p.client)
	idToken, err := p.verifier.Verify(verifyCtx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verifying the identity token: %w", err)
	}
	if expectedNonce != "" && idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("the nonce of the token does not match the login that was started")
	}

	raw := map[string]any{}
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("reading the claims: %w", err)
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
		return nil, fmt.Errorf("the token carries no subject identifier")
	}
	return claims, nil
}

// LogoutURL builds the logout address at the provider.
func (p *Provider) LogoutURL(idToken, redirectAfter string) string {
	var endpoint struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := p.provider.Claims(&endpoint); err != nil || endpoint.EndSessionEndpoint == "" {
		return redirectAfter
	}
	// The parameters are encoded: a return address with a query of its own
	// would otherwise be read by the provider as part of the logout request.
	query := neturl.Values{"client_id": {p.config.ClientID}}
	if idToken != "" {
		query.Set("id_token_hint", idToken)
	}
	if redirectAfter != "" {
		query.Set("post_logout_redirect_uri", redirectAfter)
	}
	return endpoint.EndSessionEndpoint + "?" + query.Encode()
}

// ErrAdminLogoutDisabled means the installation did not turn the provider
// logout on. It is not a failure: the local denial holds without it.
var ErrAdminLogoutDisabled = errors.New("the provider logout is not enabled")

// ErrNotKeycloak means an issuer without a realm in its address.
var ErrNotKeycloak = errors.New("the issuer is not a Keycloak realm")

// ErrSubjectNotFound means the provider knows no user by that name.
var ErrSubjectNotFound = errors.New("the provider knows no such user")

// keycloakRealm splits the issuer into the address of the server and the realm
// name.
func keycloakRealm(issuer string) (server, realm string, ok bool) {
	base, name, found := strings.Cut(strings.TrimSuffix(issuer, "/"), "/realms/")
	if !found || name == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	return base, name, true
}

// LogoutSubject ends every session the provider holds for the user, so a user
// disabled in the panel is not logged into other applications by the
// provider's own session until it expires.
func (p *Provider) LogoutSubject(ctx context.Context, subject string) error {
	if !p.config.AdminLogout {
		return ErrAdminLogoutDisabled
	}
	server, realm, ok := keycloakRealm(p.Issuer())
	if !ok {
		return ErrNotKeycloak
	}
	if strings.TrimSpace(subject) == "" {
		return fmt.Errorf("%w: the subject is empty", ErrSubjectNotFound)
	}
	token, err := p.serviceToken(ctx)
	if err != nil {
		return err
	}
	admin := server + "/admin/realms/" + neturl.PathEscape(realm)

	// The lookup asks for the exact name: a search by prefix would match "anna"
	// against "annabel", and logging the wrong person out is a different mistake
	// from logging nobody out.
	query := neturl.Values{"username": {subject}, "exact": {"true"}, "max": {"2"}}
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := p.adminCall(ctx, token, http.MethodGet, admin+"/users?"+query.Encode(), &users); err != nil {
		return fmt.Errorf("looking the user up: %w", err)
	}
	id := ""
	for _, user := range users {
		if strings.EqualFold(user.Username, subject) {
			id = user.ID
			break
		}
	}
	if id == "" {
		return fmt.Errorf("%w: %s", ErrSubjectNotFound, subject)
	}
	if err := p.adminCall(ctx, token, http.MethodPost, admin+"/users/"+neturl.PathEscape(id)+"/logout", nil); err != nil {
		return fmt.Errorf("ending the sessions of %s: %w", subject, err)
	}
	return nil
}

// serviceToken gets an access token for the panel's own client through the
// client credentials grant.
func (p *Provider) serviceToken(ctx context.Context) (string, error) {
	form := neturl.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.oauth.Endpoint.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := p.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("the token endpoint: %w", err)
	}
	defer response.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&body); err != nil {
		return "", fmt.Errorf("the token endpoint answered %d with an unreadable body", response.StatusCode)
	}
	if response.StatusCode != http.StatusOK || body.AccessToken == "" {
		return "", fmt.Errorf("the token endpoint refused the client credentials: %s",
			firstNonEmpty(body.Error, http.StatusText(response.StatusCode)))
	}
	return body.AccessToken, nil
}

// adminCall makes one request to the admin API with the service token.
func (p *Provider) adminCall(ctx context.Context, token, method, address string, out any) error {
	request, err := http.NewRequestWithContext(ctx, method, address, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("the admin API answered %d %s", response.StatusCode, http.StatusText(response.StatusCode))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("the admin API answered with an unreadable body: %w", err)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// timeClaim reads a timestamp expressed in seconds of the epoch.
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

// stringsClaim reads the list of groups. The providers return it one time as
// an array and another as a single string, so we accept both shapes.
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
