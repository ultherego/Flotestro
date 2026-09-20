package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
)

// The scenario of the architecture document: a FreeIPA user logs in through
// Keycloak and the panel accepts the identity token only fully checked.

const (
	testClientID    = "flotestro-panel"
	testRedirectURL = "https://panel.example.test/auth/callback"
	testSubject     = "3f1c2a90-freeipa-uid"
)

// testKeys are generated once: a 2048-bit key costs a noticeable fraction of
// a second and every test needs the same two - the issuer's and a rogue one.
var testKeys struct {
	once   sync.Once
	issuer *rsa.PrivateKey
	rogue  *rsa.PrivateKey
	err    error
}

func signingKeys(t *testing.T) (issuer, rogue *rsa.PrivateKey) {
	t.Helper()
	testKeys.once.Do(func() {
		if testKeys.issuer, testKeys.err = rsa.GenerateKey(rand.Reader, 2048); testKeys.err != nil {
			return
		}
		testKeys.rogue, testKeys.err = rsa.GenerateKey(rand.Reader, 2048)
	})
	if testKeys.err != nil {
		t.Fatalf("generating the signing keys: %v", testKeys.err)
	}
	return testKeys.issuer, testKeys.rogue
}

// fakeIssuer stands in for Keycloak.
type fakeIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	keyID  string

	mu       sync.Mutex
	idToken  string
	refusal  string
	lastForm url.Values
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, _ := signingKeys(t)
	issuer := &fakeIssuer{key: key, keyID: "keycloak-rs256-1"}

	mux := http.NewServeMux()
	// The issuer in the discovery document has to equal the address the provider
	// was configured with: go-oidc refuses discovery otherwise, which is the
	// first line of defence against a redirect to another provider.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                issuer.server.URL,
			"authorization_endpoint":                issuer.server.URL + "/auth",
			"token_endpoint":                        issuer.server.URL + "/token",
			"jwks_uri":                              issuer.server.URL + "/keys",
			"end_session_endpoint":                  issuer.server.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		public := issuer.key.PublicKey
		writeJSON(w, http.StatusOK, map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": issuer.keyID,
				"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		issuer.mu.Lock()
		defer issuer.mu.Unlock()
		issuer.lastForm = r.PostForm
		if issuer.refusal != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": issuer.refusal, "error_description": "refused by the test",
			})
			return
		}
		// The refresh token is rotated the way Keycloak does it, so a test
		// can see that the provider passes the new one on.
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  "access-" + r.PostForm.Get("grant_type"),
			"token_type":    "Bearer",
			"expires_in":    300,
			"refresh_token": "refresh-2",
			"id_token":      issuer.idToken,
		})
	})

	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)
	return issuer
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// claims are the claims Keycloak puts in the identity token of a FreeIPA
// user, valid for the fake issuer and the panel's client.
func (f *fakeIssuer) claims(nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":                f.server.URL,
		"sub":                testSubject,
		"aud":                testClientID,
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"nonce":              nonce,
		"preferred_username": "jkowalski",
		"name":               "Jan Kowalski",
		"email":              "jkowalski@example.test",
		"groups":             []string{"flotestro-operators"},
	}
}

// mint sets the identity token the token endpoint will hand out next.
func (f *fakeIssuer) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	return f.mintWith(t, f.key, f.keyID, claims)
}

func (f *fakeIssuer) mintWith(t *testing.T, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	token := signRS256(t, key, keyID, claims)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idToken = token
	return token
}

func (f *fakeIssuer) refuseWith(code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refusal = code
}

func (f *fakeIssuer) lastTokenRequest() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastForm
}

// signRS256 builds a compact JWS by hand.
func signRS256(t *testing.T, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": keyID})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing the token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// discoverProvider builds the provider the way cmd/control-plane does,
// pointed at the fake issuer.
func discoverProvider(t *testing.T, issuer *fakeIssuer, groupsClaim string) *Provider {
	t.Helper()
	provider, err := Discover(context.Background(), Config{
		IssuerURL:    issuer.server.URL,
		ClientID:     testClientID,
		ClientSecret: "panel-secret",
		RedirectURL:  testRedirectURL,
		GroupsClaim:  groupsClaim,
		HTTPClient:   issuer.server.Client(),
	})
	if err != nil {
		t.Fatalf("discovering the fake issuer: %v", err)
	}
	return provider
}

// login runs the code exchange of a freshly started flow against a token
// minted from the given claims, and returns what the panel would see.
func login(t *testing.T, provider *Provider, issuer *fakeIssuer, claims map[string]any) (*TokenSet, *Claims, error) {
	t.Helper()
	flow, err := provider.BeginAuth(StepUp{})
	if err != nil {
		t.Fatalf("beginning the login: %v", err)
	}
	// A test that says nothing about the nonce gets the one of this flow, so
	// that a refusal comes from the check under test and not from the nonce.
	if nonce, _ := claims["nonce"].(string); nonce == "" {
		claims["nonce"] = flow.Nonce
	}
	issuer.mint(t, claims)
	return provider.Exchange(context.Background(), "code-1", flow.CodeVerifier, flow.Nonce)
}

// refused checks that a login failed, and failed for the stated reason: a
// token refused for some other defect would make a negative test pass without
// proving anything about the check under test.
func refused(t *testing.T, claims *Claims, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the token was accepted: %+v", claims)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("the token was refused for another reason than %q: %v", reason, err)
	}
	if claims != nil {
		t.Fatalf("claims were returned together with the error: %+v", claims)
	}
}

func TestAKeycloakLoginOfAFreeIPAUserYieldsTheIdentityAndTheGroups(t *testing.T) {
	issuer := newFakeIssuer(t)
	provider := discoverProvider(t, issuer, "")

	flow, err := provider.BeginAuth(StepUp{})
	if err != nil {
		t.Fatal(err)
	}
	// The nonce and the PKCE challenge leave with the authorisation request;
	// the callback is later held to the same nonce.
	authURL, err := url.Parse(flow.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	query := authURL.Query()
	if query.Get("nonce") != flow.Nonce || query.Get("code_challenge_method") != "S256" ||
		query.Get("code_challenge") == "" || query.Get("client_id") != testClientID {
		t.Fatalf("authorisation request = %s", flow.AuthURL)
	}

	minted := issuer.mint(t, issuer.claims(flow.Nonce))
	tokens, claims, err := provider.Exchange(context.Background(), "code-1", flow.CodeVerifier, flow.Nonce)
	if err != nil {
		t.Fatalf("the login was refused: %v", err)
	}

	if claims.Subject != testSubject || claims.PreferredUsername != "jkowalski" ||
		claims.Name != "Jan Kowalski" || claims.Email != "jkowalski@example.test" {
		t.Errorf("identity = %+v", claims)
	}
	if !slices.Equal(claims.Groups, []string{"flotestro-operators"}) {
		t.Errorf("groups = %q, expected [flotestro-operators]", claims.Groups)
	}
	if tokens.IDToken != minted || tokens.RefreshToken != "refresh-2" || tokens.AccessToken == "" {
		t.Errorf("tokens = %+v", tokens)
	}
	if tokens.ExpiresAt.IsZero() {
		t.Error("the expiry of the access token was not carried over")
	}

	// The verifier of PKCE goes to the token endpoint, otherwise the code
	// alone would be enough for whoever intercepted the redirect.
	form := issuer.lastTokenRequest()
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "code-1" ||
		form.Get("code_verifier") != flow.CodeVerifier || form.Get("redirect_uri") != testRedirectURL {
		t.Errorf("token request = %v", form)
	}
	if provider.Issuer() != issuer.server.URL {
		t.Errorf("Issuer() = %q, expected %q", provider.Issuer(), issuer.server.URL)
	}
}

func TestATokenOfAnotherIssuerIsRefused(t *testing.T) {
	// Signed by the right key but claiming to come from elsewhere: a token
	// of another realm on the same Keycloak would look like this.
	issuer := newFakeIssuer(t)
	provider := discoverProvider(t, issuer, "")

	claims := issuer.claims("")
	claims["iss"] = "https://sso.example.test/realms/another-realm"
	_, got, err := login(t, provider, issuer, claims)
	refused(t, got, err, "issued by a different provider")
}

func TestATokenForAnotherClientIsRefused(t *testing.T) {
	// The same user, the same issuer, but a token minted for another
	// application registered at the provider.
	issuer := newFakeIssuer(t)
	provider := discoverProvider(t, issuer, "")

	claims := issuer.claims("")
	claims["aud"] = "another-client"
	_, got, err := login(t, provider, issuer, claims)
	refused(t, got, err, "expected audience")
}

func TestATokenWithTheNonceOfAnotherLoginIsRefused(t *testing.T) {
	// A valid token injected into a flow it did not start: without the
	// nonce check a captured token could finish somebody else's login.
	issuer := newFakeIssuer(t)
	provider := discoverProvider(t, issuer, "")

	claims := issuer.claims("nonce-of-another-login")
	_, got, err := login(t, provider, issuer, claims)
	refused(t, got, err, "nonce")
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	issuer := newFakeIssuer(t)
	provider := discoverProvider(t, issuer, "")

	claims := issuer.claims("")
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	_, got, err := login(t, provider, issuer, claims)
	refused(t, got, err, "expired")
	var expired *coreoidc.TokenExpiredError
	if !errors.As(err, &expired) {
		t.Errorf("the refusal is not the expiry error of the library: %v", err)
	}
}

func TestATokenSignedByAnotherKeyIsRefused(t *testing.T) {
	// Every claim is right; only the key is not the one the issuer publishes.
	issuer := newFakeIssuer(t)
	provider := discoverProvider(t, issuer, "")
	_, rogue := signingKeys(t)

	flow, err := provider.BeginAuth(StepUp{})
	if err != nil {
		t.Fatal(err)
	}
	issuer.mintWith(t, rogue, "rogue-key", issuer.claims(flow.Nonce))
	_, got, err := provider.Exchange(context.Background(), "code-1", flow.CodeVerifier, flow.Nonce)
	refused(t, got, err, "failed to verify signature")
}

func TestTheGroupsClaimIsReadAsConfigured(t *testing.T) {
	issuer := newFakeIssuer(t)

	t.Run("a token without the claim yields no groups", func(t *testing.T) {
		// The code yields nil rather than an empty slice.
		provider := discoverProvider(t, issuer, "")
		claims := issuer.claims("")
		delete(claims, "groups")
		_, got, err := login(t, provider, issuer, claims)
		if err != nil {
			t.Fatalf("a token without groups was refused: %v", err)
		}
		if got.Groups != nil {
			t.Errorf("groups = %#v, expected nil", got.Groups)
		}
	})

	t.Run("the configured claim name is honoured", func(t *testing.T) {
		// Keycloak can be set up to expose realm roles instead of groups; the flag
		// names the claim, and the default one must then be ignored even when
		// present.
		provider := discoverProvider(t, issuer, "realm_roles")
		claims := issuer.claims("")
		claims["realm_roles"] = []string{"flotestro-operators"}
		claims["groups"] = []string{"a-group-that-does-not-count"}
		_, got, err := login(t, provider, issuer, claims)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Groups, []string{"flotestro-operators"}) {
			t.Errorf("groups = %q, expected [flotestro-operators]", got.Groups)
		}
	})

	t.Run("a Keycloak group path loses its leading slash", func(t *testing.T) {
		// Keycloak's group mapper emits full paths ("/flotestro-operators");
		// the role mapping is keyed by the plain name.
		provider := discoverProvider(t, issuer, "")
		claims := issuer.claims("")
		claims["groups"] = []string{"/flotestro-operators", "/flotestro-viewers"}
		_, got, err := login(t, provider, issuer, claims)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Groups, []string{"flotestro-operators", "flotestro-viewers"}) {
			t.Errorf("groups = %q", got.Groups)
		}
	})

	t.Run("a single string is read as one group", func(t *testing.T) {
		provider := discoverProvider(t, issuer, "")
		claims := issuer.claims("")
		claims["groups"] = "flotestro-operators"
		_, got, err := login(t, provider, issuer, claims)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Groups, []string{"flotestro-operators"}) {
			t.Errorf("groups = %q, expected [flotestro-operators]", got.Groups)
		}
	})
}

func TestARenewalYieldsTheGroupsOfTheNewToken(t *testing.T) {
	// The group snapshot of a session follows the token of the renewal, so a user
	// moved between groups in FreeIPA changes role without logging in again.
	issuer := newFakeIssuer(t)
	provider := discoverProvider(t, issuer, "")

	claims := issuer.claims("")
	delete(claims, "nonce")
	claims["groups"] = []string{"flotestro-operators", "flotestro-admins"}
	minted := issuer.mint(t, claims)

	tokens, got, err := provider.Refresh(context.Background(), "refresh-1")
	if err != nil {
		t.Fatalf("the renewal failed: %v", err)
	}
	if got == nil || !slices.Equal(got.Groups, []string{"flotestro-operators", "flotestro-admins"}) {
		t.Errorf("claims = %+v", got)
	}
	if tokens.IDToken != minted || tokens.RefreshToken != "refresh-2" {
		t.Errorf("tokens = %+v", tokens)
	}
	form := issuer.lastTokenRequest()
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-1" {
		t.Errorf("token request = %v", form)
	}

	t.Run("a renewed token of another issuer is still refused", func(t *testing.T) {
		// The renewal skips the nonce, not the rest of the verification.
		claims := issuer.claims("")
		claims["iss"] = "https://sso.example.test/realms/another-realm"
		issuer.mint(t, claims)
		_, got, err := provider.Refresh(context.Background(), "refresh-1")
		refused(t, got, err, "issued by a different provider")
	})
}

func TestAnInvalidGrantAtTheRenewalIsRecognised(t *testing.T) {
	// This is the answer the refresher ends a session on: the provider no longer
	// honours the refresh token.
	issuer := newFakeIssuer(t)
	provider := discoverProvider(t, issuer, "")

	issuer.refuseWith("invalid_grant")
	_, _, err := provider.Refresh(context.Background(), "refresh-1")
	if err == nil {
		t.Fatal("the renewal succeeded on an invalid_grant answer")
	}
	if !IsInvalidGrant(err) {
		t.Errorf("invalid_grant was not recognised: %v", err)
	}

	issuer.refuseWith("temporarily_unavailable")
	_, _, err = provider.Refresh(context.Background(), "refresh-1")
	if err == nil {
		t.Fatal("the renewal succeeded on a refusal")
	}
	if IsInvalidGrant(err) {
		t.Errorf("a transient refusal was taken for a gone user: %v", err)
	}
}
