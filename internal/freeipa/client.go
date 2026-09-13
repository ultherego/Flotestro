// Package freeipa is the adapter for the FreeIPA directory. It uses the
// documented JSON-RPC over HTTPS with Kerberos authentication.
//
// Writing straight to LDAP is deliberately impossible in this package: it
// would bypass FreeIPA's validation, plugins and semantics, and the panel
// would create objects the directory itself would consider inconsistent.
package freeipa

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Config describes the connection with the directory.
type Config struct {
	// ServerURL is the address of the IPA server, e.g. https://ipa.flotestro.test.
	ServerURL string
	Realm     string
	// Principal is the connector's own service principal. We use neither the
	// admin account nor the Directory Manager.
	Principal string
	// KeytabPath points at the connector's keytab. The keytab does not reach the database.
	KeytabPath string
	// KRB5ConfPath points at the Kerberos configuration.
	KRB5ConfPath string
	// CACertPath is the CA certificate of the directory.
	CACertPath string
	// CacheTTL is the short lifetime of an answer. The panel does not
	// replicate the directory, so the cache only protects the IPA server from
	// an excess of queries.
	CacheTTL time.Duration
}

// Enabled says whether the connector is configured.
func (c Config) Enabled() bool {
	return c.ServerURL != "" && c.Principal != "" && c.KeytabPath != ""
}

// Client talks to the directory.
type Client struct {
	config     Config
	http       *http.Client
	krbConfig  *config.Config
	krbKeytab  *keytab.Keytab
	sessionURL string
	jsonURL    string
	referer    string

	mu     sync.Mutex
	cache  map[string]cacheEntry
	logged bool
}

type cacheEntry struct {
	value     any
	expiresAt time.Time
}

// New creates a directory client.
func New(cfg Config) (*Client, error) {
	if !cfg.Enabled() {
		return nil, fmt.Errorf("the directory connector is not configured")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	if cfg.KRB5ConfPath == "" {
		cfg.KRB5ConfPath = "/etc/krb5.conf"
	}

	krbConfig, err := config.Load(cfg.KRB5ConfPath)
	if err != nil {
		return nil, fmt.Errorf("Kerberos configuration: %w", err)
	}
	krbKeytab, err := keytab.Load(cfg.KeytabPath)
	if err != nil {
		return nil, fmt.Errorf("keytab %s: %w", cfg.KeytabPath, err)
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("directory CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the directory CA file contains no certificate")
		}
		tlsConfig.RootCAs = pool
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	base := strings.TrimSuffix(cfg.ServerURL, "/")
	return &Client{
		config: cfg,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Jar:       jar,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		krbConfig:  krbConfig,
		krbKeytab:  krbKeytab,
		sessionURL: base + "/ipa/session/login_kerberos",
		jsonURL:    base + "/ipa/session/json",
		referer:    base + "/ipa",
		cache:      map[string]cacheEntry{},
	}, nil
}

// Principal returns the connector's identity.
func (c *Client) Principal() string { return c.config.Principal }

// login exchanges the Kerberos ticket for a directory HTTP session.
func (c *Client) login(ctx context.Context) error {
	username, realm := splitPrincipal(c.config.Principal, c.config.Realm)

	krbClient := client.NewWithKeytab(username, realm, c.krbKeytab, c.krbConfig,
		client.DisablePAFXFAST(true))
	if err := krbClient.Login(); err != nil {
		// Fail closed: without a ticket we fall back to no other
		// authentication method, in particular not to an administrator
		// password.
		return fmt.Errorf("Kerberos login as %s: %w", c.config.Principal, err)
	}
	defer krbClient.Destroy()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.sessionURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Referer", c.referer)

	spnegoClient := spnego.NewClient(krbClient, c.http, "")
	response, err := spnegoClient.Do(request)
	if err != nil {
		return fmt.Errorf("the directory session: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("the directory session: code %d", response.StatusCode)
	}
	c.logged = true
	return nil
}

// rpcRequest is the JSON-RPC envelope of the directory.
type rpcRequest struct {
	Method string `json:"method"`
	Params []any  `json:"params"`
	ID     int    `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Name    string `json:"name"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// call runs a directory command. The command name comes solely from the
// list of explicitly supported commands, never from a user's request.
func (c *Client) call(ctx context.Context, method string, args []string, options map[string]any) (json.RawMessage, error) {
	if !allowedMethod(method) {
		return nil, fmt.Errorf("the command %q is not supported by the adapter", method)
	}
	if options == nil {
		options = map[string]any{}
	}
	// The directory requires a positional list even for commands without
	// arguments; an empty pointer serialises to null and is rejected.
	if args == nil {
		args = []string{}
	}
	// The directory returns shortened records by default; version pins the contract.
	options["version"] = apiVersion

	payload, err := json.Marshal(rpcRequest{
		Method: method,
		Params: []any{args, options},
	})
	if err != nil {
		return nil, err
	}

	result, err := c.post(ctx, payload)
	if err == nil {
		return result, nil
	}
	// The directory session expires; one re-login is the normal path.
	if !strings.Contains(err.Error(), "401") {
		return nil, err
	}
	c.logged = false
	if err := c.login(ctx); err != nil {
		return nil, err
	}
	return c.post(ctx, payload)
}

func (c *Client) post(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if !c.logged {
		if err := c.login(ctx); err != nil {
			return nil, err
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.jsonURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	// FreeIPA rejects requests without a Referer header as CSRF protection.
	request.Header.Set("Referer", c.referer)

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("the query to the directory: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("the directory refused the session: 401")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the directory: code %d", response.StatusCode)
	}

	var decoded rpcResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("the directory response: %w", err)
	}
	if decoded.Error != nil {
		return nil, fmt.Errorf("the directory: %s (%s)", decoded.Error.Message, decoded.Error.Name)
	}
	return decoded.Result, nil
}

// findRaw runs a search in raw mode. It is used solely where the friendly
// view filters out the attribute we need.
func (c *Client) findRaw(ctx context.Context, method string) ([]map[string]any, error) {
	return c.find(ctx, method, true)
}

// apiVersion pins the version of the directory contract. Without it the
// server may change the shape of its answers after an upgrade.
const apiVersion = "2.254"

// allowedMethods are the only commands the adapter is able to run. The list
// is closed: there is no way to call an arbitrary IPA command.
var allowedMethods = map[string]bool{
	"user_find":     true,
	"user_show":     true,
	"group_find":    true,
	"group_show":    true,
	"host_find":     true,
	"host_show":     true,
	"hbacrule_find": true,
	"sudorule_find": true,
	"ping":          true,

	// The write operations. Each is carried out solely by the control plane
	// after the plan is approved; the adapter exposes no commands that delete
	// an account or change the configuration of the directory itself.
	"user_add":            true,
	"user_mod":            true,
	"user_disable":        true,
	"user_enable":         true,
	"group_add_member":    true,
	"group_remove_member": true,
	// The host entry and the one-time enrollment password. Deleting a host
	// from the directory is not available here: it would cut off the
	// administrators' access.
	"host_add": true,
	"host_mod": true,

	// Directory DNS. Reading zones and records plus adding and removing a
	// single value. Commands that change the zone itself - its name servers,
	// SOA or DNSSEC - the adapter does not expose: that is the directory's
	// configuration rather than the content the fleet panel runs.
	"dnszone_find":   true,
	"dnsrecord_find": true,
	"dnsrecord_show": true,
	"dnsrecord_add":  true,
	"dnsrecord_del":  true,
}

func allowedMethod(method string) bool { return allowedMethods[method] }

// splitPrincipal splits a principal into the name and the realm.
func splitPrincipal(principal, defaultRealm string) (string, string) {
	if name, realm, found := strings.Cut(principal, "@"); found {
		return name, realm
	}
	return principal, defaultRealm
}

// cached returns a result from the short cache or fetches it from the
// directory. The panel does not replicate the directory; the cache protects
// the IPA server from an excess of queries when a view is refreshed.
func cached[T any](ctx context.Context, c *Client, key string, load func() (T, error)) (T, error) {
	c.mu.Lock()
	entry, ok := c.cache[key]
	c.mu.Unlock()
	if ok && time.Now().Before(entry.expiresAt) {
		if value, ok := entry.value.(T); ok {
			return value, nil
		}
	}

	value, err := load()
	if err != nil {
		var zero T
		return zero, err
	}

	c.mu.Lock()
	c.cache[key] = cacheEntry{value: value, expiresAt: time.Now().Add(c.config.CacheTTL)}
	c.mu.Unlock()
	return value, nil
}

// The patterns of directory object names. A name never reaches a shell
// command, but validation is a second line of defence and rejects shapes
// that can be neither an account nor a group name.
var (
	userNamePattern  = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)
	groupNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$`)
	hostNamePattern  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)
)

// validateSSHPublicKey rejects material that is not a public key.
// A private key must never reach the directory or the logs.
func validateSSHPublicKey(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("empty SSH key")
	}
	if strings.Contains(trimmed, "PRIVATE KEY") {
		return fmt.Errorf("a private key was given; only a public key reaches the directory")
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return fmt.Errorf("the SSH key does not have the form <type> <material>")
	}
	switch fields[0] {
	case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return nil
	default:
		return fmt.Errorf("unsupported SSH key type %q", fields[0])
	}
}
