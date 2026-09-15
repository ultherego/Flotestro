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
	"errors"
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

	mu    sync.Mutex
	cache map[string]cacheEntry
	// generation counts the invalidations. A read that started before a
	// write and finished after it must not put the state from before the
	// write back into the cache; it compares the generation it started in.
	generation uint64
	// logged says whether the directory session is believed alive. It is
	// read and written by every caller of the client at once, so it goes
	// under the same mutex as the cache.
	logged bool
	// The health of the connection, read from the calls themselves rather
	// than from a probe of its own: the last time the directory answered,
	// the last time it could not be reached, and the last command it
	// refused. An operator reading "unreachable" wants to know since when.
	lastSuccessAt time.Time
	lastError     string
	lastErrorAt   time.Time
	lastRefusal   string
	lastRefusalAt time.Time
}

func (c *Client) noteSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastSuccessAt = time.Now().UTC()
}

func (c *Client) noteFailure(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastError = err.Error()
	c.lastErrorAt = time.Now().UTC()
}

func (c *Client) noteRefusal(message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRefusal = message
	c.lastRefusalAt = time.Now().UTC()
}

// KeytabEntry describes one key of the connector's keytab, without the key.
type KeytabEntry struct {
	Principal string `json:"principal"`
	KVNO      uint32 `json:"kvno"`
	// Timestamp is when the key was written into the keytab. A keytab
	// carries no expiry: the directory decides when a key stops working,
	// and the file does not know it.
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

// Health is the state of the connector as the panel can know it without
// asking the directory: the identity it uses, what its keytab holds, when
// the directory last answered and last failed, and how old the cache is.
type Health struct {
	Principal string `json:"principal"`
	// KeytabReadable says whether the keytab file was read at start; the
	// entries come from that read. False comes with KeytabDetail.
	KeytabReadable bool          `json:"keytab_readable"`
	KeytabDetail   string        `json:"keytab_detail,omitempty"`
	KeytabEntries  []KeytabEntry `json:"keytab_entries"`
	LastSuccessAt  *time.Time    `json:"last_success_at,omitempty"`
	LastError      string        `json:"last_error,omitempty"`
	LastErrorAt    *time.Time    `json:"last_error_at,omitempty"`
	// LastRefusal is the last command the directory refused, with its
	// class: a refusal is an answer, not an outage, so it stands apart.
	LastRefusal   string     `json:"last_refusal,omitempty"`
	LastRefusalAt *time.Time `json:"last_refusal_at,omitempty"`
	CacheEntries  int        `json:"cache_entries"`
	// CacheOldestAt is when the oldest live entry was read from the
	// directory; nil with no entries, because an empty cache has no age.
	CacheOldestAt   *time.Time `json:"cache_oldest_at,omitempty"`
	CacheTTLSeconds int        `json:"cache_ttl_seconds"`
}

// Health reports the connector's state. No call reaches the directory
// here; the reachability check is a separate Ping, so a health view of a
// directory that is down still comes back at once.
func (c *Client) Health() Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	health := Health{
		Principal:       c.config.Principal,
		KeytabEntries:   []KeytabEntry{},
		CacheEntries:    0,
		CacheTTLSeconds: int(c.config.CacheTTL / time.Second),
	}
	if c.krbKeytab == nil || len(c.krbKeytab.Entries) == 0 {
		health.KeytabDetail = "the keytab holds no entries or was not read"
	} else {
		health.KeytabReadable = true
		for _, entry := range c.krbKeytab.Entries {
			principal := strings.Join(entry.Principal.Components, "/")
			if entry.Principal.Realm != "" {
				principal += "@" + entry.Principal.Realm
			}
			item := KeytabEntry{Principal: principal, KVNO: entry.KVNO}
			if item.KVNO == 0 {
				item.KVNO = uint32(entry.KVNO8)
			}
			if !entry.Timestamp.IsZero() {
				stamp := entry.Timestamp.UTC()
				item.Timestamp = &stamp
			}
			health.KeytabEntries = append(health.KeytabEntries, item)
		}
	}
	if !c.lastSuccessAt.IsZero() {
		at := c.lastSuccessAt
		health.LastSuccessAt = &at
	}
	if !c.lastErrorAt.IsZero() {
		at := c.lastErrorAt
		health.LastError = c.lastError
		health.LastErrorAt = &at
	}
	if !c.lastRefusalAt.IsZero() {
		at := c.lastRefusalAt
		health.LastRefusal = c.lastRefusal
		health.LastRefusalAt = &at
	}
	now := time.Now()
	for _, entry := range c.cache {
		if !now.Before(entry.expiresAt) {
			continue
		}
		health.CacheEntries++
		readAt := entry.expiresAt.Add(-c.config.CacheTTL).UTC()
		if health.CacheOldestAt == nil || readAt.Before(*health.CacheOldestAt) {
			health.CacheOldestAt = &readAt
		}
	}
	return health
}

func (c *Client) isLogged() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.logged
}

func (c *Client) setLogged(logged bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logged = logged
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
	c.setLogged(true)
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

// DirectoryError is an answer of the directory that refuses a call: the
// name is the directory's own class (ValidationError, NotFound,
// DuplicateEntry...). It is kept as a type, because a refusal is not the
// same thing as a directory that cannot be reached: the first does not
// change with a retry, the second may.
type DirectoryError struct {
	Name    string
	Message string
}

func (e *DirectoryError) Error() string {
	return "the directory: " + e.Message + " (" + e.Name + ")"
}

// Permanent says that repeating the same call gives the same answer. The
// scheduler settles a task on such an error instead of trying again until
// the deadline.
func (e *DirectoryError) Permanent() bool {
	switch e.Name {
	case "ValidationError", "NotFound", "DuplicateEntry", "ACIError", "RequirementError", "ConversionError":
		return true
	}
	return false
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// errSessionExpired says the directory no longer accepts the session
// cookie. It is the one error after which a call logs in again; a refused
// command or a broken connection comes back as it is, whatever its text.
var errSessionExpired = errors.New("the directory refused the session")

// call runs a directory command. The command name comes solely from the
// list of explicitly supported commands, never from a user's request.
func (c *Client) call(ctx context.Context, method string, args []string, options map[string]any) (json.RawMessage, error) {
	if !allowedMethod(method) && !guardedMethod(method, options) {
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
	if !errors.Is(err, errSessionExpired) {
		return nil, err
	}
	c.setLogged(false)
	if err := c.login(ctx); err != nil {
		c.noteFailure(err)
		return nil, err
	}
	return c.post(ctx, payload)
}

func (c *Client) post(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if !c.isLogged() {
		if err := c.login(ctx); err != nil {
			// A login that fails is the outage an operator asks about
			// first: the keytab, the KDC or the directory itself.
			c.noteFailure(err)
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
		c.noteFailure(fmt.Errorf("the query to the directory: %w", err))
		return nil, fmt.Errorf("the query to the directory: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized {
		// An expired session is the normal path, not a fault of the
		// connector: the caller logs in again. It is not counted as an error.
		return nil, fmt.Errorf("%w: 401", errSessionExpired)
	}
	if response.StatusCode != http.StatusOK {
		c.noteFailure(fmt.Errorf("the directory: code %d", response.StatusCode))
		return nil, fmt.Errorf("the directory: code %d", response.StatusCode)
	}

	var decoded rpcResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		c.noteFailure(fmt.Errorf("the directory response: %w", err))
		return nil, fmt.Errorf("the directory response: %w", err)
	}
	// FLOTESTRO_IPA_TRACE prints every exchange with the directory; for
	// troubleshooting a connector, never for normal operation - the
	// records carry personal data.
	if os.Getenv("FLOTESTRO_IPA_TRACE") != "" {
		fmt.Fprintf(os.Stderr, "ipa-trace request=%s\nipa-trace result=%s\n", truncateTrace(payload), truncateTrace(decoded.Result))
	}
	if decoded.Error != nil {
		// A refused command is an answer of a reachable directory: the
		// connector works, the request did not. The health view keeps the
		// last refusal too, because an operator asking "why did the change
		// fail" reads it there.
		c.noteSuccess()
		c.noteRefusal(decoded.Error.Name + ": " + decoded.Error.Message)
		return nil, &DirectoryError{Name: decoded.Error.Name, Message: decoded.Error.Message}
	}
	c.noteSuccess()
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
	"user_find":      true,
	"user_show":      true,
	"group_find":     true,
	"group_show":     true,
	"host_find":      true,
	"host_show":      true,
	"hostgroup_find": true,
	"hbacrule_find":  true,
	"hbacrule_show":  true,
	"sudorule_find":  true,
	"sudorule_show":  true,
	"ping":           true,
	// The Kerberos service principals of the hosts, read only: the panel
	// shows which principal has a keytab and who manages it. The keytab
	// itself never leaves the directory - there is no service_add,
	// service_del or any command that issues or exports key material.
	"service_find": true,
	"service_show": true,
	// hbactest is the directory's own simulation of an access rule: the
	// verdict the host will apply, not a reconstruction by the panel.
	"hbactest": true,

	// The write operations. Each is carried out solely by the control plane
	// after the plan is approved; the adapter exposes no commands that delete
	// an account or change the configuration of the directory itself.
	"user_add":            true,
	"user_mod":            true,
	"user_disable":        true,
	"user_enable":         true,
	"group_add_member":    true,
	"group_remove_member": true,
	// Host group membership. An HBAC or sudo rule reaches a host through
	// its host groups, so moving a host between groups changes who may sign
	// in where; it is carried out like a user group change - plan, second
	// person, execution - and never creates or deletes the group itself.
	"hostgroup_add_member":    true,
	"hostgroup_remove_member": true,
	// The host entry and the one-time enrollment password. Deleting a host
	// from the directory is not available here: it would cut off the
	// administrators' access.
	"host_add": true,
	"host_mod": true,
	// A host whose keytab is on record cannot be given a new join password;
	// disabling the entry revokes the keytab and the certificates, and the
	// entry stays. It is used only for a host the operator is joining anew.
	"host_disable": true,

	// The access and sudo rules. A rule is declared as a whole and brought to
	// that state member kind by member kind; the panel writes only the rules
	// it manages and never touches the services, commands or hosts they name.
	"hbacrule_add":                  true,
	"hbacrule_mod":                  true,
	"hbacrule_del":                  true,
	"hbacrule_enable":               true,
	"hbacrule_disable":              true,
	"hbacrule_add_user":             true,
	"hbacrule_remove_user":          true,
	"hbacrule_add_host":             true,
	"hbacrule_remove_host":          true,
	"hbacrule_add_service":          true,
	"hbacrule_remove_service":       true,
	"sudorule_add":                  true,
	"sudorule_mod":                  true,
	"sudorule_del":                  true,
	"sudorule_enable":               true,
	"sudorule_disable":              true,
	"sudorule_add_user":             true,
	"sudorule_remove_user":          true,
	"sudorule_add_host":             true,
	"sudorule_remove_host":          true,
	"sudorule_add_allow_command":    true,
	"sudorule_remove_allow_command": true,
	"sudorule_add_runasuser":        true,
	"sudorule_remove_runasuser":     true,
	"sudorule_add_runasgroup":       true,
	"sudorule_remove_runasgroup":    true,
	"sudorule_add_option":           true,
	"sudorule_remove_option":        true,

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

// guardedMethods are the commands the adapter runs only with a fixed
// option in the request, because the same command without it does
// something the panel must never do. The one entry is user_del with
// preserve: the directory then keeps the entry, its UID and its history as
// a preserved account, which the document names as the default stage of a
// removal. A plain user_del erases the account; it stays out of
// allowedMethods, and this guard refuses it too - a second check, not a
// way around the first.
var guardedMethods = map[string]func(options map[string]any) bool{
	"user_del": func(options map[string]any) bool {
		preserve, _ := options["preserve"].(bool)
		return preserve
	},
}

// guardedMethod says whether the command may run with these options.
func guardedMethod(method string, options map[string]any) bool {
	guard, ok := guardedMethods[method]
	if !ok || options == nil {
		return false
	}
	return guard(options)
}

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
	started := c.generation
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
	if c.generation == started {
		c.cache[key] = cacheEntry{value: value, expiresAt: time.Now().Add(c.config.CacheTTL)}
	}
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

func truncateTrace(raw []byte) string {
	if len(raw) > 4000 {
		return string(raw[:4000]) + "..."
	}
	return string(raw)
}
