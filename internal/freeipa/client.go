// Package freeipa jest adapterem katalogu FreeIPA. Uzywa udokumentowanego
// JSON-RPC po HTTPS z uwierzytelnieniem Kerberos.
//
// Zapis bezposrednio do LDAP jest swiadomie niemozliwy w tym pakiecie: omijalby
// walidacje, pluginy i semantyke FreeIPA, przez co panel tworzylby obiekty,
// ktorych sam katalog uznalby za niespojne.
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

// Config opisuje polaczenie z katalogiem.
type Config struct {
	// ServerURL jest adresem serwera IPA, np. https://ipa.flotestro.test.
	ServerURL string
	Realm     string
	// Principal jest wlasnym service principalem connectora. Nie uzywamy
	// konta admin ani Directory Managera.
	Principal string
	// KeytabPath wskazuje keytab connectora. Keytab nie trafia do bazy.
	KeytabPath string
	// KRB5ConfPath wskazuje konfiguracje Kerberosa.
	KRB5ConfPath string
	// CACertPath jest certyfikatem CA katalogu.
	CACertPath string
	// CacheTTL jest krotkim czasem zycia odpowiedzi. Panel nie replikuje
	// katalogu, wiec cache ma tylko chronic serwer IPA przed nadmiarem zapytan.
	CacheTTL time.Duration
}

// Enabled mowi, czy connector jest skonfigurowany.
func (c Config) Enabled() bool {
	return c.ServerURL != "" && c.Principal != "" && c.KeytabPath != ""
}

// Client rozmawia z katalogiem.
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

// New tworzy klienta katalogu.
func New(cfg Config) (*Client, error) {
	if !cfg.Enabled() {
		return nil, fmt.Errorf("connector katalogu nie jest skonfigurowany")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	if cfg.KRB5ConfPath == "" {
		cfg.KRB5ConfPath = "/etc/krb5.conf"
	}

	krbConfig, err := config.Load(cfg.KRB5ConfPath)
	if err != nil {
		return nil, fmt.Errorf("konfiguracja Kerberosa: %w", err)
	}
	krbKeytab, err := keytab.Load(cfg.KeytabPath)
	if err != nil {
		return nil, fmt.Errorf("keytab %s: %w", cfg.KeytabPath, err)
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("certyfikat CA katalogu: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("certyfikat CA katalogu nie zawiera certyfikatu")
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

// Principal zwraca tozsamosc connectora.
func (c *Client) Principal() string { return c.config.Principal }

// login wymienia bilet Kerberos na sesje HTTP katalogu.
func (c *Client) login(ctx context.Context) error {
	username, realm := splitPrincipal(c.config.Principal, c.config.Realm)

	krbClient := client.NewWithKeytab(username, realm, c.krbKeytab, c.krbConfig,
		client.DisablePAFXFAST(true))
	if err := krbClient.Login(); err != nil {
		// Fail closed: bez biletu nie przechodzimy na zadna inna metode
		// uwierzytelnienia, w szczegolnosci na haslo administratora.
		return fmt.Errorf("logowanie Kerberos jako %s: %w", c.config.Principal, err)
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
		return fmt.Errorf("sesja katalogu: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("sesja katalogu: kod %d", response.StatusCode)
	}
	c.logged = true
	return nil
}

// rpcRequest jest koperta JSON-RPC katalogu.
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

// call wykonuje polecenie katalogu. Nazwa polecenia pochodzi wylacznie
// z listy jawnie wspieranych komend, nigdy z zadania uzytkownika.
func (c *Client) call(ctx context.Context, method string, args []string, options map[string]any) (json.RawMessage, error) {
	if !allowedMethod(method) {
		return nil, fmt.Errorf("polecenie %q nie jest wspierane przez adapter", method)
	}
	if options == nil {
		options = map[string]any{}
	}
	// Katalog wymaga listy pozycyjnej nawet dla polecen bez argumentow;
	// pusty wskaznik serializuje sie do null i jest odrzucany.
	if args == nil {
		args = []string{}
	}
	// Katalog domyslnie zwraca skrocone rekordy; version stabilizuje kontrakt.
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
	// Sesja katalogu wygasa; jedno ponowne logowanie jest normalna sciezka.
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
	// FreeIPA odrzuca zapytania bez naglowka Referer jako ochrone przed CSRF.
	request.Header.Set("Referer", c.referer)

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("zapytanie do katalogu: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("katalog odrzucil sesje: 401")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("katalog: kod %d", response.StatusCode)
	}

	var decoded rpcResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("odpowiedz katalogu: %w", err)
	}
	if decoded.Error != nil {
		return nil, fmt.Errorf("katalog: %s (%s)", decoded.Error.Message, decoded.Error.Name)
	}
	return decoded.Result, nil
}

// findRaw wykonuje wyszukiwanie w trybie surowym. Uzywamy go wylacznie tam,
// gdzie widok przyjazny odfiltrowuje potrzebny atrybut.
func (c *Client) findRaw(ctx context.Context, method string) ([]map[string]any, error) {
	return c.find(ctx, method, true)
}

// apiVersion przypina wersje kontraktu katalogu. Bez tego serwer moze zmienic
// ksztalt odpowiedzi po aktualizacji.
const apiVersion = "2.254"

// allowedMethods to jedyne polecenia, jakie adapter potrafi wykonac.
// Lista jest zamknieta: nie istnieje sposob wywolania dowolnego polecenia IPA.
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

	// Operacje zapisu. Kazda jest wykonywana wylacznie przez control plane
	// po zatwierdzeniu planu; adapter nie udostepnia polecen usuwajacych
	// konta ani zmieniajacych konfiguracje samego katalogu.
	"user_add":            true,
	"user_mod":            true,
	"user_disable":        true,
	"user_enable":         true,
	"group_add_member":    true,
	"group_remove_member": true,
	// Wpis hosta i jednorazowe haslo dolaczenia. Usuniecie hosta z katalogu
	// nie jest tu dostepne: odcielo by dostep administratorom.
	"host_add": true,
	"host_mod": true,

	// DNS katalogowy. Odczyt stref i rekordow oraz dopisanie i usuniecie
	// pojedynczej wartosci. Polecen zmieniajacych sama strefe - jej serwery
	// nazw, SOA czy DNSSEC - adapter nie udostepnia: to konfiguracja
	// katalogu, a nie zawartosc, ktora prowadzi panel floty.
	"dnszone_find":   true,
	"dnsrecord_find": true,
	"dnsrecord_show": true,
	"dnsrecord_add":  true,
	"dnsrecord_del":  true,
}

func allowedMethod(method string) bool { return allowedMethods[method] }

// splitPrincipal rozdziela principal na nazwe i realm.
func splitPrincipal(principal, defaultRealm string) (string, string) {
	if name, realm, found := strings.Cut(principal, "@"); found {
		return name, realm
	}
	return principal, defaultRealm
}

// cached zwraca wynik z krotkiego cache albo pobiera go z katalogu.
// Panel nie replikuje katalogu; cache chroni serwer IPA przed nadmiarem
// zapytan przy odswiezaniu widoku.
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

// Wzorce nazw obiektow katalogu. Nazwa nigdy nie trafia do polecenia powloki,
// ale walidacja jest druga linia obrony i odrzuca ksztalty, ktore nie moga byc
// nazwa konta ani grupy.
var (
	userNamePattern  = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)
	groupNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$`)
	hostNamePattern  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)
)

// validateSSHPublicKey odrzuca material, ktory nie jest kluczem publicznym.
// Klucz prywatny nigdy nie moze trafic do katalogu ani do logow.
func validateSSHPublicKey(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("pusty klucz SSH")
	}
	if strings.Contains(trimmed, "PRIVATE KEY") {
		return fmt.Errorf("podano klucz prywatny; do katalogu trafia wylacznie klucz publiczny")
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return fmt.Errorf("klucz SSH nie ma postaci <typ> <material>")
	}
	switch fields[0] {
	case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return nil
	default:
		return fmt.Errorf("nieobslugiwany typ klucza SSH %q", fields[0])
	}
}
