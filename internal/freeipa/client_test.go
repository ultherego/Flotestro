package freeipa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// countingDirectory stands in for the two doors of the directory: the
// Kerberos session door and the JSON-RPC door. It counts the knocks on each
// and answers the RPC door with whatever status the test set, so the test
// sees how many times the adapter came back rather than what it asked.
type countingDirectory struct {
	server    *httptest.Server
	logins    atomic.Int64
	calls     atomic.Int64
	rpcStatus atomic.Int64
}

func newCountingDirectory(t *testing.T, rpcStatus int) *countingDirectory {
	t.Helper()
	fake := &countingDirectory{}
	fake.rpcStatus.Store(int64(rpcStatus))
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ipa/session/login_kerberos":
			fake.logins.Add(1)
			w.WriteHeader(http.StatusOK)
		case "/ipa/session/json":
			fake.calls.Add(1)
			status := int(fake.rpcStatus.Load())
			w.WriteHeader(status)
			if status == http.StatusOK {
				_, _ = w.Write([]byte(`{"result":{"result":{}},"error":null}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// clientWithoutATicket builds a client whose keytab has no keys: the only
// way to exercise the login path without a KDC. Kerberos refuses to issue a
// ticket from an empty keytab before any packet leaves the process, which is
// exactly the failure of a missing or unreadable keytab in production.
func (f *countingDirectory) clientWithoutATicket(logged bool) *Client {
	return &Client{
		config:     Config{ServerURL: f.server.URL, Principal: "flotestro/panel@FLOTESTRO.TEST", CacheTTL: time.Minute},
		http:       f.server.Client(),
		krbConfig:  config.New(),
		krbKeytab:  keytab.New(),
		sessionURL: f.server.URL + "/ipa/session/login_kerberos",
		jsonURL:    f.server.URL + "/ipa/session/json",
		referer:    f.server.URL + "/ipa",
		cache:      map[string]cacheEntry{},
		logged:     logged,
	}
}

// writeKRB5Conf writes the smallest Kerberos configuration the constructor
// accepts, so that a failing constructor fails on the keytab and on nothing
// else.
func writeKRB5Conf(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "krb5.conf")
	content := "[libdefaults]\n default_realm = FLOTESTRO.TEST\n dns_lookup_kdc = false\n" +
		"[realms]\n FLOTESTRO.TEST = {\n  kdc = ipa.flotestro.test\n }\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestTheConstructorRefusesAKeytabItCannotUse checks that the connector
// does not come up half-configured: a keytab that is missing or is not a
// keytab is an error at start, not a surprise at the first query.
func TestTheConstructorRefusesAKeytabItCannotUse(t *testing.T) {
	krb5 := writeKRB5Conf(t)
	garbage := filepath.Join(t.TempDir(), "panel.keytab")
	if err := os.WriteFile(garbage, []byte("this is not a keytab"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing":    filepath.Join(t.TempDir(), "does-not-exist.keytab"),
		"unreadable": garbage,
	} {
		t.Run(name, func(t *testing.T) {
			client, err := New(Config{
				ServerURL: "https://ipa.flotestro.test", Realm: "FLOTESTRO.TEST",
				Principal: "flotestro/panel", KeytabPath: path, KRB5ConfPath: krb5,
			})
			if err == nil || client != nil {
				t.Fatalf("a client came up with a %s keytab", name)
			}
			if !strings.Contains(err.Error(), "keytab") {
				t.Fatalf("the error does not name the keytab: %v", err)
			}
		})
	}
}

// TestLoginWithoutAUsableKeytabFailsClosed is the fail-closed guarantee of
// the design: no ticket means no session, and in particular no attempt with
// any other credential. The directory doors are not even knocked on.
func TestLoginWithoutAUsableKeytabFailsClosed(t *testing.T) {
	fake := newCountingDirectory(t, http.StatusOK)
	client := fake.clientWithoutATicket(false)

	err := client.login(context.Background())
	if err == nil {
		t.Fatal("a login without a ticket succeeded")
	}
	if !strings.Contains(err.Error(), "Kerberos login as flotestro/panel@FLOTESTRO.TEST") {
		t.Fatalf("the error does not say the Kerberos step failed: %v", err)
	}
	if client.logged {
		t.Fatal("the client marks the session as established after a failed login")
	}
	if fake.logins.Load() != 0 || fake.calls.Load() != 0 {
		t.Fatalf("the directory was reached without a ticket: %d logins, %d calls",
			fake.logins.Load(), fake.calls.Load())
	}
}

// TestTheConfigurationHasNoPasswordField pins the contract at compile
// level: the connector authenticates with a keytab only. A password field
// would be the beginning of a fallback the design forbids, and it would
// sooner or later reach the database or the settings screen.
func TestTheConfigurationHasNoPasswordField(t *testing.T) {
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, forbidden := range []string{"password", "passwd", "secret"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("the directory configuration has a field %s; the connector authenticates with a keytab only",
					typ.Field(i).Name)
			}
		}
	}
}

// TestACallReLogsInOnceAfterA401AndThenGivesUp checks the normal path of an
// expired session and its bound. After a 401 the adapter tries to log in
// exactly once; when that fails the error comes back instead of a second
// query with a dead session or a loop of retries. A successful re-login
// needs a KDC, so the test observes the bound through the failing one: the
// query is not repeated and the session is left marked as gone, so the next
// call goes through the login again instead of trusting a stale cookie.
func TestACallReLogsInOnceAfterA401AndThenGivesUp(t *testing.T) {
	fake := newCountingDirectory(t, http.StatusUnauthorized)
	client := fake.clientWithoutATicket(true)

	_, err := client.call(context.Background(), "hbactest", nil,
		map[string]any{"user": "alice", "targethost": "web1.flotestro.test", "service": "sshd"})
	if err == nil {
		t.Fatal("a call the directory refused with 401 succeeded")
	}
	if !strings.Contains(err.Error(), "Kerberos login") {
		t.Fatalf("the error is not the failed re-login: %v", err)
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("the query was sent %d times, expected once before the re-login", fake.calls.Load())
	}
	if fake.logins.Load() != 0 {
		t.Fatalf("the session door was reached %d times without a ticket", fake.logins.Load())
	}
	if client.logged {
		t.Fatal("the client still trusts the session the directory refused")
	}

	// The next call starts from the login, not from the dead session: the
	// query counter stays where it was.
	if _, err := client.call(context.Background(), "hbactest", nil, map[string]any{}); err == nil {
		t.Fatal("a call after a failed re-login succeeded")
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("a query went out on a session known to be dead: %d queries", fake.calls.Load())
	}
}

// TestACallWithALiveSessionDoesNotLogInAgain guards the other bound: a
// session that works is used as it is, so the directory does not see a
// Kerberos exchange per query.
func TestACallWithALiveSessionDoesNotLogInAgain(t *testing.T) {
	fake := newCountingDirectory(t, http.StatusOK)
	client := fake.clientWithoutATicket(true)

	if _, err := client.call(context.Background(), "hbactest", nil, map[string]any{}); err != nil {
		t.Fatalf("a call with a live session failed: %v", err)
	}
	if fake.logins.Load() != 0 || fake.calls.Load() != 1 {
		t.Fatalf("%d logins and %d queries for one call", fake.logins.Load(), fake.calls.Load())
	}
}
