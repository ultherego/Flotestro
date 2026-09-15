package freeipa

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The lifecycle commands: what the adapter sends for a preservation, an
// expiration, a POSIX edit, a password reset and a host group change - and
// what it refuses to send at all.

func TestAPlainUserDelNeverReachesTheDirectory(t *testing.T) {
	fake, client := newFakeDirectory(t)
	// The closed list does not know user_del, and the guard admits it with
	// preserve alone: without the flag the call is refused before any
	// request is built, so the fake sees nothing.
	for name, options := range map[string]map[string]any{
		"no options":     nil,
		"empty options":  {},
		"preserve false": {"preserve": false},
		"preserve text":  {"preserve": "true"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := client.call(context.Background(), "user_del", []string{"jane"}, options)
			if err == nil || !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("a plain user_del was not refused: %v", err)
			}
		})
	}
	if fake.count("user_del") != 0 {
		t.Fatalf("the fake received %d user_del calls", fake.count("user_del"))
	}
	if allowedMethod("user_del") {
		t.Fatal("user_del entered the closed list; the guard is the only door")
	}
}

func TestPreserveUserSendsTheGuardedUserDel(t *testing.T) {
	fake, client := newFakeDirectory(t)
	if err := client.PreserveUser(context.Background(), "jane"); err != nil {
		t.Fatalf("preserving: %v", err)
	}
	call, ok := fake.find("user_del")
	if !ok {
		t.Fatal("no user_del was sent")
	}
	if preserve, _ := call.Options["preserve"].(bool); !preserve {
		t.Fatalf("user_del was sent without preserve: %v", call.Options)
	}
	if len(call.Args) != 1 || call.Args[0] != "jane" {
		t.Fatalf("user_del named %v", call.Args)
	}
	if err := client.PreserveUser(context.Background(), "../root"); err == nil {
		t.Fatal("an invalid account name was accepted")
	}
}

func TestSetUserExpirySendsGeneralizedTimeAndClearsWithNull(t *testing.T) {
	fake, client := newFakeDirectory(t)
	at := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	cleared := time.Time{}
	err := client.SetUserExpiry(context.Background(), "jane", Expiry{
		PrincipalExpiresAt: &at, PasswordExpiresAt: &cleared,
	})
	if err != nil {
		t.Fatalf("setting the expiry: %v", err)
	}
	call, ok := fake.find("user_mod")
	if !ok {
		t.Fatal("no user_mod was sent")
	}
	if got := call.Options["krbprincipalexpiration"]; got != "20261231235959Z" {
		t.Fatalf("the principal expiration was sent as %v", got)
	}
	// The zero time clears: the directory reads null as "remove the
	// attribute", and "never expires" is then an ordered state rather
	// than an omission.
	if value, present := call.Options["krbpasswordexpiration"]; !present || value != nil {
		t.Fatalf("the password expiration was sent as %v (present %v)", value, present)
	}
	if err := client.SetUserExpiry(context.Background(), "jane", Expiry{}); err == nil {
		t.Fatal("an expiry change naming nothing was accepted")
	}
}

func TestSetUserPOSIXSendsOnlyTheNamedAttributes(t *testing.T) {
	fake, client := newFakeDirectory(t)
	err := client.SetUserPOSIX(context.Background(), "jane", POSIXSpec{Shell: "/bin/zsh", UIDNumber: "12345"})
	if err != nil {
		t.Fatalf("the POSIX change: %v", err)
	}
	call, _ := fake.find("user_mod")
	if call.Options["loginshell"] != "/bin/zsh" || call.Options["uidnumber"] != "12345" {
		t.Fatalf("the attributes were sent as %v", call.Options)
	}
	for _, absent := range []string{"gidnumber", "homedirectory"} {
		if _, present := call.Options[absent]; present {
			t.Fatalf("%s was sent although it was not named", absent)
		}
	}
	for name, spec := range map[string]POSIXSpec{
		"nothing":              {},
		"a relative home":      {HomeDir: "home/jane"},
		"a shell with a space": {Shell: "/bin/sh -c"},
		"a uid with letters":   {UIDNumber: "12a"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := spec.Validate(); err == nil {
				t.Fatal("an invalid POSIX change passed validation")
			}
		})
	}
}

func TestResetUserPasswordReturnsTheDirectorysPasswordOnce(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["user_mod"] = answerWith(map[string]any{
		"uid": []any{"jane"}, "randompassword": "Zx9-temporary",
	})
	password, err := client.ResetUserPassword(context.Background(), "jane")
	if err != nil {
		t.Fatalf("the reset: %v", err)
	}
	if password != "Zx9-temporary" {
		t.Fatalf("the password came back as %q", password)
	}
	call, _ := fake.find("user_mod")
	if random, _ := call.Options["random"].(bool); !random {
		t.Fatalf("the reset did not ask for a random password: %v", call.Options)
	}
	if _, present := call.Options["userpassword"]; present {
		t.Fatal("a password chosen by the panel was sent; the directory generates it")
	}

	// A directory that answers without a password is a failure, not an
	// empty secret handed to the requester.
	fake.answers["user_mod"] = answerWith(map[string]any{"uid": []any{"jane"}})
	if _, err := client.ResetUserPassword(context.Background(), "jane"); err == nil {
		t.Fatal("an answer without a password passed as a reset")
	}
}

func TestHostGroupMembersGoThroughTheMemberCommands(t *testing.T) {
	fake, client := newFakeDirectory(t)
	if err := client.AddHostGroupMembers(context.Background(), "web", []string{"web1.example.test"}); err != nil {
		t.Fatalf("adding: %v", err)
	}
	if err := client.RemoveHostGroupMembers(context.Background(), "web", []string{"web2.example.test"}); err != nil {
		t.Fatalf("removing: %v", err)
	}
	add, _ := fake.find("hostgroup_add_member")
	if got := optionStrings(add, "host"); len(got) != 1 || got[0] != "web1.example.test" {
		t.Fatalf("the add named %v", got)
	}
	if fake.count("hostgroup_remove_member") != 1 {
		t.Fatal("no removal was sent")
	}
	for name, run := range map[string]func() error{
		"a short host name": func() error {
			return client.AddHostGroupMembers(context.Background(), "web", []string{"web1"})
		},
		"no hosts": func() error {
			return client.AddHostGroupMembers(context.Background(), "web", nil)
		},
		"a bad group": func() error {
			return client.AddHostGroupMembers(context.Background(), "web; rm", []string{"web1.example.test"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil {
				t.Fatal("an invalid membership change was sent")
			}
		})
	}
}

func TestAPartialHostGroupChangeIsNotASuccess(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["hostgroup_add_member"] = func(rpcCall) (any, *rpcError) {
		return map[string]any{
			"result": map[string]any{"cn": []any{"web"}},
			"failed": map[string]any{"member": map[string]any{
				"host": []any{[]any{"web9.example.test", "no such entry"}},
			}},
		}, nil
	}
	err := client.AddHostGroupMembers(context.Background(), "web",
		[]string{"web1.example.test", "web9.example.test"})
	if err == nil || !strings.Contains(err.Error(), "web9.example.test") {
		t.Fatalf("a partial success passed as a success: %v", err)
	}
}

func TestServicesReadTheKeytabFlagOrLeaveItOpen(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["service_find"] = func(rpcCall) (any, *rpcError) {
		return map[string]any{"result": []any{
			map[string]any{
				"krbcanonicalname": []any{"HTTP/web1.example.test@EXAMPLE.TEST"},
				"krbprincipalname": []any{"HTTP/web1.example.test@EXAMPLE.TEST", "HTTP/www.example.test@EXAMPLE.TEST"},
				"has_keytab":       true,
				"managedby_host":   []any{"web1.example.test"},
			},
			map[string]any{
				"krbprincipalname": []any{"ldap/ipa.example.test@EXAMPLE.TEST"},
				"has_keytab":       false,
			},
			map[string]any{
				"krbprincipalname": []any{"cifs/nas.example.test@EXAMPLE.TEST"},
			},
		}, "count": 3, "truncated": false}, nil
	}
	services, err := client.Services(context.Background())
	if err != nil {
		t.Fatalf("reading the services: %v", err)
	}
	if len(services) != 3 {
		t.Fatalf("read %d services", len(services))
	}
	web := services[0]
	if web.Service != "HTTP" || web.Host != "web1.example.test" {
		t.Fatalf("the principal was split into %q and %q", web.Service, web.Host)
	}
	if web.HasKeytab == nil || !*web.HasKeytab {
		t.Fatal("the keytab flag of the web service was not read")
	}
	if len(web.Aliases) != 1 || web.Aliases[0] != "HTTP/www.example.test@EXAMPLE.TEST" {
		t.Fatalf("the aliases were read as %v", web.Aliases)
	}
	if services[1].HasKeytab == nil || *services[1].HasKeytab {
		t.Fatal("a service without a keytab was not read as such")
	}
	// A directory that did not say leaves the question open: nil, not
	// false. "Unknown" must never read as "no keytab".
	if services[2].HasKeytab != nil {
		t.Fatalf("a service the directory said nothing about got the flag %v", *services[2].HasKeytab)
	}
}

func TestGeneralizedTimeIsParsedAndAMissingValueIsNil(t *testing.T) {
	parsed := generalizedTime("20261231235959Z")
	if parsed == nil || parsed.Year() != 2026 || parsed.Month() != time.December || parsed.Hour() != 23 {
		t.Fatalf("the time was parsed as %v", parsed)
	}
	if generalizedTime("") != nil {
		t.Fatal("an empty value became a time; a missing expiration means never")
	}
	if generalizedTime("not a time") != nil {
		t.Fatal("rubbish became a time")
	}
	if GeneralizedTime(*parsed) != "20261231235959Z" {
		t.Fatalf("the round trip gave %s", GeneralizedTime(*parsed))
	}
	// The friendly view wraps a time in an object; the reader unwraps it.
	record := map[string]any{"krbpasswordexpiration": []any{map[string]any{"__datetime__": "20260101000000Z"}}}
	if got := first(record, "krbpasswordexpiration"); got != "20260101000000Z" {
		t.Fatalf("the wrapped time was read as %q", got)
	}
}

func TestPreservedUsersAreReadApartAndMarked(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["user_find"] = func(call rpcCall) (any, *rpcError) {
		if preserved, _ := call.Options["preserved"].(bool); preserved {
			return map[string]any{"result": []any{map[string]any{"uid": []any{"gone"}}}, "count": 1}, nil
		}
		return map[string]any{"result": []any{map[string]any{"uid": []any{"jane"}}}, "count": 1}, nil
	}
	live, err := client.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := client.PreservedUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].UID != "jane" || live[0].Preserved {
		t.Fatalf("the live accounts were read as %+v", live)
	}
	if len(preserved) != 1 || preserved[0].UID != "gone" || !preserved[0].Preserved {
		t.Fatalf("the preserved accounts were read as %+v", preserved)
	}
}

func TestHealthReportsTheCallsWithoutAskingTheDirectory(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["user_find"] = func(rpcCall) (any, *rpcError) {
		return map[string]any{"result": []any{map[string]any{"uid": []any{"jane"}}}, "count": 1}, nil
	}
	before := client.Health()
	if before.LastSuccessAt != nil || before.LastErrorAt != nil || before.CacheEntries != 0 {
		t.Fatalf("a fresh client reports %+v", before)
	}
	if _, err := client.Users(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := client.Health()
	if after.LastSuccessAt == nil {
		t.Fatal("a successful call left no trace")
	}
	if after.CacheEntries != 1 || after.CacheOldestAt == nil {
		t.Fatalf("the cache is reported as %d entries, oldest %v", after.CacheEntries, after.CacheOldestAt)
	}
	// A refusal is an answer of a reachable directory: it is recorded as a
	// refusal and does not count as an outage.
	fake.answers["user_show"] = notFound
	if _, err := client.ShowUser(context.Background(), "nobody"); err == nil {
		t.Fatal("a NotFound answer passed")
	}
	refused := client.Health()
	if refused.LastRefusalAt == nil || !strings.Contains(refused.LastRefusal, "NotFound") {
		t.Fatalf("the refusal was recorded as %+v", refused)
	}
	if refused.LastErrorAt != nil {
		t.Fatal("a refusal was counted as an outage")
	}
	if refused.KeytabReadable {
		t.Fatal("a client without a keytab reports a readable keytab")
	}
	if fake.count("ping") != 0 {
		t.Fatal("the health view asked the directory")
	}
}
