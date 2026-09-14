package freeipa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDirectory stands in for the JSON-RPC endpoint of the directory. It
// records every command with its arguments and answers from a table, so a
// test checks what the adapter sends rather than what a directory would do.
type fakeDirectory struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex
	calls  []rpcCall
	// answers maps a method to a handler; a method without one succeeds
	// with an empty result.
	answers map[string]func(call rpcCall) (any, *rpcError)
}

type rpcCall struct {
	Method  string
	Args    []string
	Options map[string]any
}

func newFakeDirectory(t *testing.T) (*fakeDirectory, *Client) {
	t.Helper()
	fake := &fakeDirectory{t: t, answers: map[string]func(rpcCall) (any, *rpcError){}}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.handle))
	t.Cleanup(fake.server.Close)

	// The client is built by hand: the constructor needs a keytab and a
	// Kerberos configuration, and the session is marked as established so
	// no login is attempted against the fake.
	client := &Client{
		config:  Config{ServerURL: fake.server.URL, Principal: "flotestro/panel@TEST", CacheTTL: time.Minute},
		http:    fake.server.Client(),
		jsonURL: fake.server.URL + "/ipa/session/json",
		referer: fake.server.URL + "/ipa",
		cache:   map[string]cacheEntry{},
		logged:  true,
	}
	return fake, client
}

func (f *fakeDirectory) handle(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Params) != 2 {
		http.Error(w, "bad envelope", http.StatusBadRequest)
		return
	}
	call := rpcCall{Method: request.Method}
	_ = json.Unmarshal(request.Params[0], &call.Args)
	_ = json.Unmarshal(request.Params[1], &call.Options)

	f.mu.Lock()
	f.calls = append(f.calls, call)
	answer := f.answers[call.Method]
	f.mu.Unlock()

	var result any = map[string]any{"result": map[string]any{}}
	var failure *rpcError
	if answer != nil {
		result, failure = answer(call)
	}
	encoded, _ := json.Marshal(map[string]any{"result": result, "error": failure})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encoded)
}

// methods lists the commands sent so far, in order.
func (f *fakeDirectory) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.calls))
	for _, call := range f.calls {
		names = append(names, call.Method)
	}
	return names
}

// find returns the first call of a method.
func (f *fakeDirectory) find(method string) (rpcCall, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, call := range f.calls {
		if call.Method == method {
			return call, true
		}
	}
	return rpcCall{}, false
}

func (f *fakeDirectory) count(method string) int {
	return len(slices.DeleteFunc(f.methods(), func(name string) bool { return name != method }))
}

func notFound(rpcCall) (any, *rpcError) {
	return nil, &rpcError{Code: 4001, Name: "NotFound", Message: "rule: rule not found"}
}

func answerWith(fields map[string]any) func(rpcCall) (any, *rpcError) {
	return func(rpcCall) (any, *rpcError) {
		return map[string]any{"result": fields}, nil
	}
}

func optionStrings(call rpcCall, key string) []string {
	values, _ := call.Options[key].([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.(string))
	}
	return result
}

func TestEnsureHBACRuleCreatesAMissingRuleAndFillsIt(t *testing.T) {
	fake, client := newFakeDirectory(t)
	// The first read finds nothing; the read after the write sees the rule.
	shown := 0
	fake.answers["hbacrule_show"] = func(call rpcCall) (any, *rpcError) {
		shown++
		if shown == 1 {
			return notFound(call)
		}
		return answerWith(map[string]any{
			"cn": []any{"ops-ssh"}, "ipaenabledflag": []any{false},
			"memberuser_group": []any{"ops"}, "memberhost_hostgroup": []any{"web"},
			"memberservice_hbacsvc": []any{"sshd"},
		})(call)
	}

	rule, err := client.EnsureHBACRule(context.Background(), HBACRuleSpec{
		Name: "ops-ssh", Description: "operators on the web tier", Enabled: false,
		UserGroups: []string{"ops"}, HostGroups: []string{"web"}, Services: []string{"sshd"},
	})
	if err != nil {
		t.Fatalf("EnsureHBACRule: %v", err)
	}
	if rule == nil || rule.Name != "ops-ssh" || rule.Enabled {
		t.Fatalf("the rule read back is %+v", rule)
	}

	want := []string{"hbacrule_show", "hbacrule_add", "hbacrule_add_user", "hbacrule_add_host",
		"hbacrule_add_service", "hbacrule_disable", "hbacrule_show"}
	if got := fake.methods(); !slices.Equal(got, want) {
		t.Fatalf("the commands were %v, expected %v", got, want)
	}
	added, _ := fake.find("hbacrule_add")
	if added.Args[0] != "ops-ssh" || added.Options["description"] != "operators on the web tier" {
		t.Fatalf("hbacrule_add was sent as %+v", added)
	}
	hosts, _ := fake.find("hbacrule_add_host")
	if got := optionStrings(hosts, "hostgroup"); !slices.Equal(got, []string{"web"}) {
		t.Fatalf("the host groups were sent as %v", got)
	}
	if _, present := hosts.Options["host"]; present {
		t.Fatal("an empty member kind was sent to the directory")
	}
}

func TestEnsureHBACRuleReachesTheDeclaredMembers(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["hbacrule_show"] = answerWith(map[string]any{
		"cn": []any{"ops-ssh"}, "ipaenabledflag": []any{true}, "description": []any{"old"},
		"memberuser_user": []any{"alice", "bob"}, "hostcategory": []any{"all"},
		"memberservice_hbacsvc": []any{"sshd"},
	})

	_, err := client.EnsureHBACRule(context.Background(), HBACRuleSpec{
		Name: "ops-ssh", Description: "new", Enabled: true,
		Users: []string{"bob", "carol"}, Hosts: []string{"web1.flotestro.test"},
		Services: []string{"sshd"},
	})
	if err != nil {
		t.Fatalf("EnsureHBACRule: %v", err)
	}

	// The category has to be cleared before a host can be added: the
	// directory refuses a member next to a category of the same kind.
	methods := fake.methods()
	modAt := slices.Index(methods, "hbacrule_mod")
	addHostAt := slices.Index(methods, "hbacrule_add_host")
	if modAt < 0 || addHostAt < 0 || modAt > addHostAt {
		t.Fatalf("the category was not cleared before adding hosts: %v", methods)
	}
	mod, _ := fake.find("hbacrule_mod")
	if value, present := mod.Options["hostcategory"]; !present || value != nil {
		t.Fatalf("hbacrule_mod did not clear the host category: %+v", mod.Options)
	}
	if mod.Options["description"] != "new" {
		t.Fatalf("hbacrule_mod did not change the description: %+v", mod.Options)
	}

	removed, _ := fake.find("hbacrule_remove_user")
	if got := optionStrings(removed, "user"); !slices.Equal(got, []string{"alice"}) {
		t.Fatalf("removed %v, expected alice alone", got)
	}
	added, _ := fake.find("hbacrule_add_user")
	if got := optionStrings(added, "user"); !slices.Equal(got, []string{"carol"}) {
		t.Fatalf("added %v, expected carol alone", got)
	}
	// Services did not change and the rule stays enabled: no command for either.
	for _, method := range []string{"hbacrule_add_service", "hbacrule_remove_service",
		"hbacrule_enable", "hbacrule_disable", "hbacrule_add"} {
		if slices.Contains(methods, method) {
			t.Errorf("%s was sent although nothing changed there", method)
		}
	}
}

func TestEnsureHBACRuleSetsACategoryAfterRemovingMembers(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["hbacrule_show"] = answerWith(map[string]any{
		"cn": []any{"everyone"}, "ipaenabledflag": []any{true},
		"memberhost_host": []any{"web1.flotestro.test"},
	})
	_, err := client.EnsureHBACRule(context.Background(), HBACRuleSpec{
		Name: "everyone", Enabled: true, AllHosts: true, AllUsers: true, AllServices: true,
	})
	if err != nil {
		t.Fatalf("EnsureHBACRule: %v", err)
	}
	methods := fake.methods()
	removeAt := slices.Index(methods, "hbacrule_remove_host")
	modAt := slices.Index(methods, "hbacrule_mod")
	if removeAt < 0 || modAt < removeAt {
		t.Fatalf("the members were not removed before the category was set: %v", methods)
	}
	mod, _ := fake.find("hbacrule_mod")
	for _, category := range []string{"usercategory", "hostcategory", "servicecategory"} {
		if mod.Options[category] != "all" {
			t.Errorf("%s = %v, expected all", category, mod.Options[category])
		}
	}
}

func TestAPartialMembershipFailureIsNotASuccess(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["hbacrule_show"] = answerWith(map[string]any{"cn": []any{"r"}, "ipaenabledflag": []any{true}})
	fake.answers["hbacrule_add_user"] = func(rpcCall) (any, *rpcError) {
		return map[string]any{
			"completed": 1,
			"failed": map[string]any{"memberuser": map[string]any{
				"user": []any{[]any{"ghost", "no such entry"}},
			}},
		}, nil
	}
	_, err := client.EnsureHBACRule(context.Background(), HBACRuleSpec{
		Name: "r", Enabled: true, Users: []string{"alice", "ghost"},
	})
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("a partial failure passed as success: %v", err)
	}
}

func TestEnsureSudoRuleWritesEveryMemberKind(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["sudorule_show"] = answerWith(map[string]any{
		"cn": []any{"ops-restart"}, "ipaenabledflag": []any{true}, "ipasudoopt": []any{"!authenticate"},
		"memberallowcmd_sudocmd": []any{"/usr/bin/systemctl"},
	})
	_, err := client.EnsureSudoRule(context.Background(), SudoRuleSpec{
		Name: "ops-restart", Enabled: true,
		UserGroups: []string{"ops"}, HostGroups: []string{"web"},
		Commands:   []string{"/usr/bin/systemctl", "/usr/bin/journalctl"},
		RunAsUsers: []string{"root"}, Options: []string{"!requiretty"},
	})
	if err != nil {
		t.Fatalf("EnsureSudoRule: %v", err)
	}
	methods := fake.methods()
	for _, method := range []string{"sudorule_add_user", "sudorule_add_host",
		"sudorule_add_allow_command", "sudorule_add_runasuser",
		"sudorule_remove_option", "sudorule_add_option"} {
		if !slices.Contains(methods, method) {
			t.Errorf("%s was not sent: %v", method, methods)
		}
	}
	commands, _ := fake.find("sudorule_add_allow_command")
	if got := optionStrings(commands, "sudocmd"); !slices.Equal(got, []string{"/usr/bin/journalctl"}) {
		t.Fatalf("the commands added were %v", got)
	}
	// The directory takes one option per call, as a plain string.
	removed, _ := fake.find("sudorule_remove_option")
	if removed.Options["ipasudoopt"] != "!authenticate" {
		t.Fatalf("the option removed was %v", removed.Options["ipasudoopt"])
	}
	added, _ := fake.find("sudorule_add_option")
	if added.Options["ipasudoopt"] != "!requiretty" {
		t.Fatalf("the option added was %v", added.Options["ipasudoopt"])
	}
	if slices.Contains(methods, "sudorule_add") || slices.Contains(methods, "sudorule_mod") {
		t.Errorf("the entry itself was rewritten although nothing changed there: %v", methods)
	}
}

func TestRemovingAMissingRuleIsNotAnError(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["sudorule_del"] = notFound
	if err := client.RemoveSudoRule(context.Background(), "gone"); err != nil {
		t.Fatalf("removing a rule that does not exist failed: %v", err)
	}
	if fake.count("sudorule_del") != 1 {
		t.Fatal("sudorule_del was not sent")
	}
	if err := client.RemoveHBACRule(context.Background(), "bad name!"); err == nil {
		t.Fatal("an invalid rule name reached the directory")
	}
}

func TestWritingARuleInvalidatesTheCache(t *testing.T) {
	fake, client := newFakeDirectory(t)
	reads := 0
	fake.answers["hbacrule_find"] = func(rpcCall) (any, *rpcError) {
		reads++
		return map[string]any{"result": []any{}, "count": 0, "truncated": false}, nil
	}
	fake.answers["hbacrule_show"] = answerWith(map[string]any{"cn": []any{"r"}, "ipaenabledflag": []any{true}})

	ctx := context.Background()
	if _, err := client.HBACRules(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HBACRules(ctx); err != nil {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Fatalf("the second read went to the directory (%d reads)", reads)
	}
	if err := client.RemoveHBACRule(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HBACRules(ctx); err != nil {
		t.Fatal(err)
	}
	if reads != 2 {
		t.Fatalf("the read after a write did not reach the directory (%d reads)", reads)
	}
}

func TestHBACTestParsesTheVerdict(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["hbactest"] = func(call rpcCall) (any, *rpcError) {
		if call.Options["user"] != "alice" || call.Options["targethost"] != "web1.flotestro.test" ||
			call.Options["service"] != "sshd" {
			return nil, &rpcError{Name: "ValidationError", Message: "unexpected parameters"}
		}
		return map[string]any{
			"value":      true,
			"matched":    []any{"ops-ssh"},
			"notmatched": []any{"admins-console", map[string]any{"cn": []any{"detailed"}}},
			"error":      []any{"missing-rule"},
			"warning":    []any{"a remark of the directory"},
			"summary":    nil,
		}, nil
	}
	result, err := client.HBACTest(context.Background(), "alice", "web1.flotestro.test", "sshd")
	if err != nil {
		t.Fatalf("HBACTest: %v", err)
	}
	if !result.Allowed {
		t.Fatal("the verdict was read as denied")
	}
	if !slices.Equal(result.Matched, []string{"ops-ssh"}) {
		t.Fatalf("matched = %v", result.Matched)
	}
	if !slices.Equal(result.NotMatched, []string{"admins-console", "detailed"}) {
		t.Fatalf("not matched = %v", result.NotMatched)
	}
	if !slices.Equal(result.Errors, []string{"missing-rule"}) || len(result.Warnings) != 1 {
		t.Fatalf("errors = %v, warnings = %v", result.Errors, result.Warnings)
	}
}

func TestHBACTestRejectsBadNamesBeforeTheDirectory(t *testing.T) {
	fake, client := newFakeDirectory(t)
	_, err := client.HBACTest(context.Background(), "alice; drop", "web1.flotestro.test", "sshd")
	if err == nil {
		t.Fatal("an invalid account name was accepted")
	}
	if len(fake.methods()) != 0 {
		t.Fatal("the invalid name reached the directory")
	}
}

func TestRuleSpecValidation(t *testing.T) {
	good := HBACRuleSpec{Name: "ops-ssh", Users: []string{"alice"}, HostGroups: []string{"web"},
		Services: []string{"sshd"}}
	if err := good.Validate(); err != nil {
		t.Fatalf("a valid rule was rejected: %v", err)
	}
	badHBAC := map[string]HBACRuleSpec{
		"a name with a space":        {Name: "ops ssh"},
		"a name too long":            {Name: strings.Repeat("a", 65)},
		"a member with a semicolon":  {Name: "r", Users: []string{"alice;"}},
		"a host without a domain":    {Name: "r", Hosts: []string{"web1"}},
		"a category next to members": {Name: "r", AllHosts: true, Hosts: []string{"web1.flotestro.test"}},
	}
	for name, spec := range badHBAC {
		t.Run(name, func(t *testing.T) {
			if err := spec.Validate(); err == nil {
				t.Fatal("an invalid rule passed validation")
			}
		})
	}

	goodSudo := SudoRuleSpec{Name: "ops", UserGroups: []string{"ops"}, AllHosts: true,
		Commands: []string{"/usr/bin/systemctl restart nginx"}, RunAsUsers: []string{"root"},
		Options: []string{"!authenticate", "env_keep=EDITOR", "requiretty"}}
	if err := goodSudo.Validate(); err != nil {
		t.Fatalf("a valid sudo rule was rejected: %v", err)
	}
	badSudo := map[string]SudoRuleSpec{
		"a relative command":       {Name: "r", Commands: []string{"systemctl"}},
		"an unknown option":        {Name: "r", Options: []string{"nopasswd_please"}},
		"the sudoers NOPASSWD tag": {Name: "r", Options: []string{"NOPASSWD"}},
		"run-as next to any user":  {Name: "r", RunAsAnyUser: true, RunAsUsers: []string{"root"}},
	}
	for name, spec := range badSudo {
		t.Run(name, func(t *testing.T) {
			if err := spec.Validate(); err == nil {
				t.Fatal("an invalid sudo rule passed validation")
			}
		})
	}
}

func TestTheRuleCommandsAreOnTheAllowedList(t *testing.T) {
	for _, method := range []string{"hbacrule_add", "hbacrule_mod", "hbacrule_del",
		"hbacrule_add_user", "hbacrule_remove_host", "hbacrule_add_service", "hbacrule_enable",
		"sudorule_add", "sudorule_add_allow_command", "sudorule_add_runasuser",
		"sudorule_add_option", "sudorule_remove_option", "hbactest", "hostgroup_find"} {
		if !allowedMethod(method) {
			t.Errorf("the command %s is not allowed", method)
		}
	}
	// The objects a rule names - services, commands, host groups - are not
	// created from the panel: a rule refers to what the directory already has.
	for _, method := range []string{"hbacsvc_add", "sudocmd_add", "hostgroup_add",
		"sudorule_add_deny_command", "hbacrule_add_sourcehost"} {
		if allowedMethod(method) {
			t.Errorf("the command %s should not be allowed", method)
		}
	}
}

func TestDiffIgnoresOrderAndDuplicates(t *testing.T) {
	result := diff([]string{"a", "b", "b"}, []string{"b", "c", "c", "a"})
	if !slices.Equal(result.added, []string{"c"}) || len(result.removed) != 0 {
		t.Fatalf("diff = %+v", result)
	}
}

// TestHBACTestParsesADenial mirrors the verdict test for the answer that
// matters most to an operator: "no". A denial has to come back as denied
// with the rules that were evaluated and did not match, so the screen can
// say why - not as an empty success.
func TestHBACTestParsesADenial(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["hbactest"] = func(call rpcCall) (any, *rpcError) {
		if call.Options["user"] != "bob" || call.Options["targethost"] != "web1.flotestro.test" ||
			call.Options["service"] != "sshd" {
			return nil, &rpcError{Name: "ValidationError", Message: "unexpected parameters"}
		}
		return map[string]any{
			"value":      false,
			"matched":    []any{},
			"notmatched": []any{"ops-ssh", map[string]any{"cn": []any{"admins-console"}}},
			"error":      []any{},
			"warning":    []any{},
			"summary":    "Access denied",
		}, nil
	}
	result, err := client.HBACTest(context.Background(), "bob", "web1.flotestro.test", "sshd")
	if err != nil {
		t.Fatalf("HBACTest: %v", err)
	}
	if result.Allowed {
		t.Fatal("a denial was read as allowed")
	}
	if result.User != "bob" || result.Host != "web1.flotestro.test" || result.Service != "sshd" {
		t.Fatalf("the verdict answers for %+v", result)
	}
	// The reason of a denial is the list of rules that did not match; an
	// absent list would read as "no rules at all" on the screen.
	if result.Matched == nil || len(result.Matched) != 0 {
		t.Fatalf("matched = %v, expected an empty list", result.Matched)
	}
	if !slices.Equal(result.NotMatched, []string{"ops-ssh", "admins-console"}) {
		t.Fatalf("not matched = %v", result.NotMatched)
	}
	if len(result.Errors) != 0 || len(result.Warnings) != 0 {
		t.Fatalf("errors = %v, warnings = %v", result.Errors, result.Warnings)
	}
}

// TestEnsureSudoRuleNeverEmitsACategoryForNamedMembers guards the boundary
// between a rule for named hosts and commands and a rule for everything. A
// category of "all" next to named members is the widest rule the directory
// can hold, and it would arrive silently: the members would still be listed
// and the screen would look narrow. So a spec with names must never send a
// category, and a spec that narrows an ALL rule down to names must clear
// the category before the names go in.
func TestEnsureSudoRuleNeverEmitsACategoryForNamedMembers(t *testing.T) {
	t.Run("a new rule with names", func(t *testing.T) {
		fake, client := newFakeDirectory(t)
		fake.answers["sudorule_show"] = func(call rpcCall) (any, *rpcError) {
			if fake.count("sudorule_add") == 0 {
				return notFound(call)
			}
			return map[string]any{"result": map[string]any{
				"cn": []any{"ops-restart"}, "ipaenabledflag": []any{true},
				"memberhost_host":        []any{"web1.flotestro.test"},
				"memberallowcmd_sudocmd": []any{"/usr/bin/systemctl"},
			}}, nil
		}
		_, err := client.EnsureSudoRule(context.Background(), SudoRuleSpec{
			Name: "ops-restart", Enabled: true, UserGroups: []string{"ops"},
			Hosts: []string{"web1.flotestro.test"}, Commands: []string{"/usr/bin/systemctl"},
		})
		if err != nil {
			t.Fatalf("EnsureSudoRule: %v", err)
		}
		assertNoAllCategory(t, fake)
		if _, sent := fake.find("sudorule_mod"); sent {
			t.Fatalf("a rule of named members modified the entry itself: %v", fake.methods())
		}
	})

	t.Run("an ALL rule narrowed to names", func(t *testing.T) {
		fake, client := newFakeDirectory(t)
		// The directory holds the widest shape: every host, every command.
		fake.answers["sudorule_show"] = answerWith(map[string]any{
			"cn": []any{"ops-restart"}, "ipaenabledflag": []any{true},
			"hostcategory": []any{"all"}, "cmdcategory": []any{"all"},
			"memberuser_group": []any{"ops"},
		})
		_, err := client.EnsureSudoRule(context.Background(), SudoRuleSpec{
			Name: "ops-restart", Enabled: true, UserGroups: []string{"ops"},
			Hosts: []string{"web1.flotestro.test"}, Commands: []string{"/usr/bin/systemctl"},
		})
		if err != nil {
			t.Fatalf("EnsureSudoRule: %v", err)
		}
		assertNoAllCategory(t, fake)

		mod, sent := fake.find("sudorule_mod")
		if !sent {
			t.Fatalf("the categories were not cleared: %v", fake.methods())
		}
		for _, category := range []string{"hostcategory", "cmdcategory"} {
			value, present := mod.Options[category]
			if !present || value != nil {
				t.Errorf("%s was not cleared: present=%v value=%v", category, present, value)
			}
		}
		// The user category was never set and must not be touched: clearing
		// what is clear would be an EmptyModError on some directory versions.
		if _, present := mod.Options["usercategory"]; present {
			t.Errorf("usercategory was sent although the rule never had it: %v", mod.Options)
		}

		// A category and members of the same kind exclude each other, so the
		// clearing has to precede the members.
		methods := fake.methods()
		modAt := slices.Index(methods, "sudorule_mod")
		hostAt := slices.Index(methods, "sudorule_add_host")
		commandAt := slices.Index(methods, "sudorule_add_allow_command")
		if hostAt < 0 || commandAt < 0 || modAt > hostAt || modAt > commandAt {
			t.Fatalf("the members went in before the categories were cleared: %v", methods)
		}
	})
}

// assertNoAllCategory fails when any command sent to the directory sets a
// category to "all".
func assertNoAllCategory(t *testing.T, fake *fakeDirectory) {
	t.Helper()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, call := range fake.calls {
		for _, category := range []string{"usercategory", "hostcategory", "cmdcategory",
			"ipasudorunasusercategory"} {
			if call.Options[category] == "all" {
				t.Fatalf("%s sent %s=all for a rule of named members: %v", call.Method, category, call.Options)
			}
		}
	}
}
