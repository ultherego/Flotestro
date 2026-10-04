package freeipa

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// sudoDirectory holds one sudo rule the way the directory does: the state
// answers the reads, and every command changes it. One command can be made to
// fail, so that a change can be interrupted at a chosen step.
type sudoDirectory struct {
	present     bool
	name        string
	description string
	enabled     bool
	// members is keyed by the command and the member kind: the directory tells a
	// run-as account from a member account by the command, not by the key.
	members    map[string][]string
	options    []string
	categories map[string]bool
	// failMethod and failNth name the command that fails: the nth call of it, or
	// every call when failNth is zero.
	failMethod string
	failNth    int
	// dropped is a member the directory keeps out of the rule while reporting
	// the command that added it as a success.
	dropped string
	seen    map[string]int
	// inService is the rule after every command that left it enabled.
	inService []string
}

// sudoRecordFields maps a member key to the field a read answers with.
var sudoRecordFields = map[string]string{
	"user:user": "memberuser_user", "user:group": "memberuser_group",
	"host:host": "memberhost_host", "host:hostgroup": "memberhost_hostgroup",
	"allow_command:sudocmd":      "memberallowcmd_sudocmd",
	"allow_command:sudocmdgroup": "memberallowcmd_sudocmdgroup",
	"runasuser:user":             "ipasudorunas_user", "runasgroup:group": "ipasudorunasgroup_group",
}

func newSudoDirectory(t *testing.T, rule *SudoRule) (*fakeDirectory, *Client, *sudoDirectory) {
	t.Helper()
	fake, client := newFakeDirectory(t)
	store := &sudoDirectory{
		members: map[string][]string{}, categories: map[string]bool{}, seen: map[string]int{},
	}
	if rule != nil {
		store.present, store.name, store.description, store.enabled = true, rule.Name, rule.Description, rule.Enabled
		store.members["user:user"] = rule.Users
		store.members["user:group"] = rule.UserGroups
		store.members["host:host"] = rule.Hosts
		store.members["host:hostgroup"] = rule.HostGroups
		store.members["allow_command:sudocmd"] = rule.Commands
		store.members["allow_command:sudocmdgroup"] = rule.CommandGroups
		store.members["runasuser:user"] = rule.RunAs
		store.members["runasgroup:group"] = rule.RunAsGroups
		store.options = rule.Options
		store.categories["usercategory"] = rule.AllUsers
		store.categories["hostcategory"] = rule.AllHosts
		store.categories["cmdcategory"] = rule.AllCommands
		store.categories["ipasudorunasusercategory"] = rule.RunAsAnyUser
	}
	handlers := map[string]func(rpcCall) (any, *rpcError){
		"sudorule_show":                 store.show,
		"sudorule_add":                  store.add,
		"sudorule_del":                  store.remove,
		"sudorule_mod":                  store.modify,
		"sudorule_enable":               store.switchTo(true),
		"sudorule_disable":              store.switchTo(false),
		"sudorule_add_option":           store.changeOption(true),
		"sudorule_remove_option":        store.changeOption(false),
		"sudorule_add_user":             store.changeMembers(true),
		"sudorule_add_host":             store.changeMembers(true),
		"sudorule_add_allow_command":    store.changeMembers(true),
		"sudorule_add_runasuser":        store.changeMembers(true),
		"sudorule_add_runasgroup":       store.changeMembers(true),
		"sudorule_remove_user":          store.changeMembers(false),
		"sudorule_remove_host":          store.changeMembers(false),
		"sudorule_remove_allow_command": store.changeMembers(false),
		"sudorule_remove_runasuser":     store.changeMembers(false),
		"sudorule_remove_runasgroup":    store.changeMembers(false),
	}
	for method, handler := range handlers {
		fake.answers[method] = store.guard(method, handler)
	}
	return fake, client, store
}

// guard lets every command through but the one the test interrupts.
func (s *sudoDirectory) guard(method string, handler func(rpcCall) (any, *rpcError)) func(rpcCall) (any, *rpcError) {
	return func(call rpcCall) (any, *rpcError) {
		s.seen[method]++
		if method == s.failMethod && (s.failNth == 0 || s.seen[method] == s.failNth) {
			return nil, &rpcError{Code: 4203, Name: "ExecutionError", Message: "the directory refused " + method}
		}
		answer, failure := handler(call)
		if s.present && s.enabled {
			s.inService = append(s.inService, s.state())
		}
		return answer, failure
	}
}

func (s *sudoDirectory) show(call rpcCall) (any, *rpcError) {
	if !s.present {
		return notFound(call)
	}
	return map[string]any{"result": s.record()}, nil
}

func (s *sudoDirectory) add(call rpcCall) (any, *rpcError) {
	if s.present {
		return nil, &rpcError{Code: 4002, Name: "DuplicateEntry", Message: "rule: already exists"}
	}
	description, _ := call.Options["description"].(string)
	// The directory creates a sudo rule enabled.
	s.present, s.name, s.description, s.enabled = true, call.Args[0], description, true
	return map[string]any{"result": s.record()}, nil
}

func (s *sudoDirectory) remove(call rpcCall) (any, *rpcError) {
	if !s.present {
		return notFound(call)
	}
	s.present, s.enabled = false, false
	s.members, s.options, s.categories = map[string][]string{}, nil, map[string]bool{}
	return map[string]any{"result": map[string]any{}}, nil
}

func (s *sudoDirectory) modify(call rpcCall) (any, *rpcError) {
	if !s.present {
		return notFound(call)
	}
	if value, present := call.Options["description"]; present {
		text, _ := value.(string)
		s.description = text
	}
	for category := range sudoCategoryFields {
		if value, present := call.Options[category]; present {
			s.categories[category] = value == "all"
		}
	}
	return map[string]any{"result": s.record()}, nil
}

func (s *sudoDirectory) switchTo(enabled bool) func(rpcCall) (any, *rpcError) {
	return func(call rpcCall) (any, *rpcError) {
		if !s.present {
			return notFound(call)
		}
		s.enabled = enabled
		return map[string]any{"result": true}, nil
	}
}

func (s *sudoDirectory) changeMembers(add bool) func(rpcCall) (any, *rpcError) {
	return func(call rpcCall) (any, *rpcError) {
		if !s.present {
			return notFound(call)
		}
		for key := range sudoRecordFields {
			command, kind, _ := strings.Cut(key, ":")
			if !strings.HasSuffix(call.Method, "_"+command) {
				continue
			}
			for _, name := range optionStrings(call, kind) {
				held := s.members[key]
				if add {
					if !slices.Contains(held, name) && name != s.dropped {
						held = append(held, name)
					}
				} else {
					held = slices.DeleteFunc(held, func(member string) bool { return member == name })
				}
				s.members[key] = held
			}
		}
		return map[string]any{"result": map[string]any{}}, nil
	}
}

func (s *sudoDirectory) changeOption(add bool) func(rpcCall) (any, *rpcError) {
	return func(call rpcCall) (any, *rpcError) {
		if !s.present {
			return notFound(call)
		}
		option, _ := call.Options["ipasudoopt"].(string)
		if add {
			if !slices.Contains(s.options, option) {
				s.options = append(s.options, option)
			}
		} else {
			s.options = slices.DeleteFunc(s.options, func(held string) bool { return held == option })
		}
		return map[string]any{"result": map[string]any{}}, nil
	}
}

// sudoCategoryFields are the categories of a sudo rule.
var sudoCategoryFields = map[string]string{
	"usercategory": "user", "hostcategory": "host",
	"cmdcategory": "command", "ipasudorunasusercategory": "run-as account",
}

// record is the rule as the directory answers a read.
func (s *sudoDirectory) record() map[string]any {
	record := map[string]any{"cn": []any{s.name}, "ipaenabledflag": []any{s.enabled}}
	if s.description != "" {
		record["description"] = []any{s.description}
	}
	lists := map[string][]string{"ipasudoopt": s.options}
	for key, field := range sudoRecordFields {
		lists[field] = s.members[key]
	}
	for field, names := range lists {
		if len(names) == 0 {
			continue
		}
		values := make([]any, 0, len(names))
		for _, name := range names {
			values = append(values, name)
		}
		record[field] = values
	}
	for category, all := range s.categories {
		if all {
			record[category] = []any{"all"}
		}
	}
	return record
}

// state is the rule as a comparable text, so that two states can be held
// against each other without caring about the order of the members.
func (s *sudoDirectory) state() string {
	if !s.present {
		return "no rule"
	}
	sorted := func(names []string) string {
		copied := slices.Clone(names)
		slices.Sort(copied)
		return strings.Join(copied, ",")
	}
	keys := make([]string, 0, len(sudoRecordFields))
	for key := range sudoRecordFields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	parts := []string{fmt.Sprintf("enabled=%t description=%q options=[%s]",
		s.enabled, s.description, sorted(s.options))}
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=[%s]", key, sorted(s.members[key])))
	}
	categories := make([]string, 0, len(s.categories))
	for category := range sudoCategoryFields {
		categories = append(categories, fmt.Sprintf("%s=%t", category, s.categories[category]))
	}
	slices.Sort(categories)
	return strings.Join(append(parts, categories...), " ")
}

// theSudoRuleToChange is the rule the interruption tests start from: in service,
// with members of every kind, an option and one category.
func theSudoRuleToChange() *SudoRule {
	return &SudoRule{
		Name: "ops-restart", Description: "operators", Enabled: true,
		Users: []string{"alice", "bob"}, UserGroups: []string{"ops"}, AllHosts: true,
		Commands: []string{"/usr/bin/systemctl"}, RunAs: []string{"root", "deploy"},
		Options: []string{"!authenticate"},
	}
}

// theSudoDeclaration changes the description, every kind of member, the options
// and both categories, so that an interruption has a step of each kind to fall
// on.
func theSudoDeclaration() SudoRuleSpec {
	return SudoRuleSpec{
		Name: "ops-restart", Description: "operators and auditors", Enabled: true,
		Users: []string{"bob", "carol"}, UserGroups: []string{"audit"},
		Hosts: []string{"web1.flotestro.test"}, AllCommands: true,
		RunAsUsers: []string{"root", "backup"}, Options: []string{"!requiretty"},
	}
}

func TestANewSudoRuleIsCreatedDisabledAndEnabledLast(t *testing.T) {
	fake, client, store := newSudoDirectory(t, nil)
	rule, err := client.EnsureSudoRule(context.Background(), SudoRuleSpec{
		Name: "ops-restart", Description: "restarting services", Enabled: true,
		UserGroups: []string{"ops"}, AllHosts: true,
		Commands: []string{"/usr/bin/systemctl"}, RunAsUsers: []string{"root"},
		Options: []string{"!authenticate"},
	})
	if err != nil {
		t.Fatalf("EnsureSudoRule: %v", err)
	}
	if rule == nil || !rule.Enabled {
		t.Fatalf("the rule read back is %+v", rule)
	}
	methods := fake.methods()
	disabled := slices.Index(methods, "sudorule_disable")
	if created := slices.Index(methods, "sudorule_add"); disabled != created+1 {
		t.Fatalf("the new rule was not disabled right after it was created: %v", methods)
	}
	// Every member, command and option goes in while the rule is out of service,
	// and the flag comes last, after the read that confirms the state.
	enabled := slices.Index(methods, "sudorule_enable")
	for index, method := range methods {
		if !strings.Contains(method, "_add_") && !strings.Contains(method, "_remove_") {
			continue
		}
		if index < disabled || index > enabled {
			t.Fatalf("%s ran outside the disabled window: %v", method, methods)
		}
	}
	if reads := slices.Index(methods[disabled:], "sudorule_show"); reads < 0 || disabled+reads > enabled {
		t.Fatalf("the rule was enabled without being read back: %v", methods)
	}
	// The only state in service before the end is the rule as the directory
	// creates it: no member, no command, so it allows nothing.
	for _, snapshot := range store.inService {
		if snapshot != store.state() && !strings.Contains(snapshot, "allow_command:sudocmd=[]") {
			t.Fatalf("the rule was in service with a part of its commands: %s", snapshot)
		}
	}
}

func TestAnInterruptedSudoCreationLeavesNoRuleBehind(t *testing.T) {
	// One interruption per step of the change, in the order the steps run.
	steps := []struct {
		name   string
		method string
		nth    int
	}{
		{"after the rule is added", "sudorule_disable", 1},
		{"adding the user groups", "sudorule_add_user", 1},
		{"adding the commands", "sudorule_add_allow_command", 1},
		{"adding the run-as accounts", "sudorule_add_runasuser", 1},
		{"adding the options", "sudorule_add_option", 1},
		{"setting the categories", "sudorule_mod", 1},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			fake, client, store := newSudoDirectory(t, nil)
			store.failMethod, store.failNth = step.method, step.nth
			_, err := client.EnsureSudoRule(context.Background(), SudoRuleSpec{
				Name: "ops-restart", Enabled: true, UserGroups: []string{"ops"}, AllHosts: true,
				Commands: []string{"/usr/bin/systemctl"}, RunAsUsers: []string{"root"},
				Options: []string{"!authenticate"},
			})
			var change *RuleChangeError
			if !errors.As(err, &change) {
				t.Fatalf("the interrupted change ended as %v", err)
			}
			if change.Outcome != RuleWithdrawn {
				t.Fatalf("the outcome was %s (%v)", change.Outcome, err)
			}
			if store.present {
				t.Fatalf("the rule stayed in the directory as %s", store.state())
			}
			if slices.Contains(fake.methods(), "sudorule_enable") {
				t.Fatalf("the rule was enabled although the change failed: %v", fake.methods())
			}
		})
	}
}

func TestAnInterruptedSudoChangePutsThePreviousStateBack(t *testing.T) {
	steps := []struct {
		name   string
		method string
		nth    int
	}{
		{"taking the rule out of service", "sudorule_disable", 1},
		{"clearing the category", "sudorule_mod", 1},
		{"removing the users", "sudorule_remove_user", 1},
		{"removing the commands", "sudorule_remove_allow_command", 1},
		{"removing the run-as accounts", "sudorule_remove_runasuser", 1},
		{"adding the users", "sudorule_add_user", 1},
		{"adding the hosts", "sudorule_add_host", 1},
		{"adding the run-as accounts", "sudorule_add_runasuser", 1},
		{"removing the options", "sudorule_remove_option", 1},
		{"adding the options", "sudorule_add_option", 1},
		{"setting the categories", "sudorule_mod", 2},
	}
	_, _, prior := newSudoDirectory(t, theSudoRuleToChange())
	before := prior.state()
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			_, client, store := newSudoDirectory(t, theSudoRuleToChange())
			store.failMethod, store.failNth = step.method, step.nth
			_, err := client.EnsureSudoRule(context.Background(), theSudoDeclaration())
			var change *RuleChangeError
			if !errors.As(err, &change) {
				t.Fatalf("the interrupted change ended as %v", err)
			}
			if change.Outcome != RuleRestored || change.Restore != nil {
				t.Fatalf("the outcome was %s: %v", change.Outcome, err)
			}
			if change.Step == "" {
				t.Fatal("the failure does not name the step that failed")
			}
			if got := store.state(); got != before {
				t.Fatalf("the rule stands as\n%s\nand stood as\n%s", got, before)
			}
			for _, snapshot := range store.inService {
				if snapshot != before {
					t.Fatalf("the rule was in service with a half-written state:\n%s", snapshot)
				}
			}
		})
	}
}

func TestASudoRuleThatReadsBackWrongIsNotEnabled(t *testing.T) {
	fake, client, store := newSudoDirectory(t, theSudoRuleToChange())
	// The directory answers the command that adds the run-as account with a
	// success and keeps the account out of the rule; only the read tells.
	store.dropped = "backup"
	_, _, prior := newSudoDirectory(t, theSudoRuleToChange())

	_, err := client.EnsureSudoRule(context.Background(), theSudoDeclaration())
	var change *RuleChangeError
	if !errors.As(err, &change) {
		t.Fatalf("the change passed as a success: %v", err)
	}
	if !strings.Contains(change.Step, "read back") {
		t.Fatalf("the failure names the step %q", change.Step)
	}
	if change.Outcome != RuleRestored {
		t.Fatalf("the outcome was %s: %v", change.Outcome, err)
	}
	if got := store.state(); got != prior.state() {
		t.Fatalf("the rule stands as\n%s\nand stood as\n%s", got, prior.state())
	}
	// The rule came back into service with the state it had before, and was
	// never in service with the half the declaration asked for.
	for _, snapshot := range store.inService {
		if snapshot != prior.state() {
			t.Fatalf("the rule was in service with\n%s", snapshot)
		}
	}
	if !slices.Contains(fake.methods(), "sudorule_disable") {
		t.Fatalf("the rule was never taken out of service: %v", fake.methods())
	}
}

func TestASudoRestoreThatFailsLeavesTheRuleDisabled(t *testing.T) {
	_, client, store := newSudoDirectory(t, theSudoRuleToChange())
	// The command that adds run-as accounts fails for the change and for the
	// restore alike: the previous accounts cannot go back.
	store.failMethod, store.failNth = "sudorule_add_runasuser", 0
	_, err := client.EnsureSudoRule(context.Background(), theSudoDeclaration())
	var change *RuleChangeError
	if !errors.As(err, &change) {
		t.Fatalf("the interrupted change ended as %v", err)
	}
	if change.Outcome != RuleRestoreFailed || change.Restore == nil {
		t.Fatalf("the outcome was %s with restore %v", change.Outcome, change.Restore)
	}
	if !store.present || store.enabled {
		t.Fatalf("the rule is %s, and it must stay out of service", store.state())
	}
	if !strings.Contains(err.Error(), "could not be put back") {
		t.Fatalf("the failure does not say the restore failed: %v", err)
	}
}
