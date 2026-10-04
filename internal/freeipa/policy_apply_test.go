package freeipa

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// hbacDirectory holds one access rule the way the directory does: the state
// answers the reads, and every command changes it. One command can be made to
// fail, so that a change can be interrupted at a chosen step.
type hbacDirectory struct {
	rule *HBACRule
	// failMethod and failNth name the command that fails: the nth call of it,
	// or every call when failNth is zero.
	failMethod string
	failNth    int
	// dropped is an account the directory keeps out of the rule while reporting
	// the command that added it as a success.
	dropped string
	seen    map[string]int
	// enabledStates records the rule after every command that left it enabled.
	enabledStates []HBACRule
}

func newHBACDirectory(t *testing.T, rule *HBACRule) (*fakeDirectory, *Client, *hbacDirectory) {
	t.Helper()
	fake, client := newFakeDirectory(t)
	store := &hbacDirectory{rule: rule, seen: map[string]int{}}
	handlers := map[string]func(rpcCall) (any, *rpcError){
		"hbacrule_show":           store.show,
		"hbacrule_add":            store.add,
		"hbacrule_del":            store.remove,
		"hbacrule_mod":            store.modify,
		"hbacrule_enable":         store.switchTo(true),
		"hbacrule_disable":        store.switchTo(false),
		"hbacrule_add_user":       store.changeMembers(true),
		"hbacrule_add_host":       store.changeMembers(true),
		"hbacrule_add_service":    store.changeMembers(true),
		"hbacrule_remove_user":    store.changeMembers(false),
		"hbacrule_remove_host":    store.changeMembers(false),
		"hbacrule_remove_service": store.changeMembers(false),
	}
	for method, handler := range handlers {
		fake.answers[method] = store.guard(method, handler)
	}
	return fake, client, store
}

// guard lets every command through but the one the test interrupts.
func (s *hbacDirectory) guard(method string, handler func(rpcCall) (any, *rpcError)) func(rpcCall) (any, *rpcError) {
	return func(call rpcCall) (any, *rpcError) {
		s.seen[method]++
		if method == s.failMethod && (s.failNth == 0 || s.seen[method] == s.failNth) {
			return nil, &rpcError{Code: 4203, Name: "ExecutionError", Message: "the directory refused " + method}
		}
		answer, failure := handler(call)
		if s.rule != nil && s.rule.Enabled {
			s.enabledStates = append(s.enabledStates, *s.rule)
		}
		return answer, failure
	}
}

func (s *hbacDirectory) show(call rpcCall) (any, *rpcError) {
	if s.rule == nil {
		return notFound(call)
	}
	return map[string]any{"result": s.record()}, nil
}

func (s *hbacDirectory) add(call rpcCall) (any, *rpcError) {
	if s.rule != nil {
		return nil, &rpcError{Code: 4002, Name: "DuplicateEntry", Message: "rule: already exists"}
	}
	description, _ := call.Options["description"].(string)
	// The directory creates an access rule enabled.
	s.rule = &HBACRule{Name: call.Args[0], Description: description, Enabled: true}
	return map[string]any{"result": s.record()}, nil
}

func (s *hbacDirectory) remove(call rpcCall) (any, *rpcError) {
	if s.rule == nil {
		return notFound(call)
	}
	s.rule = nil
	return map[string]any{"result": map[string]any{}}, nil
}

func (s *hbacDirectory) modify(call rpcCall) (any, *rpcError) {
	if s.rule == nil {
		return notFound(call)
	}
	if value, present := call.Options["description"]; present {
		text, _ := value.(string)
		s.rule.Description = text
	}
	categories := map[string]*bool{
		"usercategory": &s.rule.AllUsers, "hostcategory": &s.rule.AllHosts,
		"servicecategory": &s.rule.AllServices,
	}
	for key, flag := range categories {
		if value, present := call.Options[key]; present {
			*flag = value == "all"
		}
	}
	return map[string]any{"result": s.record()}, nil
}

func (s *hbacDirectory) switchTo(enabled bool) func(rpcCall) (any, *rpcError) {
	return func(call rpcCall) (any, *rpcError) {
		if s.rule == nil {
			return notFound(call)
		}
		s.rule.Enabled = enabled
		return map[string]any{"result": true}, nil
	}
}

func (s *hbacDirectory) changeMembers(add bool) func(rpcCall) (any, *rpcError) {
	return func(call rpcCall) (any, *rpcError) {
		if s.rule == nil {
			return notFound(call)
		}
		for key, members := range s.memberFields() {
			for _, name := range optionStrings(call, key) {
				if add {
					if !slices.Contains(*members, name) {
						*members = append(*members, name)
					}
					continue
				}
				*members = slices.DeleteFunc(*members, func(held string) bool { return held == name })
			}
			if add && s.dropped != "" {
				*members = slices.DeleteFunc(*members, func(held string) bool { return held == s.dropped })
			}
		}
		return map[string]any{"result": map[string]any{}}, nil
	}
}

func (s *hbacDirectory) memberFields() map[string]*[]string {
	return map[string]*[]string{
		"user": &s.rule.Users, "group": &s.rule.UserGroups,
		"host": &s.rule.Hosts, "hostgroup": &s.rule.HostGroups,
		"hbacsvc": &s.rule.Services, "hbacsvcgroup": &s.rule.ServiceGroups,
	}
}

// record is the rule as the directory answers a read.
func (s *hbacDirectory) record() map[string]any {
	record := map[string]any{"cn": []any{s.rule.Name}, "ipaenabledflag": []any{s.rule.Enabled}}
	if s.rule.Description != "" {
		record["description"] = []any{s.rule.Description}
	}
	lists := map[string][]string{
		"memberuser_user": s.rule.Users, "memberuser_group": s.rule.UserGroups,
		"memberhost_host": s.rule.Hosts, "memberhost_hostgroup": s.rule.HostGroups,
		"memberservice_hbacsvc": s.rule.Services, "memberservice_hbacsvcgroup": s.rule.ServiceGroups,
	}
	for key, names := range lists {
		if len(names) == 0 {
			continue
		}
		values := make([]any, 0, len(names))
		for _, name := range names {
			values = append(values, name)
		}
		record[key] = values
	}
	categories := map[string]bool{
		"usercategory": s.rule.AllUsers, "hostcategory": s.rule.AllHosts,
		"servicecategory": s.rule.AllServices,
	}
	for key, all := range categories {
		if all {
			record[key] = []any{"all"}
		}
	}
	return record
}

// state is the rule as a comparable text, so that two states can be held
// against each other without caring about the order of the members.
func state(rule *HBACRule) string {
	if rule == nil {
		return "no rule"
	}
	sorted := func(names []string) string {
		copied := slices.Clone(names)
		slices.Sort(copied)
		return strings.Join(copied, ",")
	}
	return fmt.Sprintf("enabled=%t description=%q users=[%s] groups=[%s] hosts=[%s] hostgroups=[%s] services=[%s] servicegroups=[%s] all=%t/%t/%t",
		rule.Enabled, rule.Description, sorted(rule.Users), sorted(rule.UserGroups),
		sorted(rule.Hosts), sorted(rule.HostGroups), sorted(rule.Services), sorted(rule.ServiceGroups),
		rule.AllUsers, rule.AllHosts, rule.AllServices)
}

// theRuleToChange is the rule the interruption tests start from: enabled, with
// members of every kind and one category.
func theRuleToChange() *HBACRule {
	return &HBACRule{
		Name: "ops-ssh", Description: "operators", Enabled: true,
		Users: []string{"alice", "bob"}, UserGroups: []string{"ops"},
		HostGroups: []string{"web"}, AllServices: true,
	}
}

// theDeclaration changes the description, every kind of member and both
// categories, so that an interruption has a step of each kind to fall on.
func theDeclaration() HBACRuleSpec {
	return HBACRuleSpec{
		Name: "ops-ssh", Description: "operators and auditors", Enabled: true,
		AllUsers: true, Hosts: []string{"web1.flotestro.test"}, HostGroups: []string{"db"},
		Services: []string{"sshd"},
	}
}

func TestANewRuleIsCreatedDisabledAndEnabledLast(t *testing.T) {
	fake, client, store := newHBACDirectory(t, nil)
	rule, err := client.EnsureHBACRule(context.Background(), HBACRuleSpec{
		Name: "ops-ssh", Description: "operators on the web tier", Enabled: true,
		UserGroups: []string{"ops"}, HostGroups: []string{"web"}, Services: []string{"sshd"},
	})
	if err != nil {
		t.Fatalf("EnsureHBACRule: %v", err)
	}
	if rule == nil || !rule.Enabled {
		t.Fatalf("the rule read back is %+v", rule)
	}
	methods := fake.methods()
	disabled := slices.Index(methods, "hbacrule_disable")
	if created := slices.Index(methods, "hbacrule_add"); disabled != created+1 {
		t.Fatalf("the new rule was not disabled right after it was created: %v", methods)
	}
	// Every member goes in while the rule is out of service, and the flag comes
	// last, after the read that confirms the state.
	enabled := slices.Index(methods, "hbacrule_enable")
	for index, method := range methods {
		if !strings.Contains(method, "_add_") && !strings.Contains(method, "_remove_") {
			continue
		}
		if index < disabled || index > enabled {
			t.Fatalf("%s ran outside the disabled window: %v", method, methods)
		}
	}
	if reads := slices.Index(methods[disabled:], "hbacrule_show"); reads < 0 || disabled+reads > enabled {
		t.Fatalf("the rule was enabled without being read back: %v", methods)
	}
	for _, snapshot := range store.enabledStates {
		// The only enabled state before the end is the rule as the directory
		// creates it: no member and no category, so it grants nothing.
		if state(&snapshot) != state(store.rule) && len(snapshot.UserGroups)+len(snapshot.HostGroups)+len(snapshot.Services) > 0 {
			t.Fatalf("the rule was enabled with a part of its members: %s", state(&snapshot))
		}
	}
}

func TestAnInterruptedCreationLeavesNoRuleBehind(t *testing.T) {
	// One interruption per step of the change, in the order the steps run.
	steps := []struct {
		name   string
		method string
		nth    int
	}{
		{"after the rule is added", "hbacrule_disable", 1},
		{"adding the host groups", "hbacrule_add_host", 1},
		{"adding the services", "hbacrule_add_service", 1},
		{"setting the categories", "hbacrule_mod", 1},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			fake, client, store := newHBACDirectory(t, nil)
			store.failMethod, store.failNth = step.method, step.nth
			_, err := client.EnsureHBACRule(context.Background(), HBACRuleSpec{
				Name: "ops-ssh", Enabled: true, AllUsers: true,
				HostGroups: []string{"web"}, Services: []string{"sshd"},
			})
			var change *RuleChangeError
			if !errors.As(err, &change) {
				t.Fatalf("the interrupted change ended as %v", err)
			}
			if change.Outcome != RuleWithdrawn {
				t.Fatalf("the outcome was %s (%v)", change.Outcome, err)
			}
			if store.rule != nil {
				t.Fatalf("the rule stayed in the directory as %s", state(store.rule))
			}
			if slices.Contains(fake.methods(), "hbacrule_enable") {
				t.Fatalf("the rule was enabled although the change failed: %v", fake.methods())
			}
		})
	}
}

func TestARuleThatCouldNotBeAddedIsNotDeleted(t *testing.T) {
	fake, client, _ := newHBACDirectory(t, nil)
	fake.answers["hbacrule_add"] = func(rpcCall) (any, *rpcError) {
		return nil, &rpcError{Code: 4002, Name: "DuplicateEntry", Message: "rule: already exists"}
	}
	_, err := client.EnsureHBACRule(context.Background(), HBACRuleSpec{
		Name: "ops-ssh", Enabled: true, UserGroups: []string{"ops"}, Services: []string{"sshd"},
	})
	var change *RuleChangeError
	if !errors.As(err, &change) || change.Outcome != RuleWithdrawn {
		t.Fatalf("the refused creation ended as %v", err)
	}
	// A rule of that name the change did not add belongs to somebody else.
	if slices.Contains(fake.methods(), "hbacrule_del") {
		t.Fatalf("the change deleted a rule it never created: %v", fake.methods())
	}
}

func TestAnInterruptedChangePutsThePreviousStateBack(t *testing.T) {
	steps := []struct {
		name   string
		method string
		nth    int
	}{
		{"taking the rule out of service", "hbacrule_disable", 1},
		{"clearing the category", "hbacrule_mod", 1},
		{"removing the users", "hbacrule_remove_user", 1},
		{"removing the host groups", "hbacrule_remove_host", 1},
		{"adding the hosts", "hbacrule_add_host", 1},
		{"adding the services", "hbacrule_add_service", 1},
		{"setting the categories", "hbacrule_mod", 2},
	}
	before := state(theRuleToChange())
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			_, client, store := newHBACDirectory(t, theRuleToChange())
			store.failMethod, store.failNth = step.method, step.nth
			_, err := client.EnsureHBACRule(context.Background(), theDeclaration())
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
			if got := state(store.rule); got != before {
				t.Fatalf("the rule stands as\n%s\nand stood as\n%s", got, before)
			}
			for _, snapshot := range store.enabledStates {
				if got := state(&snapshot); got != before {
					t.Fatalf("the rule was enabled with a half-written state:\n%s", got)
				}
			}
		})
	}
}

func TestARuleThatReadsBackWrongIsNotEnabled(t *testing.T) {
	fake, client, store := newHBACDirectory(t, theRuleToChange())
	// The directory answers the command that adds the host group with a success
	// and keeps the group out of the rule; only the read tells.
	store.dropped = "db"

	_, err := client.EnsureHBACRule(context.Background(), theDeclaration())
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
	if got, before := state(store.rule), state(theRuleToChange()); got != before {
		t.Fatalf("the rule stands as\n%s\nand stood as\n%s", got, before)
	}
	// The rule came back into service with the state it had before, and was
	// never in service with the half the declaration asked for.
	for _, snapshot := range store.enabledStates {
		if got := state(&snapshot); got != state(theRuleToChange()) {
			t.Fatalf("the rule was enabled with\n%s", got)
		}
	}
	if !slices.Contains(fake.methods(), "hbacrule_disable") {
		t.Fatalf("the rule was never taken out of service: %v", fake.methods())
	}
}

func TestARestoreThatFailsLeavesTheRuleDisabled(t *testing.T) {
	_, client, store := newHBACDirectory(t, theRuleToChange())
	// The command that adds hosts fails for the change and for the restore
	// alike: the previous host group cannot go back.
	store.failMethod, store.failNth = "hbacrule_add_host", 0
	_, err := client.EnsureHBACRule(context.Background(), theDeclaration())
	var change *RuleChangeError
	if !errors.As(err, &change) {
		t.Fatalf("the interrupted change ended as %v", err)
	}
	if change.Outcome != RuleRestoreFailed || change.Restore == nil {
		t.Fatalf("the outcome was %s with restore %v", change.Outcome, change.Restore)
	}
	if store.rule == nil || store.rule.Enabled {
		t.Fatalf("the rule is %s, and it must stay out of service", state(store.rule))
	}
	if !strings.Contains(err.Error(), "could not be put back") {
		t.Fatalf("the failure does not say the restore failed: %v", err)
	}
}
