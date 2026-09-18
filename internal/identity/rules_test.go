package identity

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// fakeDirectory is a directory held in memory: enough for the planner's
// impact rules, which read and never write.
type fakeDirectory struct {
	principal  string
	users      []freeipa.User
	groups     []freeipa.Group
	hosts      []freeipa.Host
	hostGroups []freeipa.HostGroup
	hbac       []freeipa.HBACRule
	sudo       []freeipa.SudoRule
	services   []freeipa.Service
}

func (f *fakeDirectory) Principal() string {
	return f.principal
}

func (f *fakeDirectory) Users(context.Context) ([]freeipa.User, error) {
	return f.users, nil
}

func (f *fakeDirectory) ShowUser(_ context.Context, uid string) (*freeipa.User, error) {
	for index := range f.users {
		if f.users[index].UID == uid {
			return &f.users[index], nil
		}
	}
	return nil, fmt.Errorf("the account %s does not exist", uid)
}

func (f *fakeDirectory) Groups(context.Context) ([]freeipa.Group, error) {
	return f.groups, nil
}

func (f *fakeDirectory) Hosts(context.Context) ([]freeipa.Host, error) {
	return f.hosts, nil
}

func (f *fakeDirectory) HostGroups(context.Context) ([]freeipa.HostGroup, error) {
	return f.hostGroups, nil
}

func (f *fakeDirectory) HBACRules(context.Context) ([]freeipa.HBACRule, error) {
	return f.hbac, nil
}

func (f *fakeDirectory) SudoRules(context.Context) ([]freeipa.SudoRule, error) {
	return f.sudo, nil
}

func (f *fakeDirectory) Zones(context.Context) ([]freeipa.Zone, error) {
	return nil, nil
}

func (f *fakeDirectory) Records(context.Context, string) ([]freeipa.Record, error) {
	return nil, nil
}

func (f *fakeDirectory) Services(context.Context) ([]freeipa.Service, error) {
	return f.services, nil
}

// The two reads a preserve plan binds itself to. The fake answers what a
// directory that can do the move would: an entry with its own identity and
// a connector allowed to rename it.
func (f *fakeDirectory) UserEntry(_ context.Context, uid string) (freeipa.EntryReference, error) {
	return freeipa.EntryReference{
		DN:              "uid=" + uid + ",cn=users,cn=accounts,dc=lab,dc=test",
		EntryUUID:       "entry-" + uid,
		ModifyTimestamp: "20260918120000Z",
	}, nil
}

func (f *fakeDirectory) CapabilitiesFor(context.Context, string) (freeipa.DirectoryCapabilities, error) {
	return freeipa.DirectoryCapabilities{UserCreate: true, UserDisable: true, UserModDN: true}, nil
}

// labDirectory is a small fleet: two web hosts in a group, one database
// host, the administrator with the default allow_all rule and an operator.
func labDirectory() *fakeDirectory {
	return &fakeDirectory{
		principal: "flotestro/panel.flotestro.test@FLOTESTRO.TEST",
		users: []freeipa.User{
			{UID: "admin", Groups: []string{"admins"}},
			{UID: "alice", Groups: []string{"ops"}},
			{UID: "bob", Groups: []string{"ops", "dba"}},
		},
		groups: []freeipa.Group{{Name: "admins"}, {Name: "ops"}, {Name: "dba"}},
		hosts: []freeipa.Host{
			{FQDN: "web1.flotestro.test", MemberOf: []string{"web"}},
			{FQDN: "web2.flotestro.test", MemberOf: []string{"web"}},
			{FQDN: "db1.flotestro.test"},
		},
		hostGroups: []freeipa.HostGroup{{Name: "web", Hosts: []string{"web1.flotestro.test", "web2.flotestro.test"}}},
		hbac: []freeipa.HBACRule{
			{Name: "allow_all", Enabled: true, AllUsers: true, AllHosts: true, AllServices: true, AllowsEverything: true},
			{Name: "ops-web", Enabled: true, UserGroups: []string{"ops"}, HostGroups: []string{"web"}, Services: []string{"sshd"}},
		},
		sudo: []freeipa.SudoRule{
			{Name: "dba-db", Enabled: true, UserGroups: []string{"dba"}, Hosts: []string{"db1.flotestro.test"}, AllCommands: true},
		},
	}
}

func TestTheRulePlanResolvesHostsAndUsers(t *testing.T) {
	directory := labDirectory()
	plan, err := NewPlanner(directory).Build(context.Background(), ActionHBACRuleEnsure, Payload{
		HBACRule: &HBACRulePayload{
			Name: "ops-ssh", Enabled: true, UserGroups: []string{"ops"},
			HostGroups: []string{"web"}, Hosts: []string{"db1.flotestro.test"}, Services: []string{"sshd"},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// A host group resolves to its hosts, a group to its accounts.
	if !slices.Equal(plan.ReachableHosts, []string{"db1.flotestro.test", "web1.flotestro.test", "web2.flotestro.test"}) {
		t.Fatalf("reachable hosts = %v", plan.ReachableHosts)
	}
	if !slices.Equal(plan.AffectedUsers, []string{"alice", "bob"}) {
		t.Fatalf("affected users = %v", plan.AffectedUsers)
	}
	if plan.Replaces || plan.Blocked() {
		t.Fatalf("a new rule was planned as %+v", plan)
	}
	if len(plan.Warnings) != 0 {
		t.Fatalf("a narrow rule got warnings: %v", plan.Warnings)
	}
}

func TestTheRulePlanShowsTheDiffAgainstTheExistingRule(t *testing.T) {
	directory := labDirectory()
	plan, err := NewPlanner(directory).Build(context.Background(), ActionHBACRuleEnsure, Payload{
		HBACRule: &HBACRulePayload{
			Name: "ops-web", Enabled: false, UserGroups: []string{"ops", "dba"},
			HostGroups: []string{"web"}, Services: []string{"sshd", "login"},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !plan.Replaces {
		t.Fatal("the plan does not say that the rule exists")
	}
	joined := strings.Join(plan.Steps, "\n")
	for _, want := range []string{"adding user groups: dba", "adding services: login", "disabling the rule"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the steps lack %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "removing") {
		t.Errorf("the steps remove something although nothing goes away:\n%s", joined)
	}
}

func TestTheRulePlanWarnsAboutARuleThatOpensEverything(t *testing.T) {
	directory := labDirectory()
	plan, err := NewPlanner(directory).Build(context.Background(), ActionHBACRuleEnsure, Payload{
		HBACRule: &HBACRulePayload{Name: "everyone", Enabled: true, AllUsers: true, AllHosts: true, AllServices: true},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Warnings) == 0 || !strings.Contains(plan.Warnings[0], "whole fleet") {
		t.Fatalf("warnings = %v", plan.Warnings)
	}
	if plan.ReachableHosts[0] != "every host" || plan.AffectedUsers[0] != "every user" {
		t.Fatalf("hosts = %v, users = %v", plan.ReachableHosts, plan.AffectedUsers)
	}
}

func TestTheRulePlanRefusesToCutOffTheAdministrator(t *testing.T) {
	// The only rule letting admin in is allow_all; removing it is a conflict
	// on every host, not a warning.
	directory := labDirectory()
	plan, err := NewPlanner(directory).Build(context.Background(), ActionHBACRuleRemove, Payload{
		HBACRule: &HBACRulePayload{Name: "allow_all"},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !plan.Blocked() {
		t.Fatalf("removing the last rule for admin was not a conflict: %+v", plan)
	}
	if !strings.Contains(strings.Join(plan.Conflicts, "\n"), "admin") {
		t.Fatalf("the conflict does not name the account: %v", plan.Conflicts)
	}

	// Disabling the rule by ensuring it disabled is the same cut.
	plan, err = NewPlanner(directory).Build(context.Background(), ActionHBACRuleEnsure, Payload{
		HBACRule: &HBACRulePayload{Name: "allow_all", Enabled: false, AllUsers: true, AllHosts: true, AllServices: true},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !plan.Blocked() {
		t.Fatalf("disabling the last rule for admin was not a conflict: %+v", plan)
	}

	// With another rule for the administrators the removal goes through.
	directory.hbac = append(directory.hbac, freeipa.HBACRule{
		Name: "admins-everywhere", Enabled: true, UserGroups: []string{"admins"}, AllHosts: true, AllServices: true,
	})
	plan, err = NewPlanner(directory).Build(context.Background(), ActionHBACRuleRemove, Payload{
		HBACRule: &HBACRulePayload{Name: "allow_all"},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if plan.Blocked() {
		t.Fatalf("a removal that keeps admin's access was blocked: %v", plan.Conflicts)
	}
}

func TestTheRulePlanSaysWhenItCouldNotCheckTheAdministrator(t *testing.T) {
	directory := labDirectory()
	directory.users = directory.users[1:]
	plan, err := NewPlanner(directory).Build(context.Background(), ActionHBACRuleRemove, Payload{
		HBACRule: &HBACRulePayload{Name: "ops-web"},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !slices.ContainsFunc(plan.Warnings, func(warning string) bool {
		return strings.Contains(warning, "admin") && strings.Contains(warning, "could not check")
	}) {
		t.Fatalf("the plan stayed silent about the missing account: %v", plan.Warnings)
	}
}

func TestAUserPrincipalOfThePanelIsGuardedToo(t *testing.T) {
	directory := labDirectory()
	directory.principal = "alice@FLOTESTRO.TEST"
	plan, err := NewPlanner(directory).Build(context.Background(), ActionHBACRuleEnsure, Payload{
		HBACRule: &HBACRulePayload{Name: "allow_all", Enabled: false, AllUsers: true, AllHosts: true, AllServices: true},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// alice still enters the web hosts through ops-web, but loses db1.
	conflicts := strings.Join(plan.Conflicts, "\n")
	if !strings.Contains(conflicts, "alice") || !strings.Contains(conflicts, "db1.flotestro.test") {
		t.Fatalf("conflicts = %v", plan.Conflicts)
	}
	if strings.Contains(conflicts, "alice into: db1.flotestro.test, web1") {
		t.Fatalf("a host alice keeps was listed as lost: %v", plan.Conflicts)
	}
}

func TestTheRulePlanNamesUnknownMembers(t *testing.T) {
	directory := labDirectory()
	plan, err := NewPlanner(directory).Build(context.Background(), ActionHBACRuleEnsure, Payload{
		HBACRule: &HBACRulePayload{
			Name: "ghosts", Enabled: true, Users: []string{"nobody"}, UserGroups: []string{"ghosts"},
			Hosts: []string{"gone.flotestro.test"}, HostGroups: []string{"nowhere"}, Services: []string{"sshd"},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Conflicts) != 4 {
		t.Fatalf("conflicts = %v, expected one per unknown member", plan.Conflicts)
	}
}

func TestTheSudoPlanWarnsAboutRootWithoutAPassword(t *testing.T) {
	directory := labDirectory()
	plan, err := NewPlanner(directory).Build(context.Background(), ActionSudoRuleEnsure, Payload{
		SudoRule: &SudoRulePayload{
			Name: "ops-root", Enabled: true, UserGroups: []string{"ops"}, HostGroups: []string{"web"},
			AllCommands: true, RunAsUsers: []string{"root"}, Options: []string{"!authenticate"},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	joined := strings.Join(plan.Warnings, "\n")
	for _, want := range []string{"!authenticate", "every command", "as root", "full root access"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the warnings lack %q:\n%s", want, joined)
		}
	}
	if !slices.Equal(plan.ReachableHosts, []string{"web1.flotestro.test", "web2.flotestro.test"}) {
		t.Fatalf("reachable hosts = %v", plan.ReachableHosts)
	}
	if plan.Blocked() {
		t.Fatalf("a dangerous sudo rule was blocked instead of warned about: %v", plan.Conflicts)
	}
}

func TestTheSudoPlanDiffsTheExistingRule(t *testing.T) {
	directory := labDirectory()
	plan, err := NewPlanner(directory).Build(context.Background(), ActionSudoRuleEnsure, Payload{
		SudoRule: &SudoRulePayload{
			Name: "dba-db", Enabled: true, UserGroups: []string{"dba"}, Hosts: []string{"db1.flotestro.test"},
			Commands: []string{"/usr/bin/systemctl"},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	joined := strings.Join(plan.Steps, "\n")
	for _, want := range []string{"adding commands: /usr/bin/systemctl", "no longer covering every command"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the steps lack %q:\n%s", want, joined)
		}
	}
	if !plan.Replaces {
		t.Fatal("the plan does not say that the rule exists")
	}
}

func TestRemovingAMissingRuleIsAConflict(t *testing.T) {
	directory := labDirectory()
	plan, err := NewPlanner(directory).Build(context.Background(), ActionSudoRuleRemove, Payload{
		SudoRule: &SudoRulePayload{Name: "nothing"},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !plan.Blocked() {
		t.Fatal("removing a rule that does not exist was planned as possible")
	}
}

func TestEffectiveAccessProjectsTheRulesOntoTheHost(t *testing.T) {
	directory := labDirectory()
	access, err := EffectiveAccess(context.Background(), directory, "web1", "flotestro.test")
	if err != nil {
		t.Fatalf("EffectiveAccess: %v", err)
	}
	if !access.Known || access.FQDN != "web1.flotestro.test" {
		t.Fatalf("the host was not matched by its short name: %+v", access)
	}
	if !slices.Equal(access.HostGroups, []string{"web"}) {
		t.Fatalf("host groups = %v", access.HostGroups)
	}
	names := make([]string, 0, len(access.HBACRules))
	for _, rule := range access.HBACRules {
		names = append(names, rule.Name)
	}
	if !slices.Equal(names, []string{"allow_all", "ops-web"}) {
		t.Fatalf("HBAC rules = %v", names)
	}
	for _, rule := range access.HBACRules {
		if rule.Name == "ops-web" {
			if !slices.Equal(rule.Via, []string{"host group web"}) {
				t.Fatalf("ops-web reaches the host via %v", rule.Via)
			}
			if !slices.Equal(rule.ReachedUsers, []string{"alice", "bob"}) {
				t.Fatalf("ops-web lets in %v", rule.ReachedUsers)
			}
		}
	}
	// The database rule does not reach a web host.
	if len(access.SudoRules) != 0 {
		t.Fatalf("sudo rules = %+v", access.SudoRules)
	}
}

func TestEffectiveAccessOfAnUnknownHostIsUnknownNotEmpty(t *testing.T) {
	directory := labDirectory()
	access, err := EffectiveAccess(context.Background(), directory, "stranger.example.test", "")
	if err != nil {
		t.Fatalf("EffectiveAccess: %v", err)
	}
	if access.Known || access.Detail == "" {
		t.Fatalf("an unknown host was described as %+v", access)
	}
	// Lists are empty rather than absent, so a client does not read "no
	// data" as "no rules".
	if access.HBACRules == nil || access.SudoRules == nil || access.HostGroups == nil {
		t.Fatal("the lists of an unknown host are absent instead of empty")
	}
}
