package identity

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// The impact of a rule change.

// guardedAccounts are the accounts whose access to a host the plan refuses to
// remove with the last rule: the directory administrator, and the panel's own
// principal when it is a user rather than a service.
func (p *Planner) guardedAccounts() []string {
	accounts := []string{"admin"}
	principal, _, _ := strings.Cut(p.directory.Principal(), "@")
	if principal != "" && principal != "admin" && !strings.Contains(principal, "/") {
		accounts = append(accounts, principal)
	}
	return accounts
}

func (p *Planner) planHBACRule(ctx context.Context, spec *HBACRulePayload) (Plan, error) {
	plan := Plan{Summary: fmt.Sprintf("Ensuring the HBAC rule %s", spec.Name)}
	view, err := loadDirectoryView(ctx, p.directory)
	if err != nil {
		return plan, err
	}

	var current *freeipa.HBACRule
	for index := range view.hbac {
		if view.hbac[index].Name == spec.Name {
			current = &view.hbac[index]
			break
		}
	}
	if current == nil {
		plan.Steps = append(plan.Steps, "creating the rule "+spec.Name)
	} else {
		plan.Replaces = true
		plan.Steps = append(plan.Steps, "the rule "+spec.Name+" exists; bringing it to the declared state")
		plan.Steps = append(plan.Steps, memberDiffSteps("users", current.Users, spec.Users)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("user groups", current.UserGroups, spec.UserGroups)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("hosts", current.Hosts, spec.Hosts)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("host groups", current.HostGroups, spec.HostGroups)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("services", current.Services, spec.Services)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("service groups", current.ServiceGroups, spec.ServiceGroups)...)
		plan.Steps = append(plan.Steps, categorySteps("users", current.AllUsers, spec.AllUsers)...)
		plan.Steps = append(plan.Steps, categorySteps("hosts", current.AllHosts, spec.AllHosts)...)
		plan.Steps = append(plan.Steps, categorySteps("services", current.AllServices, spec.AllServices)...)
		if current.Enabled != spec.Enabled {
			plan.Steps = append(plan.Steps, enableStep(spec.Enabled))
		}
	}
	if current == nil && !spec.Enabled {
		plan.Steps = append(plan.Steps, "the rule stays disabled")
	}

	plan.Conflicts = append(plan.Conflicts, view.missingMembers(spec.Users, spec.UserGroups, spec.Hosts, spec.HostGroups)...)
	plan.ReachableHosts = view.hostsReached(spec.Hosts, spec.HostGroups, spec.AllHosts)
	plan.AffectedUsers = view.usersReached(spec.Users, spec.UserGroups, spec.AllUsers)
	if spec.AllHosts {
		plan.ReachableHosts = append([]string{"every host"}, plan.ReachableHosts...)
	}
	if spec.AllUsers {
		plan.AffectedUsers = append([]string{"every user"}, plan.AffectedUsers...)
	}

	if spec.Enabled {
		switch {
		case spec.AllUsers && spec.AllHosts && spec.AllServices:
			plan.Warnings = append(plan.Warnings,
				"the rule lets every user into every service on every host: it opens the whole fleet with one entry")
		case spec.AllHosts && spec.AllServices:
			plan.Warnings = append(plan.Warnings,
				"the rule allows every service on every host to the users it names")
		case spec.AllHosts:
			plan.Warnings = append(plan.Warnings, "the rule reaches every host in the directory")
		}
		if len(spec.Services) == 0 && len(spec.ServiceGroups) == 0 && !spec.AllServices {
			plan.Warnings = append(plan.Warnings, "the rule names no service, so it matches nothing until one is added")
		}
	}

	// The rule after the change replaces the rule of the same name, if any.
	after := replaceHBACRule(view.hbac, freeipa.HBACRule{
		Name: spec.Name, Enabled: spec.Enabled,
		Users: spec.Users, UserGroups: spec.UserGroups, Hosts: spec.Hosts, HostGroups: spec.HostGroups,
		Services: spec.Services, ServiceGroups: spec.ServiceGroups,
		AllUsers: spec.AllUsers, AllHosts: spec.AllHosts, AllServices: spec.AllServices,
	}, false)
	p.guardAdministratorAccess(view, after, &plan)
	return plan, nil
}

func (p *Planner) planHBACRuleRemoval(ctx context.Context, name string) (Plan, error) {
	plan := Plan{
		Summary: fmt.Sprintf("Removing the HBAC rule %s", name),
		Steps:   []string{"removing the rule " + name},
	}
	view, err := loadDirectoryView(ctx, p.directory)
	if err != nil {
		return plan, err
	}
	index := slices.IndexFunc(view.hbac, func(rule freeipa.HBACRule) bool { return rule.Name == name })
	if index < 0 {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the directory has no HBAC rule %s", name))
		return plan, nil
	}
	current := view.hbac[index]
	plan.ReachableHosts = view.hostsReached(current.Hosts, current.HostGroups, current.AllHosts)
	plan.AffectedUsers = view.usersReached(current.Users, current.UserGroups, current.AllUsers)
	if current.Enabled && (len(plan.ReachableHosts) > 0 || len(plan.AffectedUsers) > 0) {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("the rule lets %d users into %d hosts now; they lose that access",
				len(plan.AffectedUsers), len(plan.ReachableHosts)))
	}
	if !current.Enabled {
		plan.Warnings = append(plan.Warnings, "the rule is disabled; removing it changes no access")
	}
	p.guardAdministratorAccess(view, replaceHBACRule(view.hbac, current, true), &plan)
	return plan, nil
}

func (p *Planner) planSudoRule(ctx context.Context, spec *SudoRulePayload) (Plan, error) {
	plan := Plan{Summary: fmt.Sprintf("Ensuring the sudo rule %s", spec.Name)}
	view, err := loadDirectoryView(ctx, p.directory)
	if err != nil {
		return plan, err
	}

	var current *freeipa.SudoRule
	for index := range view.sudo {
		if view.sudo[index].Name == spec.Name {
			current = &view.sudo[index]
			break
		}
	}
	if current == nil {
		plan.Steps = append(plan.Steps, "creating the rule "+spec.Name)
	} else {
		plan.Replaces = true
		plan.Steps = append(plan.Steps, "the rule "+spec.Name+" exists; bringing it to the declared state")
		plan.Steps = append(plan.Steps, memberDiffSteps("users", current.Users, spec.Users)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("user groups", current.UserGroups, spec.UserGroups)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("hosts", current.Hosts, spec.Hosts)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("host groups", current.HostGroups, spec.HostGroups)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("commands", current.Commands, spec.Commands)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("command groups", current.CommandGroups, spec.CommandGroups)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("run-as users", current.RunAs, spec.RunAsUsers)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("run-as groups", current.RunAsGroups, spec.RunAsGroups)...)
		plan.Steps = append(plan.Steps, memberDiffSteps("options", current.Options, spec.Options)...)
		plan.Steps = append(plan.Steps, categorySteps("users", current.AllUsers, spec.AllUsers)...)
		plan.Steps = append(plan.Steps, categorySteps("hosts", current.AllHosts, spec.AllHosts)...)
		plan.Steps = append(plan.Steps, categorySteps("commands", current.AllCommands, spec.AllCommands)...)
		plan.Steps = append(plan.Steps, categorySteps("run-as users", current.RunAsAnyUser, spec.RunAsAnyUser)...)
		if current.Enabled != spec.Enabled {
			plan.Steps = append(plan.Steps, enableStep(spec.Enabled))
		}
	}
	if current == nil && !spec.Enabled {
		plan.Steps = append(plan.Steps, "the rule stays disabled")
	}

	plan.Conflicts = append(plan.Conflicts, view.missingMembers(spec.Users, spec.UserGroups, spec.Hosts, spec.HostGroups)...)
	for _, user := range spec.RunAsUsers {
		// root is not an account of the directory, yet it is the account a
		// sudo rule most often runs as.
		if user != "root" && !view.hasUser(user) {
			plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the run-as account %s does not exist in the directory", user))
		}
	}
	plan.ReachableHosts = view.hostsReached(spec.Hosts, spec.HostGroups, spec.AllHosts)
	plan.AffectedUsers = view.usersReached(spec.Users, spec.UserGroups, spec.AllUsers)
	if spec.AllHosts {
		plan.ReachableHosts = append([]string{"every host"}, plan.ReachableHosts...)
	}
	if spec.AllUsers {
		plan.AffectedUsers = append([]string{"every user"}, plan.AffectedUsers...)
	}
	plan.SudoRules = []string{spec.Name}

	if spec.Enabled {
		plan.Warnings = append(plan.Warnings, sudoWarnings(spec)...)
	}
	return plan, nil
}

func (p *Planner) planSudoRuleRemoval(ctx context.Context, name string) (Plan, error) {
	plan := Plan{
		Summary:   fmt.Sprintf("Removing the sudo rule %s", name),
		Steps:     []string{"removing the rule " + name},
		SudoRules: []string{name},
	}
	view, err := loadDirectoryView(ctx, p.directory)
	if err != nil {
		return plan, err
	}
	index := slices.IndexFunc(view.sudo, func(rule freeipa.SudoRule) bool { return rule.Name == name })
	if index < 0 {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the directory has no sudo rule %s", name))
		return plan, nil
	}
	current := view.sudo[index]
	plan.ReachableHosts = view.hostsReached(current.Hosts, current.HostGroups, current.AllHosts)
	plan.AffectedUsers = view.usersReached(current.Users, current.UserGroups, current.AllUsers)
	if current.Enabled && (len(plan.ReachableHosts) > 0 || len(plan.AffectedUsers) > 0) {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("the rule grants %d users privileges on %d hosts now; they lose them",
				len(plan.AffectedUsers), len(plan.ReachableHosts)))
	}
	if !current.Enabled {
		plan.Warnings = append(plan.Warnings, "the rule is disabled; removing it changes no privileges")
	}
	return plan, nil
}

// sudoWarnings names what makes a sudo rule dangerous: no password, every
// command, every host, acting as root or as anybody.
func sudoWarnings(spec *SudoRulePayload) []string {
	var warnings []string
	for _, option := range spec.Options {
		if strings.TrimSpace(option) == "!authenticate" {
			warnings = append(warnings, "the rule requires no password confirmation (!authenticate)")
			break
		}
	}
	if spec.AllCommands {
		warnings = append(warnings, "the rule allows every command")
	}
	if spec.AllHosts {
		warnings = append(warnings, "the rule reaches every host in the directory")
	}
	if spec.AllUsers {
		warnings = append(warnings, "the rule applies to every user")
	}
	if spec.RunAsAnyUser {
		warnings = append(warnings, "the rule allows acting as any user")
	} else if slices.Contains(spec.RunAsUsers, "root") {
		warnings = append(warnings, "the rule runs commands as root")
	}
	if spec.AllCommands && (spec.RunAsAnyUser || slices.Contains(spec.RunAsUsers, "root") || len(spec.RunAsUsers) == 0) {
		// A rule with every command and no run-as restriction is root on the hosts
		// it reaches; with !
		warnings = append(warnings, "the rule is equivalent to full root access on the hosts it reaches")
	}
	return warnings
}

// missingMembers names the members the directory does not know.
func (v *directoryView) missingMembers(users, groups, hosts, hostGroups []string) []string {
	var conflicts []string
	for _, user := range users {
		if !v.hasUser(user) {
			conflicts = append(conflicts, fmt.Sprintf("the account %s does not exist in the directory", user))
		}
	}
	for _, group := range groups {
		if !v.hasGroup(group) {
			conflicts = append(conflicts, fmt.Sprintf("the group %s does not exist in the directory", group))
		}
	}
	for _, host := range hosts {
		if !v.hasHost(host) {
			conflicts = append(conflicts, fmt.Sprintf("the host %s does not exist in the directory", host))
		}
	}
	for _, group := range hostGroups {
		if !v.hasHostGroup(group) {
			conflicts = append(conflicts, fmt.Sprintf("the host group %s does not exist in the directory", group))
		}
	}
	return conflicts
}

// memberDiffSteps describes the difference between the current and the
// declared members of one kind.
func memberDiffSteps(kind string, current, wanted []string) []string {
	var steps []string
	var added, removed []string
	for _, name := range wanted {
		if !slices.Contains(current, name) {
			added = append(added, name)
		}
	}
	for _, name := range current {
		if !slices.Contains(wanted, name) {
			removed = append(removed, name)
		}
	}
	if len(added) > 0 {
		steps = append(steps, fmt.Sprintf("adding %s: %s", kind, strings.Join(added, ", ")))
	}
	if len(removed) > 0 {
		steps = append(steps, fmt.Sprintf("removing %s: %s", kind, strings.Join(removed, ", ")))
	}
	return steps
}

func categorySteps(kind string, current, wanted bool) []string {
	switch {
	case wanted && !current:
		return []string{"covering every " + strings.TrimSuffix(kind, "s") + " instead of the listed " + kind}
	case current && !wanted:
		return []string{"no longer covering every " + strings.TrimSuffix(kind, "s") + "; only the listed " + kind}
	default:
		return nil
	}
}

func enableStep(enabled bool) string {
	if enabled {
		return "enabling the rule"
	}
	return "disabling the rule"
}

// replaceHBACRule returns the rule set as it will stand after the change:
// the rule of the same name replaced by the declared one, or removed.
func replaceHBACRule(rules []freeipa.HBACRule, rule freeipa.HBACRule, remove bool) []freeipa.HBACRule {
	after := make([]freeipa.HBACRule, 0, len(rules)+1)
	for _, existing := range rules {
		if existing.Name != rule.Name {
			after = append(after, existing)
		}
	}
	if !remove {
		after = append(after, rule)
	}
	return after
}

// guardAdministratorAccess compares the hosts the guarded accounts may enter
// before and after the change.
func (p *Planner) guardAdministratorAccess(view *directoryView, after []freeipa.HBACRule, plan *Plan) {
	for _, account := range p.guardedAccounts() {
		user := slices.IndexFunc(view.users, func(candidate freeipa.User) bool { return candidate.UID == account })
		if user < 0 {
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("the account %s was not found in the directory; the plan could not check whether it keeps access", account))
			continue
		}
		groups := view.users[user].Groups
		before := view.hostsEnterable(view.hbac, account, groups)
		remaining := view.hostsEnterable(after, account, groups)
		var lost []string
		for _, host := range before {
			if !slices.Contains(remaining, host) {
				lost = append(lost, host)
			}
		}
		if len(lost) > 0 {
			plan.Conflicts = append(plan.Conflicts,
				fmt.Sprintf("the change removes the last HBAC rule letting %s into: %s",
					account, strings.Join(lost, ", ")))
		}
	}
}

// hostsEnterable lists the hosts at least one enabled rule lets the account into.
func (v *directoryView) hostsEnterable(rules []freeipa.HBACRule, uid string, groups []string) []string {
	var hosts []string
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !rule.AllUsers && !matchesSubject(rule.Users, rule.UserGroups, uid, groups) {
			continue
		}
		if !rule.AllServices && len(rule.Services) == 0 && len(rule.ServiceGroups) == 0 {
			// A rule without services lets nobody in, whatever else it says.
			continue
		}
		hosts = append(hosts, v.hostsReached(rule.Hosts, rule.HostGroups, rule.AllHosts)...)
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}
