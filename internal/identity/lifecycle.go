package identity

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// The plans of the lifecycle changes: what an expiration, a POSIX edit, a
// preservation, a password reset or a host group change does to the
// directory and to the fleet, read before a second person approves it.

// findUser looks an account up in the directory's list. The list is the
// cached read the rest of the plan uses, so the plan is consistent with
// itself.
func (p *Planner) findUser(ctx context.Context, uid string) (*freeipa.User, error) {
	users, err := p.directory.Users(ctx)
	if err != nil {
		return nil, err
	}
	for index := range users {
		if users[index].UID == uid {
			return &users[index], nil
		}
	}
	return nil, nil
}

// planUserExpire shows what expires when.
func (p *Planner) planUserExpire(ctx context.Context, spec *ExpiryPayload) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Changing the expiration of the account %s", spec.UID),
		AffectedUsers: []string{spec.UID},
	}
	expiry, err := spec.Spec()
	if err != nil {
		return plan, err
	}
	plan.Steps = append(plan.Steps, expiryStep("the Kerberos principal", expiry.PrincipalExpiresAt)...)
	plan.Steps = append(plan.Steps, expiryStep("the password", expiry.PasswordExpiresAt)...)

	user, err := p.findUser(ctx, spec.UID)
	if err != nil {
		return plan, err
	}
	if user == nil {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the account %s does not exist in the directory", spec.UID))
		return plan, nil
	}
	plan.CurrentGroups = user.Groups
	if user.PrincipalExpiresAt != nil {
		plan.Steps = append(plan.Steps, "note: the principal expires now at "+user.PrincipalExpiresAt.Format(time.RFC3339))
	}
	if expiry.PrincipalExpiresAt != nil && !expiry.PrincipalExpiresAt.IsZero() {
		if expiry.PrincipalExpiresAt.Before(time.Now()) {
			plan.Warnings = append(plan.Warnings,
				"the principal expiration is in the past: every Kerberos login of the account stops at once")
		}
		access, err := p.accessFor(ctx, user.Groups, spec.UID)
		if err != nil {
			return plan, err
		}
		plan.ReachableHosts = access.hosts
		plan.SudoRules = access.sudo
		if len(access.hosts) > 0 {
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("after the expiration the account no longer signs in to %d hosts", len(access.hosts)))
		}
	}
	if expiry.PasswordExpiresAt != nil && !expiry.PasswordExpiresAt.IsZero() && expiry.PasswordExpiresAt.Before(time.Now()) {
		plan.Warnings = append(plan.Warnings, "the password expiration is in the past: the next login has to change the password")
	}
	if user.Disabled {
		plan.Warnings = append(plan.Warnings, "the account is locked; an expiration changes nothing until it is unlocked")
	}
	return plan, nil
}

func expiryStep(what string, at *time.Time) []string {
	switch {
	case at == nil:
		return nil
	case at.IsZero():
		return []string{"clearing the expiration of " + what + ": it then never expires"}
	default:
		return []string{"setting the expiration of " + what + " to " + at.UTC().Format(time.RFC3339)}
	}
}

// planUserPOSIX shows the attributes before and after. A new UID or GID
// number changes whom the files on every host belong to, and that is the
// warning the second person reads.
func (p *Planner) planUserPOSIX(ctx context.Context, spec *POSIXPayload) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Changing the POSIX attributes of the account %s", spec.UID),
		AffectedUsers: []string{spec.UID},
	}
	wanted := spec.Spec()
	user, err := p.findUser(ctx, spec.UID)
	if err != nil {
		return plan, err
	}
	if user == nil {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the account %s does not exist in the directory", spec.UID))
		return plan, nil
	}
	plan.CurrentGroups = user.Groups
	for _, change := range []struct{ name, current, wanted string }{
		{"UID number", user.UIDNumber, wanted.UIDNumber},
		{"GID number", user.GIDNumber, wanted.GIDNumber},
		{"shell", user.Shell, wanted.Shell},
		{"home directory", user.HomeDir, wanted.HomeDir},
	} {
		if change.wanted == "" {
			continue
		}
		if change.wanted == change.current {
			plan.Steps = append(plan.Steps, fmt.Sprintf("the %s stays %s", change.name, change.current))
			continue
		}
		plan.Steps = append(plan.Steps, fmt.Sprintf("the %s changes from %s to %s",
			change.name, firstNonEmpty(change.current, "(unset)"), change.wanted))
	}
	if wanted.UIDNumber != "" && wanted.UIDNumber != user.UIDNumber {
		plan.Warnings = append(plan.Warnings,
			"a new UID number changes whom the account's files belong to on every host; the files keep the old number")
		// Another account with the number would make two people own the
		// same files. The directory refuses a duplicate too; the plan says
		// it first.
		users, err := p.directory.Users(ctx)
		if err != nil {
			return plan, err
		}
		for _, other := range users {
			if other.UID != spec.UID && other.UIDNumber == wanted.UIDNumber {
				plan.Conflicts = append(plan.Conflicts,
					fmt.Sprintf("the UID number %s belongs to the account %s", wanted.UIDNumber, other.UID))
			}
		}
	}
	if wanted.GIDNumber != "" && wanted.GIDNumber != user.GIDNumber {
		plan.Warnings = append(plan.Warnings, "a new GID number changes the primary group of the account's new files on every host")
	}
	if wanted.Shell != "" && wanted.Shell != user.Shell {
		plan.Warnings = append(plan.Warnings, "the shell must exist on every host the account signs in to; a missing one refuses the login")
	}
	if len(plan.Steps) == 0 {
		plan.Conflicts = append(plan.Conflicts, "the change names no attribute that differs")
	}
	return plan, nil
}

// planUserPreserve shows what a removal takes away. The entry stays as a
// preserved account, so the UID and the history survive; the access, the
// sessions and the memberships do not.
func (p *Planner) planUserPreserve(ctx context.Context, uid string) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Preserving the account %s", uid),
		AffectedUsers: []string{uid},
		Steps: []string{
			"the local denial marker in the panel",
			"revoking the panel sessions",
			"ending the sessions at the identity provider",
			"removing the account from the directory with its entry preserved",
		},
	}
	user, err := p.findUser(ctx, uid)
	if err != nil {
		return plan, err
	}
	if user == nil {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the account %s does not exist in the directory", uid))
		return plan, nil
	}
	plan.CurrentGroups = user.Groups
	plan.ResultingGroups = []string{}
	access, err := p.accessFor(ctx, user.Groups, uid)
	if err != nil {
		return plan, err
	}
	plan.ReachableHosts = access.hosts
	plan.SudoRules = access.sudo
	plan.Warnings = append(plan.Warnings,
		"a preserved account cannot be brought back from the panel; the entry, its UID number and its history stay in the directory")
	if len(user.Groups) > 0 {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("the account leaves %d groups", len(user.Groups)))
	}
	if len(access.sudo) > 0 {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("the account loses %d sudo rules", len(access.sudo)))
	}
	if slices.Contains(p.guardedAccounts(), uid) {
		plan.Conflicts = append(plan.Conflicts,
			"the account "+uid+" is the directory administrator or the panel's own account; it is not removed from here")
	}
	return plan, nil
}

// planPasswordReset says what the reset does and what it does not: the
// value goes to the requester once, and the first login has to change it.
func (p *Planner) planPasswordReset(ctx context.Context, uid string) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Resetting the password of the account %s", uid),
		AffectedUsers: []string{uid},
		Steps: []string{
			"the directory generates a new password and marks it expired",
			"the requester reads the one-time password once; it is neither stored nor recorded",
		},
	}
	user, err := p.findUser(ctx, uid)
	if err != nil {
		return plan, err
	}
	if user == nil {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the account %s does not exist in the directory", uid))
		return plan, nil
	}
	plan.CurrentGroups = user.Groups
	if user.Disabled {
		plan.Warnings = append(plan.Warnings, "the account is locked; the new password works only after it is unlocked")
	}
	plan.Warnings = append(plan.Warnings,
		"the one-time password waits for the requester for a short while after the change runs; a value not read in time needs a new reset")
	return plan, nil
}

// planHostGroupMembers shows which rules the group carries: a host joining
// it comes under every access and sudo rule that names the group, and a
// host leaving it drops out of them.
func (p *Planner) planHostGroupMembers(ctx context.Context, spec *HostGroupPayload) (Plan, error) {
	plan := Plan{
		Summary: fmt.Sprintf("Changing the membership of the host group %s", spec.Group),
	}
	if len(spec.Add) > 0 {
		plan.Steps = append(plan.Steps, "adding the hosts: "+strings.Join(spec.Add, ", "))
	}
	if len(spec.Remove) > 0 {
		plan.Steps = append(plan.Steps, "removing the hosts: "+strings.Join(spec.Remove, ", "))
	}
	view, err := loadDirectoryView(ctx, p.directory)
	if err != nil {
		return plan, err
	}
	index := slices.IndexFunc(view.hostGroups, func(group freeipa.HostGroup) bool { return group.Name == spec.Group })
	if index < 0 {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the host group %s does not exist", spec.Group))
		return plan, nil
	}
	group := view.hostGroups[index]
	plan.CurrentGroups = group.Hosts

	resulting := append([]string{}, group.Hosts...)
	for _, host := range spec.Add {
		if !view.hasHost(host) {
			plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the directory has no host %s", host))
		}
		if !slices.ContainsFunc(resulting, func(member string) bool { return strings.EqualFold(member, host) }) {
			resulting = append(resulting, host)
		}
	}
	for _, host := range spec.Remove {
		if !slices.ContainsFunc(group.Hosts, func(member string) bool { return strings.EqualFold(member, host) }) {
			plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the host %s is not a member of %s", host, spec.Group))
		}
	}
	resulting = slices.DeleteFunc(resulting, func(member string) bool {
		return slices.ContainsFunc(spec.Remove, func(host string) bool { return strings.EqualFold(member, host) })
	})
	slices.Sort(resulting)
	plan.ResultingGroups = resulting
	plan.ReachableHosts = append(append([]string{}, spec.Add...), spec.Remove...)

	// The rules that name the group, and through them the users that reach
	// the hosts: this is what a membership hands over or takes away.
	var hbacNames, users []string
	for _, rule := range view.hbac {
		if !rule.Enabled || !slices.Contains(rule.HostGroups, spec.Group) {
			continue
		}
		hbacNames = append(hbacNames, rule.Name)
		users = append(users, view.usersReached(rule.Users, rule.UserGroups, rule.AllUsers)...)
	}
	for _, rule := range view.sudo {
		if !rule.Enabled || !slices.Contains(rule.HostGroups, spec.Group) {
			continue
		}
		label := rule.Name
		if rule.Critical {
			label += " (critical: " + strings.Join(rule.CriticalReasons, ", ") + ")"
			plan.Warnings = append(plan.Warnings, "the sudo rule "+rule.Name+" is critical and reaches the group")
		}
		plan.SudoRules = append(plan.SudoRules, label)
	}
	slices.Sort(users)
	plan.AffectedUsers = slices.Compact(users)
	if len(hbacNames) > 0 {
		plan.Steps = append(plan.Steps, "the access rules that name the group: "+strings.Join(hbacNames, ", "))
	}
	if len(spec.Add) > 0 && len(hbacNames) == 0 && len(plan.SudoRules) == 0 {
		plan.Warnings = append(plan.Warnings, "no enabled rule names the group; the membership grants nothing today")
	}
	if len(spec.Add) > 0 && len(plan.AffectedUsers) > 0 {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("%d users gain access to the added hosts through the group", len(plan.AffectedUsers)))
	}
	if len(spec.Remove) > 0 {
		// A host leaving the group may leave the reach of the last rule that
		// lets an administrator in. The same guard as on a rule change: the
		// hosts are read as they will be once they have left the group.
		after := *view
		after.hosts = hostsLeavingGroup(view.hosts, spec.Remove, spec.Group)
		for _, account := range p.guardedAccounts() {
			user := slices.IndexFunc(view.users, func(candidate freeipa.User) bool { return candidate.UID == account })
			if user < 0 {
				continue
			}
			groups := view.users[user].Groups
			before := view.hostsEnterable(view.hbac, account, groups)
			remaining := after.hostsEnterable(view.hbac, account, groups)
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
	return plan, nil
}

// hostsLeavingGroup returns the hosts with the group taken out of the
// memberships of the ones that leave it.
func hostsLeavingGroup(hosts []freeipa.Host, leaving []string, group string) []freeipa.Host {
	result := make([]freeipa.Host, 0, len(hosts))
	for _, host := range hosts {
		if slices.ContainsFunc(leaving, func(name string) bool { return strings.EqualFold(name, host.FQDN) }) {
			host.MemberOf = slices.DeleteFunc(slices.Clone(host.MemberOf), func(member string) bool {
				return strings.EqualFold(member, group)
			})
		}
		result = append(result, host)
	}
	return result
}
