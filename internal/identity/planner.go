package identity

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// Planner builds a preview of a change's impact. The plan shows the resulting
// membership, the hosts reachable through HBAC and the sudo rules before
// anything happens.
type Planner struct {
	directory *freeipa.Client
}

func NewPlanner(directory *freeipa.Client) *Planner {
	return &Planner{directory: directory}
}

// Build computes the plan for a change.
func (p *Planner) Build(ctx context.Context, action ActionType, payload Payload) (Plan, error) {
	switch action {
	case ActionUserCreate:
		return p.planUserCreate(ctx, payload.User)
	case ActionUserDisable:
		return p.planUserAccess(ctx, payload.Reference.UID, false)
	case ActionUserEnable:
		return p.planUserAccess(ctx, payload.Reference.UID, true)
	case ActionGroupMembers:
		return p.planGroupMembers(ctx, payload.Group)
	case ActionSSHKeys:
		return p.planSSHKeys(ctx, payload.SSHKeys)
	case ActionDNSRecordEnsure:
		return p.planRecord(ctx, payload.DNS, true)
	case ActionDNSRecordRemove:
		return p.planRecord(ctx, payload.DNS, false)
	default:
		return Plan{}, fmt.Errorf("unknown type of change %q", action)
	}
}

func (p *Planner) planUserCreate(ctx context.Context, spec *UserPayload) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Creating the account %s", spec.UID),
		AffectedUsers: []string{spec.UID},
		Steps:         []string{"creating the account in the directory"},
	}
	if len(spec.Groups) > 0 {
		plan.Steps = append(plan.Steps, "adding to the groups: "+strings.Join(spec.Groups, ", "))
		plan.ResultingGroups = spec.Groups
	}
	if len(spec.SSHKeys) > 0 {
		plan.Steps = append(plan.Steps, fmt.Sprintf("setting %d SSH keys", len(spec.SSHKeys)))
	}

	// A name conflict stops the execution: the directory does not merge
	// accounts automatically, and the panel must not do it on its behalf.
	users, err := p.directory.Users(ctx)
	if err != nil {
		return plan, err
	}
	for _, user := range users {
		if user.UID == spec.UID {
			plan.Conflicts = append(plan.Conflicts,
				fmt.Sprintf("the account %s already exists (UID %s)", user.UID, user.UIDNumber))
		}
	}

	groups, err := p.directory.Groups(ctx)
	if err != nil {
		return plan, err
	}
	known := map[string]bool{}
	for _, group := range groups {
		known[group.Name] = true
	}
	for _, wanted := range spec.Groups {
		if !known[wanted] {
			plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the group %s does not exist", wanted))
		}
	}

	access, err := p.accessFor(ctx, spec.Groups, spec.UID)
	if err != nil {
		return plan, err
	}
	plan.ReachableHosts = access.hosts
	plan.SudoRules = access.sudo
	plan.Warnings = append(plan.Warnings, access.warnings...)
	return plan, nil
}

// planUserAccess shows the access that will be taken away or restored.
func (p *Planner) planUserAccess(ctx context.Context, uid string, enabling bool) (Plan, error) {
	verb := "Locking"
	if enabling {
		verb = "Unlocking"
	}
	plan := Plan{
		Summary:       fmt.Sprintf("%s the account %s", verb, uid),
		AffectedUsers: []string{uid},
	}

	users, err := p.directory.Users(ctx)
	if err != nil {
		return plan, err
	}
	var found *freeipa.User
	for index := range users {
		if users[index].UID == uid {
			found = &users[index]
			break
		}
	}
	if found == nil {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the account %s does not exist in the directory", uid))
		return plan, nil
	}
	plan.CurrentGroups = found.Groups

	if enabling {
		plan.Steps = []string{"unlocking the account in the directory"}
	} else {
		// The order matters: the local denial marker takes effect at once,
		// before the change in the directory reaches the hosts.
		plan.Steps = []string{
			"the local denial marker in the panel",
			"revoking the panel sessions",
			"locking the account in the directory",
		}
	}

	access, err := p.accessFor(ctx, found.Groups, uid)
	if err != nil {
		return plan, err
	}
	plan.ReachableHosts = access.hosts
	plan.SudoRules = access.sudo
	if !enabling && len(access.sudo) > 0 {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("the account loses %d sudo rules", len(access.sudo)))
	}
	if !enabling && found.Disabled {
		plan.Warnings = append(plan.Warnings, "the account is already locked in the directory")
	}
	return plan, nil
}

func (p *Planner) planGroupMembers(ctx context.Context, spec *GroupPayload) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Changing the membership of the group %s", spec.Group),
		AffectedUsers: append(append([]string{}, spec.Add...), spec.Remove...),
	}
	if len(spec.Add) > 0 {
		plan.Steps = append(plan.Steps, "adding: "+strings.Join(spec.Add, ", "))
	}
	if len(spec.Remove) > 0 {
		plan.Steps = append(plan.Steps, "removing: "+strings.Join(spec.Remove, ", "))
	}

	groups, err := p.directory.Groups(ctx)
	if err != nil {
		return plan, err
	}
	var target *freeipa.Group
	for index := range groups {
		if groups[index].Name == spec.Group {
			target = &groups[index]
			break
		}
	}
	if target == nil {
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("the group %s does not exist", spec.Group))
		return plan, nil
	}

	plan.CurrentGroups = target.Members
	resulting := append([]string{}, target.Members...)
	for _, user := range spec.Add {
		if !slices.Contains(resulting, user) {
			resulting = append(resulting, user)
		}
	}
	resulting = slices.DeleteFunc(resulting, func(user string) bool {
		return slices.Contains(spec.Remove, user)
	})
	slices.Sort(resulting)
	plan.ResultingGroups = resulting

	access, err := p.accessFor(ctx, []string{spec.Group}, "")
	if err != nil {
		return plan, err
	}
	plan.ReachableHosts = access.hosts
	plan.SudoRules = access.sudo
	plan.Warnings = append(plan.Warnings, access.warnings...)

	// Adding to a privileged group is a change of high risk.
	if len(access.sudo) > 0 && len(spec.Add) > 0 {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("the group grants access to %d sudo rules", len(access.sudo)))
	}
	return plan, nil
}

func (p *Planner) planSSHKeys(ctx context.Context, spec *SSHKeysPayload) (Plan, error) {
	plan := Plan{
		Summary:       fmt.Sprintf("Setting the SSH keys of the account %s", spec.UID),
		AffectedUsers: []string{spec.UID},
		Steps:         []string{fmt.Sprintf("setting %d public keys", len(spec.Keys))},
	}
	if len(spec.Keys) == 0 {
		plan.Warnings = append(plan.Warnings,
			"an empty list removes every key of the account and can cut off SSH login")
	}

	user, err := p.directory.ShowUser(ctx, spec.UID)
	if err != nil {
		plan.Conflicts = append(plan.Conflicts, err.Error())
		return plan, nil
	}
	if len(user.SSHKeyFingerprints) > 0 {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("the account has %d keys now; they will be replaced", len(user.SSHKeyFingerprints)))
	}
	return plan, nil
}

// access describes the access that follows from group membership.
type access struct {
	hosts    []string
	sudo     []string
	warnings []string
}

// accessFor computes which hosts and sudo rules a membership leads to.
func (p *Planner) accessFor(ctx context.Context, groups []string, uid string) (access, error) {
	var result access
	if len(groups) == 0 && uid == "" {
		return result, nil
	}

	rules, err := p.directory.HBACRules(ctx)
	if err != nil {
		return result, err
	}
	for _, rule := range rules {
		if !rule.Enabled || !matchesSubject(rule.Users, rule.UserGroups, uid, groups) {
			continue
		}
		if rule.AllowsEverything {
			result.hosts = append(result.hosts, "every host (the rule "+rule.Name+")")
			result.warnings = append(result.warnings,
				"the access follows from the rule "+rule.Name+" covering the whole fleet")
			continue
		}
		result.hosts = append(result.hosts, rule.Hosts...)
		for _, group := range rule.HostGroups {
			result.hosts = append(result.hosts, "the host group "+group)
		}
	}

	sudoRules, err := p.directory.SudoRules(ctx)
	if err != nil {
		return result, err
	}
	for _, rule := range sudoRules {
		if !rule.Enabled || !matchesSubject(rule.Users, rule.UserGroups, uid, groups) {
			continue
		}
		label := rule.Name
		if rule.Critical {
			label += " (critical: " + strings.Join(rule.CriticalReasons, ", ") + ")"
			result.warnings = append(result.warnings, "the sudo rule "+rule.Name+" is critical")
		}
		result.sudo = append(result.sudo, label)
	}

	slices.Sort(result.hosts)
	result.hosts = slices.Compact(result.hosts)
	return result, nil
}

// matchesSubject says whether the rule covers the account or one of its groups.
func matchesSubject(ruleUsers, ruleGroups []string, uid string, groups []string) bool {
	if uid != "" && slices.Contains(ruleUsers, uid) {
		return true
	}
	for _, group := range groups {
		if slices.Contains(ruleGroups, group) {
			return true
		}
	}
	return false
}

// planRecord describes what will happen to a record in the directory.
//
// The reverse record is a separate step of the plan rather than a detail of
// the write: it decides what a query about an address answers, and it is the
// thing most often forgotten.
func (p *Planner) planRecord(ctx context.Context, spec *DNSRecordPayload, adding bool) (Plan, error) {
	verb := "Adding"
	step := "adding the record"
	if !adding {
		verb = "Removing"
		step = "removing the record"
	}
	full := freeipa.FullName(spec.Zone, spec.Name)
	plan := Plan{
		Summary: fmt.Sprintf("%s the record %s %s %s", verb, spec.Type, full, spec.Value),
		Steps:   []string{step + " " + spec.Type + " " + full + " -> " + spec.Value},
	}

	reverseZone, reverseName := "", ""
	if spec.Reverse {
		computed, name, err := freeipa.ReverseZone(spec.Value)
		if err != nil {
			return plan, err
		}
		reverseZone, reverseName = computed, name
		if spec.ReverseZone != "" {
			// A zone named explicitly is sometimes narrower than /24: the
			// relative name is then computed against it rather than against
			// the split the panel assumed by itself.
			reverseZone = strings.TrimSuffix(spec.ReverseZone, ".")
			reverseName, err = freeipa.NameInZone(spec.Value, reverseZone)
			if err != nil {
				return plan, err
			}
		}
		plan.Steps = append(plan.Steps, step+" the reverse PTR "+reverseName+"."+reverseZone+
			" -> "+full)
	}

	zones, err := p.directory.Zones(ctx)
	if err != nil {
		return plan, err
	}
	known := map[string]bool{}
	for _, zone := range zones {
		known[zone.Name] = true
	}
	if !known[strings.TrimSuffix(spec.Zone, ".")] {
		// The panel does not create a zone: that is a decision about the
		// division of the namespace rather than about one entry.
		plan.Conflicts = append(plan.Conflicts,
			fmt.Sprintf("the directory has no zone %s", spec.Zone))
	}
	if spec.Reverse && !known[strings.TrimSuffix(reverseZone, ".")] {
		plan.Conflicts = append(plan.Conflicts,
			fmt.Sprintf("the directory has no reverse zone %s", reverseZone))
	}

	// The current state of the record: whether such an entry exists and with what value.
	records, err := p.directory.Records(ctx, strings.TrimSuffix(spec.Zone, "."))
	if err != nil {
		// No access to the zone does not invalidate the plan, but the
		// operator is to know that the panel did not compare it with the
		// state of the directory.
		plan.Conflicts = append(plan.Conflicts,
			"the records of the zone were not read: "+err.Error())
		return plan, nil
	}
	for _, record := range records {
		if record.Name != spec.Name || record.Type != spec.Type {
			continue
		}
		if slices.Contains(record.Values, spec.Value) {
			if adding {
				plan.Conflicts = append(plan.Conflicts,
					fmt.Sprintf("the record %s %s already has the value %s", spec.Type, full, spec.Value))
			}
			continue
		}
		// A record with a different value is not an error: a name may point
		// at several addresses. But the operator is to see that before the
		// write.
		plan.Steps = append(plan.Steps, fmt.Sprintf("note: %s %s already points at %s",
			spec.Type, full, strings.Join(record.Values, ", ")))
		if !adding && !slices.Contains(record.Values, spec.Value) {
			plan.Conflicts = append(plan.Conflicts,
				fmt.Sprintf("the record %s %s does not have the value %s", spec.Type, full, spec.Value))
		}
	}
	return plan, nil
}
