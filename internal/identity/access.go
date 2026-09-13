package identity

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// The effective access of a host is a projection: the host's groups, the
// access rules that reach it and the sudo rules that reach it, read from
// the directory and resolved through the group memberships. Nothing here
// decides anything - the host's own SSSD applies the rules - so the panel
// shows what the directory holds and says plainly when it could not read it.

// HostAccess is the effective access of one host.
type HostAccess struct {
	Hostname string `json:"hostname"`
	// Known says whether the directory has an entry for the host. Without
	// one nothing below is determined: rules may still reach the host under
	// a name the panel does not know, so the view says "unknown", not "none".
	Known  bool   `json:"known"`
	Detail string `json:"detail,omitempty"`
	FQDN   string `json:"fqdn,omitempty"`
	// Enrolled says whether the entry holds a host key, that is whether the
	// host has ever joined.
	Enrolled   bool         `json:"enrolled"`
	HostGroups []string     `json:"host_groups"`
	HBACRules  []HBACAccess `json:"hbac_rules"`
	SudoRules  []SudoAccess `json:"sudo_rules"`
}

// HBACAccess is an access rule together with the way it reaches the host.
type HBACAccess struct {
	freeipa.HBACRule
	// Via says how the rule reaches the host: by name, through a host group
	// or by covering every host.
	Via []string `json:"via"`
	// ReachedUsers are the accounts the rule lets in, resolved through the
	// groups the directory knows.
	ReachedUsers []string `json:"reached_users,omitempty"`
}

// SudoAccess is a sudo rule together with the way it reaches the host.
type SudoAccess struct {
	freeipa.SudoRule
	Via          []string `json:"via"`
	ReachedUsers []string `json:"reached_users,omitempty"`
}

// directoryView is one consistent read of what the projection needs.
type directoryView struct {
	users      []freeipa.User
	groups     []freeipa.Group
	hosts      []freeipa.Host
	hostGroups []freeipa.HostGroup
	hbac       []freeipa.HBACRule
	sudo       []freeipa.SudoRule
}

func loadDirectoryView(ctx context.Context, directory Directory) (*directoryView, error) {
	var view directoryView
	var err error
	if view.users, err = directory.Users(ctx); err != nil {
		return nil, err
	}
	if view.groups, err = directory.Groups(ctx); err != nil {
		return nil, err
	}
	if view.hosts, err = directory.Hosts(ctx); err != nil {
		return nil, err
	}
	if view.hostGroups, err = directory.HostGroups(ctx); err != nil {
		return nil, err
	}
	if view.hbac, err = directory.HBACRules(ctx); err != nil {
		return nil, err
	}
	if view.sudo, err = directory.SudoRules(ctx); err != nil {
		return nil, err
	}
	return &view, nil
}

// EffectiveAccess computes the projection for one host. The host is looked
// up by its name and, when the name is short, by the name completed with the
// domain the host reported.
func EffectiveAccess(ctx context.Context, directory Directory, hostname, domain string) (HostAccess, error) {
	result := HostAccess{
		Hostname:   hostname,
		HostGroups: []string{},
		HBACRules:  []HBACAccess{},
		SudoRules:  []SudoAccess{},
	}
	view, err := loadDirectoryView(ctx, directory)
	if err != nil {
		return result, err
	}

	host := view.findHost(hostname, domain)
	if host == nil {
		result.Detail = fmt.Sprintf("the directory has no entry for %s; the rules that reach it are unknown", hostname)
		return result, nil
	}
	result.Known = true
	result.FQDN = host.FQDN
	result.Enrolled = host.Enrolled
	result.HostGroups = append(result.HostGroups, host.MemberOf...)
	slices.Sort(result.HostGroups)

	for _, rule := range view.hbac {
		via := reachesHost(host, rule.Hosts, rule.HostGroups, rule.AllHosts)
		if len(via) == 0 {
			continue
		}
		result.HBACRules = append(result.HBACRules, HBACAccess{
			HBACRule:     rule,
			Via:          via,
			ReachedUsers: view.usersReached(rule.Users, rule.UserGroups, rule.AllUsers),
		})
	}
	for _, rule := range view.sudo {
		via := reachesHost(host, rule.Hosts, rule.HostGroups, rule.AllHosts)
		if len(via) == 0 {
			continue
		}
		result.SudoRules = append(result.SudoRules, SudoAccess{
			SudoRule:     rule,
			Via:          via,
			ReachedUsers: view.usersReached(rule.Users, rule.UserGroups, rule.AllUsers),
		})
	}
	return result, nil
}

// findHost matches a host name against the directory entries. Names are
// compared without regard to case; a short name is completed with the
// domain the host reported, because the directory knows hosts by FQDN.
func (v *directoryView) findHost(hostname, domain string) *freeipa.Host {
	candidates := []string{strings.ToLower(strings.TrimSuffix(hostname, "."))}
	if !strings.Contains(hostname, ".") && domain != "" {
		candidates = append(candidates, strings.ToLower(hostname+"."+strings.TrimSuffix(domain, ".")))
	}
	for index := range v.hosts {
		if slices.Contains(candidates, strings.ToLower(v.hosts[index].FQDN)) {
			return &v.hosts[index]
		}
	}
	return nil
}

// reachesHost says how a rule's host side reaches the host. The host's
// memberships come from the directory, which lists nested groups as well,
// so a rule on a parent group reaches the hosts of the groups nested in it.
func reachesHost(host *freeipa.Host, ruleHosts, ruleHostGroups []string, allHosts bool) []string {
	var via []string
	if allHosts {
		via = append(via, "every host")
	}
	for _, name := range ruleHosts {
		if strings.EqualFold(name, host.FQDN) {
			via = append(via, "host "+host.FQDN)
		}
	}
	for _, group := range ruleHostGroups {
		if slices.ContainsFunc(host.MemberOf, func(member string) bool { return strings.EqualFold(member, group) }) {
			via = append(via, "host group "+group)
		}
	}
	return via
}

// hostsReached resolves the host side of a rule to host names. A rule that
// covers every host resolves to every host the directory knows.
func (v *directoryView) hostsReached(ruleHosts, ruleHostGroups []string, allHosts bool) []string {
	var hosts []string
	for index := range v.hosts {
		if len(reachesHost(&v.hosts[index], ruleHosts, ruleHostGroups, allHosts)) > 0 {
			hosts = append(hosts, v.hosts[index].FQDN)
		}
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// usersReached resolves the user side of a rule to account names. Group
// membership comes from the accounts' own memberships, which the directory
// lists with nesting resolved.
func (v *directoryView) usersReached(ruleUsers, ruleGroups []string, allUsers bool) []string {
	var users []string
	for _, user := range v.users {
		switch {
		case allUsers:
			users = append(users, user.UID)
		case slices.Contains(ruleUsers, user.UID):
			users = append(users, user.UID)
		default:
			for _, group := range ruleGroups {
				if slices.Contains(user.Groups, group) {
					users = append(users, user.UID)
					break
				}
			}
		}
	}
	slices.Sort(users)
	return slices.Compact(users)
}

func (v *directoryView) hasUser(uid string) bool {
	return slices.ContainsFunc(v.users, func(user freeipa.User) bool { return user.UID == uid })
}

func (v *directoryView) hasGroup(name string) bool {
	return slices.ContainsFunc(v.groups, func(group freeipa.Group) bool { return group.Name == name })
}

func (v *directoryView) hasHost(fqdn string) bool {
	return slices.ContainsFunc(v.hosts, func(host freeipa.Host) bool { return strings.EqualFold(host.FQDN, fqdn) })
}

func (v *directoryView) hasHostGroup(name string) bool {
	return slices.ContainsFunc(v.hostGroups, func(group freeipa.HostGroup) bool { return group.Name == name })
}
