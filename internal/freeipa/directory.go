package freeipa

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// User is a POSIX account in the directory. The panel stores neither
// passwords nor a copy of the directory; this data is read on request and
// cached briefly.
type User struct {
	UID         string   `json:"uid"`
	FirstName   string   `json:"first_name,omitempty"`
	LastName    string   `json:"last_name,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Email       []string `json:"email,omitempty"`
	UIDNumber   string   `json:"uid_number,omitempty"`
	GIDNumber   string   `json:"gid_number,omitempty"`
	HomeDir     string   `json:"home_directory,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	// Disabled corresponds to nsaccountlock in the directory.
	Disabled bool `json:"disabled"`
	// SSHKeyFingerprints shows the keys without their content.
	SSHKeyFingerprints []string `json:"ssh_key_fingerprints,omitempty"`
}

// Group is a POSIX group.
type Group struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	GIDNumber   string   `json:"gid_number,omitempty"`
	Members     []string `json:"members,omitempty"`
	MemberOf    []string `json:"member_of,omitempty"`
}

// Host is a host entry in the directory.
type Host struct {
	FQDN        string   `json:"fqdn"`
	Description string   `json:"description,omitempty"`
	Enrolled    bool     `json:"enrolled"`
	EnrolledAt  string   `json:"enrolled_at,omitempty"`
	MemberOf    []string `json:"member_of,omitempty"`
}

// HBACRule describes an access rule for hosts and services.
type HBACRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Users       []string `json:"users,omitempty"`
	UserGroups  []string `json:"user_groups,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	HostGroups  []string `json:"host_groups,omitempty"`
	Services    []string `json:"services,omitempty"`
	// AllowsEverything marks an allow_all rule. The document advises against
	// it: it opens access to the whole fleet with one entry.
	AllowsEverything bool `json:"allows_everything"`
}

// SudoRule describes a privilege escalation rule.
type SudoRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Users       []string `json:"users,omitempty"`
	UserGroups  []string `json:"user_groups,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	HostGroups  []string `json:"host_groups,omitempty"`
	Commands    []string `json:"commands,omitempty"`
	RunAs       []string `json:"run_as,omitempty"`
	Options     []string `json:"options,omitempty"`
	// Critical marks a rule of raised risk: NOPASSWD or ALL.
	Critical bool `json:"critical"`
	// CriticalReasons says what exactly makes the rule risky.
	CriticalReasons []string `json:"critical_reasons,omitempty"`
}

// Ping checks the connectivity and the authentication of the connector.
func (c *Client) Ping(ctx context.Context) (string, error) {
	result, err := c.call(ctx, "ping", nil, nil)
	if err != nil {
		return "", err
	}
	var decoded struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return "", err
	}
	return decoded.Summary, nil
}

// Users returns the accounts from the directory.
func (c *Client) Users(ctx context.Context) ([]User, error) {
	return cached(ctx, c, "users", func() ([]User, error) {
		records, err := c.findRecords(ctx, "user_find")
		if err != nil {
			return nil, err
		}
		users := make([]User, 0, len(records))
		for _, record := range records {
			users = append(users, User{
				UID:                first(record, "uid"),
				FirstName:          first(record, "givenname"),
				LastName:           first(record, "sn"),
				DisplayName:        first(record, "displayname"),
				Email:              strings_(record, "mail"),
				UIDNumber:          first(record, "uidnumber"),
				GIDNumber:          first(record, "gidnumber"),
				HomeDir:            first(record, "homedirectory"),
				Shell:              first(record, "loginshell"),
				Groups:             strings_(record, "memberof_group"),
				Disabled:           boolean(record, "nsaccountlock"),
				SSHKeyFingerprints: strings_(record, "sshpubkeyfp"),
			})
		}
		return users, nil
	})
}

// Groups returns the groups from the directory.
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	return cached(ctx, c, "groups", func() ([]Group, error) {
		records, err := c.findRecords(ctx, "group_find")
		if err != nil {
			return nil, err
		}
		groups := make([]Group, 0, len(records))
		for _, record := range records {
			groups = append(groups, Group{
				Name:        first(record, "cn"),
				Description: first(record, "description"),
				GIDNumber:   first(record, "gidnumber"),
				Members:     strings_(record, "member_user"),
				MemberOf:    strings_(record, "memberof_group"),
			})
		}
		return groups, nil
	})
}

// Hosts returns the hosts registered in the directory.
func (c *Client) Hosts(ctx context.Context) ([]Host, error) {
	return cached(ctx, c, "hosts", func() ([]Host, error) {
		// Raw mode is necessary here: krbLastPwdChange, the only indicator of
		// enrollment available without a query per host, is filtered out of
		// the friendly view.
		records, err := c.findRaw(ctx, "host_find")
		if err != nil {
			return nil, err
		}
		hosts := make([]Host, 0, len(records))
		for _, record := range records {
			// has_keytab is an attribute computed solely by host_show, so
			// using it would require a query per host - exactly what the
			// document forbids. krbLastPwdChange appears at the moment the
			// host key is set, so it tells enrolled hosts from mere entries
			// in the directory.
			enrolledAt := first(record, "krblastpwdchange")
			hosts = append(hosts, Host{
				FQDN:        first(record, "fqdn"),
				Description: first(record, "description"),
				Enrolled:    enrolledAt != "",
				EnrolledAt:  enrolledAt,
				MemberOf:    hostGroupsFromDNs(strings_(record, "memberof")),
			})
		}
		return hosts, nil
	})
}

// HBACRules returns the access rules.
func (c *Client) HBACRules(ctx context.Context) ([]HBACRule, error) {
	return cached(ctx, c, "hbac", func() ([]HBACRule, error) {
		records, err := c.findRecords(ctx, "hbacrule_find")
		if err != nil {
			return nil, err
		}
		rules := make([]HBACRule, 0, len(records))
		for _, record := range records {
			rule := HBACRule{
				Name:        first(record, "cn"),
				Description: first(record, "description"),
				Enabled:     boolean(record, "ipaenabledflag"),
				Users:       strings_(record, "memberuser_user"),
				UserGroups:  strings_(record, "memberuser_group"),
				Hosts:       strings_(record, "memberhost_host"),
				HostGroups:  strings_(record, "memberhost_hostgroup"),
				Services:    strings_(record, "memberservice_hbacsvc"),
			}
			// A rule covering everybody, every host and every service opens
			// access to the whole fleet with one entry.
			rule.AllowsEverything = first(record, "usercategory") == "all" &&
				first(record, "hostcategory") == "all" &&
				first(record, "servicecategory") == "all"
			rules = append(rules, rule)
		}
		return rules, nil
	})
}

// SudoRules returns the sudo rules together with the risk marking.
func (c *Client) SudoRules(ctx context.Context) ([]SudoRule, error) {
	return cached(ctx, c, "sudo", func() ([]SudoRule, error) {
		records, err := c.findRecords(ctx, "sudorule_find")
		if err != nil {
			return nil, err
		}
		rules := make([]SudoRule, 0, len(records))
		for _, record := range records {
			rule := SudoRule{
				Name:        first(record, "cn"),
				Description: first(record, "description"),
				Enabled:     boolean(record, "ipaenabledflag"),
				Users:       strings_(record, "memberuser_user"),
				UserGroups:  strings_(record, "memberuser_group"),
				Hosts:       strings_(record, "memberhost_host"),
				HostGroups:  strings_(record, "memberhost_hostgroup"),
				Commands:    strings_(record, "memberallowcmd_sudocmd"),
				RunAs:       strings_(record, "ipasudorunas_user"),
				Options:     strings_(record, "ipasudoopt"),
			}
			rule.Critical, rule.CriticalReasons = sudoRisk(record, rule)
			rules = append(rules, rule)
		}
		return rules, nil
	})
}

// sudoRisk marks the rules of raised risk. NOPASSWD and ALL are named in the
// document as critical: the first removes the confirmation of identity, the
// second grants full root privileges.
func sudoRisk(record map[string]any, rule SudoRule) (bool, []string) {
	var reasons []string
	for _, option := range rule.Options {
		if option == "!authenticate" || option == "NOPASSWD" || option == "nopasswd" {
			reasons = append(reasons, "the rule requires no password confirmation")
			break
		}
	}
	if first(record, "cmdcategory") == "all" {
		reasons = append(reasons, "the rule covers every command")
	}
	if first(record, "hostcategory") == "all" {
		reasons = append(reasons, "the rule covers every host")
	}
	if first(record, "usercategory") == "all" {
		reasons = append(reasons, "the rule covers every user")
	}
	if first(record, "runasusercategory") == "all" {
		reasons = append(reasons, "the rule allows acting as any user")
	}
	return len(reasons) > 0, reasons
}

// findRecords runs a search in the friendly view.
func (c *Client) findRecords(ctx context.Context, method string) ([]map[string]any, error) {
	return c.find(ctx, method, false)
}

// find runs a search command and returns the directory's records.
func (c *Client) find(ctx context.Context, method string, raw bool) ([]map[string]any, error) {
	options := map[string]any{
		"all": true,
		// Zero means no limit on the server's side; the test directory is
		// small, and a large one will need paging.
		"sizelimit": 0,
	}
	if raw {
		options["raw"] = true
	}
	result, err := c.call(ctx, method, []string{}, options)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Result    []map[string]any `json:"result"`
		Count     int              `json:"count"`
		Truncated bool             `json:"truncated"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, fmt.Errorf("the %s response: %w", method, err)
	}
	if decoded.Truncated {
		// A truncated result is worse than an error: it would look like a
		// complete list.
		return nil, fmt.Errorf("the directory truncated the result of %s; paging is required", method)
	}
	return decoded.Result, nil
}

// hostGroupsFromDNs takes the names of host groups out of full DNs. In raw
// mode the directory returns membership as DNs rather than as names.
func hostGroupsFromDNs(dns []string) []string {
	var groups []string
	for _, dn := range dns {
		if !strings.Contains(dn, "cn=hostgroups") {
			continue
		}
		first, _, found := strings.Cut(dn, ",")
		if !found {
			continue
		}
		if name, ok := strings.CutPrefix(first, "cn="); ok {
			groups = append(groups, name)
		}
	}
	return groups
}

// FreeIPA returns values as lists, even for single-valued fields.
func first(record map[string]any, key string) string {
	values := strings_(record, key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// lookup finds a value regardless of the case of the field name.
// The directory returns "krbLastPwdChange" one time and "krblastpwdchange"
// another, depending on the response mode; pinning to one spelling ends in
// silently missing data.
func lookup(record map[string]any, key string) any {
	if value, ok := record[key]; ok {
		return value
	}
	lower := strings.ToLower(key)
	for name, value := range record {
		if strings.ToLower(name) == lower {
			return value
		}
	}
	return nil
}

func strings_(record map[string]any, key string) []string {
	switch value := lookup(record, key).(type) {
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				result = append(result, text)
				continue
			}
			// The directory sometimes returns {"__base64__": ...} objects or numbers.
			if nested, ok := item.(map[string]any); ok {
				if text, ok := nested["__base64__"].(string); ok {
					result = append(result, text)
				}
			}
		}
		return result
	case string:
		return []string{value}
	case bool:
		return []string{fmt.Sprint(value)}
	default:
		return nil
	}
}

func boolean(record map[string]any, key string) bool {
	switch value := lookup(record, key).(type) {
	case bool:
		return value
	case []any:
		if len(value) > 0 {
			if flag, ok := value[0].(bool); ok {
				return flag
			}
			if text, ok := value[0].(string); ok {
				return text == "TRUE" || text == "true"
			}
		}
	}
	return false
}
