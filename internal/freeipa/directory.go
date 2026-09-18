package freeipa

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
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
	// The Kerberos side of the lifecycle. An expiration that is not set is
	// nil, not a date: the directory then never expires the principal.
	PrincipalExpiresAt *time.Time `json:"principal_expires_at,omitempty"`
	PasswordExpiresAt  *time.Time `json:"password_expires_at,omitempty"`
	LastPasswordChange *time.Time `json:"last_password_change,omitempty"`
	// Preserved marks an account removed with its entry kept: the UID and
	// the history stay, the account cannot sign in. Such accounts are
	// listed apart from the live ones.
	Preserved bool `json:"preserved,omitempty"`
}

// userFromRecord reads an account as the directory's find and show
// commands describe it. The two commands share the shape, and one reader
// keeps a field added for one of them from going missing in the other.
func userFromRecord(record map[string]any, preserved bool) User {
	return User{
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
		PrincipalExpiresAt: generalizedTime(first(record, "krbprincipalexpiration")),
		PasswordExpiresAt:  generalizedTime(first(record, "krbpasswordexpiration")),
		LastPasswordChange: generalizedTime(first(record, "krblastpwdchange")),
		Preserved:          preserved,
	}
}

// generalizedTime parses the LDAP time the directory returns, such as
// 20261231235959Z. Anything else - including an empty value - is nil rather
// than the zero time, because a missing expiration means "never", and the
// zero time would read as the year one.
func generalizedTime(value string) *time.Time {
	if value == "" {
		return nil
	}
	for _, layout := range []string{"20060102150405Z", time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			parsed = parsed.UTC()
			return &parsed
		}
	}
	return nil
}

// GeneralizedTime formats a time the way the directory reads it.
func GeneralizedTime(value time.Time) string {
	return value.UTC().Format("20060102150405Z")
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
	// ManagedBy names the hosts allowed to manage this entry's keytab and
	// certificates; a host always manages itself.
	ManagedBy []string `json:"managed_by,omitempty"`
}

// Service is a Kerberos service principal of a host, such as
// HTTP/web1.example.test. The panel shows whether it has a keytab and who
// manages it; the keytab itself never leaves the directory.
type Service struct {
	Principal string `json:"principal"`
	// Service is the part before the slash, Host the part after it.
	Service string `json:"service"`
	Host    string `json:"host"`
	// HasKeytab is nil when the directory did not say: the friendly view
	// computes it, the raw one does not, and "unknown" must not read as "no".
	HasKeytab *bool    `json:"has_keytab"`
	ManagedBy []string `json:"managed_by,omitempty"`
	Aliases   []string `json:"aliases,omitempty"`
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
	// ServiceGroups are HBAC service groups such as "Sudo".
	ServiceGroups []string `json:"service_groups,omitempty"`
	// AllUsers, AllHosts and AllServices mirror the categories of the rule:
	// a category set to "all" stands in for a member list.
	AllUsers    bool `json:"all_users"`
	AllHosts    bool `json:"all_hosts"`
	AllServices bool `json:"all_services"`
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
	// CommandGroups are sudo command groups.
	CommandGroups []string `json:"command_groups,omitempty"`
	RunAs         []string `json:"run_as,omitempty"`
	RunAsGroups   []string `json:"run_as_groups,omitempty"`
	Options       []string `json:"options,omitempty"`
	// AllUsers, AllHosts and AllCommands mirror the categories of the rule;
	// RunAsAnyUser mirrors the run-as user category.
	AllUsers     bool `json:"all_users"`
	AllHosts     bool `json:"all_hosts"`
	AllCommands  bool `json:"all_commands"`
	RunAsAnyUser bool `json:"run_as_any_user"`
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
			users = append(users, userFromRecord(record, false))
		}
		return users, nil
	})
}

// PreservedUsers returns the accounts removed with their entry kept. The
// directory lists them only when asked, and apart from the live accounts:
// a preserved account cannot sign in, belongs to no group and must not be
// counted among the users a rule reaches.
func (c *Client) PreservedUsers(ctx context.Context) ([]User, error) {
	return cached(ctx, c, "users-preserved", func() ([]User, error) {
		records, err := c.findWith(ctx, "user_find", map[string]any{"preserved": true})
		if err != nil {
			return nil, err
		}
		users := make([]User, 0, len(records))
		for _, record := range records {
			users = append(users, userFromRecord(record, true))
		}
		return users, nil
	})
}

// Services returns the Kerberos service principals of the hosts.
func (c *Client) Services(ctx context.Context) ([]Service, error) {
	return cached(ctx, c, "services", func() ([]Service, error) {
		records, err := c.findRecords(ctx, "service_find")
		if err != nil {
			return nil, err
		}
		services := make([]Service, 0, len(records))
		for _, record := range records {
			principal := first(record, "krbcanonicalname")
			aliases := strings_(record, "krbprincipalname")
			if principal == "" && len(aliases) > 0 {
				principal = aliases[0]
			}
			service, host := splitServicePrincipal(principal)
			item := Service{
				Principal: principal,
				Service:   service,
				Host:      host,
				ManagedBy: strings_(record, "managedby_host"),
			}
			for _, alias := range aliases {
				if alias != principal {
					item.Aliases = append(item.Aliases, alias)
				}
			}
			// has_keytab is computed by the directory in the friendly view;
			// a krbLastPwdChange without it says the same thing. Neither
			// present leaves the question open.
			if lookup(record, "has_keytab") != nil {
				flag := boolean(record, "has_keytab")
				item.HasKeytab = &flag
			} else if first(record, "krblastpwdchange") != "" {
				flag := true
				item.HasKeytab = &flag
			}
			services = append(services, item)
		}
		return services, nil
	})
}

// splitServicePrincipal takes HTTP/web1.example.test@REALM apart into the
// service and the host.
func splitServicePrincipal(principal string) (string, string) {
	name, _, _ := strings.Cut(principal, "@")
	service, host, found := strings.Cut(name, "/")
	if !found {
		return name, ""
	}
	return service, host
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
				ManagedBy:   hostsFromDNs(strings_(record, "managedby")),
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
			rules = append(rules, hbacRuleFromRecord(record))
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
			rules = append(rules, sudoRuleFromRecord(record))
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
	// The directory names the attribute ipasudorunasusercategory; the short
	// spelling is kept for records that arrived without the prefix.
	if first(record, "ipasudorunasusercategory") == "all" || first(record, "runasusercategory") == "all" {
		reasons = append(reasons, "the rule allows acting as any user")
	}
	return len(reasons) > 0, reasons
}

// findRecords runs a search in the friendly view.
func (c *Client) findRecords(ctx context.Context, method string) ([]map[string]any, error) {
	return c.find(ctx, method, false)
}

// findWith runs a search in the friendly view with extra options, such as
// the flag that lists preserved accounts.
func (c *Client) findWith(ctx context.Context, method string, extra map[string]any) ([]map[string]any, error) {
	return c.findOptions(ctx, method, false, extra)
}

// find runs a search command and returns the directory's records.
func (c *Client) find(ctx context.Context, method string, raw bool) ([]map[string]any, error) {
	return c.findOptions(ctx, method, raw, nil)
}

func (c *Client) findOptions(ctx context.Context, method string, raw bool, extra map[string]any) ([]map[string]any, error) {
	records, truncated, err := c.search(ctx, method, raw, extra)
	if err != nil {
		return nil, err
	}
	if truncated {
		// A truncated result is worse than an error: it would look like a
		// complete list.
		return nil, fmt.Errorf("the directory truncated the result of %s; paging is required", method)
	}
	return records, nil
}

// findProbe asks a bounded question - "is there at least one of these" -
// and reads the directory's truncation flag as the expected answer rather
// than as a failure.
//
// The preflight is the reason this exists. A search with a size limit of
// one comes back marked truncated the moment the directory holds a second
// matching entry, and findOptions refuses such an answer because a
// truncated list taken for a complete one is the worse mistake. Here the
// limit is the question, so the flag says nothing was hidden that the
// caller wanted: the caller asked for one record and got one. Reading it as
// an error is what turned a directory with preserved accounts in it into a
// directory that appeared to have no container for them.
func (c *Client) findProbe(ctx context.Context, method string, extra map[string]any) ([]map[string]any, error) {
	records, _, err := c.search(ctx, method, false, extra)
	return records, err
}

// search runs a search command and reports the records with the
// directory's own statement about whether it cut the list short.
func (c *Client) search(ctx context.Context, method string, raw bool, extra map[string]any) ([]map[string]any, bool, error) {
	options := map[string]any{
		"all": true,
		// Zero means no limit on the server's side; the test directory is
		// small, and a large one will need paging.
		"sizelimit": 0,
	}
	if raw {
		options["raw"] = true
	}
	for key, value := range extra {
		options[key] = value
	}
	result, err := c.call(ctx, method, []string{}, options)
	if err != nil {
		return nil, false, err
	}
	var decoded struct {
		Result    []map[string]any `json:"result"`
		Count     int              `json:"count"`
		Truncated bool             `json:"truncated"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, false, fmt.Errorf("the %s response: %w", method, err)
	}
	return decoded.Result, decoded.Truncated, nil
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

// hostsFromDNs takes host names out of full DNs. In raw mode managedby
// arrives as fqdn=...,cn=computers,... rather than as names.
func hostsFromDNs(dns []string) []string {
	var hosts []string
	for _, dn := range dns {
		first, _, found := strings.Cut(dn, ",")
		if !found {
			continue
		}
		if name, ok := strings.CutPrefix(first, "fqdn="); ok {
			hosts = append(hosts, name)
		}
	}
	return hosts
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
			// The directory wraps binary values as {"__base64__": ...} and
			// timestamps as {"__datetime__": ...}; both carry a string.
			if nested, ok := item.(map[string]any); ok {
				for _, wrapper := range []string{"__base64__", "__datetime__"} {
					if text, ok := nested[wrapper].(string); ok {
						result = append(result, text)
						break
					}
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
