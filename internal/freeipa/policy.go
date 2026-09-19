package freeipa

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// The access and sudo rules of the directory.

// ruleNamePattern bounds the name of an access or sudo rule.
var ruleNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

// serviceNamePattern bounds the name of an HBAC service or service group.
var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

// HostGroup is a group of hosts in the directory.
type HostGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	// HostGroups are the groups nested in this one.
	HostGroups []string `json:"host_groups,omitempty"`
}

// HBACRuleSpec declares the wanted state of an access rule.
type HBACRuleSpec struct {
	Name        string
	Description string
	Enabled     bool
	Users       []string
	UserGroups  []string
	Hosts       []string
	HostGroups  []string
	Services    []string
	// ServiceGroups are HBAC service groups such as "Sudo".
	ServiceGroups []string
	// AllUsers, AllHosts and AllServices set the category of the rule to "all".
	AllUsers    bool
	AllHosts    bool
	AllServices bool
}

// Validate checks the declaration before anything goes to the directory.
func (s HBACRuleSpec) Validate() error {
	if !ruleNamePattern.MatchString(s.Name) {
		return fmt.Errorf("invalid rule name %q", s.Name)
	}
	if err := validateMembers(s.Users, userNamePattern, "account"); err != nil {
		return err
	}
	if err := validateMembers(s.UserGroups, groupNamePattern, "group"); err != nil {
		return err
	}
	if err := validateMembers(s.Hosts, hostNamePattern, "host"); err != nil {
		return err
	}
	if err := validateMembers(s.HostGroups, groupNamePattern, "host group"); err != nil {
		return err
	}
	if err := validateMembers(s.Services, serviceNamePattern, "service"); err != nil {
		return err
	}
	if err := validateMembers(s.ServiceGroups, serviceNamePattern, "service group"); err != nil {
		return err
	}
	if s.AllUsers && (len(s.Users) > 0 || len(s.UserGroups) > 0) {
		return fmt.Errorf("a rule covering every user cannot also list users")
	}
	if s.AllHosts && (len(s.Hosts) > 0 || len(s.HostGroups) > 0) {
		return fmt.Errorf("a rule covering every host cannot also list hosts")
	}
	if s.AllServices && (len(s.Services) > 0 || len(s.ServiceGroups) > 0) {
		return fmt.Errorf("a rule covering every service cannot also list services")
	}
	if strings.ContainsAny(s.Description, "\n\r") {
		return fmt.Errorf("the description contains a newline")
	}
	return nil
}

// SudoRuleSpec declares the wanted state of a sudo rule.
type SudoRuleSpec struct {
	Name        string
	Description string
	Enabled     bool
	Users       []string
	UserGroups  []string
	Hosts       []string
	HostGroups  []string
	// Commands are the allowed commands, as full paths.
	Commands      []string
	CommandGroups []string
	RunAsUsers    []string
	RunAsGroups   []string
	// Options are sudo options such as "!authenticate".
	Options []string
	// AllUsers, AllHosts and AllCommands set the category of the rule to
	// "all"; RunAsAnyUser allows acting as any user.
	AllUsers     bool
	AllHosts     bool
	AllCommands  bool
	RunAsAnyUser bool
}

// sudoOptionNames are the sudo options the panel writes.
var sudoOptionNames = []string{
	"authenticate", "requiretty", "env_reset", "env_keep", "env_check", "env_delete",
	"setenv", "noexec", "log_input", "log_output", "mail_badpass", "mail_always",
	"use_pty", "timestamp_timeout", "passwd_tries", "passwd_timeout", "umask",
	"secure_path", "logfile", "iolog_dir", "iolog_file", "lecture", "root_sudo",
	"visiblepw", "preserve_groups", "shell_noargs", "set_home", "always_set_home",
	"editor", "runcwd", "runchroot", "closefrom", "verifypw", "listpw", "exempt_group",
	"ignore_dot", "tty_tickets", "pwfeedback", "fqdn", "insults", "mailto", "mailsub",
	"badpass_message", "apparmor_profile", "selinux", "role", "type",
}

// ValidateSudoOption checks that an option has a known name. The form is
// "name", "!name" or "name=value".
func ValidateSudoOption(option string) error {
	trimmed := strings.TrimSpace(option)
	if trimmed == "" {
		return fmt.Errorf("empty sudo option")
	}
	if strings.ContainsAny(trimmed, "\n\r") {
		return fmt.Errorf("the sudo option %q contains a newline", option)
	}
	if strings.EqualFold(trimmed, "NOPASSWD") {
		// NOPASSWD is a tag of the sudoers file; the directory expresses it
		// as the option "!authenticate".
		return fmt.Errorf("NOPASSWD is not a directory option; use !authenticate")
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(trimmed, "!"), "=")
	if !slices.Contains(sudoOptionNames, name) {
		return fmt.Errorf("unknown sudo option %q", name)
	}
	return nil
}

// Validate checks the declaration before anything goes to the directory.
func (s SudoRuleSpec) Validate() error {
	if !ruleNamePattern.MatchString(s.Name) {
		return fmt.Errorf("invalid rule name %q", s.Name)
	}
	if err := validateMembers(s.Users, userNamePattern, "account"); err != nil {
		return err
	}
	if err := validateMembers(s.UserGroups, groupNamePattern, "group"); err != nil {
		return err
	}
	if err := validateMembers(s.Hosts, hostNamePattern, "host"); err != nil {
		return err
	}
	if err := validateMembers(s.HostGroups, groupNamePattern, "host group"); err != nil {
		return err
	}
	for _, command := range s.Commands {
		// A command without a path is resolved on the host at the moment of
		// use; the rule would then allow whatever stands first on the PATH.
		if !strings.HasPrefix(command, "/") || strings.ContainsAny(command, "\n\r") || len(command) > 255 {
			return fmt.Errorf("the sudo command %q is not an absolute path", command)
		}
	}
	if err := validateMembers(s.CommandGroups, groupNamePattern, "command group"); err != nil {
		return err
	}
	if err := validateMembers(s.RunAsUsers, userNamePattern, "run-as account"); err != nil {
		return err
	}
	if err := validateMembers(s.RunAsGroups, groupNamePattern, "run-as group"); err != nil {
		return err
	}
	for _, option := range s.Options {
		if err := ValidateSudoOption(option); err != nil {
			return err
		}
	}
	if s.AllUsers && (len(s.Users) > 0 || len(s.UserGroups) > 0) {
		return fmt.Errorf("a rule covering every user cannot also list users")
	}
	if s.AllHosts && (len(s.Hosts) > 0 || len(s.HostGroups) > 0) {
		return fmt.Errorf("a rule covering every host cannot also list hosts")
	}
	if s.AllCommands && (len(s.Commands) > 0 || len(s.CommandGroups) > 0) {
		return fmt.Errorf("a rule covering every command cannot also list commands")
	}
	if s.RunAsAnyUser && len(s.RunAsUsers) > 0 {
		return fmt.Errorf("a rule acting as any user cannot also list run-as accounts")
	}
	if strings.ContainsAny(s.Description, "\n\r") {
		return fmt.Errorf("the description contains a newline")
	}
	return nil
}

func validateMembers(values []string, pattern *regexp.Regexp, kind string) error {
	for _, value := range values {
		if !pattern.MatchString(value) {
			return fmt.Errorf("invalid %s name %q", kind, value)
		}
	}
	return nil
}

// HBACTestResult is the verdict of the directory's own simulation.
type HBACTestResult struct {
	User    string `json:"user"`
	Host    string `json:"host"`
	Service string `json:"service"`
	// Allowed is the verdict: whether at least one enabled rule matched.
	Allowed bool `json:"allowed"`
	// Matched and NotMatched name the rules the directory evaluated.
	Matched    []string `json:"matched"`
	NotMatched []string `json:"not_matched"`
	// Errors names rules the directory could not evaluate; Warnings carries its
	// remarks.
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// HostGroups returns the host groups of the directory.
func (c *Client) HostGroups(ctx context.Context) ([]HostGroup, error) {
	return cached(ctx, c, "hostgroups", func() ([]HostGroup, error) {
		records, err := c.findRecords(ctx, "hostgroup_find")
		if err != nil {
			return nil, err
		}
		groups := make([]HostGroup, 0, len(records))
		for _, record := range records {
			groups = append(groups, HostGroup{
				Name:        first(record, "cn"),
				Description: first(record, "description"),
				Hosts:       strings_(record, "member_host"),
				HostGroups:  strings_(record, "member_hostgroup"),
			})
		}
		return groups, nil
	})
}

// HBACTest asks the directory whether the user may use the service on the
// host.
func (c *Client) HBACTest(ctx context.Context, user, host, service string) (HBACTestResult, error) {
	result := HBACTestResult{User: user, Host: host, Service: service}
	if !userNamePattern.MatchString(user) {
		return result, fmt.Errorf("invalid account name %q", user)
	}
	if !hostNamePattern.MatchString(host) {
		return result, fmt.Errorf("invalid host name %q", host)
	}
	if !serviceNamePattern.MatchString(service) {
		return result, fmt.Errorf("invalid service name %q", service)
	}
	raw, err := c.call(ctx, "hbactest", nil, map[string]any{
		"user":       user,
		"targethost": host,
		"service":    service,
	})
	if err != nil {
		return result, fmt.Errorf("simulating the access of %s to %s: %w", user, host, err)
	}
	var decoded struct {
		Value      bool     `json:"value"`
		Matched    []any    `json:"matched"`
		NotMatched []any    `json:"notmatched"`
		Error      []any    `json:"error"`
		Warning    []string `json:"warning"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return result, fmt.Errorf("the hbactest response: %w", err)
	}
	result.Allowed = decoded.Value
	result.Matched = ruleNames(decoded.Matched)
	result.NotMatched = ruleNames(decoded.NotMatched)
	result.Errors = ruleNames(decoded.Error)
	result.Warnings = decoded.Warning
	return result, nil
}

// ruleNames reads the rule names out of an hbactest list.
func ruleNames(items []any) []string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		switch value := item.(type) {
		case string:
			names = append(names, value)
		case map[string]any:
			if name := first(value, "cn"); name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

// ShowHBACRule reads one access rule; nil means the directory has no such rule.
func (c *Client) ShowHBACRule(ctx context.Context, name string) (*HBACRule, error) {
	record, err := c.showRule(ctx, "hbacrule_show", name)
	if err != nil || record == nil {
		return nil, err
	}
	rule := hbacRuleFromRecord(record)
	return &rule, nil
}

// ShowSudoRule reads one sudo rule; nil means the directory has no such rule.
func (c *Client) ShowSudoRule(ctx context.Context, name string) (*SudoRule, error) {
	record, err := c.showRule(ctx, "sudorule_show", name)
	if err != nil || record == nil {
		return nil, err
	}
	rule := sudoRuleFromRecord(record)
	return &rule, nil
}

func (c *Client) showRule(ctx context.Context, method, name string) (map[string]any, error) {
	if !ruleNamePattern.MatchString(name) {
		return nil, fmt.Errorf("invalid rule name %q", name)
	}
	result, err := c.call(ctx, method, []string{name}, map[string]any{"all": true})
	if err != nil {
		// A missing rule is a state of the directory, not a failure of the
		// read: the caller decides whether to create it.
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var decoded struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, fmt.Errorf("the %s response: %w", method, err)
	}
	return decoded.Result, nil
}

// isNotFound recognises the directory's answer for a missing object. The
// directory names the error NotFound and the message ends in "not found".
func isNotFound(err error) bool {
	text := err.Error()
	return strings.Contains(text, "(NotFound)") || strings.Contains(text, "not found")
}

// isEmptyModification recognises a modification that changed nothing.
func isEmptyModification(err error) bool {
	text := err.Error()
	return strings.Contains(text, "(EmptyModError)") || strings.Contains(text, "no modifications")
}

// EnsureHBACRule brings the rule to the declared state and returns it as the
// directory holds it afterwards.
func (c *Client) EnsureHBACRule(ctx context.Context, spec HBACRuleSpec) (*HBACRule, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	current, err := c.ShowHBACRule(ctx, spec.Name)
	if err != nil {
		return nil, fmt.Errorf("reading the HBAC rule %s: %w", spec.Name, err)
	}
	// Every step from here on changes the directory, so the cache is stale
	// whatever happens next - also after a failure half-way through.
	defer c.invalidate()

	if current == nil {
		options := map[string]any{}
		if spec.Description != "" {
			options["description"] = spec.Description
		}
		if _, err := c.call(ctx, "hbacrule_add", []string{spec.Name}, options); err != nil {
			return nil, fmt.Errorf("creating the HBAC rule %s: %w", spec.Name, err)
		}
		current = &HBACRule{Name: spec.Name, Enabled: true}
	} else {
		options := map[string]any{}
		if current.Description != spec.Description {
			options["description"] = nullable(spec.Description)
		}
		// Clearing a category first makes room for the members it excluded.
		if current.AllUsers && !spec.AllUsers {
			options["usercategory"] = nil
		}
		if current.AllHosts && !spec.AllHosts {
			options["hostcategory"] = nil
		}
		if current.AllServices && !spec.AllServices {
			options["servicecategory"] = nil
		}
		if err := c.modifyRule(ctx, "hbacrule_mod", spec.Name, options); err != nil {
			return nil, err
		}
	}

	steps := []memberStep{
		{"hbacrule_remove_user", "user", diff(current.Users, spec.Users).removed},
		{"hbacrule_remove_user", "group", diff(current.UserGroups, spec.UserGroups).removed},
		{"hbacrule_remove_host", "host", diff(current.Hosts, spec.Hosts).removed},
		{"hbacrule_remove_host", "hostgroup", diff(current.HostGroups, spec.HostGroups).removed},
		{"hbacrule_remove_service", "hbacsvc", diff(current.Services, spec.Services).removed},
		{"hbacrule_remove_service", "hbacsvcgroup", diff(current.ServiceGroups, spec.ServiceGroups).removed},
		{"hbacrule_add_user", "user", diff(current.Users, spec.Users).added},
		{"hbacrule_add_user", "group", diff(current.UserGroups, spec.UserGroups).added},
		{"hbacrule_add_host", "host", diff(current.Hosts, spec.Hosts).added},
		{"hbacrule_add_host", "hostgroup", diff(current.HostGroups, spec.HostGroups).added},
		{"hbacrule_add_service", "hbacsvc", diff(current.Services, spec.Services).added},
		{"hbacrule_add_service", "hbacsvcgroup", diff(current.ServiceGroups, spec.ServiceGroups).added},
	}
	for _, step := range steps {
		if err := c.changeRuleMembers(ctx, step.method, spec.Name, step.kind, step.names); err != nil {
			return nil, err
		}
	}

	categories := map[string]any{}
	if spec.AllUsers && !current.AllUsers {
		categories["usercategory"] = "all"
	}
	if spec.AllHosts && !current.AllHosts {
		categories["hostcategory"] = "all"
	}
	if spec.AllServices && !current.AllServices {
		categories["servicecategory"] = "all"
	}
	if err := c.modifyRule(ctx, "hbacrule_mod", spec.Name, categories); err != nil {
		return nil, err
	}

	if err := c.setRuleEnabled(ctx, "hbacrule", spec.Name, current.Enabled, spec.Enabled); err != nil {
		return nil, err
	}
	return c.ShowHBACRule(ctx, spec.Name)
}

// RemoveHBACRule deletes an access rule. A rule that does not exist is not
// an error: the wanted state holds.
func (c *Client) RemoveHBACRule(ctx context.Context, name string) error {
	return c.removeRule(ctx, "hbacrule_del", name)
}

// EnsureSudoRule brings the sudo rule to the declared state and returns it
// as the directory holds it afterwards. The order follows EnsureHBACRule.
func (c *Client) EnsureSudoRule(ctx context.Context, spec SudoRuleSpec) (*SudoRule, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	current, err := c.ShowSudoRule(ctx, spec.Name)
	if err != nil {
		return nil, fmt.Errorf("reading the sudo rule %s: %w", spec.Name, err)
	}
	defer c.invalidate()

	if current == nil {
		options := map[string]any{}
		if spec.Description != "" {
			options["description"] = spec.Description
		}
		if _, err := c.call(ctx, "sudorule_add", []string{spec.Name}, options); err != nil {
			return nil, fmt.Errorf("creating the sudo rule %s: %w", spec.Name, err)
		}
		current = &SudoRule{Name: spec.Name, Enabled: true}
	} else {
		options := map[string]any{}
		if current.Description != spec.Description {
			options["description"] = nullable(spec.Description)
		}
		if current.AllUsers && !spec.AllUsers {
			options["usercategory"] = nil
		}
		if current.AllHosts && !spec.AllHosts {
			options["hostcategory"] = nil
		}
		if current.AllCommands && !spec.AllCommands {
			options["cmdcategory"] = nil
		}
		if current.RunAsAnyUser && !spec.RunAsAnyUser {
			options["ipasudorunasusercategory"] = nil
		}
		if err := c.modifyRule(ctx, "sudorule_mod", spec.Name, options); err != nil {
			return nil, err
		}
	}

	steps := []memberStep{
		{"sudorule_remove_user", "user", diff(current.Users, spec.Users).removed},
		{"sudorule_remove_user", "group", diff(current.UserGroups, spec.UserGroups).removed},
		{"sudorule_remove_host", "host", diff(current.Hosts, spec.Hosts).removed},
		{"sudorule_remove_host", "hostgroup", diff(current.HostGroups, spec.HostGroups).removed},
		{"sudorule_remove_allow_command", "sudocmd", diff(current.Commands, spec.Commands).removed},
		{"sudorule_remove_allow_command", "sudocmdgroup", diff(current.CommandGroups, spec.CommandGroups).removed},
		{"sudorule_remove_runasuser", "user", diff(current.RunAs, spec.RunAsUsers).removed},
		{"sudorule_remove_runasgroup", "group", diff(current.RunAsGroups, spec.RunAsGroups).removed},
		{"sudorule_add_user", "user", diff(current.Users, spec.Users).added},
		{"sudorule_add_user", "group", diff(current.UserGroups, spec.UserGroups).added},
		{"sudorule_add_host", "host", diff(current.Hosts, spec.Hosts).added},
		{"sudorule_add_host", "hostgroup", diff(current.HostGroups, spec.HostGroups).added},
		{"sudorule_add_allow_command", "sudocmd", diff(current.Commands, spec.Commands).added},
		{"sudorule_add_allow_command", "sudocmdgroup", diff(current.CommandGroups, spec.CommandGroups).added},
		{"sudorule_add_runasuser", "user", diff(current.RunAs, spec.RunAsUsers).added},
		{"sudorule_add_runasgroup", "group", diff(current.RunAsGroups, spec.RunAsGroups).added},
	}
	for _, step := range steps {
		if err := c.changeRuleMembers(ctx, step.method, spec.Name, step.kind, step.names); err != nil {
			return nil, err
		}
	}

	// The directory takes one option per call.
	options := diff(current.Options, spec.Options)
	for _, option := range options.removed {
		if _, err := c.call(ctx, "sudorule_remove_option", []string{spec.Name},
			map[string]any{"ipasudoopt": option}); err != nil {
			return nil, fmt.Errorf("removing the option %s from the sudo rule %s: %w", option, spec.Name, err)
		}
	}
	for _, option := range options.added {
		if _, err := c.call(ctx, "sudorule_add_option", []string{spec.Name},
			map[string]any{"ipasudoopt": option}); err != nil {
			return nil, fmt.Errorf("adding the option %s to the sudo rule %s: %w", option, spec.Name, err)
		}
	}

	categories := map[string]any{}
	if spec.AllUsers && !current.AllUsers {
		categories["usercategory"] = "all"
	}
	if spec.AllHosts && !current.AllHosts {
		categories["hostcategory"] = "all"
	}
	if spec.AllCommands && !current.AllCommands {
		categories["cmdcategory"] = "all"
	}
	if spec.RunAsAnyUser && !current.RunAsAnyUser {
		categories["ipasudorunasusercategory"] = "all"
	}
	if err := c.modifyRule(ctx, "sudorule_mod", spec.Name, categories); err != nil {
		return nil, err
	}

	if err := c.setRuleEnabled(ctx, "sudorule", spec.Name, current.Enabled, spec.Enabled); err != nil {
		return nil, err
	}
	return c.ShowSudoRule(ctx, spec.Name)
}

// RemoveSudoRule deletes a sudo rule. A rule that does not exist is not an
// error: the wanted state holds.
func (c *Client) RemoveSudoRule(ctx context.Context, name string) error {
	return c.removeRule(ctx, "sudorule_del", name)
}

func (c *Client) removeRule(ctx context.Context, method, name string) error {
	if !ruleNamePattern.MatchString(name) {
		return fmt.Errorf("invalid rule name %q", name)
	}
	defer c.invalidate()
	if _, err := c.call(ctx, method, []string{name}, nil); err != nil && !isNotFound(err) {
		return fmt.Errorf("removing the rule %s: %w", name, err)
	}
	return nil
}

// modifyRule sends a modification and treats "nothing changed" as success.
func (c *Client) modifyRule(ctx context.Context, method, name string, options map[string]any) error {
	if len(options) == 0 {
		return nil
	}
	if _, err := c.call(ctx, method, []string{name}, options); err != nil && !isEmptyModification(err) {
		return fmt.Errorf("modifying the rule %s: %w", name, err)
	}
	return nil
}

// setRuleEnabled switches the rule with the dedicated commands. The flag
// attribute changed its type between directory versions; the commands did not.
func (c *Client) setRuleEnabled(ctx context.Context, family, name string, current, wanted bool) error {
	if current == wanted {
		return nil
	}
	method := family + "_disable"
	if wanted {
		method = family + "_enable"
	}
	if _, err := c.call(ctx, method, []string{name}, nil); err != nil {
		if strings.Contains(err.Error(), "already") {
			return nil
		}
		return fmt.Errorf("changing the state of the rule %s: %w", name, err)
	}
	return nil
}

type memberStep struct {
	method string
	kind   string
	names  []string
}

// changeRuleMembers adds or removes members of one kind.
func (c *Client) changeRuleMembers(ctx context.Context, method, name, kind string, members []string) error {
	if len(members) == 0 {
		return nil
	}
	result, err := c.call(ctx, method, []string{name}, map[string]any{kind: members})
	if err != nil {
		return fmt.Errorf("%s of the rule %s: %w", strings.ReplaceAll(method, "_", " "), name, err)
	}
	if problems := failedMembers(result); len(problems) > 0 {
		return fmt.Errorf("%s of the rule %s: some members were not changed: %s",
			strings.ReplaceAll(method, "_", " "), name, strings.Join(problems, "; "))
	}
	return nil
}

// failedMembers reads the "failed" list of a membership command.
func failedMembers(result json.RawMessage) []string {
	var decoded struct {
		Failed map[string]map[string][]any `json:"failed"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil
	}
	var problems []string
	for _, category := range decoded.Failed {
		for _, entries := range category {
			for _, entry := range entries {
				problems = append(problems, fmt.Sprint(entry))
			}
		}
	}
	slices.Sort(problems)
	return problems
}

// memberDiff is the difference between the current and the declared members.
type memberDiff struct {
	added   []string
	removed []string
}

// diff compares two member lists regardless of order and duplicates.
func diff(current, wanted []string) memberDiff {
	var result memberDiff
	for _, name := range wanted {
		if !slices.Contains(current, name) && !slices.Contains(result.added, name) {
			result.added = append(result.added, name)
		}
	}
	for _, name := range current {
		if !slices.Contains(wanted, name) && !slices.Contains(result.removed, name) {
			result.removed = append(result.removed, name)
		}
	}
	return result
}

// nullable turns an empty string into null, which the directory reads as
// "remove the attribute".
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// hbacRuleFromRecord reads an access rule out of a directory record.
func hbacRuleFromRecord(record map[string]any) HBACRule {
	rule := HBACRule{
		Name:          first(record, "cn"),
		Description:   first(record, "description"),
		Enabled:       boolean(record, "ipaenabledflag"),
		Users:         strings_(record, "memberuser_user"),
		UserGroups:    strings_(record, "memberuser_group"),
		Hosts:         strings_(record, "memberhost_host"),
		HostGroups:    strings_(record, "memberhost_hostgroup"),
		Services:      strings_(record, "memberservice_hbacsvc"),
		ServiceGroups: strings_(record, "memberservice_hbacsvcgroup"),
		AllUsers:      first(record, "usercategory") == "all",
		AllHosts:      first(record, "hostcategory") == "all",
		AllServices:   first(record, "servicecategory") == "all",
	}
	// A rule covering everybody, every host and every service opens access
	// to the whole fleet with one entry.
	rule.AllowsEverything = rule.AllUsers && rule.AllHosts && rule.AllServices
	return rule
}

// sudoRuleFromRecord reads a sudo rule out of a directory record.
func sudoRuleFromRecord(record map[string]any) SudoRule {
	rule := SudoRule{
		Name:          first(record, "cn"),
		Description:   first(record, "description"),
		Enabled:       boolean(record, "ipaenabledflag"),
		Users:         strings_(record, "memberuser_user"),
		UserGroups:    strings_(record, "memberuser_group"),
		Hosts:         strings_(record, "memberhost_host"),
		HostGroups:    strings_(record, "memberhost_hostgroup"),
		Commands:      strings_(record, "memberallowcmd_sudocmd"),
		CommandGroups: strings_(record, "memberallowcmd_sudocmdgroup"),
		// root is not an account of the directory, so the directory keeps
		// it as an external run-as user; the rule reads the same either way.
		RunAs:        append(strings_(record, "ipasudorunas_user"), strings_(record, "ipasudorunasextuser")...),
		RunAsGroups:  append(strings_(record, "ipasudorunasgroup_group"), strings_(record, "ipasudorunasextgroup")...),
		Options:      strings_(record, "ipasudoopt"),
		AllUsers:     first(record, "usercategory") == "all",
		AllHosts:     first(record, "hostcategory") == "all",
		AllCommands:  first(record, "cmdcategory") == "all",
		RunAsAnyUser: first(record, "ipasudorunasusercategory") == "all",
	}
	rule.Critical, rule.CriticalReasons = sudoRisk(record, rule)
	return rule
}
