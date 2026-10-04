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

// The outcome of a rule change that stopped half-way.
const (
	// RuleRestored: the rule carries the state it carried before the change,
	// the enabled flag included.
	RuleRestored = "hbac_rule_restored"
	// RuleWithdrawn: the rule was being created, so it is not in the directory -
	// it was taken out again, or it was never added.
	RuleWithdrawn = "hbac_rule_withdrawn"
	// RuleRestoreFailed: the previous state could not be put back, so what the
	// rule carries is nobody's decision any more. The loudest of the outcomes.
	RuleRestoreFailed = "hbac_rule_restore_failed"
)

// RuleChangeError reports a rule change that did not go through: the step that
// failed, and what became of the rule afterwards.
type RuleChangeError struct {
	// Rule is the name of the rule; Step names the part of the change that failed.
	Rule string
	Step string
	// Outcome is RuleRestored, RuleWithdrawn or RuleRestoreFailed.
	Outcome string
	// Err is the failure that stopped the change; Restore says why the previous
	// state could not be put back, when it could not.
	Err     error
	Restore error
}

func (e *RuleChangeError) Error() string {
	if e.Restore != nil {
		return fmt.Sprintf("the rule %s, %s: %v; the previous state could not be put back: %v [%s]",
			e.Rule, e.Step, e.Err, e.Restore, e.Outcome)
	}
	return fmt.Sprintf("the rule %s, %s: %v [%s]", e.Rule, e.Step, e.Err, e.Outcome)
}

func (e *RuleChangeError) Unwrap() error { return e.Err }

// EnsureHBACRule brings the rule to the declared state and returns it as the
// directory holds it afterwards. The rule grants nothing while the change runs:
// it is created, or taken out of service, disabled, and it is enabled only once
// the directory answers with the declared state.
func (c *Client) EnsureHBACRule(ctx context.Context, spec HBACRuleSpec) (*HBACRule, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	before, err := c.ShowHBACRule(ctx, spec.Name)
	if err != nil {
		return nil, fmt.Errorf("reading the HBAC rule %s: %w", spec.Name, err)
	}
	// Every step from here on changes the directory, so the cache is stale
	// whatever happens next - also after a failure half-way through.
	defer c.invalidate()

	if step, err := c.applyHBACRule(ctx, spec, before); err != nil {
		if before == nil && step == stepCreateRule {
			// The rule was never added, so there is nothing to take back - and a
			// rule of that name that appeared meanwhile is not this change's.
			return nil, &RuleChangeError{Rule: spec.Name, Step: step, Outcome: RuleWithdrawn, Err: err}
		}
		return nil, c.restoreHBACRule(ctx, spec.Name, step, err, before)
	}

	// The flag is set on the strength of what the directory answers, not of what
	// the change believes it sent: a member the directory dropped would otherwise
	// be enabled along with the rest.
	const readBack = "comparing the rule read back with the declaration"
	rule, err := c.ShowHBACRule(ctx, spec.Name)
	if err != nil {
		return nil, c.restoreHBACRule(ctx, spec.Name, readBack, err, before)
	}
	if rule == nil {
		return nil, c.restoreHBACRule(ctx, spec.Name, readBack,
			fmt.Errorf("the directory no longer holds the rule"), before)
	}
	if gaps := hbacRuleDifferences(*rule, spec); len(gaps) > 0 {
		return nil, c.restoreHBACRule(ctx, spec.Name, readBack,
			fmt.Errorf("the rule is incomplete: %s", strings.Join(gaps, "; ")), before)
	}
	if !spec.Enabled {
		return rule, nil
	}
	if err := c.setRuleEnabled(ctx, "hbacrule", spec.Name, false, true); err != nil {
		return nil, c.restoreHBACRule(ctx, spec.Name, "enabling the rule", err, before)
	}
	enabled, err := c.ShowHBACRule(ctx, spec.Name)
	if err != nil {
		return nil, fmt.Errorf("reading the HBAC rule %s back: %w", spec.Name, err)
	}
	if enabled == nil || !enabled.Enabled {
		return nil, c.restoreHBACRule(ctx, spec.Name, "enabling the rule",
			fmt.Errorf("the rule reads back disabled although the directory accepted the change"), before)
	}
	return enabled, nil
}

// applyHBACRule writes the declared members and categories with the rule
// disabled. It names the step that failed, if one did.
func (c *Client) applyHBACRule(ctx context.Context, spec HBACRuleSpec, current *HBACRule) (string, error) {
	for _, step := range c.hbacRuleSteps(spec, current) {
		if err := step.run(ctx); err != nil {
			return step.name, err
		}
	}
	return "", nil
}

// hbacRuleSteps is the change broken into the directory commands it takes, in
// the order the directory accepts them.
func (c *Client) hbacRuleSteps(spec HBACRuleSpec, current *HBACRule) []ruleStep {
	var steps []ruleStep
	if current == nil {
		current = &HBACRule{Name: spec.Name}
		options := map[string]any{}
		if spec.Description != "" {
			options["description"] = spec.Description
		}
		steps = append(steps, ruleStep{stepCreateRule, func(ctx context.Context) error {
			if _, err := c.call(ctx, "hbacrule_add", []string{spec.Name}, options); err != nil {
				return fmt.Errorf("creating the HBAC rule %s: %w", spec.Name, err)
			}
			return nil
		}})
		// The directory creates a rule enabled, so it would take part in the
		// decision before it has a single member.
		steps = append(steps, ruleStep{"disabling the new rule", func(ctx context.Context) error {
			return c.setRuleEnabled(ctx, "hbacrule", spec.Name, true, false)
		}})
	} else {
		if current.Enabled {
			// A rule being changed grants whatever its half-written members say,
			// so it comes out of service until the new state is confirmed.
			steps = append(steps, ruleStep{"taking the rule out of service", func(ctx context.Context) error {
				return c.setRuleEnabled(ctx, "hbacrule", spec.Name, true, false)
			}})
		}
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
		steps = append(steps, ruleStep{"clearing the categories the declaration drops", func(ctx context.Context) error {
			return c.modifyRule(ctx, "hbacrule_mod", spec.Name, options)
		}})
	}

	members := []memberStep{
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
	for _, member := range members {
		steps = append(steps, ruleStep{hbacMemberLabel(member.method, member.kind), func(ctx context.Context) error {
			return c.changeRuleMembers(ctx, member.method, spec.Name, member.kind, member.names)
		}})
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
	steps = append(steps, ruleStep{"setting the categories", func(ctx context.Context) error {
		return c.modifyRule(ctx, "hbacrule_mod", spec.Name, categories)
	}})
	return steps
}

// restoreHBACRule puts the rule back the way it stood before the change and
// returns the error that tells both halves of the story.
func (c *Client) restoreHBACRule(ctx context.Context, name, step string, cause error, before *HBACRule) error {
	failure := &RuleChangeError{Rule: name, Step: step, Err: cause}
	if before == nil {
		// The directory held no such rule before the change, so that is the
		// state to go back to.
		if err := c.removeRule(ctx, "hbacrule_del", name); err != nil {
			failure.Outcome, failure.Restore = RuleRestoreFailed, err
			return failure
		}
		failure.Outcome = RuleWithdrawn
		return failure
	}
	if err := c.restoreHBACState(ctx, *before); err != nil {
		failure.Outcome, failure.Restore = RuleRestoreFailed, err
		return failure
	}
	failure.Outcome = RuleRestored
	return failure
}

// restoreHBACState writes the previous state back whole - members, categories
// and description - and only then the enabled flag the rule had.
func (c *Client) restoreHBACState(ctx context.Context, before HBACRule) error {
	now, err := c.ShowHBACRule(ctx, before.Name)
	if err != nil {
		return err
	}
	if now == nil {
		return fmt.Errorf("the directory no longer holds the rule")
	}
	wanted := hbacSpecOf(before)
	wanted.Enabled = false
	if step, err := c.applyHBACRule(ctx, wanted, now); err != nil {
		return fmt.Errorf("%s: %w", step, err)
	}
	back, err := c.ShowHBACRule(ctx, before.Name)
	if err != nil {
		return err
	}
	if back == nil {
		return fmt.Errorf("the directory no longer holds the rule")
	}
	if gaps := hbacRuleDifferences(*back, wanted); len(gaps) > 0 {
		return fmt.Errorf("the previous state did not come back whole: %s", strings.Join(gaps, "; "))
	}
	return c.setRuleEnabled(ctx, "hbacrule", before.Name, false, before.Enabled)
}

// hbacSpecOf reads a rule as a declaration of itself, so that the state before
// a change can be written back with the same path that changed it.
func hbacSpecOf(rule HBACRule) HBACRuleSpec {
	return HBACRuleSpec{
		Name: rule.Name, Description: rule.Description, Enabled: rule.Enabled,
		Users: rule.Users, UserGroups: rule.UserGroups,
		Hosts: rule.Hosts, HostGroups: rule.HostGroups,
		Services: rule.Services, ServiceGroups: rule.ServiceGroups,
		AllUsers: rule.AllUsers, AllHosts: rule.AllHosts, AllServices: rule.AllServices,
	}
}

// hbacRuleDifferences names where the rule the directory holds departs from the
// declaration. The enabled flag is left out: it is what the comparison decides.
func hbacRuleDifferences(rule HBACRule, spec HBACRuleSpec) []string {
	var differences []string
	if rule.Description != spec.Description {
		differences = append(differences,
			fmt.Sprintf("the description reads %q, declared %q", rule.Description, spec.Description))
	}
	members := []struct {
		kind         string
		held, wanted []string
	}{
		{"users", rule.Users, spec.Users},
		{"user groups", rule.UserGroups, spec.UserGroups},
		{"hosts", rule.Hosts, spec.Hosts},
		{"host groups", rule.HostGroups, spec.HostGroups},
		{"services", rule.Services, spec.Services},
		{"service groups", rule.ServiceGroups, spec.ServiceGroups},
	}
	for _, member := range members {
		missing, extra := memberGap(member.held, member.wanted)
		if len(missing) > 0 {
			differences = append(differences,
				fmt.Sprintf("the %s %s are not in the rule", member.kind, strings.Join(missing, ", ")))
		}
		if len(extra) > 0 {
			differences = append(differences,
				fmt.Sprintf("the %s %s are in the rule and not declared", member.kind, strings.Join(extra, ", ")))
		}
	}
	categories := []struct {
		kind         string
		held, wanted bool
	}{
		{"user", rule.AllUsers, spec.AllUsers},
		{"host", rule.AllHosts, spec.AllHosts},
		{"service", rule.AllServices, spec.AllServices},
	}
	for _, category := range categories {
		if category.held != category.wanted {
			differences = append(differences,
				fmt.Sprintf("the rule covers every %s: %t, declared %t", category.kind, category.held, category.wanted))
		}
	}
	return differences
}

// memberGap compares two member lists ignoring order and letter case: the
// directory answers with the name of the entry it found, not with the name the
// declaration spelled.
func memberGap(held, wanted []string) (missing, extra []string) {
	folded := func(names []string) []string {
		out := make([]string, 0, len(names))
		for _, name := range names {
			out = append(out, strings.ToLower(strings.TrimSpace(name)))
		}
		return out
	}
	inRule, declared := folded(held), folded(wanted)
	for index, name := range declared {
		if !slices.Contains(inRule, name) {
			missing = append(missing, wanted[index])
		}
	}
	for index, name := range inRule {
		if !slices.Contains(declared, name) {
			extra = append(extra, held[index])
		}
	}
	return missing, extra
}

// hbacMemberNames spell out a member kind for the name of a step.
var hbacMemberNames = map[string]string{
	"user": "users", "group": "user groups", "host": "hosts",
	"hostgroup": "host groups", "hbacsvc": "services", "hbacsvcgroup": "service groups",
}

func hbacMemberLabel(method, kind string) string {
	verb := "adding"
	if strings.Contains(method, "_remove_") {
		verb = "removing"
	}
	name := hbacMemberNames[kind]
	if name == "" {
		name = kind
	}
	return verb + " the " + name
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

// ruleStep is one command of a rule change, named so that a failure can say
// where the change stopped.
type ruleStep struct {
	name string
	run  func(ctx context.Context) error
}

// stepCreateRule is the step that adds the entry: the one step a failure leaves
// nothing behind to put back.
const stepCreateRule = "creating the rule"

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
