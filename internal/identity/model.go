// Package identity carries out changes in the identity directory: the plan,
// the approval and an execution made of phases. Creating a user is one
// business transaction of the panel but several operations of the
// directory.
package identity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// ActionType is the type of a change in the directory.
type ActionType string

const (
	ActionUserCreate   ActionType = "identity.user.create"
	ActionUserDisable  ActionType = "identity.user.disable"
	ActionUserEnable   ActionType = "identity.user.enable"
	ActionGroupMembers ActionType = "identity.group.members"
	ActionSSHKeys      ActionType = "identity.sshkeys.set"
	// The rest of the user lifecycle the document names: an expiration, the
	// POSIX attributes, a removal that keeps the entry, and a password reset
	// whose one-time value the requester reads once and nobody stores.
	ActionUserExpire        ActionType = "identity.user.expire"
	ActionUserPOSIX         ActionType = "identity.user.posix"
	ActionUserPreserve      ActionType = "identity.user.preserve"
	ActionUserPasswordReset ActionType = "identity.user.password.reset"
	// Host group membership decides which access and sudo rules reach a
	// host, so it goes the way of a user group change.
	ActionHostGroupMembers ActionType = "identity.hostgroup.members"
	// Directory DNS is a central change, just like an account: it concerns
	// the whole network rather than one host and goes in one transaction
	// through the directory connector - not through an agent.
	ActionDNSRecordEnsure ActionType = "dns.record.ensure"
	ActionDNSRecordRemove ActionType = "dns.record.remove"
	// The access and sudo rules. A rule reaches every host it names, so it
	// goes the same way as an account: plan, a second person, execution.
	ActionHBACRuleEnsure ActionType = "identity.hbac.rule.ensure"
	ActionHBACRuleRemove ActionType = "identity.hbac.rule.remove"
	ActionSudoRuleEnsure ActionType = "identity.sudo.rule.ensure"
	ActionSudoRuleRemove ActionType = "identity.sudo.rule.remove"
	// ActionHBACTest is a read: the directory's own simulation of an access
	// rule. It is never a change and never enters the change store; it is
	// named here so its permission stands next to the rules it reads.
	ActionHBACTest ActionType = "identity.hbac.test"
	// A service keytab rotation has two halves under one consent: the
	// directory retires the current keytab of the principal, and the fleet
	// host that carries the service fetches a new one with its own
	// credentials. No key material passes through the panel; the change
	// records the retirement and the task it ordered on the host.
	ActionKeytabRotate ActionType = "identity.keytab.rotate"
)

// State is the state of a change.
type State string

const (
	StatePlanned          State = "planned"
	StateAwaitingApproval State = "awaiting_approval"
	StateRunning          State = "running"
	StateSucceeded        State = "succeeded"
	// StatePartiallyApplied marks a change some of whose phases succeeded.
	// The document forbids presenting such a result as a success.
	StatePartiallyApplied State = "partially_applied"
	StateFailed           State = "failed"
	StateCanceled         State = "canceled"
)

// Terminal says whether the state is final.
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StatePartiallyApplied, StateFailed, StateCanceled:
		return true
	default:
		return false
	}
}

// Payload is the sum of the change types. Exactly one field is filled in.
type Payload struct {
	User      *UserPayload      `json:"user,omitempty"`
	Group     *GroupPayload     `json:"group,omitempty"`
	HostGroup *HostGroupPayload `json:"host_group,omitempty"`
	SSHKeys   *SSHKeysPayload   `json:"ssh_keys,omitempty"`
	Reference *ReferencePayload `json:"reference,omitempty"`
	Expiry    *ExpiryPayload    `json:"expiry,omitempty"`
	POSIX     *POSIXPayload     `json:"posix,omitempty"`
	DNS       *DNSRecordPayload `json:"dns,omitempty"`
	HBACRule  *HBACRulePayload  `json:"hbac_rule,omitempty"`
	SudoRule  *SudoRulePayload  `json:"sudo_rule,omitempty"`
	Keytab    *KeytabPayload    `json:"keytab,omitempty"`
}

// KeytabPayload names the service principal whose keytab is rotated, as
// service/host.example.test with an optional realm. The host is the part
// after the slash: the renewal is ordered on the fleet host of that name.
type KeytabPayload struct {
	Principal string `json:"principal"`
}

// Host is the FQDN the principal names, the host the renewal runs on.
func (p KeytabPayload) Host() string {
	name, _, _ := strings.Cut(p.Principal, "@")
	_, host, _ := strings.Cut(name, "/")
	return host
}

// HostGroupPayload describes a change of a host group's membership. The
// members are hosts named by FQDN, as the directory knows them.
type HostGroupPayload struct {
	Group  string   `json:"group"`
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// ExpiryPayload sets or clears the Kerberos expirations of an account. A
// field that is absent is left as it is; an empty string clears the
// expiration, so that "never expires" is ordered as deliberately as a
// date rather than by leaving something out.
type ExpiryPayload struct {
	UID                string  `json:"uid"`
	PrincipalExpiresAt *string `json:"principal_expires_at,omitempty"`
	PasswordExpiresAt  *string `json:"password_expires_at,omitempty"`
}

// Spec translates the payload into the adapter's declaration. The
// validation has already checked the dates, so a parse failure here is
// a defect rather than a request error.
func (p ExpiryPayload) Spec() (freeipa.Expiry, error) {
	var spec freeipa.Expiry
	var err error
	if spec.PrincipalExpiresAt, err = expiryTime(p.PrincipalExpiresAt); err != nil {
		return spec, fmt.Errorf("principal_expires_at: %w", err)
	}
	if spec.PasswordExpiresAt, err = expiryTime(p.PasswordExpiresAt); err != nil {
		return spec, fmt.Errorf("password_expires_at: %w", err)
	}
	return spec, nil
}

// expiryTime reads one expiration: nil stays nil, an empty string is the
// zero time the adapter sends as a clear, and a date must be RFC 3339.
func expiryTime(value *string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	if strings.TrimSpace(*value) == "" {
		return &time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*value))
	if err != nil {
		return nil, fmt.Errorf("the expiration is not an RFC 3339 time")
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

// POSIXPayload edits the POSIX attributes of an account. An empty field
// is left as it is.
type POSIXPayload struct {
	UID       string `json:"uid"`
	UIDNumber string `json:"uid_number,omitempty"`
	GIDNumber string `json:"gid_number,omitempty"`
	Shell     string `json:"shell,omitempty"`
	HomeDir   string `json:"home_directory,omitempty"`
}

// Spec translates the payload into the adapter's declaration.
func (p POSIXPayload) Spec() freeipa.POSIXSpec {
	return freeipa.POSIXSpec{
		UIDNumber: strings.TrimSpace(p.UIDNumber), GIDNumber: strings.TrimSpace(p.GIDNumber),
		Shell: strings.TrimSpace(p.Shell), HomeDir: strings.TrimSpace(p.HomeDir),
	}
}

// HBACRulePayload declares an access rule as a whole. Removal names the
// rule alone; the other fields are then ignored.
type HBACRulePayload struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	Enabled       bool     `json:"enabled"`
	Users         []string `json:"users,omitempty"`
	UserGroups    []string `json:"user_groups,omitempty"`
	Hosts         []string `json:"hosts,omitempty"`
	HostGroups    []string `json:"host_groups,omitempty"`
	Services      []string `json:"services,omitempty"`
	ServiceGroups []string `json:"service_groups,omitempty"`
	AllUsers      bool     `json:"all_users,omitempty"`
	AllHosts      bool     `json:"all_hosts,omitempty"`
	AllServices   bool     `json:"all_services,omitempty"`
}

// Spec translates the payload into the adapter's declaration.
func (p HBACRulePayload) Spec() freeipa.HBACRuleSpec {
	return freeipa.HBACRuleSpec{
		Name: p.Name, Description: p.Description, Enabled: p.Enabled,
		Users: p.Users, UserGroups: p.UserGroups, Hosts: p.Hosts, HostGroups: p.HostGroups,
		Services: p.Services, ServiceGroups: p.ServiceGroups,
		AllUsers: p.AllUsers, AllHosts: p.AllHosts, AllServices: p.AllServices,
	}
}

// SudoRulePayload declares a sudo rule as a whole.
type SudoRulePayload struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	Enabled       bool     `json:"enabled"`
	Users         []string `json:"users,omitempty"`
	UserGroups    []string `json:"user_groups,omitempty"`
	Hosts         []string `json:"hosts,omitempty"`
	HostGroups    []string `json:"host_groups,omitempty"`
	Commands      []string `json:"commands,omitempty"`
	CommandGroups []string `json:"command_groups,omitempty"`
	RunAsUsers    []string `json:"run_as_users,omitempty"`
	RunAsGroups   []string `json:"run_as_groups,omitempty"`
	Options       []string `json:"options,omitempty"`
	AllUsers      bool     `json:"all_users,omitempty"`
	AllHosts      bool     `json:"all_hosts,omitempty"`
	AllCommands   bool     `json:"all_commands,omitempty"`
	RunAsAnyUser  bool     `json:"run_as_any_user,omitempty"`
}

// Spec translates the payload into the adapter's declaration.
func (p SudoRulePayload) Spec() freeipa.SudoRuleSpec {
	return freeipa.SudoRuleSpec{
		Name: p.Name, Description: p.Description, Enabled: p.Enabled,
		Users: p.Users, UserGroups: p.UserGroups, Hosts: p.Hosts, HostGroups: p.HostGroups,
		Commands: p.Commands, CommandGroups: p.CommandGroups,
		RunAsUsers: p.RunAsUsers, RunAsGroups: p.RunAsGroups, Options: p.Options,
		AllUsers: p.AllUsers, AllHosts: p.AllHosts, AllCommands: p.AllCommands,
		RunAsAnyUser: p.RunAsAnyUser,
	}
}

// DNSRecordPayload describes a record in a directory zone.
type DNSRecordPayload struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
	Type string `json:"type"`
	// Value is the content of the record: an address, a name or text - depending on the type.
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
	// Reverse is the consent to add the reverse record. A PTR record is a
	// separate, visible element of the plan: it decides what a query about an
	// address answers, and forgetting it is the most common mistake when
	// adding hosts.
	Reverse bool `json:"reverse,omitempty"`
	// ReverseZone allows naming the reverse zone explicitly. Empty means the
	// zone computed from the address - and that assumes a /24 split.
	ReverseZone string `json:"reverse_zone,omitempty"`
}

// UserPayload describes the account to create.
type UserPayload struct {
	UID       string   `json:"uid"`
	FirstName string   `json:"first_name,omitempty"`
	LastName  string   `json:"last_name"`
	Email     string   `json:"email,omitempty"`
	Shell     string   `json:"shell,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	SSHKeys   []string `json:"ssh_keys,omitempty"`
}

// GroupPayload describes a change of membership.
type GroupPayload struct {
	Group  string   `json:"group"`
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// SSHKeysPayload sets the complete set of an account's public keys.
type SSHKeysPayload struct {
	UID  string   `json:"uid"`
	Keys []string `json:"keys"`
}

// ReferencePayload names an existing object of the directory.
type ReferencePayload struct {
	UID    string `json:"uid"`
	Reason string `json:"reason,omitempty"`
}

// Validate checks that the type of change and the payload agree.
func Validate(action ActionType, payload Payload) error {
	switch action {
	case ActionUserCreate:
		if payload.User == nil {
			return fmt.Errorf("the operation %s requires a user payload", action)
		}
		if payload.User.UID == "" || payload.User.LastName == "" {
			return fmt.Errorf("an account requires a name and a surname")
		}
	case ActionUserDisable, ActionUserEnable, ActionUserPreserve, ActionUserPasswordReset:
		if payload.Reference == nil || payload.Reference.UID == "" {
			return fmt.Errorf("the operation %s requires naming an account", action)
		}
	case ActionUserExpire:
		if payload.Expiry == nil || payload.Expiry.UID == "" {
			return fmt.Errorf("the operation %s requires naming an account", action)
		}
		if payload.Expiry.PrincipalExpiresAt == nil && payload.Expiry.PasswordExpiresAt == nil {
			return fmt.Errorf("the expiry change names no expiration")
		}
		// The dates are checked with the same reader the executor uses: an
		// unreadable date falls out at ordering time, not after the approval.
		if _, err := payload.Expiry.Spec(); err != nil {
			return err
		}
	case ActionUserPOSIX:
		if payload.POSIX == nil || payload.POSIX.UID == "" {
			return fmt.Errorf("the operation %s requires naming an account", action)
		}
		if err := payload.POSIX.Spec().Validate(); err != nil {
			return err
		}
	case ActionGroupMembers:
		if payload.Group == nil || payload.Group.Group == "" {
			return fmt.Errorf("the operation %s requires naming a group", action)
		}
		if len(payload.Group.Add) == 0 && len(payload.Group.Remove) == 0 {
			return fmt.Errorf("the membership change is empty")
		}
	case ActionHostGroupMembers:
		if payload.HostGroup == nil || payload.HostGroup.Group == "" {
			return fmt.Errorf("the operation %s requires naming a host group", action)
		}
		if len(payload.HostGroup.Add) == 0 && len(payload.HostGroup.Remove) == 0 {
			return fmt.Errorf("the membership change is empty")
		}
		for _, host := range append(append([]string{}, payload.HostGroup.Add...), payload.HostGroup.Remove...) {
			// The directory knows hosts by FQDN; a short name would be
			// refused by it after the approval, so it is refused here.
			if !strings.Contains(host, ".") {
				return fmt.Errorf("the host %q is not a fully qualified name", host)
			}
		}
	case ActionSSHKeys:
		if payload.SSHKeys == nil || payload.SSHKeys.UID == "" {
			return fmt.Errorf("the operation %s requires naming an account", action)
		}
	case ActionDNSRecordEnsure, ActionDNSRecordRemove:
		if payload.DNS == nil {
			return fmt.Errorf("the operation %s requires a dns payload", action)
		}
		// We check with the same code that will carry out the write: a record
		// the directory refuses is to fall out at ordering time rather than
		// after the approval.
		if err := (freeipa.RecordSpec{
			Zone: payload.DNS.Zone, Name: payload.DNS.Name, Type: payload.DNS.Type,
			Value: payload.DNS.Value, TTL: payload.DNS.TTL,
		}).Validate(); err != nil {
			return err
		}
		if payload.DNS.Reverse {
			if payload.DNS.Type != freeipa.RecordA && payload.DNS.Type != freeipa.RecordAAAA {
				return fmt.Errorf("a reverse record makes sense for an address only")
			}
			if payload.DNS.ReverseZone == "" {
				if _, _, err := freeipa.ReverseZone(payload.DNS.Value); err != nil {
					return err
				}
			} else if _, err := freeipa.NameInZone(payload.DNS.Value, payload.DNS.ReverseZone); err != nil {
				// A zone that does not cover this address would give a PTR
				// record for an entirely different host.
				return err
			}
		}
	case ActionHBACRuleEnsure:
		if payload.HBACRule == nil {
			return fmt.Errorf("the operation %s requires an hbac_rule payload", action)
		}
		// The same code that will carry out the write checks the shape: a
		// rule the directory refuses is to fall out at ordering time.
		if err := payload.HBACRule.Spec().Validate(); err != nil {
			return err
		}
		if payload.HBACRule.Enabled {
			// An enabled rule with a side missing matches nothing - or, once
			// somebody fills the side in, more than anybody planned. A draft
			// stays disabled.
			rule := payload.HBACRule
			if !rule.AllUsers && len(rule.Users) == 0 && len(rule.UserGroups) == 0 {
				return fmt.Errorf("an enabled rule requires users, groups or every user")
			}
			if !rule.AllHosts && len(rule.Hosts) == 0 && len(rule.HostGroups) == 0 {
				return fmt.Errorf("an enabled rule requires hosts, host groups or every host")
			}
			if !rule.AllServices && len(rule.Services) == 0 && len(rule.ServiceGroups) == 0 {
				return fmt.Errorf("an enabled rule requires services, service groups or every service")
			}
		}
	case ActionSudoRuleEnsure:
		if payload.SudoRule == nil {
			return fmt.Errorf("the operation %s requires a sudo_rule payload", action)
		}
		if err := payload.SudoRule.Spec().Validate(); err != nil {
			return err
		}
		if payload.SudoRule.Enabled {
			rule := payload.SudoRule
			if !rule.AllUsers && len(rule.Users) == 0 && len(rule.UserGroups) == 0 {
				return fmt.Errorf("an enabled rule requires users, groups or every user")
			}
			if !rule.AllHosts && len(rule.Hosts) == 0 && len(rule.HostGroups) == 0 {
				return fmt.Errorf("an enabled rule requires hosts, host groups or every host")
			}
			if !rule.AllCommands && len(rule.Commands) == 0 && len(rule.CommandGroups) == 0 {
				return fmt.Errorf("an enabled rule requires commands, command groups or every command")
			}
		}
	case ActionHBACRuleRemove:
		if payload.HBACRule == nil || !ruleNamePattern.MatchString(payload.HBACRule.Name) {
			return fmt.Errorf("the operation %s requires naming a rule", action)
		}
	case ActionSudoRuleRemove:
		if payload.SudoRule == nil || !ruleNamePattern.MatchString(payload.SudoRule.Name) {
			return fmt.Errorf("the operation %s requires naming a rule", action)
		}
	case ActionKeytabRotate:
		if payload.Keytab == nil {
			return fmt.Errorf("the operation %s requires a keytab payload", action)
		}
		// The same check the connector makes before service_disable: a
		// host principal is refused by name, because retiring it is a
		// re-join and would cut the host off from the directory it has to
		// fetch the new key from.
		if err := freeipa.ValidateServicePrincipal(payload.Keytab.Principal); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown type of change %q", action)
	}
	return nil
}

// ruleNamePattern bounds the name of an access or sudo rule.
var ruleNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

// Permission returns the permission required to order a change.
func (a ActionType) Permission() string {
	switch a {
	case ActionUserCreate, ActionUserDisable, ActionUserEnable, ActionSSHKeys,
		ActionUserExpire, ActionUserPOSIX, ActionUserPreserve, ActionUserPasswordReset:
		return "identity.user.write"
	case ActionGroupMembers:
		return "identity.group.write"
	case ActionHostGroupMembers:
		// A host's groups decide which rules reach it: the same scope as
		// the rules themselves.
		return "identity.policy.write"
	case ActionDNSRecordEnsure, ActionDNSRecordRemove:
		return "dns.directory.write"
	case ActionHBACTest:
		// A simulation reads the rules; it changes nothing.
		return "identity.policy.read"
	case ActionKeytabRotate:
		// The rotation has a right of its own, the architecture document's
		// "keytab rotation per separate permission": the same right the
		// host's half of it asks for, so nobody holds one half alone.
		return "identity.keytab.rotate"
	default:
		return "identity.policy.write"
	}
}

// ChangesAccess says whether the change alters who may sign in where: an
// account, its keys, a group membership or an access or sudo rule. Such a
// change is taken with fresh authentication, like an access rule on a host;
// a DNS record is not.
func (a ActionType) ChangesAccess() bool {
	switch a {
	case ActionUserCreate, ActionUserDisable, ActionUserEnable, ActionGroupMembers, ActionSSHKeys,
		ActionUserExpire, ActionUserPOSIX, ActionUserPreserve, ActionUserPasswordReset,
		ActionHostGroupMembers,
		ActionHBACRuleEnsure, ActionHBACRuleRemove, ActionSudoRuleEnsure, ActionSudoRuleRemove,
		// A keytab is the credential a service authenticates with: replacing
		// it is a change of access in both directions, and the gap between
		// the retirement and the renewal is an outage of that service.
		ActionKeytabRotate:
		return true
	default:
		return false
	}
}

// Known checks whether the type of change is supported. A simulation is
// not a change, so it is not known here: it cannot be ordered, approved or
// executed.
func (a ActionType) Known() bool {
	switch a {
	case ActionUserCreate, ActionUserDisable, ActionUserEnable, ActionGroupMembers, ActionSSHKeys,
		ActionUserExpire, ActionUserPOSIX, ActionUserPreserve, ActionUserPasswordReset,
		ActionHostGroupMembers,
		ActionDNSRecordEnsure, ActionDNSRecordRemove,
		ActionHBACRuleEnsure, ActionHBACRuleRemove, ActionSudoRuleEnsure, ActionSudoRuleRemove,
		ActionKeytabRotate:
		return true
	default:
		return false
	}
}

// PayloadHash computes the plan hash in canonical form.
func PayloadHash(action ActionType, payload Payload) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\n%s", action, encoded))
	return sum[:], nil
}

// Plan describes the impact of a change before anything happens.
type Plan struct {
	Summary string `json:"summary"`
	// Steps are the phases that will be carried out.
	Steps []string `json:"steps"`
	// AffectedUsers are the accounts the change touches.
	AffectedUsers []string `json:"affected_users,omitempty"`
	// CurrentGroups and ResultingGroups show the membership before and after.
	CurrentGroups   []string `json:"current_groups,omitempty"`
	ResultingGroups []string `json:"resulting_groups,omitempty"`
	// ReachableHosts and SudoRules show the access that follows from the membership.
	ReachableHosts []string `json:"reachable_hosts,omitempty"`
	SudoRules      []string `json:"sudo_rules,omitempty"`
	// Replaces says that a rule of the same name exists and will be brought
	// to the declared state; the steps then carry the member diff.
	Replaces bool `json:"replaces,omitempty"`
	// Warnings describe the consequences that are easy to miss.
	Warnings []string `json:"warnings,omitempty"`
	// Conflicts stop the execution: the directory already holds an object with that name.
	Conflicts []string `json:"conflicts,omitempty"`
}

// Blocked says whether the plan rules out execution.
func (p Plan) Blocked() bool { return len(p.Conflicts) > 0 }

// Phase is the result of one phase of the execution.
type Phase struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Message    string    `json:"message,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// Change is the view of a change returned by the API.
type Change struct {
	ID               string          `json:"id"`
	ActionType       string          `json:"action_type"`
	Payload          json.RawMessage `json:"payload"`
	PayloadHash      string          `json:"payload_hash"`
	Plan             json.RawMessage `json:"plan"`
	State            State           `json:"state"`
	RequiresApproval bool            `json:"requires_approval"`
	ApprovedBy       string          `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time      `json:"approved_at,omitempty"`
	CanceledBy       string          `json:"canceled_by,omitempty"`
	Phases           json.RawMessage `json:"phases"`
	ResultMessage    string          `json:"result_message,omitempty"`
	CreatedBy        string          `json:"created_by"`
	RequestID        string          `json:"request_id,omitempty"`
	StartedAt        *time.Time      `json:"started_at,omitempty"`
	FinishedAt       *time.Time      `json:"finished_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	// SecretAvailable says a one-time value of this change - the password
	// of a reset - waits for its requester. It is not a column: the value
	// lives in the memory of the process that carried the change out, and
	// so does this flag.
	SecretAvailable bool `json:"secret_available,omitempty"`
}

// StateFor decides the final state from the results of the phases.
// A partial success has its own state: presenting it as a success would hide
// the fact that some of the changes were applied and some were not.
func StateFor(phases []Phase) State {
	var succeeded, failed int
	for _, phase := range phases {
		switch phase.Status {
		case "succeeded":
			succeeded++
		case "failed":
			failed++
		}
	}
	switch {
	case failed == 0 && succeeded > 0:
		return StateSucceeded
	case failed > 0 && succeeded > 0:
		return StatePartiallyApplied
	default:
		return StateFailed
	}
}
