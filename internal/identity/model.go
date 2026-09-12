// Package identity carries out changes in the identity directory: the plan,
// the approval and an execution made of phases. Creating a user is one
// business transaction of the panel but several operations of the
// directory.
package identity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
	// Directory DNS is a central change, just like an account: it concerns
	// the whole network rather than one host and goes in one transaction
	// through the directory connector - not through an agent.
	ActionDNSRecordEnsure ActionType = "dns.record.ensure"
	ActionDNSRecordRemove ActionType = "dns.record.remove"
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
	SSHKeys   *SSHKeysPayload   `json:"ssh_keys,omitempty"`
	Reference *ReferencePayload `json:"reference,omitempty"`
	DNS       *DNSRecordPayload `json:"dns,omitempty"`
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
	case ActionUserDisable, ActionUserEnable:
		if payload.Reference == nil || payload.Reference.UID == "" {
			return fmt.Errorf("the operation %s requires naming an account", action)
		}
	case ActionGroupMembers:
		if payload.Group == nil || payload.Group.Group == "" {
			return fmt.Errorf("the operation %s requires naming a group", action)
		}
		if len(payload.Group.Add) == 0 && len(payload.Group.Remove) == 0 {
			return fmt.Errorf("the membership change is empty")
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
	default:
		return fmt.Errorf("unknown type of change %q", action)
	}
	return nil
}

// Permission returns the permission required to order a change.
func (a ActionType) Permission() string {
	switch a {
	case ActionUserCreate, ActionUserDisable, ActionUserEnable, ActionSSHKeys:
		return "identity.user.write"
	case ActionGroupMembers:
		return "identity.group.write"
	case ActionDNSRecordEnsure, ActionDNSRecordRemove:
		return "dns.directory.write"
	default:
		return "identity.policy.write"
	}
}

// Known checks whether the type of change is supported.
func (a ActionType) Known() bool {
	switch a {
	case ActionUserCreate, ActionUserDisable, ActionUserEnable, ActionGroupMembers, ActionSSHKeys,
		ActionDNSRecordEnsure, ActionDNSRecordRemove:
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
