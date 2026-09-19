package audit

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The actor of an event is remembered as it was when the event happened.

// The kinds of actor the trail distinguishes.
const (
	// ActorKindUser is a signed-in person or a token in their name.
	ActorKindUser = "user"
	// ActorKindService is an identity kept for automation.
	ActorKindService = "service"
	// ActorKindAnonymous is a request that carried no identity at all.
	ActorKindAnonymous = "anonymous"
	// ActorKindAgent is the agent of an enrolled host, acting for the host.
	ActorKindAgent = "agent"
	// ActorKindRelay is a relay: it carries a site, and it enrolls and
	// renews under its own name.
	ActorKindRelay = "relay"
	// ActorKindMachine is a machine that is not a host yet - an enrollment
	// attempt names it by its machine identifier, which is not a host.
	ActorKindMachine = "machine"
	// ActorKindSystem is the panel itself: a campaign, a policy, a sweep.
	ActorKindSystem = "system"
)

// ActorSnapshot is the actor of an event as it was at the moment of the event.
type ActorSnapshot struct {
	// PrincipalID is the immutable identifier of the identity, for a
	// person, a service or a token.
	PrincipalID string `json:"principal_id,omitempty"`
	// Subject is the name the identity signs in with, as it was.
	Subject string `json:"subject,omitempty"`
	// DisplayName is what the identity was called, as it was.
	DisplayName string `json:"display_name,omitempty"`
	// Kind is one of the ActorKind constants.
	Kind string `json:"kind,omitempty"`
	// ResourceType and ResourceID name the object that acted for a non-person: a
	// host for an agent, a relay, a campaign, a policy.
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
	// ResourceName is what the resource was called, as it was.
	ResourceName string `json:"resource_name,omitempty"`
	// CredentialID is the row of the credential the request came with -
	// the browser session or the API token - not the credential itself.
	CredentialID string `json:"credential_id,omitempty"`
}

// empty says whether the snapshot carries anything at all; an event from
// before the snapshot reads back without one.
func (a ActorSnapshot) empty() bool {
	return a == ActorSnapshot{}
}

// machineIDPattern is the form of a machine identifier: thirty-two hex digits
// without dashes.
var machineIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// systemPrefixes maps the prefix of a system actor to the resource type
// it names. The identifier after the colon is the row of that type.
var systemPrefixes = map[string]string{
	"campaign":         "campaign",
	"policy":           "policy",
	"remediation":      "remediation_plan",
	"schedule":         "campaign_schedule",
	"directory-change": "directory_change",
}

// principalSnapshot is what the trail keeps of an identity, read once per
// request.
type principalSnapshot struct {
	id          string
	displayName string
	kind        string
}

// actorSnapshot resolves the actor of the event at the moment of writing.
func (r *Recorder) actorSnapshot(ctx context.Context, q queryExecutor,
	request *requestContext, event Event) ActorSnapshot {
	switch event.ActorType {
	case ActorUser:
		return r.userSnapshot(ctx, q, request, event.ActorID)
	case ActorAgent:
		return r.agentSnapshot(ctx, q, request, event.ActorID)
	case ActorSystem:
		return r.systemSnapshot(ctx, q, event.ActorID)
	default:
		return ActorSnapshot{Subject: event.ActorID}
	}
}

// userSnapshot names a person, a service or a token by its principal.
func (r *Recorder) userSnapshot(ctx context.Context, q queryExecutor,
	request *requestContext, subject string) ActorSnapshot {
	if subject == "" || subject == "anonymous" {
		return ActorSnapshot{Subject: "anonymous", Kind: ActorKindAnonymous}
	}
	snapshot := ActorSnapshot{Subject: subject, Kind: ActorKindUser}
	if request != nil && request.actor.Subject == subject && request.actor.PrincipalID != "" {
		snapshot.PrincipalID = request.actor.PrincipalID
		snapshot.DisplayName = request.actor.DisplayName
		if request.actor.Kind != "" {
			snapshot.Kind = request.actor.Kind
		}
		snapshot.CredentialID = request.actor.CredentialID
		return snapshot
	}
	principal, ok := request.cachedPrincipal(subject)
	if !ok {
		err := q.QueryRow(ctx,
			`select id::text, display_name, kind from principals where subject = $1`, subject).
			Scan(&principal.id, &principal.displayName, &principal.kind)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				r.log.Warn("the actor of an audit event was not read", "subject", subject, "err", err)
			}
			return snapshot
		}
		request.rememberPrincipal(subject, principal)
	}
	snapshot.PrincipalID = principal.id
	snapshot.DisplayName = principal.displayName
	if principal.kind != "" {
		snapshot.Kind = principal.kind
	}
	if request != nil && request.actor.Subject == subject {
		snapshot.CredentialID = request.actor.CredentialID
	}
	return snapshot
}

// agentSnapshot names what acted as an agent: the host behind a dashed
// identifier, the relay behind one or behind a name, or a machine that is not
// a host yet.
func (r *Recorder) agentSnapshot(ctx context.Context, q queryExecutor,
	request *requestContext, id string) ActorSnapshot {
	snapshot := ActorSnapshot{Subject: id, Kind: ActorKindAgent}
	if machineIDPattern.MatchString(strings.ToLower(id)) {
		snapshot.Kind = ActorKindMachine
		snapshot.ResourceType = "machine"
		snapshot.ResourceName = id
		return snapshot
	}
	if _, err := uuid.Parse(id); err == nil && len(id) == 36 {
		if host, ok := r.hostSnapshot(ctx, q, request, id); ok {
			snapshot.ResourceType = "host"
			snapshot.ResourceID = id
			snapshot.ResourceName = host.hostname
			return snapshot
		}
		var name string
		err := q.QueryRow(ctx, `select name from relays where id = $1::uuid`, id).Scan(&name)
		if err == nil {
			snapshot.Kind = ActorKindRelay
			snapshot.ResourceType = "relay"
			snapshot.ResourceID = id
			snapshot.ResourceName = name
			return snapshot
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			r.log.Warn("the relay behind an audit event was not read", "relay", id, "err", err)
		}
		// A host identifier the panel does not know: the agent of a host removed a
		// moment ago.
		snapshot.ResourceType = "host"
		snapshot.ResourceID = id
		return snapshot
	}
	// A relay enrolls under its name before it has an identifier.
	var relayID string
	err := q.QueryRow(ctx, `select id::text from relays where name = $1`, id).Scan(&relayID)
	if err == nil {
		snapshot.Kind = ActorKindRelay
		snapshot.ResourceType = "relay"
		snapshot.ResourceID = relayID
		snapshot.ResourceName = id
		return snapshot
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		r.log.Warn("the relay behind an audit event was not read", "name", id, "err", err)
	}
	return snapshot
}

// systemSnapshot names the part of the panel that acted: a campaign, a policy,
// a schedule by its row; the gateway or a sweep by its name.
func (r *Recorder) systemSnapshot(ctx context.Context, q queryExecutor, id string) ActorSnapshot {
	snapshot := ActorSnapshot{Subject: id, Kind: ActorKindSystem}
	prefix, rest, found := strings.Cut(id, ":")
	resourceType, known := systemPrefixes[prefix]
	if !found || !known {
		return snapshot
	}
	snapshot.ResourceType = resourceType
	if _, err := uuid.Parse(rest); err != nil {
		snapshot.ResourceName = rest
		return snapshot
	}
	snapshot.ResourceID = rest
	if resourceType == "campaign" {
		var name string
		err := q.QueryRow(ctx, `select name from campaigns where id = $1::uuid`, rest).Scan(&name)
		if err == nil {
			snapshot.ResourceName = name
		} else if !errors.Is(err, pgx.ErrNoRows) {
			r.log.Warn("the campaign behind an audit event was not read", "campaign", rest, "err", err)
		}
	}
	return snapshot
}

// nullableUUID renders an identifier for a uuid column: empty stays null, and
// a value that is not an identifier stays null too rather than failing the
// insert - the text of it is still in actor_id.
func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	if _, err := uuid.Parse(value); err != nil {
		return nil
	}
	return value
}
