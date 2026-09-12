package identity

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/freeipa"
)

// SessionRevoker uniewaznia sesje panelu nalezace do tozsamosci.
type SessionRevoker interface {
	RevokeSessionsOf(ctx context.Context, principalID, reason string) (int64, error)
	ListPrincipals(ctx context.Context) ([]authz.Principal, error)
}

// Executor wykonuje zatwierdzone zmiany katalogu, faza po fazie.
type Executor struct {
	store     *Store
	directory *freeipa.Client
	sessions  SessionRevoker
	audit     *audit.Recorder
	log       *slog.Logger
	interval  time.Duration
}

func NewExecutor(store *Store, directory *freeipa.Client, sessions SessionRevoker,
	recorder *audit.Recorder, log *slog.Logger, interval time.Duration) *Executor {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	return &Executor{store: store, directory: directory, sessions: sessions,
		audit: recorder, log: log, interval: interval}
}

// Run carries out the approved changes until the context is closed.
func (e *Executor) Run(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.tick(ctx)
		}
	}
}

func (e *Executor) tick(ctx context.Context) {
	pending, err := e.store.Pending(ctx)
	if err != nil {
		e.log.Error("the directory changes were not read", "err", err)
		return
	}
	for _, change := range pending {
		claimed, err := e.store.Claim(ctx, change.ID)
		if err != nil {
			e.log.Error("the directory change was not claimed", "change_id", change.ID, "err", err)
			continue
		}
		if !claimed {
			continue
		}
		e.execute(ctx, change)
	}
}

// execute carries out a change phase by phase. Every phase has its own
// result, because a partial success must not be presented as a success.
func (e *Executor) execute(ctx context.Context, change Change) {
	var payload Payload
	if err := json.Unmarshal(change.Payload, &payload); err != nil {
		e.finish(ctx, change, StateFailed, nil, "unreadable payload: "+err.Error())
		return
	}

	action := ActionType(change.ActionType)
	var phases []Phase

	switch action {
	case ActionUserCreate:
		phases = e.createUser(ctx, payload.User)
	case ActionUserDisable:
		phases = e.setUserAccess(ctx, payload.Reference, false)
	case ActionUserEnable:
		phases = e.setUserAccess(ctx, payload.Reference, true)
	case ActionGroupMembers:
		phases = e.changeGroupMembers(ctx, payload.Group)
	case ActionSSHKeys:
		phases = e.setSSHKeys(ctx, payload.SSHKeys)
	case ActionDNSRecordEnsure:
		phases = e.writeRecord(ctx, payload.DNS, true)
	case ActionDNSRecordRemove:
		phases = e.writeRecord(ctx, payload.DNS, false)
	default:
		e.finish(ctx, change, StateFailed, nil, "unknown type of change")
		return
	}

	state := StateFor(phases)
	message := ""
	if state == StatePartiallyApplied {
		// This state exists so as not to hide the fact that some of the
		// changes were applied and some were not.
		message = "some phases failed; the directory is in an intermediate state"
	}
	e.finish(ctx, change, state, phases, message)
}

// createUser creates the account, adds it to the groups and sets the keys.
// Every step is a separate phase, because the directory carries them out
// separately and they can drift apart.
func (e *Executor) createUser(ctx context.Context, spec *UserPayload) []Phase {
	var phases []Phase

	phase := startPhase("creating the account")
	user, err := e.directory.CreateUser(ctx, freeipa.UserSpec{
		UID:       spec.UID,
		FirstName: spec.FirstName,
		LastName:  spec.LastName,
		Email:     spec.Email,
		Shell:     spec.Shell,
		SSHKeys:   spec.SSHKeys,
	})
	phases = append(phases, finishPhase(phase, err, describeUser(user)))
	if err != nil {
		// Without the account the following phases make no sense.
		return phases
	}

	for _, group := range spec.Groups {
		phase := startPhase("adding to the group " + group)
		err := e.directory.AddGroupMembers(ctx, group, []string{spec.UID})
		phases = append(phases, finishPhase(phase, err, ""))
	}
	return phases
}

// setUserAccess locks or unlocks an account.
//
// When locking, the order matters: first the local denial marker and the
// revocation of the panel sessions, and only then the directory. The reverse
// order would leave a working session for the time the change takes to
// propagate.
func (e *Executor) setUserAccess(ctx context.Context, ref *ReferencePayload, enable bool) []Phase {
	var phases []Phase

	if !enable {
		phase := startPhase("the local denial marker")
		count, err := e.store.SetLocalDeny(ctx, ref.UID, ref.Reason, true)
		phases = append(phases, finishPhase(phase, err,
			describeCount("identities marked", count)))

		phase = startPhase("revoking the panel sessions")
		revoked, err := e.revokeSessions(ctx, ref.UID, ref.Reason)
		phases = append(phases, finishPhase(phase, err,
			describeCount("sessions revoked", revoked)))
	}

	phase := startPhase("changing the account state in the directory")
	err := e.directory.SetUserEnabled(ctx, ref.UID, enable)
	phases = append(phases, finishPhase(phase, err, ""))

	if enable && err == nil {
		phase := startPhase("lifting the local denial marker")
		count, denyErr := e.store.SetLocalDeny(ctx, ref.UID, "", false)
		phases = append(phases, finishPhase(phase, denyErr,
			describeCount("identities unlocked", count)))
	}
	return phases
}

// revokeSessions ends the panel sessions belonging to an account.
func (e *Executor) revokeSessions(ctx context.Context, subject, reason string) (int64, error) {
	principals, err := e.sessions.ListPrincipals(ctx)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, principal := range principals {
		if principal.Subject != subject {
			continue
		}
		revoked, err := e.sessions.RevokeSessionsOf(ctx, principal.ID,
			firstNonEmpty(reason, "the account was locked"))
		if err != nil {
			return total, err
		}
		total += revoked
	}
	return total, nil
}

func (e *Executor) changeGroupMembers(ctx context.Context, spec *GroupPayload) []Phase {
	var phases []Phase
	if len(spec.Add) > 0 {
		phase := startPhase("adding members to the group " + spec.Group)
		err := e.directory.AddGroupMembers(ctx, spec.Group, spec.Add)
		phases = append(phases, finishPhase(phase, err, ""))
	}
	if len(spec.Remove) > 0 {
		phase := startPhase("removing members from the group " + spec.Group)
		err := e.directory.RemoveGroupMembers(ctx, spec.Group, spec.Remove)
		phases = append(phases, finishPhase(phase, err, ""))
	}
	return phases
}

func (e *Executor) setSSHKeys(ctx context.Context, spec *SSHKeysPayload) []Phase {
	phase := startPhase("setting the SSH keys of the account " + spec.UID)
	err := e.directory.SetUserSSHKeys(ctx, spec.UID, spec.Keys)
	return []Phase{finishPhase(phase, err, "")}
}

// finish records the result and notes it in the audit trail.
func (e *Executor) finish(ctx context.Context, change Change, state State,
	phases []Phase, message string) {
	if err := e.store.Finish(ctx, change.ID, state, phases, message); err != nil {
		e.log.Error("the result of the directory change was not recorded", "change_id", change.ID, "err", err)
	}

	outcome := audit.OutcomeSuccess
	if state != StateSucceeded {
		outcome = audit.OutcomeFailure
	}
	failedPhases := make([]string, 0)
	for _, phase := range phases {
		if phase.Status == "failed" {
			failedPhases = append(failedPhases, phase.Name+": "+phase.Message)
		}
	}
	e.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "identity-executor",
		Action: "directory_change.execute", TargetType: "directory_change", TargetID: change.ID,
		RequestID: change.RequestID, Outcome: outcome,
		Detail: map[string]any{
			"action_type": change.ActionType, "state": string(state),
			"created_by": change.CreatedBy, "approved_by": change.ApprovedBy,
			"failed_phases": failedPhases, "message": message,
		},
	})

	logger := e.log.Info
	if state != StateSucceeded {
		logger = e.log.Warn
	}
	logger("the directory change finished",
		"change_id", change.ID, "type", change.ActionType, "state", state,
		"phases", len(phases), "failed", len(failedPhases))
}

func startPhase(name string) Phase {
	return Phase{Name: name, StartedAt: time.Now().UTC()}
}

func finishPhase(phase Phase, err error, message string) Phase {
	phase.FinishedAt = time.Now().UTC()
	if err != nil {
		phase.Status = "failed"
		phase.Message = err.Error()
		return phase
	}
	phase.Status = "succeeded"
	phase.Message = message
	return phase
}

func describeUser(user *freeipa.User) string {
	if user == nil {
		return ""
	}
	return "UID " + user.UIDNumber + ", GID " + user.GIDNumber
}

func describeCount(label string, count int64) string {
	if count == 0 {
		return label + ": 0"
	}
	return label + ": " + itoa(count)
}

func itoa(value int64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// writeRecord adds or removes a record and - where needed - its reverse
// counterpart. Each is a separate phase, because the directory carries them
// out separately and they can drift apart: a forward record without a reverse
// one is a common, silent mistake.
func (e *Executor) writeRecord(ctx context.Context, spec *DNSRecordPayload, adding bool) []Phase {
	var phases []Phase
	if spec == nil {
		return phases
	}
	description := spec.Type + " " + spec.Name + "." + strings.TrimSuffix(spec.Zone, ".")

	main := freeipa.RecordSpec{
		Zone: strings.TrimSuffix(spec.Zone, "."), Name: spec.Name,
		Type: spec.Type, Value: spec.Value, TTL: spec.TTL,
	}
	phase := startPhase("the record " + description)
	var err error
	if adding {
		_, err = e.directory.EnsureRecord(ctx, main)
	} else {
		err = e.directory.RemoveRecord(ctx, main)
	}
	phases = append(phases, finishPhase(phase, err, spec.Value))
	if err != nil || !spec.Reverse {
		return phases
	}

	// A zone named explicitly must not leave the name computed for a /24:
	// the PTR would then be created for a different address than the one in
	// the request.
	zone, name, err := freeipa.ReverseZone(spec.Value)
	if spec.ReverseZone != "" {
		zone = strings.TrimSuffix(spec.ReverseZone, ".")
		name, err = freeipa.NameInZone(spec.Value, zone)
	}
	phase = startPhase("the reverse PTR record " + name + "." + zone)
	if err == nil {
		// The PTR target is the full name of the forward record - also when
		// the record stands at the root of the zone and is written as "@".
		target := freeipa.FullName(spec.Zone, spec.Name) + "."
		reverse := freeipa.RecordSpec{
			Zone: zone, Name: name, Type: freeipa.RecordPTR, Value: target, TTL: spec.TTL,
		}
		if adding {
			_, err = e.directory.EnsureRecord(ctx, reverse)
		} else {
			err = e.directory.RemoveRecord(ctx, reverse)
		}
	}
	phases = append(phases, finishPhase(phase, err, ""))
	return phases
}
