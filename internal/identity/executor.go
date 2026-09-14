package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/freeipa"
)

// SessionRevoker revokes the panel sessions that belong to an identity.
type SessionRevoker interface {
	RevokeSessionsOf(ctx context.Context, principalID, reason string) (int64, error)
	ListPrincipals(ctx context.Context) ([]authz.Principal, error)
}

// Executor carries out approved directory changes phase by phase.
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
		e.finish(ctx, change, StateFailed, nil, "unreadable payload: "+err.Error(), nil)
		return
	}

	action := ActionType(change.ActionType)
	var phases []Phase
	// revoked is filled in by the actions that end panel sessions, so that
	// the trail says how many - and for whom there was nothing to end.
	var revoked *sessionRevocation

	switch action {
	case ActionUserCreate:
		phases, revoked = e.createUser(ctx, payload.User)
	case ActionUserDisable:
		phases, revoked = e.setUserAccess(ctx, payload.Reference, false)
	case ActionUserEnable:
		phases, _ = e.setUserAccess(ctx, payload.Reference, true)
	case ActionGroupMembers:
		phases, revoked = e.changeGroupMembers(ctx, payload.Group)
	case ActionSSHKeys:
		phases = e.setSSHKeys(ctx, payload.SSHKeys)
	case ActionDNSRecordEnsure:
		phases = e.writeRecord(ctx, payload.DNS, true)
	case ActionDNSRecordRemove:
		phases = e.writeRecord(ctx, payload.DNS, false)
	case ActionHBACRuleEnsure, ActionHBACRuleRemove:
		phases = e.writeHBACRule(ctx, payload.HBACRule, action == ActionHBACRuleEnsure)
	case ActionSudoRuleEnsure, ActionSudoRuleRemove:
		phases = e.writeSudoRule(ctx, payload.SudoRule, action == ActionSudoRuleEnsure)
	default:
		e.finish(ctx, change, StateFailed, nil, "unknown type of change", nil)
		return
	}

	state := StateFor(phases)
	message := ""
	if state == StatePartiallyApplied {
		// This state exists so as not to hide the fact that some of the
		// changes were applied and some were not.
		message = "some phases failed; the directory is in an intermediate state"
	}
	e.finish(ctx, change, state, phases, message, revoked)
}

// createUser creates the account, adds it to the groups and sets the keys.
// Every step is a separate phase, because the directory carries them out
// separately and they can drift apart.
func (e *Executor) createUser(ctx context.Context, spec *UserPayload) ([]Phase, *sessionRevocation) {
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
		return phases, nil
	}

	joined := false
	for _, group := range spec.Groups {
		phase := startPhase("adding to the group " + group)
		err := e.directory.AddGroupMembers(ctx, group, []string{spec.UID})
		phases = append(phases, finishPhase(phase, err, ""))
		joined = joined || err == nil
	}
	if !joined {
		return phases, nil
	}
	// The account did not exist a moment ago, so as a rule there is no
	// session to end. A reused name is the exception: a principal left by
	// an earlier account of that name may still hold a session, and it
	// would carry the old groups into the new membership.
	phase, revoked := e.revokeChangedMembers(ctx, []string{spec.UID},
		"the group membership changed: "+strings.Join(spec.Groups, ", "))
	return append(phases, phase), &revoked
}

// setUserAccess locks or unlocks an account.
//
// When locking, the order matters: first the local denial marker and the
// revocation of the panel sessions, and only then the directory. The reverse
// order would leave a working session for the time the change takes to
// propagate.
func (e *Executor) setUserAccess(ctx context.Context, ref *ReferencePayload, enable bool) ([]Phase, *sessionRevocation) {
	var phases []Phase
	var revoked *sessionRevocation

	if !enable {
		phase := startPhase("the local denial marker")
		count, err := e.store.SetLocalDeny(ctx, ref.UID, ref.Reason, true)
		phases = append(phases, finishPhase(phase, err,
			describeCount("identities marked", count)))

		phase = startPhase("revoking the panel sessions")
		result, err := e.revokeSessions(ctx, ref.UID, firstNonEmpty(ref.Reason, "the account was locked"))
		phases = append(phases, finishPhase(phase, err, result.String()))
		revoked = &result
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
	return phases, revoked
}

// sessionRevocation is the outcome of ending the panel sessions of the
// directory users a change touched. A user without a panel identity has
// nothing to end; that is a fact of the result, not a failure.
type sessionRevocation struct {
	// Sessions is the number of sessions ended.
	Sessions int64 `json:"sessions_revoked"`
	// WithoutPrincipal names the users who never logged into the panel.
	WithoutPrincipal []string `json:"without_principal"`
}

// String renders the outcome as the message of a phase.
func (r sessionRevocation) String() string {
	message := describeCount("sessions revoked", r.Sessions)
	if len(r.WithoutPrincipal) > 0 {
		message += "; no panel identity for " + strings.Join(r.WithoutPrincipal, ", ")
	}
	return message
}

// MatchesDirectoryUser says whether a panel principal is the given
// directory account. The login names the principal after the provider's
// preferred_username, which for a directory-backed provider is the uid;
// when that name was already taken by a local principal, the login named
// it "uid@issuer-host" instead. Both belong to the same person in the
// directory, so both are matched. A local principal of the same name is
// matched as well: it holds no provider session, so nothing is ended
// there, and it is not worth telling the two apart here.
func MatchesDirectoryUser(subject, uid string) bool {
	if uid == "" {
		return false
	}
	return subject == uid || strings.HasPrefix(subject, uid+"@")
}

// revokeSessions ends the panel sessions belonging to a directory account.
// The listing is read once for every account; a change touches a handful
// of them and the executor runs alone, so the repeated read is cheaper
// than a query shape of its own.
func (e *Executor) revokeSessions(ctx context.Context, uid, reason string) (sessionRevocation, error) {
	result := sessionRevocation{WithoutPrincipal: []string{}}
	principals, err := e.sessions.ListPrincipals(ctx)
	if err != nil {
		return result, err
	}
	matched := false
	for _, principal := range principals {
		if !MatchesDirectoryUser(principal.Subject, uid) {
			continue
		}
		matched = true
		revoked, err := e.sessions.RevokeSessionsOf(ctx, principal.ID, reason)
		if err != nil {
			return result, err
		}
		result.Sessions += revoked
	}
	if !matched {
		result.WithoutPrincipal = append(result.WithoutPrincipal, uid)
	}
	return result, nil
}

// revokeChangedMembers ends the sessions of the users whose groups changed,
// as one phase. A session carries the groups of the moment of login; the
// membership the directory holds now is a different scope, and the only
// honest thing to do with the old one is to end it and let the next login
// take a fresh snapshot. Whether there was anything to end is part of the
// message: a user who never logged into the panel is not an error.
func (e *Executor) revokeChangedMembers(ctx context.Context, uids []string, reason string) (Phase, sessionRevocation) {
	phase := startPhase("revoking the panel sessions of the changed members")
	total := sessionRevocation{WithoutPrincipal: []string{}}
	for _, uid := range uids {
		result, err := e.revokeSessions(ctx, uid, reason)
		total.Sessions += result.Sessions
		total.WithoutPrincipal = append(total.WithoutPrincipal, result.WithoutPrincipal...)
		if err != nil {
			return finishPhase(phase, err, ""), total
		}
	}
	return finishPhase(phase, nil, total.String()), total
}

func (e *Executor) changeGroupMembers(ctx context.Context, spec *GroupPayload) ([]Phase, *sessionRevocation) {
	var phases []Phase
	// Only the members the directory actually moved lose their session: a
	// user whose change was refused still holds the scope they had.
	var changed []string
	if len(spec.Add) > 0 {
		phase := startPhase("adding members to the group " + spec.Group)
		err := e.directory.AddGroupMembers(ctx, spec.Group, spec.Add)
		phases = append(phases, finishPhase(phase, err, ""))
		if err == nil {
			changed = append(changed, spec.Add...)
		}
	}
	if len(spec.Remove) > 0 {
		phase := startPhase("removing members from the group " + spec.Group)
		err := e.directory.RemoveGroupMembers(ctx, spec.Group, spec.Remove)
		phases = append(phases, finishPhase(phase, err, ""))
		if err == nil {
			changed = append(changed, spec.Remove...)
		}
	}
	if len(changed) == 0 {
		return phases, nil
	}
	phase, revoked := e.revokeChangedMembers(ctx, changed,
		"the group membership changed: "+spec.Group)
	return append(phases, phase), &revoked
}

func (e *Executor) setSSHKeys(ctx context.Context, spec *SSHKeysPayload) []Phase {
	phase := startPhase("setting the SSH keys of the account " + spec.UID)
	err := e.directory.SetUserSSHKeys(ctx, spec.UID, spec.Keys)
	return []Phase{finishPhase(phase, err, "")}
}

// finish records the result and notes it in the audit trail.
func (e *Executor) finish(ctx context.Context, change Change, state State,
	phases []Phase, message string, revoked *sessionRevocation) {
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
	detail := map[string]any{
		"action_type": change.ActionType, "state": string(state),
		"created_by": change.CreatedBy, "approved_by": change.ApprovedBy,
		"failed_phases": failedPhases, "message": message,
	}
	if revoked != nil {
		// The count is what an auditor looks for after a membership change:
		// whether the old scope really ended. Zero with a name under
		// without_principal means there was nothing to end.
		detail["sessions_revoked"] = revoked.Sessions
		detail["without_principal"] = revoked.WithoutPrincipal
	}
	e.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "identity-executor",
		Action: "directory_change.execute", TargetType: "directory_change", TargetID: change.ID,
		RequestID: change.RequestID, Outcome: outcome,
		Detail: detail,
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

// writeHBACRule brings an access rule to the declared state or removes it.
// The adapter carries the member changes out one kind at a time, so the
// phase reports the rule as the directory holds it afterwards; a failure
// half-way leaves the message saying which command refused.
func (e *Executor) writeHBACRule(ctx context.Context, spec *HBACRulePayload, ensure bool) []Phase {
	if spec == nil {
		return nil
	}
	if !ensure {
		phase := startPhase("removing the HBAC rule " + spec.Name)
		err := e.directory.RemoveHBACRule(ctx, spec.Name)
		return []Phase{finishPhase(phase, err, "")}
	}
	phase := startPhase("ensuring the HBAC rule " + spec.Name)
	rule, err := e.directory.EnsureHBACRule(ctx, spec.Spec())
	message := ""
	if rule != nil {
		message = describeHBACRule(*rule)
	}
	return []Phase{finishPhase(phase, err, message)}
}

// writeSudoRule brings a sudo rule to the declared state or removes it.
func (e *Executor) writeSudoRule(ctx context.Context, spec *SudoRulePayload, ensure bool) []Phase {
	if spec == nil {
		return nil
	}
	if !ensure {
		phase := startPhase("removing the sudo rule " + spec.Name)
		err := e.directory.RemoveSudoRule(ctx, spec.Name)
		return []Phase{finishPhase(phase, err, "")}
	}
	phase := startPhase("ensuring the sudo rule " + spec.Name)
	rule, err := e.directory.EnsureSudoRule(ctx, spec.Spec())
	message := ""
	if rule != nil {
		message = describeSudoRule(*rule)
	}
	return []Phase{finishPhase(phase, err, message)}
}

func describeHBACRule(rule freeipa.HBACRule) string {
	state := "disabled"
	if rule.Enabled {
		state = "enabled"
	}
	return fmt.Sprintf("%s; %d users, %d user groups, %d hosts, %d host groups, %d services",
		state, len(rule.Users), len(rule.UserGroups), len(rule.Hosts), len(rule.HostGroups),
		len(rule.Services)+len(rule.ServiceGroups))
}

func describeSudoRule(rule freeipa.SudoRule) string {
	state := "disabled"
	if rule.Enabled {
		state = "enabled"
	}
	return fmt.Sprintf("%s; %d users, %d user groups, %d hosts, %d host groups, %d commands, %d options",
		state, len(rule.Users), len(rule.UserGroups), len(rule.Hosts), len(rule.HostGroups),
		len(rule.Commands)+len(rule.CommandGroups), len(rule.Options))
}
