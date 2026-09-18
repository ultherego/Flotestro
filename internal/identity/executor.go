package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/plan"
)

// The typed refusals of a directory change. A phase carries no field of its
// own for a code, so the code stands at the front of its message: a refusal
// an operator cannot look up is half a refusal.
const (
	// RefusalModDNUnsupported: the preflight proved the directory cannot
	// carry the operation out - the connector's service account may not move
	// an entry, or the container of preserved accounts is not there. Nothing
	// was ordered and nothing was changed locally.
	RefusalModDNUnsupported = "directory_moddn_unsupported"
	// RefusalPlanIncomplete: the plan of the change does not name the entry
	// it would move, so there is nothing to bind the execution to.
	RefusalPlanIncomplete = "directory_plan_incomplete"
	// RefusalDirectoryRefused: the directory refused the change itself. The
	// message carries the directory's own reason, and the local account was
	// not touched.
	RefusalDirectoryRefused = "directory_refused"
	// RefusalDirectoryUnreachable: the directory did not answer, so nothing
	// about it is known and nothing was done.
	RefusalDirectoryUnreachable = "directory_unreachable"
	// RefusalStalePlan is the shared refusal of a plan the world moved
	// under. The spelling is the one the package and storage plans use, so
	// an operator looks up one code whatever it was that moved.
	RefusalStalePlan = plan.ErrorStalePlan
)

// SessionRevoker revokes the panel sessions that belong to an identity.
type SessionRevoker interface {
	RevokeSessionsOf(ctx context.Context, principalID, reason string) (int64, error)
	ListPrincipals(ctx context.Context) ([]authz.Principal, error)
}

// ProviderLogout ends the sessions a user holds at the identity provider.
// The panel's own sessions end locally; without this the provider would go
// on logging the user into every other application behind it until its
// session ran out - the lag the architecture document warns about.
type ProviderLogout interface {
	LogoutSubject(ctx context.Context, subject string) error
}

// Executor carries out approved directory changes phase by phase.
type Executor struct {
	store     *Store
	directory *freeipa.Client
	sessions  SessionRevoker
	provider  ProviderLogout
	audit     *audit.Recorder
	log       *slog.Logger
	interval  time.Duration
	// fleet orders the host's half of a keytab rotation; it reads the
	// panel's own tables through the pool the change store holds.
	fleet HostOrderer
	// retire is the test seam for the directory half of a rotation; nil
	// means the connector's own call.
	retire func(ctx context.Context, principal string) error
	// The halves of a preserve, each replaceable on its own: what the
	// directory can do, which entry it holds, the move itself, and the
	// local denial marker. Nil means the real connector and the real
	// change store. They stand apart because the order between them is
	// what this operation is about, and a test has to be able to watch it.
	capabilities func(ctx context.Context) (freeipa.DirectoryCapabilities, error)
	entryOf      func(ctx context.Context, uid string) (freeipa.EntryReference, error)
	preserve     func(ctx context.Context, uid string) error
	localDeny    func(ctx context.Context, subject, reason string, denied bool) (int64, error)
}

func NewExecutor(store *Store, directory *freeipa.Client, sessions SessionRevoker,
	recorder *audit.Recorder, log *slog.Logger, interval time.Duration) *Executor {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	executor := &Executor{store: store, directory: directory, sessions: sessions,
		audit: recorder, log: log, interval: interval}
	if store != nil && store.Pool() != nil {
		executor.fleet = NewFleetOrderer(store.Pool(), recorder)
	}
	return executor
}

// WithHostOrderer replaces the fleet the rotation orders through: a test
// hands in a fake, and an installation may hand in a narrower one.
func (e *Executor) WithHostOrderer(fleet HostOrderer) *Executor {
	e.fleet = fleet
	return e
}

// WithProviderLogout makes a disable end the user's sessions at the identity
// provider as well. Without it the local denial stands alone.
func (e *Executor) WithProviderLogout(provider ProviderLogout) *Executor {
	e.provider = provider
	return e
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
	case ActionHostGroupMembers:
		phases = e.changeHostGroupMembers(ctx, payload.HostGroup)
	case ActionSSHKeys:
		phases = e.setSSHKeys(ctx, payload.SSHKeys)
	case ActionUserExpire:
		phases = e.setUserExpiry(ctx, payload.Expiry)
	case ActionUserPOSIX:
		phases = e.setUserPOSIX(ctx, payload.POSIX)
	case ActionUserPreserve:
		phases, revoked = e.preserveUser(ctx, change, payload.Reference)
	case ActionUserPasswordReset:
		phases = e.resetPassword(ctx, change, payload.Reference)
	case ActionDNSRecordEnsure:
		phases = e.writeRecord(ctx, payload.DNS, true)
	case ActionDNSRecordRemove:
		phases = e.writeRecord(ctx, payload.DNS, false)
	case ActionHBACRuleEnsure, ActionHBACRuleRemove:
		phases = e.writeHBACRule(ctx, payload.HBACRule, action == ActionHBACRuleEnsure)
	case ActionSudoRuleEnsure, ActionSudoRuleRemove:
		phases = e.writeSudoRule(ctx, payload.SudoRule, action == ActionSudoRuleEnsure)
	case ActionKeytabRotate:
		phases = e.rotateKeytab(ctx, change, payload.Keytab)
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

		// The provider's sessions go after the panel's own: the local denial
		// is what cuts the user off, and this closes the window in which
		// the provider would still log them into other applications. It
		// never fails the change - a provider that is off, unreachable or
		// does not know the user is recorded as such, and the disable
		// stands on the local marker and the directory.
		phase, ended := e.endProviderSessions(ctx, ref.UID)
		phases = append(phases, phase)
		result.ProviderSessionsEnded = &ended.Ended
		result.ProviderReason = ended.Reason
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
	// ProviderSessionsEnded says whether the identity provider ended the
	// user's sessions too; nil for a change that does not ask it to. False
	// comes with ProviderReason, because "not ended" has several causes
	// and only one of them is a fault.
	ProviderSessionsEnded *bool  `json:"provider_sessions_ended,omitempty"`
	ProviderReason        string `json:"provider_reason,omitempty"`
}

// providerLogout is the outcome of asking the identity provider to end a
// user's sessions.
type providerLogout struct {
	Ended  bool
	Reason string
}

// endProviderSessions asks the identity provider to end the user's sessions,
// as one phase that cannot fail the change.
//
// The phase is skipped rather than failed when the sessions were not ended:
// the disable already holds on the local marker and the directory, and a
// provider that is not configured for it, does not know the user, or is
// unreachable is a fact recorded in the result - not a reason to call the
// disable partially applied. The reason names which of those it was.
func (e *Executor) endProviderSessions(ctx context.Context, uid string) (Phase, providerLogout) {
	phase := startPhase("ending the sessions at the identity provider")
	if e.provider == nil {
		outcome := providerLogout{Reason: "no identity provider is configured"}
		return skipPhase(phase, outcome.Reason), outcome
	}
	if err := e.provider.LogoutSubject(ctx, uid); err != nil {
		outcome := providerLogout{Reason: err.Error()}
		return skipPhase(phase, "provider sessions not ended: "+outcome.Reason), outcome
	}
	return finishPhase(phase, nil, "provider sessions ended for "+uid), providerLogout{Ended: true}
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

// changeHostGroupMembers moves hosts in and out of a host group. No panel
// session ends here: a host's group changes which rules reach it, and the
// host's own SSSD picks that up; the users keep their panel scope.
func (e *Executor) changeHostGroupMembers(ctx context.Context, spec *HostGroupPayload) []Phase {
	var phases []Phase
	if len(spec.Add) > 0 {
		phase := startPhase("adding hosts to the host group " + spec.Group)
		err := e.directory.AddHostGroupMembers(ctx, spec.Group, spec.Add)
		phases = append(phases, finishPhase(phase, err, strings.Join(spec.Add, ", ")))
	}
	if len(spec.Remove) > 0 {
		phase := startPhase("removing hosts from the host group " + spec.Group)
		err := e.directory.RemoveHostGroupMembers(ctx, spec.Group, spec.Remove)
		phases = append(phases, finishPhase(phase, err, strings.Join(spec.Remove, ", ")))
	}
	return phases
}

// setUserExpiry sets or clears the expirations of an account.
func (e *Executor) setUserExpiry(ctx context.Context, spec *ExpiryPayload) []Phase {
	phase := startPhase("changing the expiration of the account " + spec.UID)
	expiry, err := spec.Spec()
	if err != nil {
		return []Phase{finishPhase(phase, err, "")}
	}
	err = e.directory.SetUserExpiry(ctx, spec.UID, expiry)
	return []Phase{finishPhase(phase, err, strings.Join(append(
		expiryStep("the Kerberos principal", expiry.PrincipalExpiresAt),
		expiryStep("the password", expiry.PasswordExpiresAt)...), "; "))}
}

// setUserPOSIX changes the POSIX attributes of an account and reports
// them as the directory holds them afterwards.
func (e *Executor) setUserPOSIX(ctx context.Context, spec *POSIXPayload) []Phase {
	phase := startPhase("changing the POSIX attributes of the account " + spec.UID)
	if err := e.directory.SetUserPOSIX(ctx, spec.UID, spec.Spec()); err != nil {
		return []Phase{finishPhase(phase, err, "")}
	}
	user, err := e.directory.ShowUser(ctx, spec.UID)
	if err != nil {
		// The write went through; a failed read-back is reported as such
		// rather than as a failed change.
		return []Phase{finishPhase(phase, nil, "changed; the account was not read back: "+err.Error())}
	}
	return []Phase{finishPhase(phase, nil, describeUser(user)+", shell "+user.Shell+", home "+user.HomeDir)}
}

// preserveUser removes an account while keeping its entry.
//
// The order is the reverse of a disable, and deliberately so. A disable locks
// locally first, because a local lock that arrives late leaves a session
// working for as long as the directory takes. A preserve cannot afford that
// order: the directory may refuse the move - a service account without the
// right to it, a container that is not there, an ACI that does not allow it -
// and a host that has already denied the user while the directory still holds
// the account is the worst of both. The user is locked out of the panel and
// out of the hosts, and no record of the account was removed anywhere. So the
// directory goes first, the local half follows only on its confirmation, and
// a refusal changes nothing locally and carries the directory's own reason.
//
// The window the reversed order opens - a panel session that outlives the
// directory entry by the moment between the two - is the smaller harm and is
// closed immediately: the account no longer exists to authenticate with, and
// the revocation is the next step rather than a later one.
//
// Before either half, two things are settled. The directory is asked what it
// can do, so an operation it would refuse is refused here instead of after
// the local account was changed. And the plan is bound to the entry it was
// made for: two operators preserving the same user, or an entry somebody
// changed between the plan and the approval, are refused as a stale plan.
func (e *Executor) preserveUser(ctx context.Context, change Change,
	ref *ReferencePayload) ([]Phase, *sessionRevocation) {
	var phases []Phase

	phase := startPhase("asking the directory what it can do")
	capabilities, err := e.directoryCapabilities(ctx)
	if err != nil {
		return append(phases, refusedPhase(phase, RefusalDirectoryUnreachable, err.Error())), nil
	}
	if reason, blocked := capabilities.PreserveBlocked(); blocked {
		return append(phases, refusedPhase(phase, RefusalModDNUnsupported,
			"the directory cannot preserve an account: "+reason)), nil
	}
	// The reads that come before the change are recorded for what they are:
	// carried out, and no part of the change. A read that succeeded must not
	// make a refused operation look like one half applied, so it counts
	// towards neither the success nor the failure of the change.
	phases = append(phases, skipPhase(phase, describeCapabilities(capabilities)))

	phase = startPhase("binding the plan to the entry")
	planned, err := preservePlan(change)
	if err != nil {
		return append(phases, refusedPhase(phase, RefusalPlanIncomplete, err.Error())), nil
	}
	current, err := e.directoryEntry(ctx, ref.UID)
	if err != nil {
		// An entry the directory no longer holds under that name is not an
		// outage: somebody preserved or removed the account between the plan
		// and now, which is exactly what the binding exists to catch.
		code := RefusalDirectoryUnreachable
		if errors.Is(err, freeipa.ErrEntryNotFound) {
			code = RefusalStalePlan
		}
		return append(phases, refusedPhase(phase, code, err.Error())), nil
	}
	if moved, ok := planned.Moved(current); ok {
		return append(phases, refusedPhase(phase, RefusalStalePlan, moved)), nil
	}
	phases = append(phases, skipPhase(phase, "the entry is the one the plan named"))

	phase = startPhase("preserving the account in the directory")
	if err := e.preserveInDirectory(ctx, ref.UID); err != nil {
		return append(phases, refusedPhase(phase, RefusalDirectoryRefused, err.Error())), nil
	}
	phases = append(phases, finishPhase(phase, nil, "the entry stays as a preserved account"))

	reason := firstNonEmpty(ref.Reason, "the account was preserved")
	phase = startPhase("the local denial marker")
	count, err := e.denyLocally(ctx, ref.UID, reason, true)
	phases = append(phases, finishPhase(phase, err, describeCount("identities marked", count)))

	phase = startPhase("revoking the panel sessions")
	result, err := e.revokeSessions(ctx, ref.UID, reason)
	phases = append(phases, finishPhase(phase, err, result.String()))

	phase, ended := e.endProviderSessions(ctx, ref.UID)
	phases = append(phases, phase)
	result.ProviderSessionsEnded = &ended.Ended
	result.ProviderReason = ended.Reason
	return phases, &result
}

// directoryCapabilities, directoryEntry, preserveInDirectory and denyLocally
// are the four halves of a preserve behind their seams. Each falls back to
// the real connector or the real change store when no seam was set.
func (e *Executor) directoryCapabilities(ctx context.Context) (freeipa.DirectoryCapabilities, error) {
	if e.capabilities != nil {
		return e.capabilities(ctx)
	}
	return e.directory.Capabilities(ctx)
}

func (e *Executor) directoryEntry(ctx context.Context, uid string) (freeipa.EntryReference, error) {
	if e.entryOf != nil {
		return e.entryOf(ctx, uid)
	}
	return e.directory.UserEntry(ctx, uid)
}

func (e *Executor) preserveInDirectory(ctx context.Context, uid string) error {
	if e.preserve != nil {
		return e.preserve(ctx, uid)
	}
	return e.directory.PreserveUser(ctx, uid)
}

func (e *Executor) denyLocally(ctx context.Context, subject, reason string,
	denied bool) (int64, error) {
	if e.localDeny != nil {
		return e.localDeny(ctx, subject, reason, denied)
	}
	return e.store.SetLocalDeny(ctx, subject, reason, denied)
}

// preservePlan reads the entry the approved plan would move.
//
// A plan that does not name it is refused rather than filled in here: the
// whole point of the binding is that the entry was read when the operator
// looked at the plan, not when the execution started.
func preservePlan(change Change) (freeipa.EntryReference, error) {
	var planned struct {
		PreserveEntry *freeipa.EntryReference `json:"preserve_entry"`
	}
	if len(change.Plan) > 0 {
		if err := json.Unmarshal(change.Plan, &planned); err != nil {
			return freeipa.EntryReference{}, fmt.Errorf("the plan of the change does not read: %w", err)
		}
	}
	if planned.PreserveEntry == nil || !planned.PreserveEntry.Complete() {
		return freeipa.EntryReference{}, errors.New(
			"the plan does not name the entry it would move; plan the change again")
	}
	return *planned.PreserveEntry, nil
}

// describeCapabilities says what the preflight established, including what
// it could not: a directory that does not report the rights on an entry is
// not a directory that granted them.
func describeCapabilities(capabilities freeipa.DirectoryCapabilities) string {
	verdict := "the directory does not report the rights on an entry"
	if capabilities.UserModDN {
		verdict = "the directory reports the connector may move an entry"
	}
	if len(capabilities.ReasonCodes) == 0 {
		return verdict
	}
	return verdict + " (" + strings.Join(capabilities.ReasonCodes, ", ") + ")"
}

// resetPassword asks the directory for a new password and keeps it for
// the requester alone, in memory. The phase message, the audit entry and
// the log never carry the value: a secret in a job output is what the
// document forbids.
func (e *Executor) resetPassword(ctx context.Context, change Change, ref *ReferencePayload) []Phase {
	phase := startPhase("resetting the password of the account " + ref.UID)
	password, err := e.directory.ResetUserPassword(ctx, ref.UID)
	if err != nil {
		return []Phase{finishPhase(phase, err, "")}
	}
	e.store.KeepSecret(change.ID, change.CreatedBy, password)
	return []Phase{finishPhase(phase, nil,
		"a one-time password was issued; it expires on first login and waits for "+change.CreatedBy+" to read it once")}
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
		// Whether the provider ended its sessions too, and if not, why: an
		// auditor reading a disable wants to know how long the user could
		// still reach the other applications.
		if revoked.ProviderSessionsEnded != nil {
			detail["provider_sessions_ended"] = *revoked.ProviderSessionsEnded
			if revoked.ProviderReason != "" {
				detail["provider_reason"] = revoked.ProviderReason
			}
		}
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

// skipPhase closes a phase that changed nothing, with what it found. A
// phase that was not carried out and a read that was both belong here: a
// skipped phase counts for neither the success nor the failure of the
// change, which is what keeps a refusal after a successful read from
// reading as a change half applied.
func skipPhase(phase Phase, message string) Phase {
	phase.FinishedAt = time.Now().UTC()
	phase.Status = "skipped"
	phase.Message = message
	return phase
}

// refusedPhase closes a phase with a typed refusal. The code stands at the
// front of the message, because a phase has no field of its own for it and a
// refusal the panel cannot act on is only half a refusal.
func refusedPhase(phase Phase, code, message string) Phase {
	phase.FinishedAt = time.Now().UTC()
	phase.Status = "failed"
	phase.Message = code + ": " + message
	return phase
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
