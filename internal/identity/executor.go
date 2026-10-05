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
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/plan"
)

// The typed refusals of a directory change.
const (
	// RefusalModDNUnsupported: the preflight proved the directory cannot carry
	// the operation out - the connector's service account may not move an entry,
	// or the container of preserved accounts is not there.
	RefusalModDNUnsupported = "directory_moddn_unsupported"
	// RefusalPlanIncomplete: the plan of the change does not name the entry
	// it would move, so there is nothing to bind the execution to.
	RefusalPlanIncomplete = "directory_plan_incomplete"
	// RefusalDirectoryRefused: the directory refused the change itself.
	RefusalDirectoryRefused = "directory_refused"
	// RefusalDirectoryUnreachable: the directory did not answer, so nothing
	// about it is known and nothing was done.
	RefusalDirectoryUnreachable = "directory_unreachable"
	// RefusalStalePlan is the shared refusal of a plan the world moved under.
	RefusalStalePlan = plan.ErrorStalePlan
	// RefusalInterrupted: a replica took the change, stopped before recording a
	// result, and the change is one that cannot be carried out a second time
	// without destroying what the first attempt produced.
	RefusalInterrupted = "directory_change_interrupted"
	// RefusalOutcomeUnknown: the change went out and the directory's answer did
	// not come back, so what it did is not known. It is not a refusal of the
	// change - that is RefusalDirectoryRefused - and it is not a success.
	RefusalOutcomeUnknown = "directory_outcome_unknown"
)

// repeatOfInterruptedChange decides what to do with a change the claim took out
// of running: an earlier attempt claimed it and never recorded a result, so
// which of its phases ran is unknown. A declarative change is simply carried
// out again. A change that hands something out once is not, because a second
// attempt takes back what the first one gave - a new password invalidates the
// one the requester already has, and a second rotation retires the key the host
// just fetched. It is recorded as partially applied, which is the honest
// reading of a change that began and whose extent nobody knows.
//
// The question is asked of the hold and not of the change: the row's state in
// the list a tick polled is a state from before the claim, and a row that reads
// "planned" there may be the running attempt this claim just took over.
func repeatOfInterruptedChange(change Change, hold Hold) ([]Phase, State, string, bool) {
	if !hold.Resumed || RepeatableAfterInterruption(ActionType(change.ActionType)) {
		return nil, "", "", false
	}
	phase := refusedPhase(startPhase("repeating the interrupted change"), RefusalInterrupted,
		"a replica took this change and recorded no result, and "+change.ActionType+
			" cannot be carried out again without taking back what the first attempt handed out")
	return []Phase{phase}, StatePartiallyApplied,
		"the change was interrupted after it had begun; read what the directory holds and plan it again",
		true
}

// SessionRevoker revokes the panel sessions that belong to an identity.
type SessionRevoker interface {
	RevokeSessionsOf(ctx context.Context, principalID, reason string) (int64, error)
	ListPrincipals(ctx context.Context) ([]authz.Principal, error)
}

// ProviderLogout ends the sessions a user holds at the identity provider.
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
	// setEnabled is the test seam for the directory half of a disable or an
	// enable; nil means the connector's own call.
	setEnabled func(ctx context.Context, uid string, enable bool) error
	// The halves of a preserve, each replaceable on its own: what the directory
	// can do, which entry it holds, the move itself, and the local denial marker.
	capabilities func(ctx context.Context, uid string) (freeipa.DirectoryCapabilities, error)
	entryOf      func(ctx context.Context, uid string) (freeipa.EntryReference, error)
	preserve     func(ctx context.Context, uid string, planned freeipa.EntryReference) (freeipa.PreserveProof, error)
	// preservedOf reads the preserved entry of an account, so an attempt can
	// tell "the account was already moved by this change" from a stale plan.
	preservedOf func(ctx context.Context, uid string) (freeipa.EntryReference, error)
	// recordPhases writes the phases of a running change; without a store there
	// is nowhere to write them, and a test replaces it.
	recordPhases func(ctx context.Context, changeID string, phases []Phase) error
	// renewClaim says whether this replica still holds the change, and
	// renewEvery how often it asks. Both are seams: the term is a quarter of an
	// hour in an installation and a millisecond in a test.
	renewClaim func(ctx context.Context, changeID string, hold Hold) (ClaimStanding, bool, error)
	renewEvery time.Duration
	// lapseAfter is the term the holder judges its own claim by; ClaimTerm in
	// an installation, and short enough to watch in a test.
	lapseAfter time.Duration
	localDeny  func(ctx context.Context, subject, reason string, denied bool) (int64, error)
	// recordArrear writes the durable obligation to finish the panel's own half
	// of an access cut; nil means the store's own write, and a test replaces it.
	recordArrear func(ctx context.Context, changeID, uid, reason string,
		principals []AccessPrincipal) error
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
		// The claim names this instance and lapses on its own, so a change
		// whose carrier stops is taken again instead of staying in running
		// where nothing reads it.
		hold, claimed, err := e.store.Claim(ctx, change.ID, jobs.InstanceID())
		if err != nil {
			e.log.Error("the directory change was not claimed", "change_id", change.ID, "err", err)
			continue
		}
		if !claimed {
			continue
		}
		// While this replica works, it says so: the term then bounds how long a
		// change stays invisible after a replica stops, and not how long the
		// change itself may take.
		working, release := e.holdClaim(ctx, change.ID, hold)
		e.execute(working, change, hold)
		release()
	}
}

// holdClaim renews the claim until the returned function is called, and returns
// the context the work runs under. Losing the claim cancels that context: a
// replica that is no longer the holder has to stop, not carry the change
// further and be refused at the write. The directory does not care which
// replica believes it owns the change.
func (e *Executor) holdClaim(ctx context.Context, changeID string, hold Hold) (context.Context, func()) {
	working, abandon := context.WithCancel(ctx)
	renewing, stop := context.WithCancel(ctx)
	// renewed carries the verdict of each renewal back to the clock below.
	renewed := make(chan renewal, 1)
	go func() {
		// The interval follows the term that is left and not the term in the
		// constant, so a claim taken after a slow statement is renewed sooner.
		standing := hold.Standing
		due := time.NewTimer(e.renewIn(standing))
		defer due.Stop()
		for {
			select {
			case <-renewing.Done():
				return
			case <-due.C:
				// The renewal has a deadline of its own. A statement that has
				// not answered by the time the next one is due has not
				// answered, and a holder waiting on it must not be waiting on
				// it instead of noticing that its claim ran out.
				asked, give := context.WithTimeout(context.WithoutCancel(renewing), e.renewTerm())
				latest, still, err := e.renew(asked, changeID, hold)
				give()
				if err != nil {
					// A renewal that failed is not a claim that was lost. The
					// clock below decides that, from the term it knows.
					e.log.Error("the claim on the directory change was not renewed",
						"change_id", changeID, "err", err)
					due.Reset(e.renewIn(standing))
					continue
				}
				if still {
					standing = latest
				}
				due.Reset(e.renewIn(standing))
				answer := renewal{held: still, standing: latest}
				select {
				case renewed <- answer:
				case <-renewing.Done():
					return
				}
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The term is known, so the holder judges it by its own clock rather
		// than by an answer that may never come: a renewal stuck in the
		// database used to mean the expiry was never reached at all, and the
		// holder worked on under a claim somebody else had taken.
		//
		// What the clock is set to is the database's own deadline and not the
		// term constant: the row expires at the time the claiming statement
		// stamped on it, which is before the answer reached this replica.
		term := e.termOf(hold.Standing)
		lapse := time.NewTimer(term)
		defer lapse.Stop()
		for {
			select {
			case <-renewing.Done():
				return
			case <-lapse.C:
				e.log.Warn("the claim on the directory change has lapsed; the work stops",
					"change_id", changeID, "term", term)
				abandon()
				return
			case answer := <-renewed:
				if !answer.held {
					e.log.Warn("the claim on the directory change is held by somebody else; the work stops",
						"change_id", changeID)
					abandon()
					return
				}
				if !lapse.Stop() {
					// The timer had already fired and its value was read by
					// nobody; draining it keeps the next term honest.
					select {
					case <-lapse.C:
					default:
					}
				}
				term = e.termOf(answer.standing)
				lapse.Reset(term)
			}
		}
	}()
	// Releasing waits for the clock and not for a renewal in flight: a
	// statement hanging in the database must not hold up the replica's next
	// change. The renewal gives up at its deadline and ends on its own, and the
	// cancelled renewing context stops it from waiting to be read.
	return working, func() {
		stop()
		<-done
		abandon()
	}
}

// renewTerm is how often the holder says it is still working, and how long one
// renewal may take.
func (e *Executor) renewTerm() time.Duration {
	if e.renewEvery > 0 {
		return e.renewEvery
	}
	return RenewTerm
}

// claimTerm is how long the holder may go without a renewal that landed before
// its claim has certainly run out.
func (e *Executor) claimTerm() time.Duration {
	if e.lapseAfter > 0 {
		return e.lapseAfter
	}
	return ClaimTerm
}

func (e *Executor) renew(ctx context.Context, changeID string, hold Hold) (ClaimStanding, bool, error) {
	if e.renewClaim != nil {
		return e.renewClaim(ctx, changeID, hold)
	}
	return e.store.RenewClaim(ctx, changeID, hold)
}

// termOf is how long the holder may work before its claim has certainly run
// out. The database's own remaining term decides it, measured from the moment
// the statement was asked. Where the database reported no term - a seam that
// answers without one - the configured term stands in, measured from that same
// moment: an unknown standing is not an unlimited one, and the fallback must
// not be the longer of the two readings.
func (e *Executor) termOf(standing ClaimStanding) time.Duration {
	deadline := standing.Deadline()
	if deadline.IsZero() {
		from := standing.Asked
		if from.IsZero() {
			from = time.Now()
		}
		deadline = from.Add(e.claimTerm())
	}
	left := time.Until(deadline)
	if left < 0 {
		return 0
	}
	return left
}

// renewIn is when the next renewal is due: a third of the term that is really
// left, and never later than the configured interval. A renewal scheduled from
// the whole term is scheduled out of a term the holder does not have.
func (e *Executor) renewIn(standing ClaimStanding) time.Duration {
	every := e.renewTerm()
	if third := e.termOf(standing) / 3; third > 0 && third < every {
		every = third
	}
	return every
}

// renewal is what the renewing goroutine hands the clock: the verdict, and -
// where the claim stands - the term the database then stated.
type renewal struct {
	held     bool
	standing ClaimStanding
}

// execute carries out a change phase by phase. Every phase has its own
// result, because a partial success must not be presented as a success.
func (e *Executor) execute(ctx context.Context, change Change, hold Hold) {
	var payload Payload
	if err := json.Unmarshal(change.Payload, &payload); err != nil {
		e.finish(ctx, change, hold, StateFailed, nil, "unreadable payload: "+err.Error(), nil)
		return
	}

	action := ActionType(change.ActionType)
	// A change read in running was claimed by a replica that never finished it,
	// so what it managed to do is unknown. Carrying a declarative change out
	// again lands on the same state; a password reset or a keytab rotation
	// destroys what the first attempt handed out, so it waits for a person.
	if refusal, state, message, stop := repeatOfInterruptedChange(change, hold); stop {
		e.finish(ctx, change, hold, state, refusal, message, nil)
		return
	}
	var phases []Phase
	// revoked is filled in by the actions that end panel sessions, so that
	// the trail says how many - and for whom there was nothing to end.
	var revoked *sessionRevocation

	switch action {
	case ActionUserCreate:
		phases, revoked = e.createUser(ctx, payload.User)
	case ActionUserDisable:
		phases, revoked = e.setUserAccess(ctx, change, payload.Reference, false)
	case ActionUserEnable:
		phases, _ = e.setUserAccess(ctx, change, payload.Reference, true)
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
		phases, revoked = e.preserveUser(ctx, change, hold, payload.Reference)
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
		e.finish(ctx, change, hold, StateFailed, nil, "unknown type of change", nil)
		return
	}

	state := StateFor(phases)
	message := ""
	if state == StatePartiallyApplied {
		// This state exists so as not to hide the fact that some of the
		// changes were applied and some were not.
		message = intermediateStateOf(phases)
	}
	e.finish(ctx, change, hold, state, phases, message, revoked)
}

// intermediateStateOf says which intermediate state a change ended in: a phase
// waiting on somebody else is not the same thing as a phase that failed, and
// the operator has to read which one this is.
func intermediateStateOf(phases []Phase) string {
	for _, phase := range phases {
		if phase.Status == PhaseOutstanding {
			return phase.Name + ": " + phase.Message
		}
	}
	return "some phases failed; the directory is in an intermediate state"
}

// createUser creates the account, adds it to the groups and sets the keys.
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
	// The account did not exist a moment ago, so as a rule there is no session to
	// end.
	phase, revoked := e.revokeChangedMembers(ctx, []string{spec.UID},
		"the group membership changed: "+strings.Join(spec.Groups, ", "))
	return append(phases, phase), &revoked
}

// deniedLocally turns the outcome of marking - or lifting - a local denial into
// a phase. An account of the directory that has never signed in to the panel
// has no identity here to deny, and that is not a failure of the step: the
// account exists where it exists and the panel knows nobody by that name.
//
// It is one function because it was two. The lock path made the distinction and
// said why in a comment; the preserve path handed the error straight to
// finishPhase, so preserving an account the panel knows nobody by ended the
// whole change as partially_applied over a step that had nothing to do. The
// gate found it on 04.10, six days after the lock path was fixed.
func deniedLocally(phase Phase, count int64, err error, marked, nothing string) Phase {
	if errors.Is(err, ErrNoPrincipal) {
		return skipPhase(phase, nothing)
	}
	return finishPhase(phase, err, describeCount(marked, count))
}

// setUserAccess locks or unlocks an account.
func (e *Executor) setUserAccess(ctx context.Context, change Change, ref *ReferencePayload,
	enable bool) ([]Phase, *sessionRevocation) {
	var phases []Phase
	var revoked *sessionRevocation

	if !enable {
		// Before either half of the cut: the local denial is a mutation too, and
		// the directory call that follows it goes out whatever the local half
		// did. A disable whose local half failed used to end partially_applied
		// with nobody to finish it.
		owed := e.oweLocalAccess(ctx, change, ref)
		phases = append(phases, owed)
		if owed.Status == "failed" {
			return phases, nil
		}

		phase := startPhase("the local denial marker")
		count, err := e.denyDirectoryUser(ctx, ref.UID, ref.Reason, true)
		// Saying "identities marked: 0" as a success was the thing ID-01 found;
		// this says which of the two it is.
		phases = append(phases, deniedLocally(phase, count, err, "identities marked",
			"the panel knows no identity by that name, so there was nothing to deny locally"))

		phase = startPhase("revoking the panel sessions")
		result, err := e.revokeSessions(ctx, ref.UID, firstNonEmpty(ref.Reason, "the account was locked"))
		phases = append(phases, finishPhase(phase, err, result.String()))

		// The provider's sessions go after the panel's own: the local denial is what
		// cuts the user off, and this closes the window in which the provider would
		// still log them into other applications.
		phase, ended := e.endProviderSessions(ctx, ref.UID)
		phases = append(phases, phase)
		result.ProviderSessionsEnded = &ended.Ended
		result.ProviderReason = ended.Reason
		revoked = &result
	}

	phase := startPhase("changing the account state in the directory")
	err := e.enableInDirectory(ctx, ref.UID, enable)
	phases = append(phases, finishPhase(phase, err, ""))

	if enable && err == nil {
		phase := startPhase("lifting the local denial marker")
		count, denyErr := e.denyDirectoryUser(ctx, ref.UID, "", false)
		// The same distinction as on the way in.
		phases = append(phases, deniedLocally(phase, count, denyErr, "identities unlocked",
			"the panel knows no identity by that name, so there was nothing to lift"))
	}
	return phases, revoked
}

// sessionRevocation is the outcome of ending the panel sessions of the
// directory users a change touched.
type sessionRevocation struct {
	// Sessions is the number of sessions ended.
	Sessions int64 `json:"sessions_revoked"`
	// WithoutPrincipal names the users who never logged into the panel.
	WithoutPrincipal []string `json:"without_principal"`
	// ProviderSessionsEnded says whether the identity provider ended the user's
	// sessions too; nil for a change that does not ask it to.
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

// MatchesDirectoryPrincipal says whether a panel identity is the given
// directory account. Both halves are asked here - the link an operator wrote
// down and the name the login carries - so the denial and the session
// revocation cannot drift apart on the question again.
func MatchesDirectoryPrincipal(principal authz.Principal, uid string) bool {
	if uid == "" {
		return false
	}
	// The link exists for an identity whose subject says nothing about the
	// account: without reading it, the field an operator fills in changed
	// nothing and the very case it was added for was covered by neither path.
	if principal.DirectoryUID != "" && strings.EqualFold(principal.DirectoryUID, uid) {
		return true
	}
	return MatchesDirectoryUser(principal.Subject, uid)
}

// MatchesDirectoryUser says whether the name of a panel principal is the given
// directory account: the account itself, or that account qualified with the
// issuer the login added.
func MatchesDirectoryUser(subject, uid string) bool {
	if uid == "" {
		return false
	}
	return subject == uid || strings.HasPrefix(subject, uid+"@")
}

// denyDirectoryUser sets - or lifts - the local denial marker on every panel
// identity that is this directory account, asking the same question the session
// revocation asks. The marker was written by the account name alone, so an
// identity the login named "uid@issuer" kept its tokens while its sessions were
// ended, and the phase said there was nothing to deny.
func (e *Executor) denyDirectoryUser(ctx context.Context, uid, reason string, denied bool) (int64, error) {
	if e.sessions == nil {
		return 0, fmt.Errorf("the panel identities cannot be read, so it is not known whom to deny")
	}
	principals, err := e.sessions.ListPrincipals(ctx)
	if err != nil {
		// Not knowing the identities is not knowing that there are none.
		return 0, fmt.Errorf("reading the panel identities of %s: %w", uid, err)
	}
	var marked int64
	var matched bool
	for _, principal := range principals {
		if !MatchesDirectoryPrincipal(principal, uid) {
			continue
		}
		matched = true
		count, err := e.denyLocally(ctx, principal.Subject, reason, denied)
		if err != nil && !errors.Is(err, ErrNoPrincipal) {
			return marked, err
		}
		marked += count
	}
	if !matched || marked == 0 {
		return 0, fmt.Errorf("%w: no identity of the panel is the directory account %q, so the denial marked nobody",
			ErrNoPrincipal, uid)
	}
	return marked, nil
}

// revokeSessions ends the panel sessions belonging to a directory account.
func (e *Executor) revokeSessions(ctx context.Context, uid, reason string) (sessionRevocation, error) {
	result := sessionRevocation{WithoutPrincipal: []string{}}
	principals, err := e.sessions.ListPrincipals(ctx)
	if err != nil {
		return result, err
	}
	matched := false
	for _, principal := range principals {
		if !MatchesDirectoryPrincipal(principal, uid) {
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

// revokeChangedMembers ends the sessions of the users whose groups changed, as
// one phase.
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

// mayHaveMoved names the accounts whose scope the directory may have changed,
// which is what decides whose session ends.
//
// A batch the directory took only in part is not a step that did nothing: the
// accounts it moved are named in the error, and their sessions end although the
// step failed - without this they kept the scope they had while the panel
// reported a failure. A batch whose outcome never came back is the same
// question with no answer, so every account it named loses its session: an
// unconfirmed change must not be accounted for as a change of nobody.
func mayHaveMoved(err error, asked []string) []string {
	if err == nil {
		return asked
	}
	var partial *freeipa.PartialChange
	if errors.As(err, &partial) {
		return partial.Applied
	}
	var uncertain *freeipa.UncertainChange
	if errors.As(err, &uncertain) {
		return uncertain.Users
	}
	return nil
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
		changed = append(changed, mayHaveMoved(err, spec.Add)...)
	}
	if len(spec.Remove) > 0 {
		phase := startPhase("removing members from the group " + spec.Group)
		err := e.directory.RemoveGroupMembers(ctx, spec.Group, spec.Remove)
		phases = append(phases, finishPhase(phase, err, ""))
		changed = append(changed, mayHaveMoved(err, spec.Remove)...)
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

// changeHostGroupMembers moves hosts in and out of a host group.
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

// phasePreserveInDirectory is the one phase of a preserve whose name is read
// back: it is the boundary between what the directory did and what the panel
// still owes, so it is a constant rather than a string written twice.
const phasePreserveInDirectory = "preserving the account in the directory"

// phaseLocalAccessOwed is the obligation the panel takes on the moment the
// directory has - or may have - moved the account: the holder's own access here
// has to go. It is recorded as a phase of its own, outstanding until it is met,
// so that the obligation survives a replica stopping and does not depend on
// reading another phase's verdict. A directory half recorded as failed can owe
// it just as much as one recorded as done.
const phaseLocalAccessOwed = "cutting off the panel access of the preserved account"

// phaseDirectoryMutationIntent is written down BEFORE the directory is asked to
// change anything, and never after it. A replica that stopped between the
// mutating call and the first obligation write used to leave nothing durable at
// all: the attempt that took the change over found no record that a mutation
// may already have been made, so it could not know what there was to preserve.
// The marker says the one thing that matters in that window - a change was
// about to go out and its effect is unknown until somebody states otherwise.
const phaseDirectoryMutationIntent = "about to change the directory"

// phaseLocalAccessOwedDurably is the write that outlives the change. The
// obligation inside the phases survives a replica stopping; it does not survive
// the change reaching a terminal state, and a change whose local half failed is
// terminal partially_applied. This phase is the row that keeps being retried
// after that.
const phaseLocalAccessOwedDurably = "recording the panel access the change owes"

// accessPrincipals resolves the panel identities a directory account covers,
// with the same question the denial and the revocation ask. It is read before
// the directory is touched, because the obligation that outlives the change
// cannot resolve them afterwards: the account the read would go to is the one
// the change is about to remove.
func (e *Executor) accessPrincipals(ctx context.Context, uid string) ([]AccessPrincipal, error) {
	if e.sessions == nil {
		return nil, fmt.Errorf(
			"the panel identities cannot be read, so it is not known whose access is owed")
	}
	principals, err := e.sessions.ListPrincipals(ctx)
	if err != nil {
		// Not knowing the identities is not knowing that there are none.
		return nil, fmt.Errorf("reading the panel identities of %s: %w", uid, err)
	}
	matched := make([]AccessPrincipal, 0, len(principals))
	for _, principal := range principals {
		if MatchesDirectoryPrincipal(principal, uid) {
			matched = append(matched,
				AccessPrincipal{Subject: principal.Subject, PrincipalID: principal.ID})
		}
	}
	return matched, nil
}

// oweLocalAccess records, before the mutating call, that the panel owes the
// local half of this access cut. The row it writes carries the identities and
// outlives the change, and a separate executor retries it until the denial and
// the revocation are read back as done.
//
// The phase it returns is failed where nothing was written, and the caller then
// does not make the call: an access cut whose local half nothing records is one
// nobody can finish, and that is the whole reason this row exists.
func (e *Executor) oweLocalAccess(ctx context.Context, change Change, ref *ReferencePayload) Phase {
	phase := startPhase(phaseLocalAccessOwedDurably)
	owe := e.recordArrear
	if owe == nil {
		if e.store == nil {
			return skipPhase(phase, "nothing records what the panel owes in this configuration")
		}
		owe = e.store.OweLocalAccess
	}
	principals, err := e.accessPrincipals(ctx, ref.UID)
	if err != nil {
		return finishPhase(phase, err, "")
	}
	reason := firstNonEmpty(ref.Reason, "the account's access was cut")
	if err := owe(ctx, change.ID, ref.UID, reason, principals); err != nil {
		return finishPhase(phase, err, "")
	}
	// It is not settled here, and not by this change at all. The one place that
	// settles it is the one that reads the effects back, so there is no second
	// settlement to agree with the first - and an account with nobody to deny
	// settles on the first pass of it anyway.
	//
	// Closed as skipped, because writing down what is owed is a record and not
	// an effect on the world. Closed as succeeded it would have counted towards
	// the change's result, and a preserve the directory refused outright - one
	// that applied nothing at all - would have read as partially_applied on the
	// strength of this phase alone.
	return skipPhase(phase,
		describeCount("panel identities the cut names", int64(len(principals))))
}

// recordedPhases reads the phases an earlier attempt wrote down. They come back
// whole, because the record of a change is everything that happened to it and
// not the last attempt's view of it - a resume that replaced them dropped the
// directory error of the attempt before it.
//
// Phases that do not read are no record, and the attempt then starts from the
// directory rather than assuming anything about what happened.
func recordedPhases(recorded json.RawMessage) []Phase {
	if len(recorded) == 0 {
		return nil
	}
	var phases []Phase
	if err := json.Unmarshal(recorded, &phases); err != nil {
		return nil
	}
	return phases
}

// outstandingMarker finds the named marker among the phases while it is still
// owed. One reader for both markers, so the obligation and the intent cannot
// come to disagree about what "still outstanding" means.
func outstandingMarker(phases []Phase, name string) (string, bool) {
	for _, phase := range phases {
		if phase.Name == name && phase.Status == PhaseOutstanding {
			return phase.Message, true
		}
	}
	return "", false
}

// settleMarker closes the named marker with what became of it. Both markers go
// through it, so neither can be left behind in a shape the other would not
// recognise - and a marker left outstanding makes the change read as one whose
// outcome is still in the air.
func settleMarker(phases []Phase, name string, close func(Phase) Phase) []Phase {
	for index := range phases {
		if phases[index].Name == name && phases[index].Status == PhaseOutstanding {
			phases[index] = close(phases[index])
		}
	}
	return phases
}

// settleIntent closes the intent marker with what the directory said about the
// effect of the call. It is a record and not a step, so it is closed as skipped:
// the verdict on the change itself is the phase of the call.
func settleIntent(phases []Phase, verdict string) []Phase {
	return settleMarker(phases, phaseDirectoryMutationIntent, func(phase Phase) Phase {
		return skipPhase(phase, verdict)
	})
}

// owesLocalAccess reads the phases an earlier attempt recorded, and the
// obligation among them if it is still outstanding.
func owesLocalAccess(recorded json.RawMessage) ([]Phase, string, bool) {
	phases := recordedPhases(recorded)
	owed, outstanding := outstandingMarker(phases, phaseLocalAccessOwed)
	if !outstanding {
		return nil, "", false
	}
	return phases, owed, true
}

// intendedMutation reads the intent an earlier attempt wrote down before it
// ordered a change in the directory. An intent still outstanding is the one
// state the marker exists for: the call was about to go out, or had gone out,
// and the attempt stopped before it could say which.
func intendedMutation(recorded json.RawMessage) ([]Phase, string, bool) {
	phases := recordedPhases(recorded)
	pending, outstanding := outstandingMarker(phases, phaseDirectoryMutationIntent)
	if !outstanding {
		return nil, "", false
	}
	return phases, pending, true
}

// payLocalAccess writes the obligation down, carries it out and settles it on
// the effects it names. The order is the point: the obligation reaches the row
// before the work starts, so an attempt that finds it does the work rather than
// reasoning about what the previous one got to.
//
// It is settled only where the phases of the local half confirm the effects -
// not where the attempt to produce them returned. A marker turned to succeeded
// over a denial that failed makes the row claim an effect it did not have, and
// leaves nothing for a later attempt to pick up.
func (e *Executor) payLocalAccess(ctx context.Context, change Change, hold Hold,
	phases []Phase, ref *ReferencePayload, owed string) ([]Phase, *sessionRevocation) {
	if _, outstanding := outstandingMarker(phases, phaseLocalAccessOwed); !outstanding {
		phases = append(phases, outstandingPhase(startPhase(phaseLocalAccessOwed), owed))
	}
	if err := e.savePhases(ctx, change, hold, phases); err != nil {
		// The obligation is not written down, so the mutation it covers does not
		// happen here: the change stays owed, visibly, rather than having an
		// effect nothing records.
		return append(phases, finishPhase(startPhase("recording what the panel owes"), err, "")), nil
	}
	local, revoked := e.cutLocalAccess(ctx, ref)
	phases = append(phases, local...)
	if !localAccessCut(local) {
		return phases, revoked
	}
	phases = settleMarker(phases, phaseLocalAccessOwed, func(phase Phase) Phase {
		return finishPhase(phase, nil, "carried out: "+owed)
	})
	return phases, revoked
}

// localAccessCut says whether the phases of the panel's own half confirm that
// the access is gone. A denial with nobody to mark is a phase that skipped and
// an access that is not there; a denial or a revocation that failed is neither.
func localAccessCut(local []Phase) bool {
	for _, phase := range local {
		if phase.Status == "failed" || phase.Status == PhaseOutstanding {
			return false
		}
	}
	return len(local) > 0
}

// savePhases writes down what has happened so far, and says whether it landed.
// The caller stops on a failure: a record that was not written is a record the
// next attempt will not have, and the mutation that would follow it would then
// be one nobody can account for - the claim may also be gone, which is one of
// the ways this write fails.
func (e *Executor) savePhases(ctx context.Context, change Change, hold Hold, phases []Phase) error {
	if e.recordPhases == nil && e.store == nil {
		return nil
	}
	save := e.recordPhases
	if save == nil {
		save = func(ctx context.Context, changeID string, phases []Phase) error {
			return e.store.SavePhases(ctx, changeID, hold, phases)
		}
	}
	err := save(ctx, change.ID, phases)
	if err != nil && e.log != nil {
		e.log.Warn("the phases of the directory change were not recorded",
			"change_id", change.ID, "err", err)
	}
	return err
}

// preserveUser removes an account while keeping its entry. The order is the
// reverse of a disable, and deliberately so.
func (e *Executor) preserveUser(ctx context.Context, change Change, hold Hold,
	ref *ReferencePayload) ([]Phase, *sessionRevocation) {
	var phases []Phase

	// An attempt that took the change as far as the directory wrote down what
	// the panel still owes. Asking the directory again would refuse as stale -
	// the active entry is gone - and the access here would stay open, so the
	// obligation is met instead of the change starting over.
	if earlier, owed, outstanding := owesLocalAccess(hold.Phases); outstanding {
		// The earlier attempt's phases are carried forward as they stand - its
		// directory error included - and this attempt's are added after them.
		phases = append(phases, earlier...)
		phases = append(phases, skipPhase(startPhase("taking the change over"),
			"an earlier attempt took it to the directory and left the panel's own half owed: "+owed))
		return e.payLocalAccess(ctx, change, hold, phases, ref, owed)
	}

	// An attempt that wrote the intent and recorded no verdict on it stopped in
	// the one window that used to leave nothing behind: the mutating call was
	// about to go out, or had gone out, and nobody said which. That is its own
	// state and it has its own recovery - asking the directory again from the
	// top would read "no active entry" as a stale plan and leave the access of
	// a possibly preserved account alive.
	if earlier, pending, outstanding := intendedMutation(hold.Phases); outstanding {
		phases = append(phases, earlier...)
		phases = append(phases, skipPhase(startPhase("taking the change over"),
			"an earlier attempt was about to change the directory and left no verdict on it: "+pending))
		return e.resumeAfterIntent(ctx, change, hold, phases, ref)
	}

	phase := startPhase("asking the directory what it can do")
	capabilities, err := e.directoryCapabilities(ctx, ref.UID)
	if err != nil {
		return append(phases, refusedPhase(phase, RefusalDirectoryUnreachable, err.Error())), nil
	}
	if reason, blocked := capabilities.PreserveBlocked(); blocked {
		return append(phases, refusedPhase(phase, RefusalModDNUnsupported,
			"the directory cannot preserve an account: "+reason+"; "+capabilities.Instruction)), nil
	}
	// The reads that come before the change are recorded for what they are:
	// carried out, and no part of the change.
	phases = append(phases, skipPhase(phase, describeCapabilities(capabilities)))

	phase = startPhase("binding the plan to the entry")
	planned, err := preservePlan(change)
	if err != nil {
		return append(phases, refusedPhase(phase, RefusalPlanIncomplete, err.Error())), nil
	}
	current, err := e.directoryEntry(ctx, ref.UID)
	if errors.Is(err, freeipa.ErrEntryNotFound) {
		// The account may be the one this very change moved: an attempt that
		// preserved it and stopped before the local half leaves no active entry
		// and a preserved one carrying the identifier the plan named. Finding
		// that, the move stands and what is left is to cut the access here -
		// the refusal below would leave the holder its sessions and tokens.
		preserved, ok, unknown := e.alreadyPreserved(ctx, ref.UID, planned)
		switch {
		case ok:
			phases = append(phases, skipPhase(phase,
				"the account is already preserved as the entry the plan named ("+preserved+")"))
			return e.payLocalAccess(ctx, change, hold, phases, ref,
				"the account is preserved as the entry the plan named ("+preserved+")")
		case unknown != "":
			// Neither a stale plan nor a move this change can claim: said as
			// the open question it is, for a person to settle.
			return append(phases, refusedPhase(phase, RefusalOutcomeUnknown,
				err.Error()+"; "+unknown)), nil
		}
	}
	if err != nil {
		// An entry the directory no longer holds under that name is not an outage:
		// somebody preserved or removed the account between the plan and now, which
		// is exactly what the binding exists to catch.
		code := RefusalDirectoryUnreachable
		if errors.Is(err, freeipa.ErrEntryNotFound) {
			code = RefusalStalePlan
		}
		return append(phases, refusedPhase(phase, code, err.Error())), nil
	}
	if moved, ok := planned.Moved(current); ok {
		return append(phases, refusedPhase(phase, RefusalStalePlan, moved)), nil
	}
	phases = append(phases, skipPhase(phase, "the entry is the one the plan named ("+planned.Binding()+")"))

	return e.moveInDirectory(ctx, change, hold, phases, ref, planned)
}

// moveInDirectory writes the intent down, orders the move and settles the
// intent on what came back. The order is the whole point of it: the record that
// a mutation is about to be made reaches the row BEFORE the call goes out, so a
// replica that stops in the window between them leaves behind the one fact the
// next attempt cannot otherwise have. Written after the call, the record was
// missing in exactly the case it exists for.
func (e *Executor) moveInDirectory(ctx context.Context, change Change, hold Hold,
	phases []Phase, ref *ReferencePayload, planned freeipa.EntryReference) ([]Phase, *sessionRevocation) {
	// The obligation that outlives the change goes down first, for the same
	// reason the intent does and in the same window.
	owed := e.oweLocalAccess(ctx, change, ref)
	phases = append(phases, owed)
	if owed.Status == "failed" {
		return phases, nil
	}

	intent := outstandingPhase(startPhase(phaseDirectoryMutationIntent),
		"the move of "+planned.Binding()+" is about to be ordered; its effect is "+
			"unknown until this change says otherwise")
	if err := e.savePhases(ctx, change, hold, append(phases, intent)); err != nil {
		// Nothing durable says the mutation is coming, so it does not go out.
		// An effect no later attempt could account for is worse than a change
		// that visibly did not start - and a lost claim is one of the ways this
		// write fails, in which case the row is not this attempt's to change.
		note := startPhase("recording the directory change the panel is about to make")
		return append(phases, finishPhase(note, err, "")), nil
	}
	phases = append(phases, intent)

	phase := startPhase(phasePreserveInDirectory)
	proof, err := e.preserveInDirectory(ctx, ref.UID, planned)
	if err != nil {
		code := RefusalDirectoryRefused
		if errors.Is(err, freeipa.ErrEntryMoved) {
			code = RefusalStalePlan
		}
		var unsettled *freeipa.PreserveUnsettled
		if !errors.As(err, &unsettled) {
			// Nothing in the directory changed, so there is nothing to follow.
			phases = settleIntent(phases, "the directory refused the move, so it had no effect")
			return append(phases, refusedPhase(phase, code, err.Error())), nil
		}
		// The account is preserved - or may be, and nobody can say otherwise -
		// so the panel's own half is owed either way. A preserved account whose
		// holder keeps its sessions and tokens is the window this leaves open.
		phases = settleIntent(phases, "the move went out and its effect is the refusal below")
		phases = append(phases, refusedPhase(phase, RefusalOutcomeUnknown, err.Error()))
		return e.payLocalAccess(ctx, change, hold, phases, ref, err.Error())
	}
	phases = settleIntent(phases, "the move went out and the directory confirmed it")
	phases = append(phases, finishPhase(phase, nil, "the entry stays as a preserved account"))

	// Whether the entry after the move is the one the operator consented to is
	// a step of its own: it was read back and compared, or it was not, and the
	// phase that said "the entry stays as a preserved account" claimed a proof
	// it did not always have.
	phase = startPhase("confirming the identity of the preserved entry")
	if proof.Confirmed {
		phases = append(phases, finishPhase(phase, nil, proof.Detail))
	} else {
		phases = append(phases, skipPhase(phase, proof.Detail))
	}
	// The obligation is written down before the local half starts: a replica
	// that stops in between leaves the record, and the attempt that takes the
	// change meets it instead of asking the directory about an account that is
	// no longer active.
	return e.payLocalAccess(ctx, change, hold, phases, ref,
		"the account is preserved in the directory")
}

// resumeAfterIntent recovers the state the intent marker exists to leave
// behind: intent written, effect unknown. It treats the unknown as unknown -
// it may not assume the mutation happened and it may not assume it did not -
// so it asks the directory and settles only on a positive identification.
//
// The entry still active and still the one the plan named is the single reading
// that says the move was not made, and the change then goes on from there. The
// entry preserved and carrying the plan's identifier says it was made, and what
// is left is the panel's own half. Everything else stays unknown, and the
// unknown owes the local half too: a preserved account whose holder keeps its
// sessions and tokens is the expensive mistake here, while a denial that was
// not needed is lifted with one call. The change is left intermediate either
// way, so a person reads what the directory could not settle.
func (e *Executor) resumeAfterIntent(ctx context.Context, change Change, hold Hold,
	phases []Phase, ref *ReferencePayload) ([]Phase, *sessionRevocation) {
	const asking = "establishing what the interrupted change did"

	planned, err := preservePlan(change)
	if err != nil {
		// Neither side carries anything to identify the entry by, so nothing
		// can settle this in either direction.
		owed := "an earlier attempt was about to preserve the account and the plan names no " +
			"entry to check it against, so whether the move was made is not known: " + err.Error()
		phases = settleIntent(phases, owed)
		phases = append(phases, refusedPhase(startPhase(asking), RefusalOutcomeUnknown, owed))
		return e.payLocalAccess(ctx, change, hold, phases, ref, owed)
	}

	current, err := e.directoryEntry(ctx, ref.UID)
	switch {
	case err == nil:
		if moved, stale := planned.Moved(current); stale {
			// Another entry holds the name now, so this change has nothing left
			// to do to it - and nothing it did can be claimed either.
			settled := "the name is held by another entry, so the interrupted call did not " +
				"move the one the plan named"
			phases = settleIntent(phases, settled)
			return append(phases, refusedPhase(startPhase(asking), RefusalStalePlan, moved)), nil
		}
		// The entry the plan named is still active. That is an identification
		// and not a guess: a move that had been made would have left no active
		// entry under the name.
		settled := "the account is still active as the entry the plan named (" + planned.Binding() +
			"), so the interrupted call did not move it"
		phases = settleIntent(phases, settled)
		phases = append(phases, skipPhase(startPhase(asking), settled))
		return e.moveInDirectory(ctx, change, hold, phases, ref, planned)
	case errors.Is(err, freeipa.ErrEntryNotFound):
		preserved, identified, unknown := e.alreadyPreserved(ctx, ref.UID, planned)
		if identified {
			settled := "the account is preserved as the entry the plan named (" + preserved +
				"), so the interrupted call moved it"
			phases = settleIntent(phases, settled)
			phases = append(phases, skipPhase(startPhase(asking), settled))
			return e.payLocalAccess(ctx, change, hold, phases, ref, settled)
		}
		owed := unknown
		if owed == "" {
			// Not active and not among the preserved ones: something happened
			// to the account that this change cannot claim and cannot rule out.
			owed = "the account is neither active nor identifiable among the preserved ones, so " +
				"whether the interrupted call moved it is not known"
		}
		phases = settleIntent(phases, owed)
		phases = append(phases, refusedPhase(startPhase(asking), RefusalOutcomeUnknown, owed))
		return e.payLocalAccess(ctx, change, hold, phases, ref, owed)
	}
	owed := "the directory did not answer, so whether the interrupted call moved the entry " +
		"is not known: " + err.Error()
	phases = settleIntent(phases, owed)
	phases = append(phases, refusedPhase(startPhase(asking), RefusalOutcomeUnknown, owed))
	return e.payLocalAccess(ctx, change, hold, phases, ref, owed)
}

// cutLocalAccess is the panel's own half of a preserve: the denial marker, the
// panel sessions and the provider's. It is its own function because it has
// three callers now - the preserve that went through, the preserve that failed
// with the account left preserved, and the attempt that finds the move already
// made.
func (e *Executor) cutLocalAccess(ctx context.Context, ref *ReferencePayload) ([]Phase, *sessionRevocation) {
	reason := firstNonEmpty(ref.Reason, "the account was preserved")
	phase := startPhase("the local denial marker")
	count, err := e.denyDirectoryUser(ctx, ref.UID, reason, true)
	phases := []Phase{deniedLocally(phase, count, err, "identities marked",
		"the panel knows no identity by that name, so there was nothing to deny locally")}

	phase = startPhase("revoking the panel sessions")
	result, err := e.revokeSessions(ctx, ref.UID, reason)
	phases = append(phases, finishPhase(phase, err, result.String()))

	phase, ended := e.endProviderSessions(ctx, ref.UID)
	phases = append(phases, phase)
	result.ProviderSessionsEnded = &ended.Ended
	result.ProviderReason = ended.Reason
	return phases, &result
}

// alreadyPreserved says whether the account is preserved as the entry the plan
// named. It answers yes only on a positive identification - both sides carry
// the identifier and they agree - because a guess here would cut off the access
// of whoever holds the name now.
//
// The third answer is its own: "nobody could say" is not "it is not there", and
// it comes back as a sentence for the refusal rather than being folded into the
// no.
func (e *Executor) alreadyPreserved(ctx context.Context, uid string,
	planned freeipa.EntryReference) (string, bool, string) {
	preserved, err := e.preservedEntry(ctx, uid)
	switch {
	case errors.Is(err, freeipa.ErrEntryNotFound):
		return "", false, ""
	case err != nil:
		return "", false, "the preserved accounts could not be read, so whether this change " +
			"moved the entry is not known: " + err.Error()
	case planned.EntryUUID == "" || preserved.EntryUUID == "":
		return "", false, "the entry among the preserved accounts carries no identifier to " +
			"compare, so whether it is the one the plan named is not known"
	}
	if _, replaced := planned.Replaced(preserved); replaced {
		return "", false, ""
	}
	return preserved.EntryUUID, true, ""
}

// directoryCapabilities, directoryEntry, preserveInDirectory and denyLocally
// are the four halves of a preserve behind their seams.
func (e *Executor) directoryCapabilities(ctx context.Context, uid string) (freeipa.DirectoryCapabilities, error) {
	if e.capabilities != nil {
		return e.capabilities(ctx, uid)
	}
	return e.directory.CapabilitiesFor(ctx, uid)
}

func (e *Executor) directoryEntry(ctx context.Context, uid string) (freeipa.EntryReference, error) {
	if e.entryOf != nil {
		return e.entryOf(ctx, uid)
	}
	return e.directory.UserEntry(ctx, uid)
}

func (e *Executor) preservedEntry(ctx context.Context, uid string) (freeipa.EntryReference, error) {
	if e.preservedOf != nil {
		return e.preservedOf(ctx, uid)
	}
	if e.directory == nil {
		return freeipa.EntryReference{}, fmt.Errorf("the directory connector is not configured")
	}
	return e.directory.PreservedEntry(ctx, uid)
}

func (e *Executor) preserveInDirectory(ctx context.Context, uid string,
	planned freeipa.EntryReference) (freeipa.PreserveProof, error) {
	if e.preserve != nil {
		return e.preserve(ctx, uid, planned)
	}
	// The adapter binds the move to the entry a second time, immediately before
	// ordering it: this check and the one above are the same question asked at
	// the two ends of the window between them.
	return e.directory.PreserveUserAt(ctx, uid, planned)
}

func (e *Executor) enableInDirectory(ctx context.Context, uid string, enable bool) error {
	if e.setEnabled != nil {
		return e.setEnabled(ctx, uid, enable)
	}
	return e.directory.SetUserEnabled(ctx, uid, enable)
}

func (e *Executor) denyLocally(ctx context.Context, subject, reason string,
	denied bool) (int64, error) {
	if e.localDeny != nil {
		return e.localDeny(ctx, subject, reason, denied)
	}
	return e.store.SetLocalDeny(ctx, subject, reason, denied)
}

// preservePlan reads the entry the approved plan would move.
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

// describeCapabilities says what the preflight established, including what it
// could not: a directory that does not report the rights on an entry is not a
// directory that granted them.
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

// resetPassword asks the directory for a new password and keeps it for the
// requester alone, in memory.
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
func (e *Executor) finish(ctx context.Context, change Change, hold Hold, state State,
	phases []Phase, message string, revoked *sessionRevocation) {
	// The result is written under a context of its own, briefly: the work's
	// context is cancelled when this replica loses the claim, and a change
	// whose result went nowhere because of that would be a change nobody can
	// read the end of.
	ctx, settled := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer settled()

	// A result that did not land is said so in the trail: the state an auditor
	// reads is the one another attempt wrote, and claiming this one as the
	// outcome of the change would be the overwrite in words.
	recorded := true
	if err := e.store.Finish(ctx, change.ID, hold, state, phases, message); err != nil {
		recorded = false
		if errors.Is(err, ErrClaimLost) {
			e.log.Warn("the result of the directory change was not recorded",
				"change_id", change.ID, "err", err)
		} else {
			e.log.Error("the result of the directory change was not recorded",
				"change_id", change.ID, "err", err)
		}
	}

	outcome := audit.OutcomeSuccess
	if state != StateSucceeded || !recorded {
		outcome = audit.OutcomeFailure
	}
	failedPhases := make([]string, 0)
	// A phase nobody has confirmed goes in the trail as well: an auditor reading
	// this change has to see that the work was ordered and not that it landed.
	outstandingPhases := make([]string, 0)
	for _, phase := range phases {
		switch phase.Status {
		case "failed":
			failedPhases = append(failedPhases, phase.Name+": "+phase.Message)
		case PhaseOutstanding:
			outstandingPhases = append(outstandingPhases, phase.Name+": "+phase.Message)
		}
	}
	detail := map[string]any{
		"action_type": change.ActionType, "state": string(state),
		"created_by": change.CreatedBy, "approved_by": change.ApprovedBy,
		"failed_phases": failedPhases, "outstanding_phases": outstandingPhases,
		"message": message, "result_recorded": recorded,
	}
	if revoked != nil {
		// The count is what an auditor looks for after a membership change: whether
		// the old scope really ended.
		detail["sessions_revoked"] = revoked.Sessions
		detail["without_principal"] = revoked.WithoutPrincipal
		// Whether the provider ended its sessions too, and if not, why: an auditor
		// reading a disable wants to know how long the user could still reach the
		// other applications.
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

// skipPhase closes a phase that changed nothing, with what it found.
func skipPhase(phase Phase, message string) Phase {
	phase.FinishedAt = time.Now().UTC()
	phase.Status = "skipped"
	phase.Message = message
	return phase
}

// outstandingPhase closes the panel's part of a phase whose result comes from
// somewhere else - a task on a host - and says what is being waited for.
func outstandingPhase(phase Phase, message string) Phase {
	phase.FinishedAt = time.Now().UTC()
	phase.Status = PhaseOutstanding
	phase.Message = message
	return phase
}

// refusedPhase closes a phase with a typed refusal.
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
// counterpart.
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

	// A zone named explicitly must not leave the name computed for a /24: the PTR
	// would then be created for a different address than the one in the request.
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
	phases := []Phase{finishPhase(phase, err, message)}

	// What the rule grants after a failed change is its own result: a rule the
	// directory would not take back is louder than the change that failed.
	var change *freeipa.RuleChangeError
	if errors.As(err, &change) {
		restore := startPhase("restoring the HBAC rule " + spec.Name)
		phases = append(phases, finishPhase(restore, change.Restore, change.Outcome))
	}
	return phases
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
	phases := []Phase{finishPhase(phase, err, message)}

	// What the rule allows after a failed change is its own result: a rule the
	// directory would not take back is louder than the change that failed.
	var change *freeipa.RuleChangeError
	if errors.As(err, &change) {
		restore := startPhase("restoring the sudo rule " + spec.Name)
		phases = append(phases, finishPhase(restore, change.Restore, change.Outcome))
	}
	return phases
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
