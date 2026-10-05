package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/freeipa"
)

// fakeSessions stands in for the session store: a fixed list of principals
// and a count of live sessions per principal.
type fakeSessions struct {
	principals []authz.Principal
	live       map[string]int64
	revoked    map[string]string
	listErr    error
}

func (f *fakeSessions) ListPrincipals(context.Context) ([]authz.Principal, error) {
	return f.principals, f.listErr
}

func (f *fakeSessions) RevokeSessionsOf(_ context.Context, principalID, reason string) (int64, error) {
	if f.revoked == nil {
		f.revoked = map[string]string{}
	}
	f.revoked[principalID] = reason
	return f.live[principalID], nil
}

func TestADirectoryUserMatchesThePrincipalsTheLoginNamedAfterIt(t *testing.T) {
	// The login names a principal after preferred_username, or after
	// "uid@issuer-host" when that name was taken.
	cases := []struct {
		subject, uid string
		matches      bool
	}{
		{"alice", "alice", true},
		{"alice@ipa.example.test", "alice", true},
		{"alice2", "alice", false},
		{"alice.smith", "alice", false},
		{"bob", "alice", false},
		{"bootstrap-admin", "alice", false},
		{"alice", "", false},
		{"", "alice", false},
	}
	for _, tc := range cases {
		if got := MatchesDirectoryUser(tc.subject, tc.uid); got != tc.matches {
			t.Errorf("MatchesDirectoryUser(%q, %q) = %v, expected %v", tc.subject, tc.uid, got, tc.matches)
		}
	}
}

func TestAMembershipChangeEndsTheSessionsOfTheMovedUsers(t *testing.T) {
	sessions := &fakeSessions{
		principals: []authz.Principal{
			{ID: "p-alice", Subject: "alice"},
			{ID: "p-alice-idp", Subject: "alice@ipa.example.test"},
			{ID: "p-bob", Subject: "bob"},
		},
		live: map[string]int64{"p-alice": 2, "p-alice-idp": 1, "p-bob": 3},
	}
	executor := &Executor{sessions: sessions}

	phase, result := executor.revokeChangedMembers(context.Background(),
		[]string{"alice", "carol"}, "the group membership changed: admins")

	if phase.Status != "succeeded" {
		t.Fatalf("phase = %s (%s), expected succeeded", phase.Status, phase.Message)
	}
	if result.Sessions != 3 {
		t.Fatalf("sessions revoked = %d, expected 3 (both principals of alice, none of bob)", result.Sessions)
	}
	// A user who never logged into the panel has nothing to end. That is
	// said in the result rather than reported as a failure.
	if len(result.WithoutPrincipal) != 1 || result.WithoutPrincipal[0] != "carol" {
		t.Fatalf("without principal = %v, expected [carol]", result.WithoutPrincipal)
	}
	if !strings.Contains(phase.Message, "sessions revoked: 3") ||
		!strings.Contains(phase.Message, "no panel identity for carol") {
		t.Fatalf("message = %q", phase.Message)
	}
	if _, ok := sessions.revoked["p-bob"]; ok {
		t.Fatal("bob was not moved and must keep the session")
	}
	if reason := sessions.revoked["p-alice"]; reason != "the group membership changed: admins" {
		t.Fatalf("reason = %q", reason)
	}
}

// Whose session ends after a membership change is decided by what the
// directory confirmed. A batch whose answer was lost confirmed nothing, and
// nothing was read as "no account moved": the users kept the scope they had.
func TestAMembershipChangeOfUnknownOutcomeEndsTheSessionsOfEveryAccountItNamed(t *testing.T) {
	asked := []string{"alice", "bob"}
	if got := mayHaveMoved(nil, asked); strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("a change the directory took whole moved %v", got)
	}
	partial := &freeipa.PartialChange{Group: "ops", Applied: []string{"alice"},
		Refused: map[string]string{"bob": "This entry is not a member"}}
	if got := mayHaveMoved(partial, asked); strings.Join(got, ",") != "alice" {
		t.Fatalf("a batch taken in part moved %v", got)
	}
	uncertain := &freeipa.UncertainChange{Group: "ops", Users: asked,
		Err: errors.New("the query to the directory: connection reset")}
	if got := mayHaveMoved(uncertain, asked); strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("a batch of unknown outcome moved %v, expected every account it named", got)
	}
	// A command the directory read and turned down changed nobody.
	refused := &freeipa.DirectoryError{Name: "NotFound", Message: "ops: group not found"}
	if got := mayHaveMoved(refused, asked); len(got) != 0 {
		t.Fatalf("a refused command moved %v", got)
	}
}

// A change read in running was claimed by a replica that recorded no result.
// Taking it again used to mean carrying it out from the top, whatever it was:
// a second password reset invalidates the password the requester already has,
// and a second keytab rotation retires the key the renewal just fetched.
func TestAnInterruptedChangeIsOnlyRepeatedWhereRepeatingItLandsOnTheSameState(t *testing.T) {
	declarative := []ActionType{ActionUserDisable, ActionUserEnable, ActionGroupMembers,
		ActionSSHKeys, ActionUserExpire, ActionUserPOSIX, ActionUserPreserve,
		ActionHBACRuleEnsure, ActionSudoRuleEnsure, ActionDNSRecordEnsure}
	resumed := Hold{Holder: "replica-b", Attempt: "22222222-2222-2222-2222-222222222222", Resumed: true}
	for _, action := range declarative {
		change := Change{ID: "c1", ActionType: string(action)}
		if _, _, _, stop := repeatOfInterruptedChange(change, resumed); stop {
			t.Errorf("%s was not carried out again although repeating it changes nothing", action)
		}
	}

	for _, action := range []ActionType{ActionUserPasswordReset, ActionKeytabRotate} {
		change := Change{ID: "c1", ActionType: string(action)}
		phases, state, message, stop := repeatOfInterruptedChange(change, resumed)
		if !stop {
			t.Fatalf("%s was carried out a second time", action)
		}
		// Not failed: part of it may well have happened, and the operator has
		// to read it as a change that began.
		if state != StatePartiallyApplied {
			t.Errorf("%s ended as %s", action, state)
		}
		if len(phases) != 1 || !strings.HasPrefix(phases[0].Message, RefusalInterrupted+":") {
			t.Errorf("the phases of %s are %+v", action, phases)
		}
		if !strings.Contains(message, "interrupted") {
			t.Errorf("the message does not say what happened: %q", message)
		}
		// The first run of the same change is carried out, of course.
		if _, _, _, stop := repeatOfInterruptedChange(change, testHold); stop {
			t.Errorf("a %s nobody had started was refused", action)
		}
		// And the question is asked of the claim, not of the state a poll saw:
		// a snapshot that says planned over a row the claim took out of running
		// used to admit the second attempt this refuses.
		stale := Change{ID: "c1", ActionType: string(action), State: StatePlanned}
		if _, _, _, stop := repeatOfInterruptedChange(stale, resumed); !stop {
			t.Errorf("a stale snapshot let %s run a second time", action)
		}
	}
}

// Losing the claim used to stop the renewer alone: the replica carried the
// change on to the end and was refused at the write, having meanwhile gone on
// talking to the directory about a change another replica was carrying out.
func TestAHolderThatLostTheClaimStopsWorking(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	lost := &Executor{log: quiet, renewEvery: time.Millisecond,
		renewClaim: func(context.Context, string, Hold) (bool, error) { return false, nil }}
	working, release := lost.holdClaim(context.Background(), "c1", testHold)
	defer release()
	select {
	case <-working.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the work went on under a claim this replica no longer holds")
	}

	// A renewal that could not be made is not a claim that was lost: the holder
	// keeps working, and keeps trying, within the term.
	unreachable := &Executor{log: quiet, renewEvery: time.Millisecond, lapseAfter: time.Hour,
		renewClaim: func(context.Context, string, Hold) (bool, error) {
			return false, errors.New("the database does not answer")
		}}
	alive, stop := unreachable.holdClaim(context.Background(), "c1", testHold)
	defer stop()
	select {
	case <-alive.Done():
		t.Fatal("a renewal that failed was read as a claim that was lost")
	case <-time.After(50 * time.Millisecond):
	}

	// The renewal that never answers is the case the expiry check could not
	// reach: it sat in the same loop, so a statement stuck in the database meant
	// the term was never judged and the holder worked on under a claim somebody
	// else had taken. The clock is its own now, and the renewal has a deadline.
	var asked atomic.Int64
	stuck := &Executor{log: quiet, renewEvery: 5 * time.Millisecond, lapseAfter: 50 * time.Millisecond,
		renewClaim: func(ctx context.Context, _ string, _ Hold) (bool, error) {
			asked.Add(1)
			<-ctx.Done()
			return false, ctx.Err()
		}}
	blocked, giveUp := stuck.holdClaim(context.Background(), "c1", testHold)
	defer giveUp()
	select {
	case <-blocked.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a holder whose renewal hangs never found out that its claim had run out")
	}
	// And the renewal was given up on rather than waited for, so it was asked
	// more than once in that time.
	if count := asked.Load(); count < 2 {
		t.Errorf("the renewal was attempted %d times, so it was waited on instead of given a deadline", count)
	}
}

func TestNothingToRevokeIsNotAFailure(t *testing.T) {
	executor := &Executor{sessions: &fakeSessions{}}
	phase, result := executor.revokeChangedMembers(context.Background(), []string{"dave"}, "moved")
	if phase.Status != "succeeded" {
		t.Fatalf("phase = %s (%s), expected succeeded", phase.Status, phase.Message)
	}
	if result.Sessions != 0 || len(result.WithoutPrincipal) != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func TestAFailedListingFailsTheRevocationPhase(t *testing.T) {
	// The directory change itself succeeded; a phase that fails here makes the
	// change partially applied, which is the truth: the membership moved and the
	// old sessions may still be alive.
	executor := &Executor{sessions: &fakeSessions{listErr: errors.New("database gone")}}
	phase, _ := executor.revokeChangedMembers(context.Background(), []string{"alice"}, "moved")
	if phase.Status != "failed" {
		t.Fatalf("phase = %s, expected failed", phase.Status)
	}
}

// fakeLogoutProvider stands in for the identity provider's admin logout: it
// remembers whom it was asked to log out and answers what the test set.
type fakeLogoutProvider struct {
	loggedOut []string
	err       error
}

func (f *fakeLogoutProvider) LogoutSubject(_ context.Context, subject string) error {
	f.loggedOut = append(f.loggedOut, subject)
	return f.err
}

func TestADisableEndsTheProviderSessionsAndNeverFailsOnThem(t *testing.T) {
	// The provider answers: the phase says so, and the result carries
	// provider_sessions_ended for the auditor.
	provider := &fakeLogoutProvider{}
	executor := &Executor{provider: provider}
	phase, ended := executor.endProviderSessions(context.Background(), "alice")
	if phase.Status != "succeeded" || !ended.Ended || ended.Reason != "" {
		t.Fatalf("phase = %s (%s), outcome = %+v", phase.Status, phase.Message, ended)
	}
	if len(provider.loggedOut) != 1 || provider.loggedOut[0] != "alice" {
		t.Fatalf("the provider was asked to log out %v", provider.loggedOut)
	}

	// The provider refuses or is unreachable: the disable holds on the local
	// marker, so the phase is skipped with the reason rather than failed - a
	// failed phase would call the whole disable partially applied, and it is not.
	refusing := &Executor{provider: &fakeLogoutProvider{err: errors.New("the admin API answered 403 Forbidden")}}
	phase, ended = refusing.endProviderSessions(context.Background(), "alice")
	if phase.Status != "skipped" || ended.Ended || !strings.Contains(ended.Reason, "403") {
		t.Fatalf("phase = %s (%s), outcome = %+v", phase.Status, phase.Message, ended)
	}
	if state := StateFor([]Phase{{Status: "succeeded"}, phase}); state != StateSucceeded {
		t.Fatalf("a skipped provider logout made the change %s", state)
	}

	// No provider configured at all: the same skip, with that reason.
	phase, ended = (&Executor{}).endProviderSessions(context.Background(), "alice")
	if phase.Status != "skipped" || ended.Ended || ended.Reason == "" {
		t.Fatalf("phase = %s (%s), outcome = %+v", phase.Status, phase.Message, ended)
	}
}

// preserveHarness is an executor whose four halves of a preserve are recorded:
// what the directory was asked, in which order, and whether the local account
// was touched at all.
type preserveHarness struct {
	executor *Executor
	// order is what happened and in which sequence. The order is the point
	// of the operation, so the test reads it rather than only the outcome.
	order        []string
	capabilities freeipa.DirectoryCapabilities
	entry        freeipa.EntryReference
	entryErr     error
	preserveErr  error
	// preserved is the entry the directory holds among its preserved accounts,
	// which is what an attempt reads when the active one is gone.
	preserved    freeipa.EntryReference
	preservedErr error
	// denyErr is what the local denial answers; recordErr is what the attempt
	// to write the phases down answers.
	denyErr   error
	recordErr error
	// saved are the snapshots of the phases written down while the change runs.
	saved [][]Phase
	// proof is what the adapter could establish about the entry after the move.
	proof freeipa.PreserveProof
}

func newPreserveHarness(t *testing.T) *preserveHarness {
	t.Helper()
	harness := &preserveHarness{
		// A directory that reports the connector may move an entry: the
		// preflight then blocks nothing and the test is about what follows.
		capabilities: freeipa.DirectoryCapabilities{UserModDN: true},
		// The entry was read back after the move and carries the identifier the
		// plan named: the ordinary case, where the preserve is proven.
		proof: freeipa.PreserveProof{Confirmed: true,
			Detail: "the preserved entry carries the identifier the plan named"},
		entry: freeipa.EntryReference{
			DN:              "uid=alice,cn=users,cn=accounts,dc=ipa,dc=example,dc=test",
			EntryUUID:       "0b1d4c8e-0000-0000-0000-000000000001",
			ModifyTimestamp: "20260917103000Z",
		},
		// Nothing is preserved under that name until a test says so.
		preservedErr: fmt.Errorf("%w: alice", freeipa.ErrEntryNotFound),
	}
	harness.executor = &Executor{
		// The account has signed in to the panel, so there is an identity here
		// to deny; the denial is aimed at the identities, not at the name.
		sessions: &fakeSessions{
			principals: []authz.Principal{{ID: "p-alice", Subject: "alice"}},
			live:       map[string]int64{},
		},
		capabilities: func(_ context.Context, uid string) (freeipa.DirectoryCapabilities, error) {
			// The question is about this account's entry: the order records which one
			// it was asked about, so a preserve that asked about somebody else would be
			// visible here.
			harness.order = append(harness.order, "capabilities:"+uid)
			return harness.capabilities, nil
		},
		entryOf: func(_ context.Context, uid string) (freeipa.EntryReference, error) {
			harness.order = append(harness.order, "entry:"+uid)
			return harness.entry, harness.entryErr
		},
		preserve: func(_ context.Context, uid string, planned freeipa.EntryReference) (freeipa.PreserveProof, error) {
			harness.order = append(harness.order, "preserve:"+uid+"@"+planned.DN)
			return harness.proof, harness.preserveErr
		},
		localDeny: func(_ context.Context, subject, _ string, denied bool) (int64, error) {
			harness.order = append(harness.order, fmt.Sprintf("deny:%s:%v", subject, denied))
			if harness.denyErr != nil {
				return 0, harness.denyErr
			}
			return 1, nil
		},
		preservedOf: func(_ context.Context, uid string) (freeipa.EntryReference, error) {
			harness.order = append(harness.order, "preserved-read:"+uid)
			return harness.preserved, harness.preservedErr
		},
		recordPhases: func(_ context.Context, _ string, phases []Phase) error {
			harness.saved = append(harness.saved, append([]Phase{}, phases...))
			return harness.recordErr
		},
	}
	return harness
}

// preserve runs the preserve under a hold of its own, the way the executor
// does after claiming the change.
func (h *preserveHarness) preserve(change Change, ref *ReferencePayload) ([]Phase, *sessionRevocation) {
	return h.executor.preserveUser(context.Background(), change, testHold, ref)
}

// testHold stands for the claim a replica takes before it executes.
var testHold = Hold{Holder: "replica-under-test", Attempt: "11111111-1111-1111-1111-111111111111"}

// preserveChange is an approved change whose plan names the entry.
func preserveChange(entry freeipa.EntryReference) Change {
	plan, _ := json.Marshal(map[string]any{
		"summary":        "Preserving the account alice",
		"preserve_entry": entry,
	})
	return Change{ID: "change-1", ActionType: string(ActionUserPreserve), Plan: plan}
}

// did says whether the recorded order contains the step. did says whether a
// step happened.
func (h *preserveHarness) did(step string) bool {
	for _, done := range h.order {
		if done == step || strings.HasPrefix(done, step+"@") {
			return true
		}
	}
	return false
}

// A directory that refuses the move leaves the local account exactly as it
// was.
func TestADirectoryThatRefusesThePreserveLeavesTheLocalAccountAsItWas(t *testing.T) {
	harness := newPreserveHarness(t)
	harness.preserveErr = &freeipa.DirectoryError{
		Name:    "ACIError",
		Message: "Insufficient access: Insufficient 'delete' privilege",
	}

	phases, revoked := harness.preserve(
		preserveChange(harness.entry), &ReferencePayload{UID: "alice"})

	if harness.did("deny:alice:true") {
		t.Fatal("the local denial marker was set although the directory refused the move")
	}
	if revoked != nil {
		t.Error("the panel sessions were revoked although the directory refused the move")
	}
	last := phases[len(phases)-1]
	if last.Status != "failed" || !strings.HasPrefix(last.Message, RefusalDirectoryRefused+":") {
		t.Fatalf("the last phase is %s (%s), expected a failure coded %s",
			last.Status, last.Message, RefusalDirectoryRefused)
	}
	// The refusal carries the directory's own reason, not a summary of it: an ACI
	// that is missing and a container that is not there are repaired differently.
	if !strings.Contains(last.Message, "ACIError") ||
		!strings.Contains(last.Message, "Insufficient 'delete' privilege") {
		t.Errorf("the refusal %q does not carry the directory's own reason", last.Message)
	}
	if state := StateFor(phases); state != StateFailed {
		t.Errorf("the change is %s, expected failed", state)
	}
}

// The directory goes first and the local half follows only on its
// confirmation. The sequence is the fix, so the sequence is what is asserted.
func TestAPreserveAsksTheDirectoryBeforeItTouchesTheLocalAccount(t *testing.T) {
	harness := newPreserveHarness(t)

	phases, revoked := harness.preserve(
		preserveChange(harness.entry), &ReferencePayload{UID: "alice"})

	want := []string{"capabilities:alice", "entry:alice",
		"preserve:alice@" + harness.entry.DN, "deny:alice:true"}
	if len(harness.order) != len(want) {
		t.Fatalf("the steps were %v, expected %v", harness.order, want)
	}
	for index := range want {
		if harness.order[index] != want[index] {
			t.Fatalf("the steps were %v, expected %v", harness.order, want)
		}
	}
	if revoked == nil {
		t.Error("the panel sessions were not revoked after a directory that confirmed")
	}
	if state := StateFor(phases); state != StateSucceeded {
		t.Errorf("the change is %s, expected succeeded", state)
	}
}

// A preserve the directory could not be asked about afterwards used to end in
// a phase reading "the entry stays as a preserved account" - a claim of a proof
// nobody had. The confirmation is a step of its own now, and it says which of
// the two it was.
func TestAPreserveSaysWhetherTheEntryAfterTheMoveWasConfirmed(t *testing.T) {
	harness := newPreserveHarness(t)
	phases, _ := harness.preserve(
		preserveChange(harness.entry), &ReferencePayload{UID: "alice"})
	confirmation, found := phaseNamed(phases, "confirming the identity of the preserved entry")
	if !found {
		t.Fatalf("no phase confirms the entry: %+v", phases)
	}
	if confirmation.Status != "succeeded" {
		t.Fatalf("a confirmed entry became %s (%s)", confirmation.Status, confirmation.Message)
	}

	// The same preserve on a directory that offers no read of its preserved
	// accounts: carried out, not proven, and the change is not a failure.
	unproven := newPreserveHarness(t)
	unproven.proof = freeipa.PreserveProof{
		Detail: "this directory offers no read of its preserved accounts, so the entry was not read after the move",
	}
	phases, revoked := unproven.preserve(
		preserveChange(unproven.entry), &ReferencePayload{UID: "alice"})
	confirmation, found = phaseNamed(phases, "confirming the identity of the preserved entry")
	if !found {
		t.Fatalf("no phase confirms the entry: %+v", phases)
	}
	if confirmation.Status != "skipped" {
		t.Fatalf("an unproven entry became %s (%s)", confirmation.Status, confirmation.Message)
	}
	if !strings.Contains(confirmation.Message, "no read of its preserved accounts") {
		t.Errorf("the phase does not say why there is no proof: %q", confirmation.Message)
	}
	// The account is preserved either way, so the panel's own half still runs.
	if !unproven.did("deny:alice:true") || revoked == nil {
		t.Errorf("the local half did not run after an unproven preserve: %v", unproven.order)
	}
	if state := StateFor(phases); state != StateSucceeded {
		t.Errorf("the change is %s, expected succeeded", state)
	}
}

// A preserve that failed after the account had been moved left the account
// preserved in the directory and returned before the local half, so its holder
// kept an unset denial marker, live sessions and live tokens. A refusal before
// the change and a failure after one are not the same thing.
func TestAPreserveThatLeftTheAccountPreservedStillCutsTheLocalAccess(t *testing.T) {
	harness := newPreserveHarness(t)
	harness.preserveErr = &freeipa.PreserveUnsettled{UID: "alice", Preserved: true, Err: fmt.Errorf(
		"%w: the entry carries another identifier; putting it back failed too",
		freeipa.ErrEntryMoved)}

	phases, revoked := harness.preserve(
		preserveChange(harness.entry), &ReferencePayload{UID: "alice"})

	directory, found := phaseNamed(phases, phasePreserveInDirectory)
	if !found || directory.Status != "failed" {
		t.Fatalf("the directory half is %+v", directory)
	}
	if !harness.did("deny:alice:true") {
		t.Fatalf("the account stays preserved and keeps its tokens: %v", harness.order)
	}
	if revoked == nil {
		t.Fatal("the panel sessions of a preserved account were not ended")
	}
	// Some of it was applied and some was not, which is what the state says.
	if state := StateFor(phases); state != StatePartiallyApplied {
		t.Errorf("the change is %s, expected partially_applied", state)
	}
	// What happened reaches the row before the local half runs, so an attempt
	// after a crash here reads it.
	if len(harness.saved) == 0 {
		t.Fatal("nothing was written down before the local half")
	}
}

// A crash between the move and the denial used to leave the access open for
// good: the next attempt found no active entry, refused as stale and stopped.
// Both ways back are asserted - the record the previous attempt wrote, and the
// preserved entry itself.
func TestAnAttemptAfterTheMoveCutsTheAccessInsteadOfRefusing(t *testing.T) {
	// The record: the previous attempt wrote down what the panel owes. The
	// obligation is read from the claim, because the claim is what took the row
	// over - and it is read whatever the verdict of the directory phase next to
	// it, which for a lost answer is a failure.
	fromRecord := newPreserveHarness(t)
	recorded, err := json.Marshal([]Phase{
		{Name: phasePreserveInDirectory, Status: "failed",
			Message: RefusalOutcomeUnknown + ": the answer of the directory was lost"},
		{Name: phaseLocalAccessOwed, Status: PhaseOutstanding,
			Message: "the account may be preserved in the directory"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resumed := Hold{Holder: "replica-b", Attempt: "33333333-3333-3333-3333-333333333333",
		Resumed: true, Phases: recorded}

	phases, revoked := fromRecord.executor.preserveUser(context.Background(),
		preserveChange(fromRecord.entry), resumed, &ReferencePayload{UID: "alice"})
	if fromRecord.did("preserve:alice") || fromRecord.did("capabilities:alice") {
		t.Fatalf("the directory was asked again about a move it had already made: %v", fromRecord.order)
	}
	if !fromRecord.did("deny:alice:true") || revoked == nil {
		t.Fatalf("the access of a preserved account stayed open: %v", fromRecord.order)
	}
	// The obligation that was met is recorded as met, so the change is not held
	// out of a result by its own marker.
	if _, owed, outstanding := owesLocalAccess(mustPhases(t, phases)); outstanding {
		t.Errorf("the obligation stayed outstanding after it was carried out: %q", owed)
	}
	// The earlier attempt's directory error is still in the record: a change's
	// phases are everything that happened to it.
	directory, found := phaseNamed(phases, phasePreserveInDirectory)
	if !found || directory.Status != "failed" {
		t.Fatalf("the resume dropped the earlier attempt's directory phase: %+v", phases)
	}
	// Some of it failed and some of it was carried out, which is what the
	// state says.
	if state := StateFor(phases); state != StatePartiallyApplied {
		t.Errorf("the change is %s, expected partially_applied", state)
	}

	// No record - the attempt stopped before writing one - but the directory
	// holds the entry the plan named among its preserved accounts.
	fromDirectory := newPreserveHarness(t)
	fromDirectory.entryErr = fmt.Errorf("%w: alice", freeipa.ErrEntryNotFound)
	fromDirectory.preserved = freeipa.EntryReference{
		DN:              "uid=alice,cn=deleted users,cn=accounts,dc=ipa,dc=example,dc=test",
		EntryUUID:       fromDirectory.entry.EntryUUID,
		ModifyTimestamp: "20260918120000Z",
	}
	fromDirectory.preservedErr = nil
	_, revoked = fromDirectory.preserve(
		preserveChange(fromDirectory.entry), &ReferencePayload{UID: "alice"})
	if !fromDirectory.did("deny:alice:true") || revoked == nil {
		t.Fatalf("the access of an account already preserved stayed open: %v", fromDirectory.order)
	}
	if fromDirectory.did("preserve:alice") {
		t.Errorf("the move was ordered a second time: %v", fromDirectory.order)
	}

	// The preserved accounts cannot be read at all: that is neither a stale
	// plan nor a move this change may claim, and it is said as the open
	// question it is rather than folded into "there is nothing there".
	cannotAsk := newPreserveHarness(t)
	cannotAsk.entryErr = fmt.Errorf("%w: alice", freeipa.ErrEntryNotFound)
	cannotAsk.preservedErr = freeipa.ErrPreservedReadUnsupported
	phases, _ = cannotAsk.preserve(
		preserveChange(cannotAsk.entry), &ReferencePayload{UID: "alice"})
	last := phases[len(phases)-1]
	if !strings.HasPrefix(last.Message, RefusalOutcomeUnknown+":") {
		t.Fatalf("the refusal is %q, expected the code %s", last.Message, RefusalOutcomeUnknown)
	}
	if !strings.Contains(last.Message, "not known") {
		t.Errorf("the refusal does not say what is open: %q", last.Message)
	}

	// Another entry under the same name: not this change's account, so the
	// refusal stands and nobody's access is cut.
	somebodyElse := newPreserveHarness(t)
	somebodyElse.entryErr = fmt.Errorf("%w: alice", freeipa.ErrEntryNotFound)
	somebodyElse.preserved = freeipa.EntryReference{
		DN:        "uid=alice,cn=deleted users,cn=accounts,dc=ipa,dc=example,dc=test",
		EntryUUID: "0b1d4c8e-0000-0000-0000-000000000009",
	}
	somebodyElse.preservedErr = nil
	phases, _ = somebodyElse.preserve(
		preserveChange(somebodyElse.entry), &ReferencePayload{UID: "alice"})
	if somebodyElse.did("deny:alice:true") {
		t.Fatalf("the access was cut over an entry the plan never named: %v", somebodyElse.order)
	}
	if last := phases[len(phases)-1]; !strings.HasPrefix(last.Message, RefusalStalePlan+":") {
		t.Fatalf("the refusal is %q, expected the code %s", last.Message, RefusalStalePlan)
	}
}

// The obligation to cut the local access is written down before the local half
// starts, which is what makes the attempt above possible - and it is written
// down for a directory half that failed with its outcome unknown just as much
// as for one that succeeded.
func TestThePreserveRecordsWhatThePanelOwesBeforeItPaysIt(t *testing.T) {
	for name, build := range map[string]func(*preserveHarness){
		"the move went through": func(*preserveHarness) {},
		"the answer was lost": func(h *preserveHarness) {
			h.preserveErr = &freeipa.PreserveUnsettled{UID: "alice", Err: fmt.Errorf(
				"preserving the account alice: the query to the directory: connection reset")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			harness := newPreserveHarness(t)
			build(harness)
			harness.preserve(preserveChange(harness.entry), &ReferencePayload{UID: "alice"})

			if len(harness.saved) == 0 {
				t.Fatal("no phases were written down while the change ran")
			}
			snapshot := harness.saved[0]
			owed, found := phaseNamed(snapshot, phaseLocalAccessOwed)
			if !found || owed.Status != PhaseOutstanding {
				t.Fatalf("the snapshot does not carry the obligation: %+v", snapshot)
			}
			if _, found := phaseNamed(snapshot, "the local denial marker"); found {
				t.Fatalf("the snapshot was written after the local half: %+v", snapshot)
			}
			// And the record is the one the resuming attempt reads.
			if _, _, outstanding := owesLocalAccess(mustPhases(t, snapshot)); !outstanding {
				t.Fatalf("an attempt reading the record would not know what is owed: %+v", snapshot)
			}
		})
	}
}

// mustPhases writes phases out the way the store does, so a test can read them
// back through the reader the executor uses.
func mustPhases(t *testing.T, phases []Phase) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(phases)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The obligation to cut the local access is settled on the effect it names and
// not on the attempt returning. Marked succeeded over a denial that failed, the
// row claimed an effect it did not have and left a later attempt nothing to
// pick up.
func TestAnObligationIsSettledOnlyOnTheEffectItNames(t *testing.T) {
	failed := newPreserveHarness(t)
	failed.denyErr = errors.New("the database does not answer")
	phases, _ := failed.preserve(preserveChange(failed.entry), &ReferencePayload{UID: "alice"})

	owed, found := phaseNamed(phases, phaseLocalAccessOwed)
	if !found || owed.Status != PhaseOutstanding {
		t.Fatalf("the obligation was settled over a denial that failed: %+v", owed)
	}
	// Which keeps the change out of a success and leaves the record a later
	// attempt reads.
	if state := StateFor(phases); state != StatePartiallyApplied {
		t.Errorf("the change is %s, expected partially_applied", state)
	}
	if _, _, outstanding := owesLocalAccess(mustPhases(t, phases)); !outstanding {
		t.Error("an attempt reading the record would not know the access is still owed")
	}

	// Nobody to mark is not a failure: the access this names is not there, so
	// the obligation is met.
	nobody := newPreserveHarness(t)
	nobody.denyErr = ErrNoPrincipal
	phases, _ = nobody.preserve(preserveChange(nobody.entry), &ReferencePayload{UID: "alice"})
	owed, found = phaseNamed(phases, phaseLocalAccessOwed)
	if !found || owed.Status != "succeeded" {
		t.Fatalf("an account the panel knows nobody by left the obligation %+v", owed)
	}

	// And where the obligation cannot be written down, the mutation it covers
	// does not happen: an effect nothing records is an effect nobody can
	// account for, and the claim may be the reason the write failed.
	unrecorded := newPreserveHarness(t)
	unrecorded.recordErr = errors.New("the change is no longer this attempt's")
	phases, revoked := unrecorded.preserve(
		preserveChange(unrecorded.entry), &ReferencePayload{UID: "alice"})
	if unrecorded.did("deny:alice:true") || revoked != nil {
		t.Fatalf("the local half ran although nothing recorded it: %v", unrecorded.order)
	}
	if last := phases[len(phases)-1]; last.Status != "failed" ||
		!strings.Contains(last.Name, "recording what the panel owes") {
		t.Fatalf("the last phase is %+v", last)
	}
}

// phaseNamed finds a phase by its name.
func phaseNamed(phases []Phase, name string) (Phase, bool) {
	for _, phase := range phases {
		if phase.Name == name {
			return phase, true
		}
	}
	return Phase{}, false
}

// Two operators preserving the same user: the second one finds the entry
// somewhere else, because a preserved account lives in another container.
func TestAnEntryThatMovedSinceThePlanRefusesAsStale(t *testing.T) {
	harness := newPreserveHarness(t)
	planned := harness.entry
	harness.entry.DN = "uid=alice,cn=deleted users,cn=accounts,cn=provisioning,dc=ipa,dc=example,dc=test"

	phases, _ := harness.preserve(
		preserveChange(planned), &ReferencePayload{UID: "alice"})

	if harness.did("preserve:alice") || harness.did("deny:alice:true") {
		t.Fatalf("a stale plan still reached the directory or the local account: %v", harness.order)
	}
	last := phases[len(phases)-1]
	if !strings.HasPrefix(last.Message, RefusalStalePlan+":") {
		t.Fatalf("the refusal is %q, expected the code %s", last.Message, RefusalStalePlan)
	}

	// The same for an entry somebody changed in the meantime: the plan was
	// made against a state that is no longer there.
	touched := newPreserveHarness(t)
	planned = touched.entry
	touched.entry.ModifyTimestamp = "20260918090000Z"
	phases, _ = touched.preserve(
		preserveChange(planned), &ReferencePayload{UID: "alice"})
	if touched.did("preserve:alice") {
		t.Fatal("an entry changed since the plan was still preserved")
	}
	if last := phases[len(phases)-1]; !strings.HasPrefix(last.Message, RefusalStalePlan+":") {
		t.Fatalf("the refusal is %q, expected the code %s", last.Message, RefusalStalePlan)
	}
}

// An entry the directory no longer holds under that name is the same story
// told by a directory that answers NotFound: somebody got there first.
func TestAnEntryTheDirectoryNoLongerHoldsRefusesAsStale(t *testing.T) {
	harness := newPreserveHarness(t)
	harness.entryErr = fmt.Errorf("%w: alice", freeipa.ErrEntryNotFound)

	phases, _ := harness.preserve(
		preserveChange(harness.entry), &ReferencePayload{UID: "alice"})

	if harness.did("preserve:alice") || harness.did("deny:alice:true") {
		t.Fatalf("an entry that is not there was still preserved: %v", harness.order)
	}
	if last := phases[len(phases)-1]; !strings.HasPrefix(last.Message, RefusalStalePlan+":") {
		t.Fatalf("the refusal is %q, expected the code %s", last.Message, RefusalStalePlan)
	}
}

// A directory that proved it cannot move an entry blocks the operation before
// anything is ordered.
func TestADirectoryThatCannotMoveAnEntryBlocksThePreserveBeforeItStarts(t *testing.T) {
	harness := newPreserveHarness(t)
	harness.capabilities = freeipa.DirectoryCapabilities{
		ReasonCodes: []string{freeipa.ReasonModDNNotPermitted},
	}

	phases, _ := harness.preserve(
		preserveChange(harness.entry), &ReferencePayload{UID: "alice"})

	if len(harness.order) != 1 || harness.order[0] != "capabilities:alice" {
		t.Fatalf("the steps were %v, expected the preflight alone", harness.order)
	}
	last := phases[len(phases)-1]
	if !strings.HasPrefix(last.Message, RefusalModDNUnsupported+":") ||
		!strings.Contains(last.Message, freeipa.ReasonModDNNotPermitted) {
		t.Fatalf("the refusal is %q, expected %s naming %s",
			last.Message, RefusalModDNUnsupported, freeipa.ReasonModDNNotPermitted)
	}
}

// A directory that does not report the rights on an entry is not a directory
// that refused them.
func TestADirectoryThatDoesNotReportRightsDoesNotBlockThePreserve(t *testing.T) {
	harness := newPreserveHarness(t)
	harness.capabilities = freeipa.DirectoryCapabilities{
		ReasonCodes: []string{freeipa.ReasonModDNRightsUnknown},
	}

	phases, _ := harness.preserve(
		preserveChange(harness.entry), &ReferencePayload{UID: "alice"})

	if !harness.did("preserve:alice") {
		t.Fatalf("an unproven right blocked the operation: %v", harness.order)
	}
	if !strings.Contains(phases[0].Message, freeipa.ReasonModDNRightsUnknown) {
		t.Errorf("the preflight phase %q does not record what it could not verify", phases[0].Message)
	}
}

// A plan that does not name the entry names nothing to bind to. It is
// refused rather than carried out against whatever the directory holds now.
func TestAPreserveWithoutAnEntryInThePlanIsRefused(t *testing.T) {
	harness := newPreserveHarness(t)
	change := Change{ID: "change-2", ActionType: string(ActionUserPreserve)}

	phases, _ := harness.preserve(
		change, &ReferencePayload{UID: "alice"})

	if harness.did("preserve:alice") || harness.did("deny:alice:true") {
		t.Fatalf("a change without a bound plan was still carried out: %v", harness.order)
	}
	if last := phases[len(phases)-1]; !strings.HasPrefix(last.Message, RefusalPlanIncomplete+":") {
		t.Fatalf("the refusal is %q, expected the code %s", last.Message, RefusalPlanIncomplete)
	}
}
