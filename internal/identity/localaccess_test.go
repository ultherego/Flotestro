package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// The obligation reaches the row before the mutating call, and it carries the
// identities resolved there and then. Resolved at retry time instead, they
// would be resolved from an account the change had already removed.
func TestTheDurableObligationIsRecordedBeforeTheDirectoryIsChanged(t *testing.T) {
	type owed struct {
		changeID   string
		uid        string
		principals []AccessPrincipal
	}
	var recorded []owed

	harness := newPreserveHarness(t)
	harness.executor.recordArrear = func(_ context.Context, changeID, uid, _ string,
		principals []AccessPrincipal) error {
		harness.order = append(harness.order, "owe:"+uid)
		recorded = append(recorded, owed{changeID, uid, principals})
		return nil
	}
	phases, _ := harness.preserve(preserveChange(harness.entry), &ReferencePayload{UID: "alice"})

	if len(recorded) != 1 {
		t.Fatalf("the obligation was recorded %d times: %v", len(recorded), harness.order)
	}
	if recorded[0].changeID != "change-1" || recorded[0].uid != "alice" {
		t.Errorf("the obligation names %+v", recorded[0])
	}
	// The identity was resolved from the panel's own principals, not from a
	// directory read, and it carries both halves: the subject to deny and the
	// identifier whose sessions end.
	if len(recorded[0].principals) != 1 ||
		recorded[0].principals[0].Subject != "alice" ||
		recorded[0].principals[0].PrincipalID != "p-alice" {
		t.Fatalf("the obligation carries %+v", recorded[0].principals)
	}
	// Before the call, and recorded as a phase of the change.
	if !orderedBefore(harness.order, "owe:alice", "preserve:alice@"+harness.entry.DN) {
		t.Fatalf("the obligation was recorded after the directory was changed: %v", harness.order)
	}
	// Recorded as a phase, and as a record rather than a step: counted as a
	// success it would have made a change that applied nothing read as
	// partially_applied on the strength of its own bookkeeping.
	if phase, found := phaseNamed(phases, phaseLocalAccessOwedDurably); !found ||
		phase.Status != "skipped" {
		t.Fatalf("the change does not record what it owed: %+v", phases)
	}

	// And where it cannot be recorded, the call does not go out: an access cut
	// whose local half nothing records is one nobody can finish.
	unrecorded := newPreserveHarness(t)
	unrecorded.executor.recordArrear = func(context.Context, string, string, string,
		[]AccessPrincipal) error {
		return errors.New("the database does not answer")
	}
	phases, _ = unrecorded.preserve(
		preserveChange(unrecorded.entry), &ReferencePayload{UID: "alice"})
	if unrecorded.did("preserve:alice@" + unrecorded.entry.DN) {
		t.Fatalf("the directory was changed with nothing recording the panel's half: %v",
			unrecorded.order)
	}
	if last := phases[len(phases)-1]; last.Status != "failed" ||
		last.Name != phaseLocalAccessOwedDurably {
		t.Fatalf("the last phase is %+v", last)
	}
}

// A disable owes the same thing, and from before either half of it: the local
// denial is a mutation too, and the directory call that follows goes out
// whatever the local half did.
func TestADisableOwesThePanelHalfBeforeItStarts(t *testing.T) {
	harness := newPreserveHarness(t)
	var owed int
	harness.executor.recordArrear = func(context.Context, string, string, string,
		[]AccessPrincipal) error {
		harness.order = append(harness.order, "owe")
		owed++
		return nil
	}
	harness.executor.setEnabled = func(_ context.Context, uid string, enable bool) error {
		harness.order = append(harness.order, fmt.Sprintf("directory:%s:%v", uid, enable))
		return nil
	}
	harness.executor.setUserAccess(context.Background(),
		Change{ID: "change-2", ActionType: string(ActionUserDisable)},
		&ReferencePayload{UID: "alice"}, false)
	if owed != 1 {
		t.Fatalf("a disable recorded the obligation %d times: %v", owed, harness.order)
	}
	if !orderedBefore(harness.order, "owe", "deny:alice:true") {
		t.Fatalf("the obligation was recorded after the denial: %v", harness.order)
	}

	// An enable owes nothing: it opens access rather than cutting it.
	owed = 0
	harness.executor.setUserAccess(context.Background(),
		Change{ID: "change-3", ActionType: string(ActionUserEnable)},
		&ReferencePayload{UID: "alice"}, true)
	if owed != 0 {
		t.Error("an enable recorded an obligation to cut the access off")
	}
}

// orderedBefore says whether the first step happened before the second.
func orderedBefore(order []string, first, second string) bool {
	firstAt, secondAt := -1, -1
	for index, step := range order {
		if step == first && firstAt < 0 {
			firstAt = index
		}
		if step == second && secondAt < 0 {
			secondAt = index
		}
	}
	return firstAt >= 0 && secondAt >= 0 && firstAt < secondAt
}

// The retry works from the identities that were written down and asks the
// directory nothing: by then the account may be gone, which is what the change
// did to it.
func TestTheRetryOfTheLocalHalfReadsNoDirectory(t *testing.T) {
	arrear := LocalAccessArrear{
		ID: "a1", ChangeID: "change-1", DirectoryUID: "alice", Attempts: 1,
		Principals: []AccessPrincipal{{Subject: "alice@ipa.example.test", PrincipalID: "p-alice"}},
	}
	var denied, revoked, loggedOut []string
	executor := &LocalAccessExecutor{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		localDeny: func(_ context.Context, subject, _ string, deny bool) (int64, error) {
			if !deny {
				t.Error("the retry lifted a denial instead of making one")
			}
			denied = append(denied, subject)
			return 1, nil
		},
		revoke: func(_ context.Context, principalID, _ string) (int64, error) {
			revoked = append(revoked, principalID)
			return 2, nil
		},
	}
	executor.provider = loggerOut(func(subject string) error {
		loggedOut = append(loggedOut, subject)
		return nil
	})

	var settled, held int
	executor.settle = func(context.Context, LocalAccessArrear) error {
		settled++
		return nil
	}
	executor.hold = func(context.Context, LocalAccessArrear, time.Duration, string) error {
		held++
		return nil
	}
	executor.pay(context.Background(), arrear)
	if settled != 1 || held != 0 {
		t.Errorf("an attempt whose effects were confirmed settled %d and was held %d times",
			settled, held)
	}

	if len(denied) != 1 || denied[0] != "alice@ipa.example.test" {
		t.Errorf("the denial was aimed at %v", denied)
	}
	if len(revoked) != 1 || revoked[0] != "p-alice" {
		t.Errorf("the revocation was aimed at %v", revoked)
	}
	// The provider is asked about the subject the panel knows the person by,
	// which is what was written down - not about the directory account name,
	// which is a different string wherever the login qualifies it.
	if len(loggedOut) != 1 || loggedOut[0] != "alice@ipa.example.test" {
		t.Errorf("the provider was asked about %v, and the directory account is %q",
			loggedOut, arrear.DirectoryUID)
	}
}

// loggerOut is a provider whose logout a test watches.
type loggerOut func(subject string) error

func (l loggerOut) LogoutSubject(_ context.Context, subject string) error { return l(subject) }

// The settlement is conditional on the effects, so the statement that settles
// names them. An obligation naming nobody must not read as confirmed through an
// empty array either, so the lists it builds are never nil.
func TestTheSettlementNamesTheEffectsItConfirms(t *testing.T) {
	arrear := LocalAccessArrear{
		Principals: []AccessPrincipal{
			{Subject: "alice", PrincipalID: "p-alice"},
			{Subject: "alice@ipa.example.test"},
		},
	}
	subjects, principalIDs := arrear.targets()
	if len(subjects) != 2 || subjects[0] != "alice" {
		t.Errorf("the subjects to confirm are %v", subjects)
	}
	// An identity with no panel identifier has no session to confirm, and is
	// not carried into the list as an empty string.
	if len(principalIDs) != 1 || principalIDs[0] != "p-alice" {
		t.Errorf("the identifiers to confirm are %v", principalIDs)
	}
	var empty LocalAccessArrear
	subjects, principalIDs = empty.targets()
	if subjects == nil || principalIDs == nil {
		t.Error("an obligation naming nobody built a null list, which matches every row")
	}

	// And a settlement with no claim does not reach the database at all: it
	// could not name the attempt it is the result of.
	store := &Store{}
	if err := store.SettleLocalAccess(context.Background(), arrear); err == nil {
		t.Fatal("an obligation with no claim was settled")
	}
}

// The backoff grows and is capped. An access cut is not asked again every five
// seconds for ever, and it is not left for an hour either.
func TestTheArrearBackoffGrowsAndIsCapped(t *testing.T) {
	if first := ArrearBackoff(1); first != ArrearBaseBackoff {
		t.Errorf("the first pause is %v, expected %v", first, ArrearBaseBackoff)
	}
	if second := ArrearBackoff(2); second != 2*ArrearBaseBackoff {
		t.Errorf("the second pause is %v", second)
	}
	for _, attempts := range []int{20, 100, 1 << 20} {
		if backoff := ArrearBackoff(attempts); backoff != ArrearMaxBackoff {
			t.Errorf("after %d attempts the pause is %v, expected the cap %v",
				attempts, backoff, ArrearMaxBackoff)
		}
	}
	// A count the row cannot have is not a pause of nothing.
	if zero := ArrearBackoff(0); zero != ArrearBaseBackoff {
		t.Errorf("an attempt count of zero gave a pause of %v", zero)
	}
}

// The obligation is one row per change: an attempt writing it a second time is
// the same obligation and not a second one, which is what the conflict clause
// says. And a write that names no change or no account is refused rather than
// landing as a row nobody can act on.
func TestAnObligationNamesItsChangeAndItsAccount(t *testing.T) {
	store := &Store{}
	ctx := context.Background()
	if err := store.OweLocalAccess(ctx, "", "alice", "", nil); err == nil {
		t.Error("an obligation owed by no change was accepted")
	}
	if err := store.OweLocalAccess(ctx, "change-1", "", "", nil); err == nil {
		t.Error("an obligation naming no account was accepted")
	}
}

// The arrears travel to the panel as both readings of the same thing: when the
// panel took the obligation on, and how long it has been owed.
func TestTheArrearsAndTheLastErrorReachThePanel(t *testing.T) {
	since := time.Now().Add(-90 * time.Minute).UTC()
	arrear := LocalAccessArrear{
		ID: "a1", ChangeID: "change-1", DirectoryUID: "alice", State: "outstanding",
		Attempts: 7, OutstandingSince: since, ArrearsSeconds: 5400,
		LastError: "revoking the sessions of alice: the database does not answer",
	}
	encoded, err := json.Marshal(arrear)
	if err != nil {
		t.Fatal(err)
	}
	var read map[string]any
	if err := json.Unmarshal(encoded, &read); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"arrears_seconds", "outstanding_since", "last_error",
		"attempts", "change_id", "directory_uid", "state"} {
		if _, found := read[field]; !found {
			t.Errorf("the panel cannot read %q of an outstanding access cut", field)
		}
	}
	if read["arrears_seconds"] != float64(5400) {
		t.Errorf("the arrears read as %v", read["arrears_seconds"])
	}
}

// The obligation is settled on the effects and not on a call returning, and
// not on which attempt produced them either. Where the effects are not there,
// the row stays owed with the sentence of what happened, so the arrears go on
// growing where the panel can read them.
func TestAnArrearIsSettledOnlyOnConfirmedEffects(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	arrear := LocalAccessArrear{
		ID: "a1", ChangeID: "change-1", DirectoryUID: "alice", Attempts: 3,
		Principals: []AccessPrincipal{{Subject: "alice", PrincipalID: "p-alice"}},
	}

	// Each of these leaves the access in place, so the settlement's own
	// condition does not hold - which is what the store answers here.
	for name, unconfirmed := range map[string]struct {
		build func(*LocalAccessExecutor)
		says  string
	}{
		"the denial failed": {
			build: func(e *LocalAccessExecutor) {
				e.localDeny = func(context.Context, string, string, bool) (int64, error) {
					return 0, errors.New("the database does not answer")
				}
			},
			says: "denying alice",
		},
		"the revocation failed": {
			build: func(e *LocalAccessExecutor) {
				e.revoke = func(context.Context, string, string) (int64, error) {
					return 0, errors.New("the database does not answer")
				}
			},
			says: "revoking the sessions of alice",
		},
		"nothing failed and nothing confirmed": {
			build: func(*LocalAccessExecutor) {},
			says:  "not read back",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var settled, held int
			var cause string
			var pause time.Duration
			executor := &LocalAccessExecutor{log: quiet,
				localDeny: func(context.Context, string, string, bool) (int64, error) {
					return 1, nil
				},
				revoke: func(context.Context, string, string) (int64, error) { return 1, nil },
				settle: func(context.Context, LocalAccessArrear) error {
					settled++
					return ErrAccessNotConfirmed
				},
				hold: func(_ context.Context, _ LocalAccessArrear,
					backoff time.Duration, why string) error {
					held++
					pause = backoff
					cause = why
					return nil
				},
			}
			unconfirmed.build(executor)
			executor.pay(context.Background(), arrear)

			if held != 1 {
				t.Fatalf("the obligation was held %d times, so it did not stay owed", held)
			}
			if settled != 1 {
				t.Errorf("the settlement was not even attempted (%d)", settled)
			}
			if !strings.Contains(cause, unconfirmed.says) {
				t.Errorf("the row was put back saying %q, which does not name %q",
					cause, unconfirmed.says)
			}
			if pause != ArrearBackoff(arrear.Attempts) {
				t.Errorf("the pause is %v, expected %v", pause, ArrearBackoff(arrear.Attempts))
			}
		})
	}

	// And the other side of "settled on the effect": a call of this attempt
	// that failed does not hold the obligation open when the access is gone
	// anyway - another replica got there first, or the identity the panel knew
	// is no longer one it knows. The effect is what the obligation named.
	for name, build := range map[string]func(*LocalAccessExecutor){
		"another replica cut it": func(e *LocalAccessExecutor) {
			e.localDeny = func(context.Context, string, string, bool) (int64, error) {
				return 0, errors.New("the database does not answer")
			}
		},
		"the panel knows nobody by that name": func(e *LocalAccessExecutor) {
			e.localDeny = func(context.Context, string, string, bool) (int64, error) {
				return 0, ErrNoPrincipal
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var settled int
			executor := &LocalAccessExecutor{log: quiet,
				localDeny: func(context.Context, string, string, bool) (int64, error) {
					return 1, nil
				},
				revoke: func(context.Context, string, string) (int64, error) { return 0, nil },
				settle: func(context.Context, LocalAccessArrear) error { settled++; return nil },
				hold: func(context.Context, LocalAccessArrear, time.Duration, string) error {
					t.Error("the obligation was held open over an access that is gone")
					return nil
				},
			}
			build(executor)
			executor.pay(context.Background(), arrear)
			if settled != 1 {
				t.Errorf("the obligation settled %d times over a confirmed effect", settled)
			}
		})
	}
}

// And the record of what is owed does not change what the change is. A preserve
// the directory refused outright applied nothing, and a phase that only wrote
// down an obligation must not turn that into partially_applied.
func TestRecordingWhatIsOwedDoesNotMakeAFailureIntoAPartialOne(t *testing.T) {
	refused := newPreserveHarness(t)
	refused.preserveErr = errors.New("the directory refused to move the entry")
	refused.executor.recordArrear = func(context.Context, string, string, string,
		[]AccessPrincipal) error {
		return nil
	}
	phases, _ := refused.preserve(
		preserveChange(refused.entry), &ReferencePayload{UID: "alice"})
	if state := StateFor(phases); state != StateFailed {
		t.Errorf("a preserve the directory refused reads %s, expected failed: %+v", state, phases)
	}
	// And the obligation row is still there, because the refusal came after the
	// row was written - the executor of it confirms there was nothing to cut and
	// settles on the first pass.
	if phase, found := phaseNamed(phases, phaseLocalAccessOwedDurably); !found ||
		phase.Status == "failed" {
		t.Errorf("the obligation was not recorded before the call: %+v", phase)
	}
}
