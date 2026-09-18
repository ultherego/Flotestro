package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

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
	// "uid@issuer-host" when that name was taken. Both are the same person
	// in the directory; a name that merely starts alike is not.
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
	// The directory change itself succeeded; a phase that fails here makes
	// the change partially applied, which is the truth: the membership moved
	// and the old sessions may still be alive.
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

	// The provider refuses or is unreachable: the disable holds on the
	// local marker, so the phase is skipped with the reason rather than
	// failed - a failed phase would call the whole disable partially
	// applied, and it is not.
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

// preserveHarness is an executor whose four halves of a preserve are
// recorded: what the directory was asked, in which order, and whether the
// local account was touched at all.
type preserveHarness struct {
	executor *Executor
	// order is what happened and in which sequence. The order is the point
	// of the operation, so the test reads it rather than only the outcome.
	order        []string
	capabilities freeipa.DirectoryCapabilities
	entry        freeipa.EntryReference
	entryErr     error
	preserveErr  error
}

func newPreserveHarness(t *testing.T) *preserveHarness {
	t.Helper()
	harness := &preserveHarness{
		// A directory that reports the connector may move an entry: the
		// preflight then blocks nothing and the test is about what follows.
		capabilities: freeipa.DirectoryCapabilities{UserModDN: true},
		entry: freeipa.EntryReference{
			DN:              "uid=alice,cn=users,cn=accounts,dc=ipa,dc=example,dc=test",
			EntryUUID:       "0b1d4c8e-0000-0000-0000-000000000001",
			ModifyTimestamp: "20260917103000Z",
		},
	}
	harness.executor = &Executor{
		sessions: &fakeSessions{live: map[string]int64{}},
		capabilities: func(_ context.Context, uid string) (freeipa.DirectoryCapabilities, error) {
			// The question is about this account's entry: the order records
			// which one it was asked about, so a preserve that asked about
			// somebody else would be visible here.
			harness.order = append(harness.order, "capabilities:"+uid)
			return harness.capabilities, nil
		},
		entryOf: func(_ context.Context, uid string) (freeipa.EntryReference, error) {
			harness.order = append(harness.order, "entry:"+uid)
			return harness.entry, harness.entryErr
		},
		preserve: func(_ context.Context, uid string, planned freeipa.EntryReference) error {
			harness.order = append(harness.order, "preserve:"+uid+"@"+planned.DN)
			return harness.preserveErr
		},
		localDeny: func(_ context.Context, subject, _ string, denied bool) (int64, error) {
			harness.order = append(harness.order, fmt.Sprintf("deny:%s:%v", subject, denied))
			return 1, nil
		},
	}
	return harness
}

// preserveChange is an approved change whose plan names the entry.
func preserveChange(entry freeipa.EntryReference) Change {
	plan, _ := json.Marshal(map[string]any{
		"summary":        "Preserving the account alice",
		"preserve_entry": entry,
	})
	return Change{ID: "change-1", ActionType: string(ActionUserPreserve), Plan: plan}
}

// did says whether the recorded order contains the step.
// did says whether a step happened. The steps carry what they were asked
// about - which account, which entry - so the match is by prefix: a test
// asks "was the account preserved", not "was it preserved against exactly
// this distinguished name", which its own assertions check separately.
func (h *preserveHarness) did(step string) bool {
	for _, done := range h.order {
		if done == step || strings.HasPrefix(done, step+"@") {
			return true
		}
	}
	return false
}

// A directory that refuses the move leaves the local account exactly as it
// was. The old order - local denial first - made a refused moddn into a user
// locked out of the panel and the hosts while the directory still held the
// account: locked out everywhere, removed nowhere.
func TestADirectoryThatRefusesThePreserveLeavesTheLocalAccountAsItWas(t *testing.T) {
	harness := newPreserveHarness(t)
	harness.preserveErr = &freeipa.DirectoryError{
		Name:    "ACIError",
		Message: "Insufficient access: Insufficient 'delete' privilege",
	}

	phases, revoked := harness.executor.preserveUser(context.Background(),
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
	// The refusal carries the directory's own reason, not a summary of it:
	// an ACI that is missing and a container that is not there are repaired
	// differently.
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

	phases, revoked := harness.executor.preserveUser(context.Background(),
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

// Two operators preserving the same user: the second one finds the entry
// somewhere else, because a preserved account lives in another container.
// The plan is bound to the entry it was made for, so the second execution is
// refused as stale instead of preserving an account twice.
func TestAnEntryThatMovedSinceThePlanRefusesAsStale(t *testing.T) {
	harness := newPreserveHarness(t)
	planned := harness.entry
	harness.entry.DN = "uid=alice,cn=deleted users,cn=accounts,cn=provisioning,dc=ipa,dc=example,dc=test"

	phases, _ := harness.executor.preserveUser(context.Background(),
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
	phases, _ = touched.executor.preserveUser(context.Background(),
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

	phases, _ := harness.executor.preserveUser(context.Background(),
		preserveChange(harness.entry), &ReferencePayload{UID: "alice"})

	if harness.did("preserve:alice") || harness.did("deny:alice:true") {
		t.Fatalf("an entry that is not there was still preserved: %v", harness.order)
	}
	if last := phases[len(phases)-1]; !strings.HasPrefix(last.Message, RefusalStalePlan+":") {
		t.Fatalf("the refusal is %q, expected the code %s", last.Message, RefusalStalePlan)
	}
}

// A directory that proved it cannot move an entry blocks the operation
// before anything is ordered. This is the preflight the document asks for:
// the panel refuses rather than discovering the ACI halfway through.
func TestADirectoryThatCannotMoveAnEntryBlocksThePreserveBeforeItStarts(t *testing.T) {
	harness := newPreserveHarness(t)
	harness.capabilities = freeipa.DirectoryCapabilities{
		ReasonCodes: []string{freeipa.ReasonModDNNotPermitted},
	}

	phases, _ := harness.executor.preserveUser(context.Background(),
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
// that refused them. The operation goes on - it now asks the directory first,
// so a refusal there costs nothing locally - and the unknown is recorded.
func TestADirectoryThatDoesNotReportRightsDoesNotBlockThePreserve(t *testing.T) {
	harness := newPreserveHarness(t)
	harness.capabilities = freeipa.DirectoryCapabilities{
		ReasonCodes: []string{freeipa.ReasonModDNRightsUnknown},
	}

	phases, _ := harness.executor.preserveUser(context.Background(),
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

	phases, _ := harness.executor.preserveUser(context.Background(),
		change, &ReferencePayload{UID: "alice"})

	if harness.did("preserve:alice") || harness.did("deny:alice:true") {
		t.Fatalf("a change without a bound plan was still carried out: %v", harness.order)
	}
	if last := phases[len(phases)-1]; !strings.HasPrefix(last.Message, RefusalPlanIncomplete+":") {
		t.Fatalf("the refusal is %q, expected the code %s", last.Message, RefusalPlanIncomplete)
	}
}
