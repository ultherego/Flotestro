package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// fakeBudgets grants or refuses by key and remembers who holds what.
type fakeBudgets struct {
	full     map[string]bool
	held     map[string][]budgets.Need
	acquires int
	asked    []asked
}

type asked struct {
	owner, claimant string
	class           budgets.Class
	needs           []budgets.Need
}

func newFakeBudgets(full ...string) *fakeBudgets {
	f := &fakeBudgets{full: map[string]bool{}, held: map[string][]budgets.Need{}}
	for _, key := range full {
		f.full[key] = true
	}
	return f
}

func (f *fakeBudgets) Acquire(_ context.Context, owner, claimant string, class budgets.Class,
	needs []budgets.Need) (budgets.Refusal, error) {
	f.acquires++
	f.asked = append(f.asked, asked{owner: owner, claimant: claimant, class: class, needs: needs})
	for _, need := range needs {
		if f.full[need.Key] {
			// All or nothing, the way the store does it: a refusal holds
			// no token of the set.
			return budgets.Refusal{Key: need.Key, Reason: budgets.ReasonCapacity,
				Used: 1, Capacity: 1}, nil
		}
	}
	f.held[owner] = needs
	return budgets.Refusal{}, nil
}

func (f *fakeBudgets) Release(_ context.Context, owner string) error {
	delete(f.held, owner)
	return nil
}

func (f *fakeBudgets) Renew(context.Context, []string) error { return nil }

// fakeWaits remembers the last reason written for every task.
type fakeWaits struct {
	reasons map[string]string
	writes  int
	fail    error
}

func (f *fakeWaits) SetWaitReason(_ context.Context, jobID, reason string) error {
	if f.fail != nil {
		return f.fail
	}
	if f.reasons == nil {
		f.reasons = map[string]string{}
	}
	f.reasons[jobID] = reason
	f.writes++
	return nil
}

func newAdmission(b Budgets, w *fakeWaits) admission {
	return admission{budgets: b, waits: w, log: slog.Default(), gateway: "gw-test"}
}

func candidate(id string, action opspec.ActionType, site string) jobs.Candidate {
	return jobs.Candidate{
		Job:  jobs.Job{ID: id, HostID: "host-" + id, ActionType: string(action), CreatedBy: "alice", Payload: json.RawMessage(`{}`)},
		Site: site,
	}
}

// TestMutationIsAdmittedAgainstTheMutationAndSiteBudgets guards the rule:
// a change asks for the fleet's mutation token and the site's token of its
// family, under the job as the owner and the operator as the claimant.
func TestMutationIsAdmittedAgainstTheMutationAndSiteBudgets(t *testing.T) {
	b := newFakeBudgets()
	w := &fakeWaits{}
	a := newAdmission(b, w)

	ok, err := a.admit(context.Background(), candidate("j1", opspec.ActionUnitRestart, "warsaw"), "")
	if err != nil || !ok {
		t.Fatalf("admit = %v, %v; want admitted", ok, err)
	}
	if len(b.asked) != 1 {
		t.Fatalf("asked %d times", len(b.asked))
	}
	ask := b.asked[0]
	if ask.owner != budgets.JobOwner("j1") || ask.claimant != budgets.JobClaimant("alice") {
		t.Errorf("owner %q, claimant %q", ask.owner, ask.claimant)
	}
	if ask.class != budgets.ClassInteractive {
		t.Errorf("an operator's restart asks as %s", ask.class)
	}
	keys := keysAsked(ask.needs)
	// The gateway of the session is this one: the queue was read for the
	// hosts connected here.
	want := []string{budgets.KeyGlobalMutations, "site:warsaw:units", "gateway:gw-test:units"}
	if strings.Join(keys, " ") != strings.Join(want, " ") {
		t.Errorf("a restart asked for %v, want %v", keys, want)
	}
	if w.writes != 0 {
		t.Errorf("an admitted task got a wait reason: %v", w.reasons)
	}
}

// TestReadIsNotBlockedByTheMutationBudget guards the separation the budgets
// exist for: a full mutation budget does not stop a state read.
func TestReadIsNotBlockedByTheMutationBudget(t *testing.T) {
	b := newFakeBudgets(budgets.KeyGlobalMutations)
	w := &fakeWaits{}
	a := newAdmission(b, w)

	ok, err := a.admit(context.Background(), candidate("r1", opspec.ActionUnitStatus, "warsaw"), "")
	if err != nil || !ok {
		t.Fatalf("a read was held by the mutation budget: %v, %v", ok, err)
	}
	keys := keysAsked(b.asked[0].needs)
	if len(keys) != 1 || keys[0] != budgets.KeyGlobalReads {
		t.Errorf("a read asked for %v", keys)
	}
}

// TestRefusedTaskWaitsWithTheBudgetNamedAndHoldsNothing guards visibility
// and the all-or-nothing grant: a task the budget refuses stays queued
// with the key written next to it and no token under its name.
func TestRefusedTaskWaitsWithTheBudgetNamedAndHoldsNothing(t *testing.T) {
	b := newFakeBudgets(budgets.KeyGlobalMutations)
	w := &fakeWaits{}
	a := newAdmission(b, w)
	c := candidate("j2", opspec.ActionUnitRestart, "warsaw")

	ok, err := a.admit(context.Background(), c, "")
	if err != nil || ok {
		t.Fatalf("admit = %v, %v; want a wait", ok, err)
	}
	want := budgets.WaitReasonPrefix + budgets.KeyGlobalMutations
	if w.reasons["j2"] != want {
		t.Errorf("wait reason = %q, want %q", w.reasons["j2"], want)
	}
	if _, holds := b.held[budgets.JobOwner("j2")]; holds {
		t.Error("a refused task holds tokens")
	}

	// The next pass sees the same refusal: the reason is already there and
	// is not rewritten.
	c.Job.WaitReason = want
	if _, err := a.admit(context.Background(), c, ""); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Errorf("the same reason was written %d times", w.writes)
	}

	// Once there is room the task is admitted, and each pass asked exactly
	// once: nothing counts twice.
	delete(b.full, budgets.KeyGlobalMutations)
	ok, err = a.admit(context.Background(), c, "")
	if err != nil || !ok {
		t.Fatalf("admit after the budget freed = %v, %v", ok, err)
	}
	if b.acquires != 3 {
		t.Errorf("three passes asked %d times", b.acquires)
	}
}

// TestCampaignAndFanOutTasksAreNotCountedTwice guards fairness: the
// orchestrator took the tokens for the target, the fan-out for its reads.
func TestCampaignAndFanOutTasksAreNotCountedTwice(t *testing.T) {
	b := newFakeBudgets(budgets.KeyGlobalMutations, budgets.KeyGlobalReads)
	a := newAdmission(b, &fakeWaits{})

	campaignID := "c1"
	c := candidate("j3", opspec.ActionUnitRestart, "warsaw")
	c.Job.CampaignID = &campaignID
	if ok, err := a.admit(context.Background(), c, ""); err != nil || !ok {
		t.Errorf("a campaign's task was asked again: %v, %v", ok, err)
	}

	fanoutID := "f1"
	r := candidate("r2", opspec.ActionUnitStatus, "warsaw")
	r.Job.FanoutID = &fanoutID
	if ok, err := a.admit(context.Background(), r, ""); err != nil || !ok {
		t.Errorf("a fan-out's task was asked again: %v, %v", ok, err)
	}
	if b.acquires != 0 {
		t.Errorf("the budgets were asked %d times for work that holds tokens already", b.acquires)
	}
}

// TestStatedClassWinsAndPanelWorkIsBackground guards the class rule: the
// operator's word first, then what can be seen.
func TestStatedClassWinsAndPanelWorkIsBackground(t *testing.T) {
	b := newFakeBudgets()
	a := newAdmission(b, &fakeWaits{})

	urgent := candidate("j4", opspec.ActionUnitStop, "warsaw")
	urgent.Job.BudgetClass = string(budgets.ClassIncident)
	sweep := candidate("j5", opspec.ActionInventoryRefresh, "warsaw")
	sweep.Job.CreatedBy = "flotestro/vuln"
	lock := candidate("j6", opspec.ActionLocalUserLock, "warsaw")

	for _, c := range []jobs.Candidate{urgent, sweep, lock} {
		if _, err := a.admit(context.Background(), c, ""); err != nil {
			t.Fatal(err)
		}
	}
	classes := []budgets.Class{b.asked[0].class, b.asked[1].class, b.asked[2].class}
	want := []budgets.Class{budgets.ClassIncident, budgets.ClassBackground, budgets.ClassIncident}
	for i := range want {
		if classes[i] != want[i] {
			t.Errorf("task %d asked as %s, want %s", i, classes[i], want[i])
		}
	}
}

// TestBackupAsksForItsRepository guards the backend key: a copy ordered by
// hand lands in the same budget as one ordered in a campaign.
func TestBackupAsksForItsRepository(t *testing.T) {
	b := newFakeBudgets()
	a := newAdmission(b, &fakeWaits{})
	c := candidate("j7", opspec.ActionBackupRun, "warsaw")
	c.Job.Payload = json.RawMessage(`{"backup":{"repository":"sftp://vault/fleet"}}`)
	if _, err := a.admit(context.Background(), c, ""); err != nil {
		t.Fatal(err)
	}
	keys := keysAsked(b.asked[0].needs)
	want := budgets.BackendKey("sftp://vault/fleet")
	if !contains(keys, want) {
		t.Errorf("a backup asked for %v, without %s", keys, want)
	}
}

// TestTokensOfTasksTheLeaseMissedGoBack guards the gap between the decision
// and the lease: a task canceled in between must not keep its grant.
func TestTokensOfTasksTheLeaseMissedGoBack(t *testing.T) {
	b := newFakeBudgets()
	a := newAdmission(b, &fakeWaits{})
	for _, id := range []string{"j8", "j9"} {
		if _, err := a.admit(context.Background(), candidate(id, opspec.ActionUnitRestart, "warsaw"), ""); err != nil {
			t.Fatal(err)
		}
	}
	leased := []jobs.LeasedJob{{Job: jobs.Job{ID: "j8"}}}
	missed := untaken([]string{"j8", "j9"}, leased)
	if len(missed) != 1 || missed[0] != "j9" {
		t.Fatalf("untaken = %v", missed)
	}
	for _, id := range missed {
		a.release(context.Background(), id)
	}
	if _, holds := b.held[budgets.JobOwner("j9")]; holds {
		t.Error("the task the lease missed still holds tokens")
	}
	if _, holds := b.held[budgets.JobOwner("j8")]; !holds {
		t.Error("the leased task lost its tokens")
	}
}

// TestUnwrittenReasonIsAnError guards that a wait the panel could not write
// down is reported rather than passed over: a silent wait is the failure
// the reason exists to prevent.
func TestUnwrittenReasonIsAnError(t *testing.T) {
	b := newFakeBudgets(budgets.KeyGlobalMutations)
	w := &fakeWaits{fail: errors.New("database away")}
	a := newAdmission(b, w)
	if _, err := a.admit(context.Background(), candidate("j10", opspec.ActionUnitRestart, "warsaw"), ""); err == nil {
		t.Error("a wait reason that was not written passed as fine")
	}
}

func keysAsked(needs []budgets.Need) []string {
	keys := make([]string, 0, len(needs))
	for _, need := range needs {
		keys = append(keys, need.Key)
	}
	return keys
}

func contains(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

// fakeTopology places hosts in failure domains, or fails to answer.
type fakeTopology struct {
	domains map[string]string
	fail    error
	asked   [][]string
}

func (f *fakeTopology) FailureDomains(_ context.Context, hostIDs []string) (map[string]string, error) {
	f.asked = append(f.asked, hostIDs)
	if f.fail != nil {
		return nil, f.fail
	}
	return f.domains, nil
}

// TestHostInAFailureDomainAsksForItsDomainBudget guards the topology
// budget of a job: a change on a host the operator placed in a rack asks
// for the rack's token of the family, next to the site's and the
// gateway's, and a host nobody placed asks for no domain at all.
func TestHostInAFailureDomainAsksForItsDomainBudget(t *testing.T) {
	b := newFakeBudgets("domain:rack-1:units")
	w := &fakeWaits{}
	a := newAdmission(b, w)
	a.topology = &fakeTopology{domains: map[string]string{"host-j20": "rack-1"}}

	placed := candidate("j20", opspec.ActionUnitRestart, "warsaw")
	unplaced := candidate("j21", opspec.ActionUnitRestart, "warsaw")
	campaignID := "c2"
	held := candidate("j22", opspec.ActionUnitRestart, "warsaw")
	held.Job.CampaignID = &campaignID
	domains, err := a.failureDomains(context.Background(), []jobs.Candidate{placed, unplaced, held})
	if err != nil {
		t.Fatal(err)
	}
	// Only the hosts that will be asked about are looked up: a campaign's
	// task holds its tokens already.
	if asked := a.topology.(*fakeTopology).asked; len(asked) != 1 || strings.Join(asked[0], " ") != "host-j20 host-j21" {
		t.Errorf("the topology was asked for %v", asked)
	}

	ok, err := a.admit(context.Background(), placed, domains[placed.Job.HostID])
	if err != nil || ok {
		t.Fatalf("a restart in a full rack: admit = %v, %v; want a wait", ok, err)
	}
	if w.reasons["j20"] != budgets.WaitReasonPrefix+"domain:rack-1:units" {
		t.Errorf("wait reason = %q", w.reasons["j20"])
	}
	ok, err = a.admit(context.Background(), unplaced, domains[unplaced.Job.HostID])
	if err != nil || !ok {
		t.Fatalf("a restart on an unplaced host: admit = %v, %v; want admitted", ok, err)
	}
	for _, key := range keysAsked(b.asked[1].needs) {
		if strings.HasPrefix(key, "domain:") {
			t.Errorf("an unplaced host asked for the domain budget %s", key)
		}
	}
}

// TestFailedDomainLookupStopsThePass guards that a limit the operator set
// does not lapse because a query did: the pass ends with the error rather
// than admitting the tasks as hosts of no domain.
func TestFailedDomainLookupStopsThePass(t *testing.T) {
	a := newAdmission(newFakeBudgets(), &fakeWaits{})
	a.topology = &fakeTopology{fail: errors.New("the database is away")}
	if _, err := a.failureDomains(context.Background(), []jobs.Candidate{candidate("j23", opspec.ActionUnitRestart, "warsaw")}); err == nil {
		t.Fatal("a failed lookup answered with no domains instead of an error")
	}
	// Without a topology there is nothing to ask and nothing to fail.
	a.topology = nil
	if domains, err := a.failureDomains(context.Background(), []jobs.Candidate{candidate("j24", opspec.ActionUnitRestart, "warsaw")}); err != nil || len(domains) != 0 {
		t.Fatalf("no topology gave %v, %v", domains, err)
	}
}
