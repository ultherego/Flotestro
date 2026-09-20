package budgets

import (
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

// TestNeedsSeparateReadsFromMutations guards the boundary these budgets exist
// for: a hundred state reads are not the same load as a hundred package
// transactions.
func TestNeedsSeparateReadsFromMutations(t *testing.T) {
	read := Needs(opspec.ActionPackageList, Topology{Site: "warsaw"}, "")
	if len(read) != 1 || read[0].Key != KeyGlobalReads {
		t.Fatalf("a read loads budgets %+v", read)
	}

	mutation := Needs(opspec.ActionPackageUpgrade, Topology{Site: "warsaw"}, "")
	if len(mutation) != 2 {
		t.Fatalf("a package transaction loads budgets %+v", mutation)
	}
	// Only the site is known here: no domain and no gateway budget appear
	// out of nothing.
	if mutation[0].Key != KeyGlobalMutations {
		t.Errorf("transaction outside the mutation budget: %+v", mutation)
	}
	if mutation[1].Key != "site:warsaw:packages" {
		t.Errorf("transaction outside the site budget: %+v", mutation)
	}
}

// TestRebootHasItsOwnSiteFamily guards the operation that has no lock class
// because it takes the whole host - and is still the thing we do not want to
// do ten times at once in one site.
func TestRebootHasItsOwnSiteFamily(t *testing.T) {
	if family := SiteFamily(opspec.ActionSystemReboot); family != "reboot" {
		t.Fatalf("reboot in family %q", family)
	}
	needs := Needs(opspec.ActionSystemReboot, Topology{Site: "warsaw"}, "")
	if len(needs) != 2 || needs[1].Key != "site:warsaw:reboot" {
		t.Fatalf("reboot loads budgets %+v", needs)
	}
}

// TestHostWithoutSiteGetsNoKeyWithAHole makes sure a missing site does not
// turn into the key "site::packages" - that is, into one shared budget for
// every host nobody has assigned yet.
func TestHostWithoutSiteGetsNoKeyWithAHole(t *testing.T) {
	needs := Needs(opspec.ActionPackageUpgrade, Topology{}, "")
	if len(needs) != 1 || needs[0].Key != KeyGlobalMutations {
		t.Fatalf("a host without a site loads budgets %+v", needs)
	}
}

// TestPatternDescribesEverySite guards the default policy: there are as many
// sites as someone created, and nobody describes each of them separately.
func TestPatternDescribesEverySite(t *testing.T) {
	if pattern := Pattern("site:warsaw:packages"); pattern != "site:*:packages" {
		t.Errorf("pattern = %q", pattern)
	}
	// A global key has no variable part, so it has no pattern either.
	if pattern := Pattern(KeyGlobalMutations); pattern != "" {
		t.Errorf("a global key got the pattern %q", pattern)
	}
}

// TestPromotionDependsOnClass makes sure the priority really means something:
// an urgent operation stops being limited by its share sooner than a
// background campaign.
func TestPromotionDependsOnClass(t *testing.T) {
	order := []Class{ClassIncident, ClassInteractive, ClassMaintenance, ClassBackground}
	previous := time.Duration(-1)
	for _, class := range order {
		age := class.PromotionAge()
		if age <= previous {
			t.Errorf("class %s waits %s, and a less urgent one %s", class, age, previous)
		}
		previous = age
	}
	if ClassIncident.PromotionAge() != 0 {
		t.Error("an incident waits for promotion instead of getting it at once")
	}
}

// TestRefusalNamesTheObstacle guards the doctrine: a refusal without a reason
// is silence, and silence is the worst answer.
func TestRefusalNamesTheObstacle(t *testing.T) {
	if !(Refusal{}).Empty() {
		t.Fatal("an empty refusal is not empty")
	}
	capacity := Refusal{Key: "site:warsaw:packages", Reason: ReasonCapacity,
		Used: 5, Capacity: 5, Waiting: 12 * time.Second}
	description := capacity.Describe()
	for _, fragment := range []string{"site:warsaw:packages", "5", "12s"} {
		if !strings.Contains(description, fragment) {
			t.Errorf("description %q does not mention %q", description, fragment)
		}
	}

	share := Refusal{Key: KeyGlobalMutations, Reason: ReasonFairShare,
		Capacity: 50, Share: 25, Held: 25}
	// A share refusal and a capacity refusal are two different situations: in
	// the first one there are free tokens, just not for this claimant.
	if share.Describe() == capacity.Describe() {
		t.Error("both refusals read the same")
	}
	if !strings.Contains(share.Describe(), "25") {
		t.Errorf("the share refusal gives no numbers: %q", share.Describe())
	}
}

// A backup repository is a resource shared by the whole fleet: a site budget
// knows nothing about the backend half the fleet writes to at once.
func TestBackendBudgetFollowsTheRepository(t *testing.T) {
	backup := Needs(opspec.ActionBackupRun, Topology{Site: "warsaw"}, "/srv/copies")
	var backend string
	for _, need := range backup {
		if strings.HasPrefix(need.Key, "backend:") {
			backend = need.Key
		}
	}
	if backend != "backend:/srv/copies:backup" {
		t.Fatalf("backend key = %q", backend)
	}
	// The default policy has to work for a repository nobody described
	// separately as well.
	if Pattern(backend) != "backend:*:backup" {
		t.Errorf("backend pattern = %q", Pattern(backend))
	}

	// Verifying a copy reads over the same link, so it loads the backend too.
	verify := Needs(opspec.ActionBackupVerify, Topology{Site: "warsaw"}, "/srv/copies")
	if len(verify) != len(backup) {
		t.Errorf("verification skips the backend budget: %+v", verify)
	}

	// An address with a scheme and a user still has to give a three-part key,
	// and two different repositories - two different keys.
	remote := BackendKey("sftp:copies@backup.example:/srv/copies")
	if Pattern(remote) != "backend:*:backup" {
		t.Errorf("remote repository pattern = %q (%s)", Pattern(remote), remote)
	}
	long := BackendKey("s3:https://example.invalid/" + strings.Repeat("a", 200))
	other := BackendKey("s3:https://example.invalid/" + strings.Repeat("a", 199) + "b")
	if long == other {
		t.Error("two long addresses landed in one budget")
	}
	if Pattern(long) != "backend:*:backup" {
		t.Errorf("long address pattern = %q", Pattern(long))
	}
	if BackendKey("") != "" {
		t.Error("an empty address got a budget key")
	}
	// An operation outside the backup module does not load the backend, even
	// when an address is present.
	if len(Needs(opspec.ActionUnitRestart, Topology{Site: "warsaw"}, "/srv/copies")) != 2 {
		t.Error("a unit restart loaded the backend budget")
	}
}

// TestJobClassFollowsTheOperatorThenTheEvidence guards the order of the class
// rule: what the order stated first, then what can be seen of the action.
func TestJobClassFollowsTheOperatorThenTheEvidence(t *testing.T) {
	cases := []struct {
		action    opspec.ActionType
		createdBy string
		stated    Class
		want      Class
	}{
		{opspec.ActionUnitRestart, "alice", "", ClassInteractive},
		{opspec.ActionUnitRestart, "alice", ClassIncident, ClassIncident},
		{opspec.ActionInventoryRefresh, PanelAuthorPrefix + "vuln", "", ClassBackground},
		{opspec.ActionLocalUserLock, "alice", "", ClassIncident},
		// A class nobody knows is not a class: the evidence decides.
		{opspec.ActionUnitRestart, "alice", Class("urgent"), ClassInteractive},
	}
	for _, c := range cases {
		if got := JobClass(c.action, c.createdBy, c.stated); got != c.want {
			t.Errorf("%s by %s stated %q: class %s, want %s", c.action, c.createdBy, c.stated, got, c.want)
		}
	}
}

// TestWaitReasonNamesTheKeyAndReadsBack guards the one fixed form the job
// list shows and the metrics count.
func TestWaitReasonNamesTheKeyAndReadsBack(t *testing.T) {
	reason := WaitReason(Refusal{Key: "site:warsaw:units", Reason: ReasonCapacity})
	if reason != "awaiting_budget:site:warsaw:units" {
		t.Fatalf("reason = %q", reason)
	}
	if key := WaitedKey(reason); key != "site:warsaw:units" {
		t.Errorf("key read back = %q", key)
	}
	if WaitReason(Refusal{}) != "" || WaitedKey("resource_busy") != "" {
		t.Error("no refusal or a reason of another kind names a budget")
	}
}

// TestUnknownOperationAsksForTheScarcerCapacity guards that an operation the
// registry does not describe is not treated as a read: unknown is not
// harmless.
func TestUnknownOperationAsksForTheScarcerCapacity(t *testing.T) {
	needs := Needs(opspec.ActionType("nobody.knows"), Topology{Site: "warsaw"}, "")
	if len(needs) == 0 || needs[0].Key != KeyGlobalMutations {
		t.Fatalf("an unknown operation loads budgets %+v", needs)
	}
}

// TestDescribedKeyReadsTheBudgetOutOfTheSentence guards the only place a
// waiting campaign target names its budget: the sentence Describe wrote.
func TestDescribedKeyReadsTheBudgetOutOfTheSentence(t *testing.T) {
	refusals := []Refusal{
		{Key: "site:warsaw:packages", Reason: ReasonCapacity, Used: 5, Capacity: 5, Waiting: 3 * time.Second},
		{Key: KeyGlobalMutations, Reason: ReasonFairShare, Capacity: 50, Share: 25, Held: 25},
		{Key: BackendKey("s3:https://bucket/repo"), Reason: ReasonCapacity, Used: 2, Capacity: 2},
	}
	for _, refusal := range refusals {
		if key := DescribedKey(refusal.Describe()); key != refusal.Key {
			t.Errorf("%q reads back as %q, want %q", refusal.Describe(), key, refusal.Key)
		}
	}
	for _, message := range []string{"", "resource busy", "budget", "budget site:warsaw:packages"} {
		if key := DescribedKey(message); key != "" {
			t.Errorf("%q names budget %q", message, key)
		}
	}
}

// TestLeaseClassIsReadFromTheHolder guards how the budget screen tells the
// classes apart although the lease records none: from the holder of the lease.
func TestLeaseClassIsReadFromTheHolder(t *testing.T) {
	cases := []struct {
		name     string
		owner    string
		claimant string
		job      *JobFacts
		want     string
	}{
		{"a job by an operator", "job:1", "jobs:alice", &JobFacts{Action: opspec.ActionUnitRestart, CreatedBy: "alice"}, string(ClassInteractive)},
		{"a job the operator marked", "job:1", "jobs:alice", &JobFacts{Action: opspec.ActionUnitRestart, CreatedBy: "alice", Stated: ClassIncident}, string(ClassIncident)},
		{"the panel's own job", "job:1", "jobs:" + PanelAuthorPrefix + "vuln", &JobFacts{Action: opspec.ActionInventoryRefresh, CreatedBy: PanelAuthorPrefix + "vuln"}, string(ClassBackground)},
		{"a job whose row is gone", "job:1", "jobs:alice", nil, ClassUnknown},
		{"a campaign target", "5a1c3e2f-0000-0000-0000-000000000000", "campaign:7", nil, string(ClassMaintenance)},
		{"a fan-out read", "fanout:3", "reads:alice", nil, string(ClassInteractive)},
		{"a stand-in of a test", "integration-test:job-budget", "integration-test", nil, ClassUnknown},
	}
	for _, c := range cases {
		if got := LeaseClass(c.owner, c.claimant, c.job); got != c.want {
			t.Errorf("%s: class %q, want %q", c.name, got, c.want)
		}
	}
}

// TestChangeLoadsItsFailureDomainAndGateway guards the topology budgets of the
// document: a change loads the site, the failure domain and the gateway.
func TestChangeLoadsItsFailureDomainAndGateway(t *testing.T) {
	where := Topology{Site: "warsaw", FailureDomain: "rack-1", Gateway: "edge-03"}
	needs := Needs(opspec.ActionUnitRestart, where, "")
	keys := make([]string, 0, len(needs))
	for _, need := range needs {
		keys = append(keys, need.Key)
	}
	want := []string{KeyGlobalMutations, "site:warsaw:units", "domain:rack-1:units", "gateway:edge-03:units"}
	if strings.Join(keys, " ") != strings.Join(want, " ") {
		t.Fatalf("a restart in a placed host loads %v, want %v", keys, want)
	}
	if read := Needs(opspec.ActionUnitStatus, where, ""); len(read) != 1 {
		t.Errorf("a read loads the topology budgets: %+v", read)
	}
	// The default policy has to reach a domain and a gateway nobody
	// described separately.
	if Pattern("domain:rack-1:units") != "domain:*:units" || Pattern("gateway:edge-03:units") != "gateway:*:units" {
		t.Error("the topology keys have no pattern of the default policy")
	}
}

// TestTopologyKeysStayInThreeParts guards the spelling of free text in a key:
// a domain named the way the document does ("cluster:pg-a") must not break the
// key into four parts, and an unknown part names no budget.
func TestTopologyKeysStayInThreeParts(t *testing.T) {
	if key := DomainKey("cluster:pg-a", "reboot"); key != "domain:cluster_pg-a:reboot" {
		t.Errorf("domain key = %q", key)
	}
	if key := GatewayKey("edge 03", "packages"); key != "gateway:edge_03:packages" {
		t.Errorf("gateway key = %q", key)
	}
	if DomainKey("", "reboot") != "" || DomainKey("rack-1", "") != "" ||
		GatewayKey("", "reboot") != "" || GatewayKey("edge-03", "") != "" {
		t.Error("an unknown domain, gateway or family got a budget key")
	}
	if DomainKey("  ", "reboot") != "" {
		t.Error("a blank domain got a budget key")
	}
}
