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
	read := Needs(opspec.ActionPackageList, "warsaw", "")
	if len(read) != 1 || read[0].Key != KeyGlobalReads {
		t.Fatalf("a read loads budgets %+v", read)
	}

	mutation := Needs(opspec.ActionPackageUpgrade, "warsaw", "")
	if len(mutation) != 2 {
		t.Fatalf("a package transaction loads budgets %+v", mutation)
	}
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
	needs := Needs(opspec.ActionSystemReboot, "warsaw", "")
	if len(needs) != 2 || needs[1].Key != "site:warsaw:reboot" {
		t.Fatalf("reboot loads budgets %+v", needs)
	}
}

// TestHostWithoutSiteGetsNoKeyWithAHole makes sure a missing site does not
// turn into the key "site::packages" - that is, into one shared budget for
// every host nobody has assigned yet.
func TestHostWithoutSiteGetsNoKeyWithAHole(t *testing.T) {
	needs := Needs(opspec.ActionPackageUpgrade, "", "")
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
	backup := Needs(opspec.ActionBackupRun, "warsaw", "/srv/copies")
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
	verify := Needs(opspec.ActionBackupVerify, "warsaw", "/srv/copies")
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
	if len(Needs(opspec.ActionUnitRestart, "warsaw", "/srv/copies")) != 2 {
		t.Error("a unit restart loaded the backend budget")
	}
}
