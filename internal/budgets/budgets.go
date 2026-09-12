// Package budgets answers one question: does the system have the capacity to
// start one more operation.
//
// This is not the same question a resource lock answers. A lock says whether
// two operations exclude each other on one host; a budget says whether the
// fleet, the site and the channel can carry them. Folding both into a single
// number gives false safety: a limit of five hosts in a campaign does not
// protect a repository from a hundred parallel reads, and a package mutex says
// nothing about the load on a site.
package budgets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

// Class is the priority with which work asks for capacity.
//
// The order only matters for as long as the promotion takes: an urgent
// operation stops being limited by its fair share after a moment, a
// maintenance campaign after minutes. No class skips capacity itself: an
// incident cannot run two network changes in a site that allows one either.
type Class string

const (
	// ClassIncident is a response to a failure: locking an account, stopping
	// a service. It waits the shortest.
	ClassIncident Class = "incident"
	// ClassInteractive is an operator working on a single host.
	ClassInteractive Class = "interactive"
	// ClassMaintenance is a planned and approved campaign.
	ClassMaintenance Class = "maintenance"
	// ClassBackground is the panel's own work: sweeps, periodic reads.
	ClassBackground Class = "background"
)

// PromotionAge says how long a class waits before its fair share stops
// binding.
//
// The fair share protects small, urgent operations from being starved by a
// large campaign. The share itself can starve too, though - a campaign that
// waits forever because someone keeps submitting new work. Promotion by age
// closes that window: capacity still has to be respected, but the share no
// longer binds.
func (c Class) PromotionAge() time.Duration {
	switch c {
	case ClassIncident:
		return 0
	case ClassInteractive:
		return 15 * time.Second
	case ClassMaintenance:
		return 2 * time.Minute
	default:
		return 5 * time.Minute
	}
}

// Known says whether the class is one of the known ones.
func Known(c Class) bool {
	switch c {
	case ClassIncident, ClassInteractive, ClassMaintenance, ClassBackground:
		return true
	default:
		return false
	}
}

// Need is a single capacity requirement.
//
// Weight is the cost: one task is usually one token, but an operation that
// pulls gigabytes should cost more than reading state.
type Need struct {
	Key    string
	Weight int
}

// Refusal reasons. Every refusal has to be distinguishable: the whole fleet
// being out of capacity and one campaign exceeding its share are two different
// situations and two different answers for the operator.
const (
	// ReasonCapacity means the budget is fully taken.
	ReasonCapacity = "capacity"
	// ReasonFairShare means there is free capacity, but not for this
	// claimant: one campaign does not take every free token.
	ReasonFairShare = "fair_share"
)

// Refusal describes a budget that had no room.
//
// Silence is not an answer: a host waiting for tokens has to show which budget
// it waits for, how much is taken and how long the wait has lasted.
type Refusal struct {
	Key      string
	Reason   string
	Used     int
	Capacity int
	// Share is the portion for a single claimant, and Held is what this
	// claimant already has. Without both numbers a "share exhausted" refusal
	// does not say whether one token was missing or a hundred.
	Share   int
	Held    int
	Waiting time.Duration
}

// Describe names the obstacle in a sentence that can be shown to an operator.
func (r Refusal) Describe() string {
	if r.Key == "" {
		return ""
	}
	if r.Reason == ReasonFairShare {
		return fmt.Sprintf("budget %s: share %d of %d tokens, holding %d, waiting %s",
			r.Key, r.Share, r.Capacity, r.Held, r.Waiting.Round(time.Second))
	}
	return fmt.Sprintf("budget %s: %d of %d taken, waiting %s",
		r.Key, r.Used, r.Capacity, r.Waiting.Round(time.Second))
}

// Empty says whether there was no refusal.
func (r Refusal) Empty() bool { return r.Key == "" }

// Keys of the global budgets. Reads and mutations have separate capacities: a
// hundred state reads are not the same load as a hundred package transactions.
const (
	KeyGlobalMutations = "global:mutations"
	KeyGlobalReads     = "global:reads"
)

// SiteFamily names the family of resources an operation loads within a site.
//
// The basis is the lock class from the operation registry: it is the one that
// names the resource an operation uses exclusively. A reboot has no lock class
// because it takes the whole host - and it is still the thing we do not want
// to do ten times at once in one site. An empty value means an operation
// without a site budget, not a zero budget: the global budget still applies.
func SiteFamily(action opspec.ActionType) string {
	switch action {
	case opspec.ActionSystemReboot, opspec.ActionSystemShutdown:
		return "reboot"
	}
	return action.LockClass()
}

// SiteKey builds the key of a site budget.
func SiteKey(site, family string) string {
	if site == "" || family == "" {
		return ""
	}
	return "site:" + site + ":" + family
}

// BackendKey builds the key of a backup repository budget.
//
// A site limit does not protect a repository: ten hosts from three sites fit
// into every site budget and are still ten streams into one backend that has
// one link and one disk.
//
// A repository address can be any text - with a scheme, a user and a path. The
// key has to stay in three parts for the default policy ("backend:*:backup")
// to work, so colons become underscores, and a long address ends with a
// fingerprint: two different repositories must not land in one budget just
// because the name was cut.
func BackendKey(repository string) string {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return ""
	}
	name := strings.NewReplacer(":", "_", " ", "_").Replace(repository)
	if len(name) > 100 {
		sum := sha256.Sum256([]byte(repository))
		name = name[:100] + "_" + hex.EncodeToString(sum[:])[:16]
	}
	return "backend:" + name + ":backup"
}

// Pattern turns an exact key into the pattern of the default policy.
//
// There are as many sites as someone created, and nobody describes each of
// them separately. A pattern allows one policy for all of them without taking
// away the option of describing one differently.
func Pattern(key string) string {
	parts := split(key)
	if len(parts) != 3 {
		return ""
	}
	return parts[0] + ":*:" + parts[2]
}

func split(key string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			parts = append(parts, key[start:i])
			start = i + 1
		}
	}
	return append(parts, key[start:])
}

// Needs lists the budgets one operation loads on one host.
//
// What is not here: a gateway budget and a failure domain budget. The panel
// does not know the topology that would define them yet - and it is better for
// them to be absent than to pretend to be a limit computed out of nothing.
// Adding them means adding entries to this list.
func Needs(action opspec.ActionType, site, repository string) []Need {
	global := KeyGlobalReads
	if action.Mutating() {
		global = KeyGlobalMutations
	}
	needs := []Need{{Key: global, Weight: 1}}

	// The site budget applies to changes. Reads load the host and its link,
	// and those have their own limits on the agent side.
	if action.Mutating() {
		if key := SiteKey(site, SiteFamily(action)); key != "" {
			needs = append(needs, Need{Key: key, Weight: 1})
		}
	}

	// A backup repository is a resource shared by the whole fleet, so it has
	// its own budget - including for reads, because verifying a copy reads
	// over the same link that writing it uses.
	//
	// The weight is one for every operation. The document speaks of weighted
	// budgets, but the weight of a copy against a verification depends on the
	// size of the data and on the backend - and a number taken without a
	// measurement would pretend to be a limit computed out of nothing.
	switch action {
	case opspec.ActionBackupRun, opspec.ActionBackupVerify, opspec.ActionBackupRestore:
		if key := BackendKey(repository); key != "" {
			needs = append(needs, Need{Key: key, Weight: 1})
		}
	}
	return needs
}
