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
	name := scopeName(repository)
	if name == "" {
		return ""
	}
	return "backend:" + name + ":backup"
}

// scopeName turns free text into the middle part of a budget key.
//
// A repository address, a failure domain an operator typed ("cluster:pg-a",
// the way the document names it) or a gateway identifier can hold colons
// and spaces. The key has to stay in three parts for the pattern of the
// default policy to find it, so those become underscores, and a long text
// ends with a fingerprint: two different scopes must not land in one
// budget just because the name was cut.
func scopeName(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	name := strings.NewReplacer(":", "_", " ", "_").Replace(text)
	if len(name) > 100 {
		sum := sha256.Sum256([]byte(text))
		name = name[:100] + "_" + hex.EncodeToString(sum[:])[:16]
	}
	return name
}

// DomainKey builds the key of a failure domain budget.
//
// A site is where the hosts stand; a failure domain is what goes down
// together, or what must not: a rack, an availability zone, a cluster whose
// members keep a service alive. Five reboots may fit in a site and still
// take every member of one cluster off at once. The domain is free text the
// operator recorded on the host, so it goes through the same spelling a
// repository address does.
func DomainKey(domain, family string) string {
	name := scopeName(domain)
	if name == "" || family == "" {
		return ""
	}
	return "domain:" + name + ":" + family
}

// GatewayKey builds the key of a gateway budget.
//
// The gateway is the pipe the changes of its hosts go through: a session
// over a relay on a thin WAN link carries fewer package transactions at once
// than a session in the data centre, whatever the site budget says. The
// gateway is the one the host's session is open on.
func GatewayKey(gateway, family string) string {
	name := scopeName(gateway)
	if name == "" || family == "" {
		return ""
	}
	return "gateway:" + name + ":" + family
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

// RepositoryOf takes the address of the backup repository out of a payload.
//
// Empty means an operation that does not touch a backend - not an unknown
// backend: operations outside the backup module have nothing to look for
// here. Both the campaign and the scheduler derive the backend key from it,
// so that a copy ordered by hand and one ordered in a campaign land in the
// same budget.
func RepositoryOf(payload opspec.Payload) string {
	if payload.Backup == nil {
		return ""
	}
	return payload.Backup.Repository
}

// Topology is where a host stands in the fleet: the site it is in, the
// failure domain it shares with the hosts that go down together, and the
// gateway its session is open on. Each part names a budget of its own for
// a change; an empty part names none - a host nobody placed in a domain
// loads no domain budget rather than a shared budget of the unplaced.
type Topology struct {
	Site          string
	FailureDomain string
	Gateway       string
}

// Needs lists the budgets one operation loads on one host.
//
// A change loads the fleet, the site, the failure domain and the gateway of
// the host, each with a token of the operation's family; a backup loads its
// repository as well. The domain and the gateway come from what the panel
// knows - the attribute an operator recorded, the session the registry
// holds - and a part it does not know loads nothing, because a limit
// computed out of nothing would only pretend to guard.
func Needs(action opspec.ActionType, where Topology, repository string) []Need {
	// An operation the registry does not describe is not a read just
	// because nothing says it changes anything: unknown is not harmless,
	// so it asks for the scarcer capacity.
	mutating := action.Mutating() || !action.Known()
	global := KeyGlobalReads
	if mutating {
		global = KeyGlobalMutations
	}
	needs := []Need{{Key: global, Weight: 1}}

	// The topology budgets apply to changes. Reads load the host and its
	// link, and those have their own limits on the agent side.
	if mutating {
		family := SiteFamily(action)
		for _, key := range []string{
			SiteKey(where.Site, family),
			DomainKey(where.FailureDomain, family),
			GatewayKey(where.Gateway, family),
		} {
			if key != "" {
				needs = append(needs, Need{Key: key, Weight: 1})
			}
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

// JobOwner names the budget owner of a single-host job.
//
// The owner is the job rather than the attempt: an attempt that lost its
// lease and went back to the queue is the same load asking again, and the
// grant it held must replace itself rather than count twice.
func JobOwner(jobID string) string { return "job:" + jobID }

// JobClaimant names the unit of fairness of a single-host job: the identity
// that ordered it. One operator clicking through twenty hosts is one
// claimant, the way a campaign over twenty hosts is - otherwise the twenty
// clicks would have twenty times the share of the campaign.
func JobClaimant(createdBy string) string { return "jobs:" + createdBy }

// WaitReasonPrefix starts the wait reason of a job that got no tokens; the
// key of the budget that had no room follows it.
const WaitReasonPrefix = "awaiting_budget:"

// WaitReason spells out why a job stays in the queue: the budget it waits
// for, by key. The list of jobs shows it and the metrics count it, so it is
// one fixed form rather than a sentence.
func WaitReason(refusal Refusal) string {
	if refusal.Empty() {
		return ""
	}
	return WaitReasonPrefix + refusal.Key
}

// WaitedKey reads the budget key back out of a wait reason. Empty means the
// job was not waiting on a budget.
func WaitedKey(reason string) string {
	if !strings.HasPrefix(reason, WaitReasonPrefix) {
		return ""
	}
	return strings.TrimPrefix(reason, WaitReasonPrefix)
}

// DescribedKey reads the budget key back out of the sentence Describe
// wrote. A campaign target that waits carries only that sentence - its
// state names the reason, the message names the budget - so the budget
// screen counts the waiting targets by reading the sentence. Empty means
// the message is not a refusal of ours.
func DescribedKey(description string) string {
	rest, ok := strings.CutPrefix(description, "budget ")
	if !ok {
		return ""
	}
	// The key has colons of its own, so the boundary is the colon that
	// Describe puts before the numbers: the first one followed by a space.
	key, _, found := strings.Cut(rest, ": ")
	if !found {
		return ""
	}
	return key
}

// ClassUnknown is the class of a lease the panel cannot read a class from:
// a lease taken by something that is neither a job, a campaign nor a fan-out.
// It is named rather than left empty or counted as background, because a
// token the panel cannot explain is still a token taken.
const ClassUnknown = "unknown"

// JobFacts is what the job of a lease says about its own class.
type JobFacts struct {
	Action    opspec.ActionType
	CreatedBy string
	Stated    Class
}

// LeaseClass names the class a lease was taken with.
//
// The lease itself records no class - only the waiting entry does - so the
// class is read from the holder: a job's from its order the way the
// scheduler read it, a campaign target's from the campaign, which always
// asks as maintenance, a fan-out's from the fan-out, which always asks as
// interactive. A job whose row is gone leaves the class unknown rather than
// guessed.
func LeaseClass(owner, claimant string, job *JobFacts) string {
	switch {
	case strings.HasPrefix(owner, "job:"):
		if job == nil {
			return ClassUnknown
		}
		return string(JobClass(job.Action, job.CreatedBy, job.Stated))
	case strings.HasPrefix(claimant, "campaign:"):
		return string(ClassMaintenance)
	case strings.HasPrefix(owner, "fanout:"):
		return string(ClassInteractive)
	}
	return ClassUnknown
}

// PanelAuthorPrefix marks a job the panel ordered on its own: a
// vulnerability sweep, a scheduled refresh. Such work is background - it
// must never make an operator wait.
const PanelAuthorPrefix = "flotestro/"

// JobClass decides how urgently a single-host job asks for capacity.
//
// A class the request stated wins: the operator knows whether a restart is
// an incident response, and the panel does not. Without one the class comes
// from what can be seen - the panel's own sweeps are background, locking an
// account is the textbook incident response, and everything else is an
// operator working on one host.
func JobClass(action opspec.ActionType, createdBy string, stated Class) Class {
	if Known(stated) {
		return stated
	}
	if strings.HasPrefix(createdBy, PanelAuthorPrefix) {
		return ClassBackground
	}
	if action == opspec.ActionLocalUserLock {
		return ClassIncident
	}
	return ClassInteractive
}
