// Package budgets answers one question: does the system have the capacity to
// start one more operation.
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
type Need struct {
	Key    string
	Weight int
}

// Refusal reasons.
const (
	// ReasonCapacity means the budget is fully taken.
	ReasonCapacity = "capacity"
	// ReasonFairShare means there is free capacity, but not for this
	// claimant: one campaign does not take every free token.
	ReasonFairShare = "fair_share"
)

// Refusal describes a budget that had no room.
type Refusal struct {
	Key      string
	Reason   string
	Used     int
	Capacity int
	// Share is the portion for a single claimant, and Held is what this claimant
	// already has.
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
func BackendKey(repository string) string {
	name := scopeName(repository)
	if name == "" {
		return ""
	}
	return "backend:" + name + ":backup"
}

// scopeName turns free text into the middle part of a budget key.
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
func DomainKey(domain, family string) string {
	name := scopeName(domain)
	if name == "" || family == "" {
		return ""
	}
	return "domain:" + name + ":" + family
}

// GatewayKey builds the key of a gateway budget.
func GatewayKey(gateway, family string) string {
	name := scopeName(gateway)
	if name == "" || family == "" {
		return ""
	}
	return "gateway:" + name + ":" + family
}

// Pattern turns an exact key into the pattern of the default policy.
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
func RepositoryOf(payload opspec.Payload) string {
	if payload.Backup == nil {
		return ""
	}
	return payload.Backup.Repository
}

// Topology is where a host stands in the fleet: the site it is in, the failure
// domain it shares with the hosts that go down together, and the gateway its
// session is open on.
type Topology struct {
	Site          string
	FailureDomain string
	Gateway       string
}

// Needs lists the budgets one operation loads on one host.
func Needs(action opspec.ActionType, where Topology, repository string) []Need {
	// An operation the registry does not describe is not a read just because
	// nothing says it changes anything: unknown is not harmless, so it asks for
	// the scarcer capacity.
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

	// A backup repository is a resource shared by the whole fleet, so it has its
	// own budget - including for reads, because verifying a copy reads over the
	// same link that writing it uses.
	switch action {
	case opspec.ActionBackupRun, opspec.ActionBackupVerify, opspec.ActionBackupRestore:
		if key := BackendKey(repository); key != "" {
			needs = append(needs, Need{Key: key, Weight: 1})
		}
	}
	return needs
}

// JobOwner names the budget owner of a single-host job.
func JobOwner(jobID string) string { return "job:" + jobID }

// JobClaimant names the unit of fairness of a single-host job: the identity
// that ordered it.
func JobClaimant(createdBy string) string { return "jobs:" + createdBy }

// WaitReasonPrefix starts the wait reason of a job that got no tokens; the
// key of the budget that had no room follows it.
const WaitReasonPrefix = "awaiting_budget:"

// WaitReason spells out why a job stays in the queue: the budget it waits for,
// by key.
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

// DescribedKey reads the budget key back out of the sentence Describe wrote.
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

// ClassUnknown is the class of a lease the panel cannot read a class from: a
// lease taken by something that is neither a job, a campaign nor a fan-out.
const ClassUnknown = "unknown"

// JobFacts is what the job of a lease says about its own class.
type JobFacts struct {
	Action    opspec.ActionType
	CreatedBy string
	Stated    Class
}

// LeaseClass names the class a lease was taken with.
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

// PanelAuthorPrefix marks a job the panel ordered on its own: a vulnerability
// sweep, a scheduled refresh.
const PanelAuthorPrefix = "flotestro/"

// JobClass decides how urgently a single-host job asks for capacity.
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
