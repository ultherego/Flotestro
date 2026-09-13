package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Plan describes the copy that will be made on this host.
//
// The same order on two hosts is two different copies: one has all the
// named directories, another has half of them not at all, a third has no
// repository yet. The operator's approval is meant to cover what really
// leaves this host - and how much it costs it.
type Plan struct {
	ID         string `json:"id"`
	Tool       string `json:"tool"`
	Repository string `json:"repository,omitempty"`
	// Action names what would happen: run (the copy is made) or verify.
	Action string `json:"action"`

	// The data scope: the directories the host really has, and those it
	// does not.
	Paths        []string `json:"paths,omitempty"`
	MissingPaths []string `json:"missing_paths,omitempty"`
	// BytesOnHost is the sum of the file sizes in the scope. An unknown
	// size stays no knowledge, not zero.
	BytesOnHost *uint64 `json:"bytes_on_host,omitempty"`

	// The repository state before the copy.
	RepositoryReady bool       `json:"repository_ready"`
	Snapshots       int        `json:"snapshots"`
	LastSuccessAt   *time.Time `json:"last_success_at,omitempty"`
	// WillInitialize says the copy creates the repository.
	WillInitialize bool `json:"will_initialize,omitempty"`
	// Retention describes the cleanup after the copy. Empty means "do not
	// clean up".
	Retention string `json:"retention,omitempty"`
	// Verified says the host checks the repository after the copy. A copy
	// without a check is not a success here, so the plan says so directly.
	Verified bool `json:"verified"`
	ReadData bool `json:"read_data,omitempty"`

	Changes []string `json:"changes,omitempty"`
	// Refusal names the reason the copy is not made on this host: no tool,
	// an unread repository without consent to create one, none of the named
	// directories present.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Plan action names.
const (
	PlanRun    = "run"
	PlanVerify = "verify"
)

// Compute computes the plan of a copy or a verification against the
// repository state.
//
// The scope size is computed by the given function: the module does not
// walk the disk itself, because the same structure serves the tests and
// the panel.
func Compute(state State, order Definition, verification, readData bool,
	size func(string) (uint64, bool)) Plan {
	plan := Plan{
		ID: order.ID, Tool: order.Tool, Repository: order.Repository,
		Action: PlanRun, Snapshots: len(state.Snapshots),
		LastSuccessAt: state.LastSuccessAt, ReadData: readData,
		// The copy ends with a repository check: a copy nobody checked is
		// not a success here.
		Verified: true,
	}
	if verification {
		plan.Action = PlanVerify
	}
	if err := order.Validate(); err != nil {
		return plan.withRefusal(err.Error())
	}

	plan.RepositoryReady = state.UnavailableReason == ""
	if !plan.RepositoryReady {
		// An unread repository and an empty repository are two different
		// answers. The former allows creating a new one only with explicit
		// consent.
		if plan.Action == PlanVerify {
			return plan.withRefusal("the repository did not answer: " + state.UnavailableReason)
		}
		if !order.Initialize {
			return plan.withRefusal("the repository did not answer (" + state.UnavailableReason +
				"); creating a new one requires explicit consent")
		}
		plan.WillInitialize = true
	}

	if plan.Action == PlanVerify {
		plan.Changes = []string{fmt.Sprintf("the repository with %d copies will be checked", plan.Snapshots)}
		if readData {
			plan.Changes = append(plan.Changes, "the check will read the data, not only the structure")
		}
		plan.PlanHash = backupPlanFingerprint(plan)
		return plan
	}

	var sum uint64
	var sumKnown bool
	for _, path := range order.Paths {
		if size == nil {
			plan.Paths = append(plan.Paths, path)
			continue
		}
		bytes, present := size(path)
		if !present {
			plan.MissingPaths = append(plan.MissingPaths, path)
			continue
		}
		plan.Paths = append(plan.Paths, path)
		sum += bytes
		sumKnown = true
	}
	sort.Strings(plan.Paths)
	sort.Strings(plan.MissingPaths)
	if sumKnown {
		copied := sum
		plan.BytesOnHost = &copied
	}
	// A copy without any existing directory would write an empty snapshot
	// that looks like a backup and is not one.
	if len(plan.Paths) == 0 && order.Runbook == "" {
		return plan.withRefusal("the host has none of the named directories")
	}

	plan.Retention = describeRetention(order)
	if plan.WillInitialize {
		plan.Changes = append(plan.Changes, "the repository "+order.Repository+" will be created")
	}
	plan.Changes = append(plan.Changes, "the copy will cover "+strings.Join(plan.Paths, ", ")+
		sizeInChange(plan.BytesOnHost))
	if len(plan.MissingPaths) > 0 {
		plan.Changes = append(plan.Changes,
			"the host does not have: "+strings.Join(plan.MissingPaths, ", "))
	}
	if order.Runbook != "" {
		plan.Changes = append(plan.Changes, "the runbook "+order.Runbook+" will run before the copy")
	}
	if plan.Retention != "" {
		plan.Changes = append(plan.Changes, "retention: "+plan.Retention)
	}
	plan.Changes = append(plan.Changes, "after the copy the host will check the repository")
	plan.PlanHash = backupPlanFingerprint(plan)
	return plan
}

// PathSize computes the size of a scope on the host disk.
func PathSize(path string) (uint64, bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, false
	}
	if !info.IsDir() {
		return uint64(info.Size()), true
	}
	var sum uint64
	entries, err := os.ReadDir(path)
	if err != nil {
		// The directory exists, but cannot be counted: it is still part of
		// the copy scope, only of unknown size.
		return 0, true
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.IsDir() {
			subtotal, _ := PathSize(path + "/" + entry.Name())
			sum += subtotal
			continue
		}
		sum += uint64(info.Size())
	}
	return sum, true
}

// Refuse records a refusal reason learned after the plan was computed and
// recomputes the fingerprint: a plan with a refusal is a different answer
// than a plan without one.
func (p *Plan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = backupPlanFingerprint(*p)
}

func (p Plan) withRefusal(reason string) Plan {
	p.Refusal = reason
	p.PlanHash = backupPlanFingerprint(p)
	return p
}

func describeRetention(order Definition) string {
	var parts []string
	for _, pair := range []struct {
		name  string
		count int
	}{
		{"last", order.KeepLast}, {"daily", order.KeepDaily},
		{"weekly", order.KeepWeekly}, {"monthly", order.KeepMonthly},
	} {
		if pair.count > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", pair.count, pair.name))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	description := "keeps " + strings.Join(parts, ", ")
	if order.Prune {
		description += "; the repository will be pruned"
	}
	return description
}

func sizeInChange(bytes *uint64) string {
	if bytes == nil {
		return " (size not computed)"
	}
	return fmt.Sprintf(" (%d MiB on disk)", *bytes>>20)
}

// backupPlanFingerprint computes the plan fingerprint excluding the
// fingerprint itself. The repository password is not in the plan, so it is
// not in the fingerprint either.
func backupPlanFingerprint(plan Plan) string {
	stripped := plan
	stripped.PlanHash = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
