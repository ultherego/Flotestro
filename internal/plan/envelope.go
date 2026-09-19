// Package plan is the one shape every planner's answer takes before it is
// approved and executed: the envelope of chapter 7 of the security remediation
// plan.
package plan

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/canonical"
)

// SchemaVersion is the layout version of the envelope this release writes.
const SchemaVersion uint32 = 1

// The stable codes of a plan refused at execution.
const (
	// ErrorStalePlan: the plan the host computes now differs from the approved
	// one - a repository, a version, an origin or an architecture moved between
	// the approval and the execution.
	ErrorStalePlan = "stale_plan"
	// ErrorReplanRequired: the planner that would execute is not the planner that
	// made the plan.
	ErrorReplanRequired = "replan_required"
	// ErrorPlanExpired: the plan outlived its validity; the state it
	// described is too old to be trusted blind.
	ErrorPlanExpired = "plan_expired"
	// ErrorEffectsPartial: the transaction ran, and the state read afterwards
	// does not show every effect the plan promised.
	ErrorEffectsPartial = "effects_partial"
)

// ErrStalePlan means the plan computed now does not hash to the approved
// digest.
var ErrStalePlan = errors.New("the plan changed since it was approved")

// ErrReplanRequired means the planner version of the approved plan is not
// the one of the executor.
var ErrReplanRequired = errors.New("the plan was made by another planner version and has to be computed again")

// ErrPlanExpired means the plan is past its expiry.
var ErrPlanExpired = errors.New("the plan expired")

// ErrEffectsPartial means the transaction did not reach every expected
// effect.
var ErrEffectsPartial = errors.New("the transaction did not reach every expected effect")

// CodeOf maps the errors of this package to their stable codes.
func CodeOf(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrStalePlan):
		return ErrorStalePlan, true
	case errors.Is(err, ErrReplanRequired):
		return ErrorReplanRequired, true
	case errors.Is(err, ErrPlanExpired):
		return ErrorPlanExpired, true
	case errors.Is(err, ErrEffectsPartial):
		return ErrorEffectsPartial, true
	}
	return "", false
}

// DefaultTTL is how long a plan stays valid when the planner sets no other
// expiry.
const DefaultTTL = 24 * time.Hour

// Precondition is a fact the helper checks again right before the change.
type Precondition struct {
	// Kind names what is checked: metadata_revision, lock_free,
	// modules_visible, space, protected_absent.
	Kind string `json:"kind"`
	// Subject is what the check is about: a path, a manager, a package.
	Subject string `json:"subject"`
	// Expected is the value the check has to find, in words a person reads.
	Expected string `json:"expected"`
}

// Step is one exact operation of the transaction: a spec the executor
// hands to the tool as it is, never a name it resolves again.
type Step struct {
	// Kind names the operation: install, upgrade, downgrade, remove.
	Kind string `json:"kind"`
	// Subject is the thing the step touches: the package name.
	Subject string `json:"subject"`
	// Spec is the exact argument of the tool: name=version for apt, the
	// full NEVRA for dnf, the archive file for pacman.
	Spec string `json:"spec"`
}

// Artifact is one thing the change fetches or replaces: the exact package with
// its architecture and the repository it comes from.
type Artifact struct {
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Origin       string `json:"origin"`
	Digest       string `json:"digest"`
}

// Effect is one observable outcome the change promises: after the transaction
// the subject has this value.
type Effect struct {
	// Kind names what is observed: package_version (the subject is installed at
	// the value), package_absent (the subject is not installed).
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Value   string `json:"value,omitempty"`
}

// Effects is what the host looks like once the plan has run, beyond the list
// of artifacts: the expected state per package, the restart the change brings
// and the bytes it moves.
type Effects struct {
	Expected []Effect `json:"expected"`
	// RebootRequired is the prediction of the planner; the state after the
	// transaction says whether it came true.
	RebootRequired bool `json:"reboot_required"`
	// ServicesRestart names the services whose libraries change.
	ServicesRestart      []string `json:"services_restart"`
	ServicesRestartKnown bool     `json:"services_restart_known"`
	// DownloadBytes is what comes down the wire; InstallDeltaBytes is how
	// the installed files grow (positive) or shrink (negative).
	DownloadBytes     uint64 `json:"download_bytes"`
	DownloadKnown     bool   `json:"download_known"`
	InstallDeltaBytes int64  `json:"install_delta_bytes"`
	InstallDeltaKnown bool   `json:"install_delta_known"`
}

// RollbackPlan says how the change can be taken back: the mechanism and its
// identifier, or unavailable with the reason.
type RollbackPlan struct {
	Mechanism string `json:"mechanism"`
	ID        string `json:"id"`
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

// Envelope is the plan as it is hashed, approved and executed.
type Envelope struct {
	SchemaVersion     uint32         `json:"schema_version"`
	PlannerVersion    string         `json:"planner_version"`
	ActionType        string         `json:"action_type"`
	HostID            string         `json:"host_id"`
	InventoryRevision string         `json:"inventory_revision"`
	ResourceRevision  string         `json:"resource_revision"`
	Preconditions     []Precondition `json:"preconditions"`
	Steps             []Step         `json:"steps"`
	Effects           Effects        `json:"effects"`
	Artifacts         []Artifact     `json:"artifacts"`
	Rollback          RollbackPlan   `json:"rollback"`
	ExpiresAt         time.Time      `json:"expires_at"`
	// Description is the plan in words for the screen.
	Description string `json:"description,omitempty"`
}

// Normalized returns the envelope in its one canonical shape: every collection
// sorted, no nil collection (a nil and an empty list describe the same plan
// and must hash the same), the expiry in UTC to the second.
func (e Envelope) Normalized() Envelope {
	out := e
	out.Preconditions = append([]Precondition(nil), e.Preconditions...)
	sort.Slice(out.Preconditions, func(i, j int) bool {
		return lessPrecondition(out.Preconditions[i], out.Preconditions[j])
	})
	out.Steps = append([]Step(nil), e.Steps...)
	sort.Slice(out.Steps, func(i, j int) bool { return lessStep(out.Steps[i], out.Steps[j]) })
	out.Artifacts = append([]Artifact(nil), e.Artifacts...)
	sort.Slice(out.Artifacts, func(i, j int) bool { return lessArtifact(out.Artifacts[i], out.Artifacts[j]) })
	out.Effects.Expected = append([]Effect(nil), e.Effects.Expected...)
	sort.Slice(out.Effects.Expected, func(i, j int) bool {
		return lessEffect(out.Effects.Expected[i], out.Effects.Expected[j])
	})
	out.Effects.ServicesRestart = append([]string(nil), e.Effects.ServicesRestart...)
	sort.Strings(out.Effects.ServicesRestart)
	if out.Preconditions == nil {
		out.Preconditions = []Precondition{}
	}
	if out.Steps == nil {
		out.Steps = []Step{}
	}
	if out.Artifacts == nil {
		out.Artifacts = []Artifact{}
	}
	if out.Effects.Expected == nil {
		out.Effects.Expected = []Effect{}
	}
	if out.Effects.ServicesRestart == nil {
		out.Effects.ServicesRestart = []string{}
	}
	out.ExpiresAt = e.ExpiresAt.UTC().Truncate(time.Second)
	return out
}

// Canonical returns the canonical bytes of the envelope: what is hashed,
// and what the panel keeps as the plan body next to the approval.
func (e Envelope) Canonical() ([]byte, error) {
	return canonical.NormalizeRFC8785(e.Normalized())
}

// Hashed returns the envelope as it is digested: normalized, without the
// description and without the identity header.
func (e Envelope) Hashed() Envelope {
	hashed := e.Normalized()
	hashed.Description = ""
	hashed.HostID = ""
	hashed.InventoryRevision = ""
	hashed.ExpiresAt = time.Time{}
	return hashed
}

// Sum returns the digest of the envelope over its content, together with
// the bytes it was computed over.
func (e Envelope) Sum() ([32]byte, []byte, error) {
	return canonical.SHA256(e.Hashed())
}

// Hash returns the digest of the envelope, or nil when the envelope cannot be
// canonicalized.
func (e Envelope) Hash() []byte {
	sum, _, err := e.Sum()
	if err != nil {
		return nil
	}
	return sum[:]
}

// HashHex is the digest as the API and the payloads spell it.
func (e Envelope) HashHex() string {
	return hex.EncodeToString(e.Hash())
}

// Reference is what an execution carries of the approved plan: the digest to
// compare, the planner that made the plan and the expiry.
type Reference struct {
	Hash           []byte
	SchemaVersion  uint32
	PlannerVersion string
	ExpiresAt      time.Time
}

// Verify compares the envelope computed now with the approved reference.
func (e Envelope) Verify(expected Reference, now time.Time) error {
	if expected.SchemaVersion != 0 && expected.SchemaVersion != e.SchemaVersion {
		return fmt.Errorf("%w: schema %d was approved, this host writes schema %d",
			ErrReplanRequired, expected.SchemaVersion, e.SchemaVersion)
	}
	if expected.PlannerVersion != "" && expected.PlannerVersion != e.PlannerVersion {
		return fmt.Errorf("%w: planner %s made the plan, planner %s would execute it",
			ErrReplanRequired, expected.PlannerVersion, e.PlannerVersion)
	}
	if !expected.ExpiresAt.IsZero() && now.After(expected.ExpiresAt) {
		return fmt.Errorf("%w at %s", ErrPlanExpired, expected.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if len(expected.Hash) == 0 {
		return fmt.Errorf("%w: the execution carries no plan digest", ErrStalePlan)
	}
	if !strings.EqualFold(hex.EncodeToString(expected.Hash), e.HashHex()) {
		return fmt.Errorf("%w: approved %s, computed now %s",
			ErrStalePlan, shortHex(expected.Hash), shortHex(e.Hash()))
	}
	return nil
}

// ParseHash reads a digest as the payloads spell it. An empty string is
// an empty digest, which Verify refuses.
func ParseHash(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	sum, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("the plan digest is not hexadecimal: %w", err)
	}
	if len(sum) != 32 {
		return nil, fmt.Errorf("the plan digest has %d bytes, a SHA-256 has 32", len(sum))
	}
	return sum, nil
}

func shortHex(sum []byte) string {
	text := hex.EncodeToString(sum)
	if len(text) > 12 {
		return text[:12]
	}
	if text == "" {
		return "none"
	}
	return text
}

func lessPrecondition(a, b Precondition) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Subject != b.Subject {
		return a.Subject < b.Subject
	}
	return a.Expected < b.Expected
}

func lessStep(a, b Step) bool {
	if a.Subject != b.Subject {
		return a.Subject < b.Subject
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Spec < b.Spec
}

func lessArtifact(a, b Artifact) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Architecture != b.Architecture {
		return a.Architecture < b.Architecture
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.Origin != b.Origin {
		return a.Origin < b.Origin
	}
	return a.Digest < b.Digest
}

func lessEffect(a, b Effect) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Subject != b.Subject {
		return a.Subject < b.Subject
	}
	return a.Value < b.Value
}
