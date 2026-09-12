// Package compliance computes a host's conformance with a hardening profile.
//
// The checks live in the panel rather than on the host, for three reasons.
// They are versioned, so a result can be repeated and compared between hosts.
// They are computed from facts the host reports in its inventory anyway, so no
// extra pass over the fleet is needed. And they are not scripts: every check
// has a type, an expected value, evidence and - where a remediation exists -
// a reference to one specific typed operation of the module responsible for
// that thing.
//
// The panel has no "fix everything" button. Remediation is a plan the
// operator reviews and separate tasks that pass through the permissions of
// their own modules.
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The severities of findings. The severity says what happens if nobody does
// anything, not how hard it is to fix.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
	SeverityInfo   = "info"
)

// The reason codes for findings without a result.
//
// An undetermined state without a code is useless: the operator does not know
// whether to wait for the next read, repair the agent or grant somebody a
// permission.
const (
	// ReasonFactMissing: the host did not report the module the check is
	// computed from.
	ReasonFactMissing = "fact_missing"
	// ReasonUnsupported: the host does not have the component the check
	// concerns. Used with the "not applicable" state rather than with the
	// undetermined one.
	ReasonUnsupported = "unsupported_system"
	// ReasonReadFailed: the fact exists, but the read did not succeed.
	ReasonReadFailed = "read_failed"
	// ReasonPermissionDenied: the read was refused for lack of permissions.
	ReasonPermissionDenied = "permission_denied"
	// ReasonStaleInventory: the read is too old to judge anything from it.
	ReasonStaleInventory = "inventory_stale"
)

// MaxReadAge sets how old a fact may be for an assessment to rest on it.
//
// The inventory cycle is an order of magnitude shorter, so crossing this
// threshold means a host that has been silent for a long time - not a
// conformant host.
const MaxReadAge = 6 * time.Hour

// CanonicalVersion versions the form the plan digest is computed from.
//
// Changing the form changes every digest, so the number is part of the text:
// a plan approved under the previous version must not be carried out after
// the rules of computation change, because it is not known what was approved
// then.
const CanonicalVersion = 1

const canonicalHeader = "flotestro/compliance-plan/v"

// Fragment is the state of one host module together with its revision.
type Fragment struct {
	Module            string
	Revision          string
	Payload           json.RawMessage
	ObservedAt        time.Time
	UnavailableReason string
}

// Host carries the facts the panel knows by itself, without asking a module.
type Host struct {
	Hostname string
	OSFamily string
	// Empty pointers mean an undetermined state, not zero.
	PendingSecurityUpdates *int
	RebootRequired         *bool
}

// Input is everything the checks are computed from.
type Input struct {
	Host      Host
	Fragments map[string]Fragment
}

// Fragment returns a module's fragment and whether it exists at all.
func (w Input) Fragment(module string) (Fragment, bool) {
	fragment, ok := w.Fragments[module]
	if !ok || len(fragment.Payload) == 0 {
		return Fragment{}, false
	}
	return fragment, true
}

// Remediation names the typed operation that removes a finding.
//
// A remediation is not a separate mechanism: it is an ordinary operation of
// the module responsible for the thing, with its own permission and its own
// risk. A finding without a remediation is not an error - some things require
// a decision the panel cannot take for the operator.
type Remediation struct {
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
	// Note says what the operation does not settle or why there is no remediation.
	Note string `json:"note,omitempty"`
	// RequiresReboot marks a step after which the host has to come up again.
	// A plan may have at most one such step and ends with it.
	RequiresReboot bool `json:"requires_reboot,omitempty"`
}

// Finding is the result of one check on one host.
type Finding struct {
	CheckID      string `json:"check_id"`
	CheckVersion int    `json:"check_version"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	// Rationale says what happens if nobody does anything.
	Rationale string `json:"rationale"`
	// Applicable says whether the check applies on this host. A host with
	// AppArmor does not fail a check that requires SELinux - it simply does
	// not concern it, and that is a different answer from "did not pass".
	Applicable bool `json:"applicable"`
	// Passed and Unknown make sense only for checks that apply.
	Passed  bool `json:"passed"`
	Unknown bool `json:"unknown"`
	// ReasonCode names the reason for a missing result. An undetermined state
	// without a code forces the operator to guess whether to wait, repair the
	// agent or grant rights.
	ReasonCode string `json:"reason_code,omitempty"`
	// Expected and Observed are written so that they can be shown side by
	// side without translation.
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Evidence string `json:"evidence,omitempty"`
	// Module, Revision and ObservedAt make the result repeatable: they say
	// which read it came from.
	Module     string    `json:"module"`
	Revision   string    `json:"revision,omitempty"`
	ObservedAt time.Time `json:"observed_at"`

	Remediation *Remediation `json:"remediation,omitempty"`
}

// NeedsAction says whether a finding waits for action.
func (u Finding) NeedsAction() bool { return u.Applicable && !u.Passed && !u.Unknown }

// Result is a check's answer.
type Result struct {
	Passed bool
	// NotApplicable is returned by a check that makes no sense on this host.
	NotApplicable bool
	Unknown       bool
	// ReasonCode is required with Unknown and with NotApplicable.
	ReasonCode  string
	Observed    string
	Evidence    string
	Remediation *Remediation
}

// Check is one versioned check.
type Check struct {
	ID        string
	Version   int
	Title     string
	Severity  string
	Rationale string
	// Module names the inventory fragment the check computes its result from.
	Module string
	// Expected describes the target state in the operator's words.
	Expected string
	Evaluate func(Input) Result
}

// Report is the complete set of findings for one host.
type Report struct {
	HostID   string    `json:"host_id"`
	Findings []Finding `json:"findings"`
	// PlanHash binds a remediation plan to the findings it came from. A
	// change in the host's state changes the hash, so an approved plan cannot
	// be carried out against a state other than the one the operator
	// reviewed.
	PlanHash string `json:"plan_hash"`
	// PlanHashVersion says which canonical form computed the digest.
	PlanHashVersion int       `json:"plan_hash_version"`
	GeneratedAt     time.Time `json:"generated_at"`
	// Counts summarise the report without the interface having to count.
	Counts map[string]int `json:"counts"`
}

// Evaluate computes the findings for a host.
func Evaluate(hostID string, input Input, now time.Time) Report {
	findings := make([]Finding, 0, len(Checks))
	for _, check := range Checks {
		findings = append(findings, run(check, input, now))
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if severityOrder(findings[i]) != severityOrder(findings[j]) {
			return severityOrder(findings[i]) < severityOrder(findings[j])
		}
		return findings[i].CheckID < findings[j].CheckID
	})
	return Report{
		HostID:          hostID,
		Findings:        findings,
		PlanHash:        PlanHash(hostID, findings),
		PlanHashVersion: CanonicalVersion,
		GeneratedAt:     now,
		Counts:          summarise(findings),
	}
}

// run carries out one check and describes the result.
func run(check Check, input Input, now time.Time) Finding {
	finding := Finding{
		CheckID: check.ID, CheckVersion: check.Version, Title: check.Title,
		Severity: check.Severity, Rationale: check.Rationale,
		Expected: check.Expected, Module: check.Module, Applicable: true,
	}
	if check.Module != "" {
		fragment, ok := input.Fragment(check.Module)
		if !ok {
			finding.Unknown = true
			finding.ReasonCode = ReasonFactMissing
			finding.Observed = "the host did not report the module " + check.Module
			return finding
		}
		finding.Revision = fragment.Revision
		finding.ObservedAt = fragment.ObservedAt
		// A module the host failed to read is not an empty module.
		if fragment.UnavailableReason != "" {
			finding.Unknown = true
			finding.ReasonCode = ReasonReadFailed
			finding.Observed = "not read: " + fragment.UnavailableReason
			return finding
		}
		// A read from a day ago describes the host of a day ago. An
		// assessment resting on it would speak about a state that may no
		// longer exist.
		if !fragment.ObservedAt.IsZero() && now.Sub(fragment.ObservedAt) > MaxReadAge {
			finding.Unknown = true
			finding.ReasonCode = ReasonStaleInventory
			finding.Observed = "last read: " + fragment.ObservedAt.Format(time.RFC3339)
			return finding
		}
	}

	result := check.Evaluate(input)
	finding.Observed = result.Observed
	finding.Evidence = result.Evidence
	finding.ReasonCode = result.ReasonCode

	switch {
	case result.NotApplicable:
		// A check that does not concern the host is neither a pass nor a
		// failure: it enters neither of those counts.
		finding.Applicable = false
		if finding.ReasonCode == "" {
			finding.ReasonCode = ReasonUnsupported
		}
	case result.Unknown:
		finding.Unknown = true
		if finding.ReasonCode == "" {
			finding.ReasonCode = ReasonFactMissing
		}
	case result.Passed:
		finding.Passed = true
	}

	// Only a finding that waits for action carries a remediation: a plan to
	// fix a correct state would be an invitation to change for no reason.
	if finding.NeedsAction() {
		finding.Remediation = result.Remediation
	}
	return finding
}

// PlanHash computes the digest of the findings that wait for action.
//
// The canonical form carries the canonicalisation version, the host and, for
// every step: the check, its version, the revision of the read the result
// came from, and the remediating operation with its payload. Changing
// anything from that list changes the digest - and the plan has to be
// reviewed anew.
func PlanHash(hostID string, findings []Finding) string {
	steps := make([]string, 0, len(findings))
	for _, finding := range findings {
		if !finding.NeedsAction() {
			continue
		}
		fields := []string{
			finding.CheckID,
			strconv.Itoa(finding.CheckVersion),
			finding.Module,
			finding.Revision,
			finding.Observed,
		}
		if finding.Remediation != nil {
			fields = append(fields, finding.Remediation.Action, string(finding.Remediation.Payload))
		} else {
			fields = append(fields, "", "")
		}
		steps = append(steps, strings.Join(fields, "\x1f"))
	}
	sort.Strings(steps)

	canonical := canonicalHeader + strconv.Itoa(CanonicalVersion) + "\n" + hostID + "\n" +
		strings.Join(steps, "\n")
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// summarise counts the findings by state and severity.
func summarise(findings []Finding) map[string]int {
	counts := map[string]int{"passed": 0, "failed": 0, "unknown": 0, "not_applicable": 0}
	for _, finding := range findings {
		switch {
		case !finding.Applicable:
			counts["not_applicable"]++
		case finding.Unknown:
			counts["unknown"]++
		case finding.Passed:
			counts["passed"]++
		default:
			counts["failed"]++
			counts[finding.Severity]++
		}
	}
	return counts
}

func severityOrder(finding Finding) int {
	if !finding.Applicable {
		return 8
	}
	if finding.Passed {
		return 9
	}
	switch finding.Severity {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 2
	}
	return 3
}
