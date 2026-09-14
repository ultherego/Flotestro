package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ultherego/flotestro/internal/compliance"
)

// A fleet remediation is the single-host plan carried over to a campaign.
//
// The operator picks checks and hosts; the panel computes every host's plan
// from its own findings, the campaign records the whole set, and one
// approval covers it. Nothing here runs anything: the runner drives the
// plans once the campaign starts them, exactly as it drives a plan ordered
// on one host.

// HostPlanKind names the shape of a per-host remediation plan as the
// campaign's plan set stores it.
const HostPlanKind = "security_remediation"

// campaignCreatorPrefix marks a plan a campaign created. The plan carries
// no campaign column; the creator is the record of who ordered it, and a
// campaign is a creator like any other.
const campaignCreatorPrefix = "campaign:"

// CampaignCreator returns the creator recorded on a plan a campaign starts.
func CampaignCreator(campaignID string) string {
	return campaignCreatorPrefix + campaignID
}

// Campaign returns the campaign that started the plan, or an empty string
// for a plan an operator ordered on one host.
func (p Plan) Campaign() string {
	if !strings.HasPrefix(p.CreatedBy, campaignCreatorPrefix) {
		return ""
	}
	return strings.TrimPrefix(p.CreatedBy, campaignCreatorPrefix)
}

// HostPlan is one host's remediation plan inside a campaign's plan set.
//
// The findings digest binds it to the state the host had when the plan was
// computed, the way a single-host order is bound; the steps are what the
// runner will carry out. The body is shaped like the plans the hosts
// compute, so the campaign screens read it the same way.
type HostPlan struct {
	Kind                string   `json:"kind"`
	FindingsHash        string   `json:"findings_hash"`
	FindingsHashVersion int      `json:"findings_hash_version"`
	Plan                PlanBody `json:"plan"`
}

// PlanBody is the content of a host plan: the steps, and the same steps
// as one line each for a summary.
type PlanBody struct {
	Changes []string `json:"changes"`
	Steps   []Step   `json:"steps"`
}

// Arrangement is the result of computing one host's plan for a set of
// checks.
type Arrangement struct {
	Plan HostPlan
	// Hash is the digest of the step set. Two hosts with the same digest
	// get the same change, whatever their findings looked like in detail.
	Hash string
	// Skipped lists the chosen checks that gave no step, with the reason.
	Skipped map[string]string
}

// Empty says whether the arrangement holds no step at all.
func (a Arrangement) Empty() bool { return len(a.Plan.Plan.Steps) == 0 }

// ErrUnknownCheck means a check identifier the report does not know.
type ErrUnknownCheck struct{ CheckID string }

func (e ErrUnknownCheck) Error() string {
	return "the check " + e.CheckID + " does not exist"
}

// Reasons a chosen check gives no step on a host.
const (
	SkipPassed   = "the check passed on this host"
	SkipUnknown  = "the state of this check is unknown on this host; an unknown finding is not eligible for a fix"
	SkipNotApply = "the check does not apply to this host"
)

// ArrangeForChecks computes one host's plan for the chosen checks.
//
// It is the single-host order made repeatable: the same findings and the
// same choice give the same steps in the same order, so the digest can
// group hosts and bind the consent. A check the host passed, does not
// answer or is not concerned by gives no step and says why; a check the
// report does not know is an error, because a typo must not turn into a
// silent no-op on the whole fleet.
func ArrangeForChecks(report compliance.Report, checkIDs []string) (Arrangement, error) {
	byID := map[string]compliance.Finding{}
	for _, finding := range report.Findings {
		byID[finding.CheckID] = finding
	}
	result := Arrangement{Skipped: map[string]string{}}
	chosen := make([]compliance.Finding, 0, len(checkIDs))
	for _, id := range checkIDs {
		finding, ok := byID[id]
		if !ok {
			return Arrangement{}, ErrUnknownCheck{CheckID: id}
		}
		switch {
		case !finding.Applicable:
			result.Skipped[id] = SkipNotApply
		case finding.Unknown:
			result.Skipped[id] = SkipUnknown
		case finding.Passed:
			result.Skipped[id] = SkipPassed
		default:
			chosen = append(chosen, finding)
		}
	}
	if len(chosen) == 0 {
		return result, nil
	}
	arranged, err := Arrange(chosen)
	for id, reason := range arranged.Skipped {
		result.Skipped[id] = reason
	}
	if err != nil {
		if len(arranged.Steps) == 0 && len(arranged.Skipped) == len(chosen) {
			// Every chosen finding lacks an operation: not a plan, but not
			// a broken order either - the reasons are in Skipped.
			return result, nil
		}
		return Arrangement{}, err
	}
	result.Plan = HostPlan{
		Kind:                HostPlanKind,
		FindingsHash:        report.PlanHash,
		FindingsHashVersion: report.PlanHashVersion,
		Plan: PlanBody{
			Changes: describeSteps(arranged.Steps),
			Steps:   arranged.Steps,
		},
	}
	result.Hash = StepSetHash(arranged.Steps)
	return result, nil
}

// StepSetHash computes the digest of a plan's steps.
//
// It covers what the host will do - the order, the check and its version,
// the operation and its payload, the reboot boundary - and nothing about
// which host does it. Hosts with the same digest are one group in the plan
// set, and a changed step on any host changes the set's digest and with it
// the consent.
func StepSetHash(steps []Step) string {
	lines := make([]string, 0, len(steps))
	for _, step := range steps {
		lines = append(lines, strings.Join([]string{
			strconv.Itoa(step.Position), step.CheckID, strconv.Itoa(step.CheckVersion),
			step.ActionType, canonicalJSON(step.Payload), strconv.FormatBool(step.RequiresReboot),
		}, "\x1f"))
	}
	sum := sha256.Sum256([]byte("flotestro-remediation-steps/1\n" + strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// canonicalJSON re-encodes a payload so that the key order does not
// change the digest.
func canonicalJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return string(raw)
	}
	return string(encoded)
}

// describeSteps gives one line per step for the plan summaries.
func describeSteps(steps []Step) []string {
	lines := make([]string, 0, len(steps))
	for _, step := range steps {
		line := step.CheckID + " → " + step.ActionType
		if step.RequiresReboot {
			line += " (reboot)"
		}
		lines = append(lines, line)
	}
	return lines
}

// DecodeHostPlan reads a host plan back from the campaign's plan set.
func DecodeHostPlan(raw json.RawMessage) (HostPlan, error) {
	var plan HostPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return HostPlan{}, fmt.Errorf("the host plan does not decode: %w", err)
	}
	if plan.Kind != HostPlanKind {
		return HostPlan{}, fmt.Errorf("the host plan has the kind %q, not a remediation plan", plan.Kind)
	}
	if len(plan.Plan.Steps) == 0 {
		return HostPlan{}, fmt.Errorf("the host plan has no steps")
	}
	return plan, nil
}

// FreshSteps returns the plan's steps ready to be recorded anew: pending,
// without identifiers or tasks from any earlier run.
func (p HostPlan) FreshSteps() []Step {
	steps := make([]Step, 0, len(p.Plan.Steps))
	for i, step := range p.Plan.Steps {
		steps = append(steps, Step{
			Position: i + 1, CheckID: step.CheckID, CheckVersion: step.CheckVersion,
			ActionType: step.ActionType, Payload: step.Payload, LockClass: step.LockClass,
			RequiresReboot: step.RequiresReboot, State: StepPending,
		})
	}
	return steps
}

// Actions lists the distinct operations of the steps, in step order.
func (p HostPlan) Actions() []string {
	seen := map[string]bool{}
	actions := make([]string, 0, len(p.Plan.Steps))
	for _, step := range p.Plan.Steps {
		if seen[step.ActionType] {
			continue
		}
		seen[step.ActionType] = true
		actions = append(actions, step.ActionType)
	}
	return actions
}

// Group is a set of hosts that get the same steps.
type Group struct {
	PlanHash string   `json:"plan_hash"`
	Steps    []Step   `json:"steps"`
	Changes  []string `json:"changes"`
	Count    int      `json:"count"`
	Hosts    []Host   `json:"hosts"`
}

// Host names one host of a group.
type Host struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
}

// GroupPlans gathers hosts by the digest of their steps. The groups come
// back largest first, then by digest, so the order is not a decision.
func GroupPlans(plans map[Host]Arrangement) []Group {
	by := map[string]*Group{}
	for host, arrangement := range plans {
		if arrangement.Empty() {
			continue
		}
		group, ok := by[arrangement.Hash]
		if !ok {
			group = &Group{
				PlanHash: arrangement.Hash,
				Steps:    arrangement.Plan.Plan.Steps,
				Changes:  arrangement.Plan.Plan.Changes,
			}
			by[arrangement.Hash] = group
		}
		group.Count++
		group.Hosts = append(group.Hosts, host)
	}
	groups := make([]Group, 0, len(by))
	for _, group := range by {
		sort.Slice(group.Hosts, func(i, j int) bool {
			if group.Hosts[i].Hostname != group.Hosts[j].Hostname {
				return group.Hosts[i].Hostname < group.Hosts[j].Hostname
			}
			return group.Hosts[i].HostID < group.Hosts[j].HostID
		})
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].PlanHash < groups[j].PlanHash
	})
	return groups
}
