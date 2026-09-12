// Package remediation drives a remediation plan through its steps.
//
// A remediation is not one operation. The steps go in order, each is an
// ordinary task of the module responsible for the thing, and each can fail.
// The plan exists so that it is known what has already gone out, what waits
// and why the rest did not start - without it a handful of unrelated tasks is
// all that is left.
package remediation

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/compliance"
	"github.com/ultherego/flotestro/internal/opspec"
)

// The states of a plan.
const (
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
	StateStopped   = "stopped"
)

// The states of a step.
const (
	StepPending   = "pending"
	StepRunning   = "running"
	StepSucceeded = "succeeded"
	StepFailed    = "failed"
	StepSkipped   = "skipped"
)

// ReturnWindow bounds the wait for a host after a step that requires a
// reboot.
//
// A reboot ends the plan, but the plan ends only once the host comes back: a
// command that was sent is not yet a running host.
const ReturnWindow = 15 * time.Minute

// Step is one stage of a plan.
type Step struct {
	ID           string          `json:"id"`
	Position     int             `json:"position"`
	CheckID      string          `json:"check_id"`
	CheckVersion int             `json:"check_version"`
	ActionType   string          `json:"action_type"`
	Payload      json.RawMessage `json:"payload"`
	// LockClass names the host resource the step uses exclusively.
	LockClass      string     `json:"lock_class,omitempty"`
	RequiresReboot bool       `json:"requires_reboot"`
	JobID          string     `json:"job_id,omitempty"`
	State          string     `json:"state"`
	Reason         string     `json:"reason,omitempty"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

// Plan is the complete set of steps approved by the operator.
type Plan struct {
	ID              string     `json:"id"`
	HostID          string     `json:"host_id"`
	PlanHash        string     `json:"plan_hash"`
	PlanHashVersion int        `json:"plan_hash_version"`
	Reason          string     `json:"reason"`
	CreatedBy       string     `json:"created_by"`
	StopOnFailure   bool       `json:"stop_on_failure"`
	State           string     `json:"state"`
	CreatedAt       time.Time  `json:"created_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	Steps           []Step     `json:"steps,omitempty"`
	// BootIDBefore makes it possible to tell whether the host really came up anew.
	BootIDBefore string `json:"boot_id_before,omitempty"`
}

// Arranged is a plan of steps ready to be recorded.
type Arranged struct {
	Steps []Step
	// Skipped lists the findings that did not enter the plan, with the reason.
	Skipped map[string]string
}

// Arrange fixes the order of the steps and guards the reboot boundary.
//
// The order is not arbitrary. First the configuration changes, then what
// requires a reboot - and the reboot comes last, because after it the host's
// state has to be assessed anew, and steps planned earlier would refer to
// facts from before the reboot. A plan with two reboots does not come into
// being: those are two plans.
func Arrange(findings []compliance.Finding) (Arranged, error) {
	result := Arranged{Skipped: map[string]string{}}
	var ordinary, reboots []Step

	for _, finding := range findings {
		if !finding.NeedsAction() {
			result.Skipped[finding.CheckID] = "the finding needs no action"
			continue
		}
		if finding.Remediation == nil || finding.Remediation.Action == "" {
			reason := "this finding has no remediating operation"
			if finding.Remediation != nil && finding.Remediation.Note != "" {
				reason = finding.Remediation.Note
			}
			result.Skipped[finding.CheckID] = reason
			continue
		}
		action := opspec.ActionType(finding.Remediation.Action)
		if !action.Known() {
			return Arranged{}, fmt.Errorf("the finding %s names the unknown operation %s",
				finding.CheckID, action)
		}
		step := Step{
			CheckID:        finding.CheckID,
			CheckVersion:   finding.CheckVersion,
			ActionType:     string(action),
			Payload:        finding.Remediation.Payload,
			LockClass:      action.LockClass(),
			RequiresReboot: finding.Remediation.RequiresReboot,
			State:          StepPending,
		}
		if step.RequiresReboot {
			reboots = append(reboots, step)
			continue
		}
		ordinary = append(ordinary, step)
	}

	if len(reboots) > 1 {
		return Arranged{}, fmt.Errorf("the plan would have %d reboots; a reboot ends a plan, so those are separate plans",
			len(reboots))
	}
	// The order within the ordinary steps is fixed so that two identical
	// plans look the same: first the lock class, then the name of the check.
	sort.SliceStable(ordinary, func(i, j int) bool {
		if ordinary[i].LockClass != ordinary[j].LockClass {
			return ordinary[i].LockClass < ordinary[j].LockClass
		}
		return ordinary[i].CheckID < ordinary[j].CheckID
	})

	steps := append(ordinary, reboots...)
	for i := range steps {
		steps[i].Position = i + 1
	}
	result.Steps = steps
	if len(steps) == 0 {
		return result, fmt.Errorf("none of the named findings has a remediating operation")
	}
	return result, nil
}

// Current returns the first step that is not settled.
func (p Plan) Current() *Step {
	for i := range p.Steps {
		switch p.Steps[i].State {
		case StepPending, StepRunning:
			return &p.Steps[i]
		}
	}
	return nil
}

// Progress summarises the execution of a plan.
func (p Plan) Progress() map[string]int {
	counts := map[string]int{}
	for _, step := range p.Steps {
		counts[step.State]++
	}
	return counts
}
