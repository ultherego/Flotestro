package files

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Plan describes the difference between the file found and the desired
// state.
//
// Two hosts with the same desired state almost never have the same diff:
// one has a file with different content, another has none at all, a third
// has it with different permissions. The operator's approval is meant to
// cover those differences, not the intent alone - and that is why the plan
// is made separately on every host.
type Plan struct {
	Path string `json:"path"`
	// Action names what would happen: create, update, no_change, remove or
	// remove_absent. Without it the list of plans is a list of paths.
	Action string `json:"action"`

	// The state found. Empty fields with Exists = false are not zero: the
	// file is absent and there is nothing to talk about.
	Exists            bool   `json:"exists"`
	SHA256            string `json:"sha256,omitempty"`
	Mode              string `json:"mode,omitempty"`
	Owner             string `json:"owner,omitempty"`
	Group             string `json:"group,omitempty"`
	Size              int64  `json:"size_bytes,omitempty"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`

	// The desired state.
	DesiredSHA256 string `json:"desired_sha256,omitempty"`
	DesiredMode   string `json:"desired_mode,omitempty"`
	DesiredOwner  string `json:"desired_owner,omitempty"`
	DesiredGroup  string `json:"desired_group,omitempty"`

	// Changes lists in human terms what will change. A content fingerprint
	// tells the operator nothing; "content" and "permissions from 0644 to
	// 0600" do.
	Changes []string `json:"changes,omitempty"`

	// ValidatorOutput is the result of checking the desired content. A plan
	// that failed validation is an answer - not a read error.
	ValidatorOutput string `json:"validator_output,omitempty"`
	ValidatorFailed bool   `json:"validator_failed,omitempty"`

	// PlanHash binds the plan to this specific difference. It enters the
	// approval fingerprint, and at write time the host checks once more
	// whether the file still looks as it did at plan time.
	PlanHash string `json:"plan_hash"`
}

// Plan action names.
const (
	PlanCreate       = "create"
	PlanUpdate       = "update"
	PlanNoChange     = "no_change"
	PlanRemove       = "remove"
	PlanRemoveAbsent = "remove_absent"
)

// Compute computes the difference between the file found and the desired
// state.
//
// The desired content is explicit here, because the panel sent it. A file
// from a secret is the exception: its content is not in the plan and not in
// the fingerprint - otherwise the plan itself would be the place of the
// leak.
func Compute(current File, desiredContent []byte, mode, owner, group string,
	fromSecret, removal bool) Plan {
	plan := Plan{
		Path: current.Path, Exists: current.Exists, Mode: current.Mode,
		Owner: current.Owner, Group: current.Group, Size: current.SizeBytes,
		UnavailableReason: current.UnavailableReason, SHA256: current.SHA256,
		DesiredMode: mode, DesiredOwner: owner, DesiredGroup: group,
	}

	if removal {
		plan.Action = PlanRemove
		if !current.Exists {
			// Removing a file that does not exist is not an error and not a
			// change. The operator is meant to see it before approving, not
			// to learn it from the report.
			plan.Action = PlanRemoveAbsent
		}
		plan.DesiredMode, plan.DesiredOwner, plan.DesiredGroup = "", "", ""
		plan.PlanHash = planFingerprint(plan)
		return plan
	}

	if !fromSecret {
		sum := sha256.Sum256(desiredContent)
		plan.DesiredSHA256 = hex.EncodeToString(sum[:])
	}

	switch {
	case !current.Exists:
		plan.Action = PlanCreate
		plan.Changes = []string{"the file will be created"}
	default:
		plan.Changes = differences(plan, fromSecret)
		plan.Action = PlanUpdate
		if len(plan.Changes) == 0 {
			plan.Action = PlanNoChange
		}
	}
	plan.PlanHash = planFingerprint(plan)
	return plan
}

// differences lists the changes visible to a human.
func differences(plan Plan, fromSecret bool) []string {
	var changes []string
	switch {
	case fromSecret:
		// Content from the store is not compared: it is not in the plan, so
		// nobody can claim it will change or that it will not.
		changes = append(changes, "the content comes from the secret store and is not compared")
	case plan.SHA256 == "":
		// The fingerprint of the current content could not be computed. That
		// does not mean "no change".
		changes = append(changes, "the current content could not be read")
	case plan.SHA256 != plan.DesiredSHA256:
		changes = append(changes, "content")
	}
	if plan.DesiredMode != "" && plan.Mode != "" && plan.DesiredMode != plan.Mode {
		changes = append(changes, fmt.Sprintf("permissions from %s to %s", plan.Mode, plan.DesiredMode))
	}
	if plan.DesiredOwner != "" && plan.Owner != "" && plan.DesiredOwner != plan.Owner {
		changes = append(changes, fmt.Sprintf("owner from %s to %s", plan.Owner, plan.DesiredOwner))
	}
	if plan.DesiredGroup != "" && plan.Group != "" && plan.DesiredGroup != plan.Group {
		changes = append(changes, fmt.Sprintf("group from %s to %s", plan.Group, plan.DesiredGroup))
	}
	sort.Strings(changes)
	return changes
}

// planFingerprint computes the fingerprint of the whole plan excluding the
// fingerprint itself.
//
// It covers the found and the desired state together: a plan computed on a
// host that changed in the meantime must yield a different fingerprint -
// because it is a different change by then.
func planFingerprint(plan Plan) string {
	stripped := plan
	stripped.PlanHash = ""
	// The validator output can be long and does not describe the difference
	// itself, so it does not enter the fingerprint: the same diff must give
	// the same fingerprint.
	stripped.ValidatorOutput = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
