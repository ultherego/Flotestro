package files

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Plan describes the difference between the file found and the desired state.
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

	// Whether each part of the inode changes, separately from the sentences
	// below.
	ContentChanges bool `json:"content_changes,omitempty"`
	ModeChanges    bool `json:"mode_changes,omitempty"`
	OwnerChanges   bool `json:"owner_changes,omitempty"`
	GroupChanges   bool `json:"group_changes,omitempty"`

	// Changes lists in human terms what will change. A content fingerprint tells
	// the operator nothing; "content" and "permissions from 0644 to 0600" do.
	Changes []string `json:"changes,omitempty"`

	// SymlinkPolicy names the rule that applied to this path.
	SymlinkPolicy string `json:"symlink_policy"`

	// Validator says what would check the content, and in which version.
	Validator ValidatorIdentity `json:"validator"`

	// ValidatorOutput is the result of checking the desired content. A plan
	// that failed validation is an answer - not a read error.
	ValidatorOutput string `json:"validator_output,omitempty"`
	ValidatorFailed bool   `json:"validator_failed,omitempty"`

	// Consumers are the services that read this file and would need a reload or a
	// restart afterwards; ConsumersReason says why there are none, because an
	// empty list is not "nothing to do".
	Consumers       []Consumer `json:"consumers,omitempty"`
	ConsumersReason string     `json:"consumers_reason,omitempty"`

	// KeptVersions is how many copies of this file the host has to go back
	// to. Zero is an answer too: a rollback of this file would refuse.
	KeptVersions int `json:"kept_versions"`

	// PlanHash binds the plan to this specific difference.
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

// Desired describes the state the order asks for.
type Desired struct {
	Content []byte
	Mode    string
	Owner   string
	Group   string
	// FromSecret marks content that comes from the secret store and
	// therefore never appears in the plan.
	FromSecret bool
	// Removal marks a plan for taking the file away.
	Removal bool
	// Validator is the check that applies to this path on this host, already
	// identified by the caller: only the host can say whether the tool is
	// installed and which version it is.
	Validator ValidatorIdentity
	// KeptVersions is how many copies of the file the host kept.
	KeptVersions int
}

// Symlink policies. There is one rule and one exception, and the plan names
// which of the two applied rather than leaving the operator to assume.
const (
	// SymlinkPolicyNoFollow: the path is opened refusing to pass through
	// any symbolic link, so a link planted in the directory leads nowhere.
	SymlinkPolicyNoFollow = "no_follow"
	// SymlinkPolicyRefused: the path itself is a symbolic link, so nothing
	// is written through it.
	SymlinkPolicyRefused = "refused_symlink"
)

// Compute computes the difference between the file found and the desired
// state.
func Compute(current File, desired Desired) Plan {
	plan := Plan{
		Path: current.Path, Exists: current.Exists, Mode: current.Mode,
		Owner: current.Owner, Group: current.Group, Size: current.SizeBytes,
		UnavailableReason: current.UnavailableReason, SHA256: current.SHA256,
		DesiredMode: desired.Mode, DesiredOwner: desired.Owner, DesiredGroup: desired.Group,
		Validator: desired.Validator, KeptVersions: desired.KeptVersions,
		SymlinkPolicy: SymlinkPolicyNoFollow,
	}
	if current.Exists && strings.Contains(current.UnavailableReason, "symbolic link") {
		plan.SymlinkPolicy = SymlinkPolicyRefused
	}
	plan.Consumers, plan.ConsumersReason = Consumers(current.Path)

	if desired.Removal {
		plan.Action = PlanRemove
		if !current.Exists {
			// Removing a file that does not exist is not an error and not a change.
			plan.Action = PlanRemoveAbsent
		}
		plan.DesiredMode, plan.DesiredOwner, plan.DesiredGroup = "", "", ""
		plan.ContentChanges = plan.Action == PlanRemove
		plan.PlanHash = planFingerprint(plan)
		return plan
	}

	if !desired.FromSecret {
		sum := sha256.Sum256(desired.Content)
		plan.DesiredSHA256 = hex.EncodeToString(sum[:])
	}

	switch {
	case !current.Exists:
		plan.Action = PlanCreate
		plan.Changes = []string{"the file will be created"}
		plan.ContentChanges = true
		plan.ModeChanges = plan.DesiredMode != ""
		plan.OwnerChanges = plan.DesiredOwner != ""
		plan.GroupChanges = plan.DesiredGroup != ""
	default:
		plan.markDifferences(desired.FromSecret)
		plan.Changes = differences(plan, desired.FromSecret)
		plan.Action = PlanUpdate
		if len(plan.Changes) == 0 {
			plan.Action = PlanNoChange
		}
	}
	plan.PlanHash = planFingerprint(plan)
	return plan
}

// markDifferences fills in which parts of the inode a write over an existing
// file touches.
func (p *Plan) markDifferences(fromSecret bool) {
	p.ContentChanges = !fromSecret && p.SHA256 != p.DesiredSHA256
	p.ModeChanges = p.DesiredMode != "" && p.Mode != "" && p.DesiredMode != p.Mode
	p.OwnerChanges = p.DesiredOwner != "" && p.Owner != "" && p.DesiredOwner != p.Owner
	p.GroupChanges = p.DesiredGroup != "" && p.Group != "" && p.DesiredGroup != p.Group
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
	if plan.ModeChanges {
		changes = append(changes, fmt.Sprintf("permissions from %s to %s", plan.Mode, plan.DesiredMode))
	}
	if plan.OwnerChanges {
		changes = append(changes, fmt.Sprintf("owner from %s to %s", plan.Owner, plan.DesiredOwner))
	}
	if plan.GroupChanges {
		changes = append(changes, fmt.Sprintf("group from %s to %s", plan.Group, plan.DesiredGroup))
	}
	sort.Strings(changes)
	return changes
}

// planFingerprint computes the fingerprint of the whole plan excluding the
// fingerprint itself.
func planFingerprint(plan Plan) string {
	stripped := plan
	stripped.PlanHash = ""
	// The validator output can be long and does not describe the difference
	// itself, so it does not enter the fingerprint: the same diff must give the
	// same fingerprint.
	stripped.ValidatorOutput = ""
	// The same goes for what surrounds the change rather than being it: the
	// version of the tool that checks the content, the services installed on the
	// host and the number of copies kept.
	stripped.Validator.Version = ""
	stripped.Validator.VersionUnavailableReason = ""
	stripped.Consumers = nil
	stripped.ConsumersReason = ""
	stripped.KeptVersions = 0
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
