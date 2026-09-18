package files

import "time"

// Change describes what a write really did to a file.
//
// The plan says what was going to happen; this says what happened, in the
// same terms, so the two can be laid side by side. An operator who
// approved a whole intended state - the bytes, the inode, the check that
// ran and what has to be reloaded - is owed an answer in the same shape,
// not a fingerprint and the word "written".
type Change struct {
	Path string `json:"path"`
	// Action is create, update or rollback.
	Action string `json:"action"`

	// The inode before and after. A write that changed only the owner
	// leaves both digests equal, and that is worth seeing.
	BeforeSHA256 string `json:"before_sha256,omitempty"`
	AfterSHA256  string `json:"after_sha256,omitempty"`
	BeforeMode   string `json:"before_mode,omitempty"`
	AfterMode    string `json:"after_mode,omitempty"`
	BeforeOwner  string `json:"before_owner,omitempty"`
	AfterOwner   string `json:"after_owner,omitempty"`
	BeforeGroup  string `json:"before_group,omitempty"`
	AfterGroup   string `json:"after_group,omitempty"`
	// Existed says whether there was a file there at all before the write.
	Existed bool `json:"existed"`
	// FromSecret marks content that came from the secret store; neither
	// digest is reported for such a file.
	FromSecret bool `json:"from_secret,omitempty"`

	// SymlinkPolicy names the rule the write was carried out under.
	SymlinkPolicy string `json:"symlink_policy"`

	// Validator is the identity of the check that ran - or did not.
	Validator       ValidatorIdentity `json:"validator"`
	ValidatorOutput string            `json:"validator_output,omitempty"`
	// Unvalidated marks content written without the check the order names,
	// because the order allowed it and the host lacks the tool.
	Unvalidated bool `json:"unvalidated,omitempty"`

	// Consumers are the services that now run on the content from before
	// the change until they are told otherwise.
	Consumers       []Consumer `json:"consumers,omitempty"`
	ConsumersReason string     `json:"consumers_reason,omitempty"`

	// KeptVersion is the copy of the previous content the host put aside
	// before the rename. Nil means there was nothing to keep, which is the
	// case of a file created now.
	KeptVersion *KeptVersion `json:"kept_version,omitempty"`
	// RestoredFrom is the version a rollback put back.
	RestoredFrom *KeptVersion `json:"restored_from,omitempty"`

	AppliedAt time.Time `json:"applied_at"`
}

// Change actions.
const (
	ChangeCreate   = "create"
	ChangeUpdate   = "update"
	ChangeRollback = "rollback"
)
