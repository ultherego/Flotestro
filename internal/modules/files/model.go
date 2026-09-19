// Package files manages the configuration files of a host. This is not a root
// file manager.
package files

import "time"

// Size above which the panel does not fetch the file content.
const MaxSize = 1 << 20

// File describes one configuration file.
type File struct {
	Path string `json:"path"`
	// SHA256 is the content fingerprint. Empty means a file that could not
	// be read - and then UnavailableReason carries the reason.
	SHA256     string     `json:"sha256,omitempty"`
	SizeBytes  int64      `json:"size_bytes"`
	Mode       string     `json:"mode,omitempty"`
	Owner      string     `json:"owner,omitempty"`
	Group      string     `json:"group,omitempty"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`
	// Managed marks a file the panel knows and has a desired state for.
	Managed bool `json:"managed"`
	// FromSecret marks a file whose content comes from the secret store.
	// For such a file the host does not report the content fingerprint.
	FromSecret bool `json:"from_secret,omitempty"`
	// DesiredSHA256 is the fingerprint of the desired state. Different from
	// SHA256 means drift: somebody changed the file outside the panel.
	DesiredSHA256 string `json:"desired_sha256,omitempty"`
	// Exists distinguishes a deleted file from an unread one.
	Exists            bool   `json:"exists"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	// Versions are the copies the host kept before the writes that displaced
	// them, newest first.
	Versions []KeptVersion `json:"versions,omitempty"`
}

// Content is a file together with its contents.
type Content struct {
	File
	Content string `json:"content"`
	// Truncated says the content is cut off. Cut-off content without the mark
	// would look like the whole file - and would go back to the host as such.
	Truncated bool `json:"truncated"`
}

// Snapshot is the picture of the managed files on the host.
type Snapshot struct {
	Files      []File    `json:"files,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	// UnavailableReason says why the state was not determined.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Write describes an ordered file change.
type Write struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Group   string `json:"group,omitempty"`
	// ExpectedSHA256 binds the write to the content the operator viewed.
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	// Validator names the content check before the write.
	Validator string `json:"validator,omitempty"`
}
