package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/ultherego/flotestro/internal/authz"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	filesmodule "github.com/ultherego/flotestro/internal/modules/files"
)

var hexFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

// fileView joins the desired state with what the host really has.
//
// The drift between the two is the whole content of this tab: a file
// changed outside the panel looks the same as a matching file until the
// fingerprints are compared.
type fileView struct {
	managedfiles.DesiredState
	ObservedSHA256 string `json:"observed_sha256,omitempty"`
	Exists         bool   `json:"exists"`
	Drift          bool   `json:"drift"`
	// DriftUnknownReason says why the panel does not compare the content.
	// Silence here would look like a match.
	DriftUnknownReason string `json:"drift_unknown_reason,omitempty"`
	Mode               string `json:"observed_mode,omitempty"`
	Owner              string `json:"observed_owner,omitempty"`
	UnavailableReason  string `json:"unavailable_reason,omitempty"`
}

// handleListManagedFiles returns the files managed on a host.
func (s *Server) handleListManagedFiles(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermFilePlan, scope, "host", hostID); !ok {
		return
	}

	states, err := s.files.List(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}

	// The actual state comes from the inventory: it is the host that says
	// how the file looks now, not the panel that remembers what it once
	// sent.
	observed := map[string]filesmodule.File{}
	fragment, err := s.inventory.Fragment(r.Context(), hostID, "files")
	if err == nil && fragment != nil && len(fragment.Payload) > 0 {
		var snapshot filesmodule.Snapshot
		if err := json.Unmarshal(fragment.Payload, &snapshot); err == nil {
			for _, file := range snapshot.Files {
				observed[file.Path] = file
			}
		}
	}

	views := make([]fileView, 0, len(states))
	for _, state := range states {
		view := fileView{DesiredState: state}
		if file, known := observed[state.Path]; known {
			view.ObservedSHA256 = file.SHA256
			view.Exists = file.Exists
			view.Mode = file.Mode
			view.Owner = file.Owner
			view.UnavailableReason = file.UnavailableReason
			// Drift means only a confirmed divergence: a file the host did
			// not read is neither matching nor diverged.
			//
			// A file from a secret is not compared at all: the panel has no
			// fingerprint of it and cannot have one. Instead of a false
			// match it says directly that it does not check the content.
			view.Drift = state.SecretName == "" && file.Exists &&
				file.SHA256 != "" && file.SHA256 != state.SHA256
			if state.SecretName != "" && file.Exists {
				view.DriftUnknownReason = "the content comes from the secret store; the panel keeps no fingerprint of it"
			}
		}
		views = append(views, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "count": len(views)})
}

// handleFileHistory returns the consecutive versions of a file.
func (s *Server) handleFileHistory(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermFilePlan, scope, "host", hostID); !ok {
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		problem(w, http.StatusBadRequest, "path_required", "path query parameter is required")
		return
	}
	versions, err := s.files.History(r.Context(), hostID, path, 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": versions, "count": len(versions)})
}

// handleFileVersion returns the content of a file version.
//
// The content is a separate permission from the list: a configuration file
// is at times sensitive even when it is not a secret - it carries
// addresses, account names and topology.
func (s *Server) handleFileVersion(w http.ResponseWriter, r *http.Request) {
	fingerprint := r.PathValue("sha256")
	if !hexFingerprint.MatchString(fingerprint) {
		problem(w, http.StatusBadRequest, "invalid_sha256", "sha256 must be 64 hex characters")
		return
	}
	if _, ok := s.authorizeCollection(w, r, authz.PermFileRead, "file"); !ok {
		return
	}
	content, err := s.files.Content(r.Context(), fingerprint)
	if errors.Is(err, managedfiles.ErrNotFound) {
		problem(w, http.StatusNotFound, "version_not_found", "no such file version")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sha256": fingerprint, "content": string(content), "size_bytes": len(content),
	})
}
