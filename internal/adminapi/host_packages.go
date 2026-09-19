package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/vuln"
)

// hostPackageList is the installed packages of one host as the panel holds
// them, with the state of the copy: when it was read, from which job, and why
// it is missing when it is.
type hostPackageList struct {
	Items []packages.InstalledPackage `json:"items"`
	Count int                         `json:"count"`
	State vuln.PackageListState       `json:"state"`
}

// handleHostPackages returns the installed packages of a host.
func (s *Server) handleHostPackages(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermPackagesRead, scope, "host", hostID); !ok {
		return
	}
	if s.hostPackages == nil {
		problem(w, http.StatusNotImplemented, "package_store_disabled",
			"the package store is disabled in this installation")
		return
	}
	state, err := s.hostPackages.State(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	items, err := s.hostPackages.Packages(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		// A host nobody has asked yet has no rows; the state says so, and
		// the list is an empty list rather than a null.
		items = []packages.InstalledPackage{}
	}
	writeJSON(w, http.StatusOK, hostPackageList{Items: items, Count: len(items), State: state})
}
