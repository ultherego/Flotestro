package adminapi

import "net/http"

// serverCapabilities describes which integrations are enabled in this
// installation.
//
// Flotestro is a fleet management panel; the integration with the identity
// directory and with an external login provider are optional. The panel
// works fully without them, and the interface must not show sections that
// have no backing in this installation.
type serverCapabilities struct {
	// IdentityProvider says whether operators log in through OIDC. Without
	// it API token authentication works.
	IdentityProvider bool   `json:"identity_provider"`
	Issuer           string `json:"issuer,omitempty"`
	// Directory says whether a directory connector is configured.
	Directory bool `json:"directory"`
	// DirectoryWrite says whether the panel may change the directory
	// content. Directory changes are a separate module: a customer may want
	// only the view, and make the changes with their own tools.
	DirectoryWrite bool `json:"directory_write"`
	// LocalUsers says whether the panel manages local accounts on hosts.
	LocalUsers bool `json:"local_users"`
	// CampaignV2 says whether this installation runs campaigns with a
	// planning phase: a plan per host, approval of the plan set, budgets
	// and target qualification. The interface must not show the mass wizard
	// where the backend does not support it - the order would end in an
	// error after filling in the form.
	//
	// Deviation from the document: the API compatibility chapter says to
	// mark the old /api/v1/campaigns as legacy and return a deprecation
	// link. This installation has no old engine - the one with the planning
	// phase has stood at this address from the start, so there is nothing
	// to mark as deprecated.
	CampaignV2 bool `json:"campaign_v2"`
}

// handleCapabilities returns the enabled integrations. The endpoint needs
// no permission: it describes the installation, not its data.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	capabilities := serverCapabilities{
		IdentityProvider: s.oidc != nil,
		Directory:        s.directory != nil,
		DirectoryWrite:   s.directory != nil && s.directoryWrite,
		LocalUsers:       true,
		// Campaigns are optional: a panel without their store still runs
		// operations on single hosts.
		CampaignV2: s.campaigns != nil,
	}
	if s.oidc != nil {
		capabilities.Issuer = s.oidc.Issuer()
	}
	writeJSON(w, http.StatusOK, capabilities)
}
