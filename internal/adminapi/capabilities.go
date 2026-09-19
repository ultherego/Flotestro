package adminapi

import "net/http"

// serverCapabilities describes which integrations are enabled in this
// installation.
type serverCapabilities struct {
	// IdentityProvider says whether operators log in through OIDC. Without
	// it API token authentication works.
	IdentityProvider bool   `json:"identity_provider"`
	Issuer           string `json:"issuer,omitempty"`
	// Directory says whether a directory connector is configured.
	Directory bool `json:"directory"`
	// DirectoryWrite says whether the panel may change the directory content.
	DirectoryWrite bool `json:"directory_write"`
	// LocalUsers says whether the panel manages local accounts on hosts.
	LocalUsers bool `json:"local_users"`
	// CampaignV2 says whether this installation runs campaigns with a planning
	// phase: a plan per host, approval of the plan set, budgets and target
	// qualification.
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
