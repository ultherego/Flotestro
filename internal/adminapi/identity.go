package adminapi

import (
	"net/http"

	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/freeipa"
	"github.com/ultherego/flotestro/internal/hosts"
)

// fleetIdentityStatus is the fleet half of the identity status: the hosts
// whose SSSD last reported itself cut off from the directory, each with the
// panel's verdict on their logins, and the verdicts counted.
type fleetIdentityStatus struct {
	OfflineFromDirectory []hosts.OfflineHost `json:"offline_from_directory"`
	OfflineCount         int                 `json:"offline_count"`
	ByVerdict            map[string]int      `json:"by_verdict"`
}

// handleIdentityStatus describes the state of the directory connection and of
// the hosts cut off from it.
func (s *Server) handleIdentityStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermIdentityRead, authz.GlobalScope, "identity", ""); !ok {
		return
	}

	offline, err := s.hosts.OfflineFromDirectory(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	fleet := fleetIdentityStatus{
		OfflineFromDirectory: offline,
		OfflineCount:         len(offline),
		ByVerdict: map[string]int{
			hosts.VerdictCachedLoginsUntil:        0,
			hosts.VerdictCachedLoginsIndefinitely: 0,
			hosts.VerdictNoCachedLogins:           0,
			hosts.VerdictUnknown:                  0,
		},
	}
	for _, host := range offline {
		fleet.ByVerdict[host.Verdict.Verdict]++
	}

	if s.directory == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false,
			"detail":     "no directory connector is configured",
			"hosts":      fleet,
		})
		return
	}

	summary, err := s.directory.Ping(r.Context())
	// The connector's own account of itself - its keytab, its last answer and its
	// last failure, the age of its cache - is read after the ping, so that the
	// ping just made is the call it reports.
	connector := s.directory.Health()
	if err != nil {
		// An unavailable directory is not a panel error: the state is
		// reported instead of pretending there is no data.
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": true,
			"reachable":  false,
			"principal":  s.directory.Principal(),
			"error":      err.Error(),
			"hosts":      fleet,
			"connector":  connector,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true,
		"reachable":  true,
		"principal":  s.directory.Principal(),
		"summary":    summary,
		"hosts":      fleet,
		"connector":  connector,
	})
}

// directoryUsers reads the live accounts, or with preserved=true the ones
// removed with their entry kept.
func directoryUsers(s *Server, r *http.Request) ([]freeipa.User, error) {
	if r.URL.Query().Get("preserved") == "true" {
		return s.directory.PreservedUsers(r.Context())
	}
	return s.directory.Users(r.Context())
}

// directoryServices reads the Kerberos service principals of the hosts.
func directoryServices(s *Server, r *http.Request) ([]freeipa.Service, error) {
	return s.directory.Services(r.Context())
}

// directoryHandler builds a read handler for one directory resource. Each of
// them requires the identity.
func directoryHandler[T any](s *Server, name string,
	load func(*Server, *http.Request) ([]T, error)) http.HandlerFunc {
	return directoryHandlerFor(s, name, authz.PermIdentityRead, load)
}

// policyHandler serves the resources describing access and privilege
// elevation.
func policyHandler[T any](s *Server, name string,
	load func(*Server, *http.Request) ([]T, error)) http.HandlerFunc {
	return directoryHandlerFor(s, name, authz.PermIdentityPolicyRead, load)
}

func directoryHandlerFor[T any](s *Server, name string, permission authz.Permission,
	load func(*Server, *http.Request) ([]T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.authorize(w, r, permission, authz.GlobalScope, "identity", name); !ok {
			return
		}
		if s.directory == nil {
			problem(w, http.StatusNotImplemented, "directory_disabled",
				"no directory connector is configured")
			return
		}
		items, err := load(s, r)
		if err != nil {
			// A directory failure is a state, not an internal panel error.
			problem(w, http.StatusBadGateway, "directory_unavailable", err.Error())
			return
		}
		if items == nil {
			items = []T{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
	}
}
