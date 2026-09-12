package agent

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

// IdentityState describes the integration of the host with the domain. It is
// collected in the inventory cycle, never in the heartbeat: querying the
// directory several times a minute from every host of the fleet would be
// exactly the load the document guards against.
type IdentityState struct {
	Enrolled bool     `json:"enrolled"`
	Domain   string   `json:"domain,omitempty"`
	Realm    string   `json:"realm,omitempty"`
	Servers  []string `json:"servers,omitempty"`

	SSSDInstalled bool  `json:"sssd_installed"`
	SSSDRunning   bool  `json:"sssd_running"`
	SSSDOnline    *bool `json:"sssd_online,omitempty"`

	CacheAgeSeconds *uint64 `json:"cache_age_seconds,omitempty"`

	HostPrincipal    string   `json:"host_principal,omitempty"`
	KeytabKVNO       *uint32  `json:"keytab_kvno,omitempty"`
	ClockSkewSeconds *float64 `json:"clock_skew_seconds,omitempty"`
	TimeSynchronized bool     `json:"time_synchronized"`

	ConfigIssues      []string `json:"config_issues,omitempty"`
	UnavailableReason string   `json:"unavailable_reason,omitempty"`
}

const ipaConfigPath = "/etc/ipa/default.conf"

// ReadIdentityState collects the domain state locally. No query goes to the
// directory server: what matters is the state of the host and not the content
// of the directory.
//
// The host keytab and the SSSD cache database are readable only by root, so
// that part goes through the helper. The agent has no access to them and should
// have none: reading the keytab means reading the authentication material of
// the host.
func ReadIdentityState(ctx context.Context) IdentityState {
	state := IdentityState{
		SSSDInstalled: exists("/usr/sbin/sssd") || exists("/usr/lib/systemd/system/sssd.service"),
	}

	config := parseIPAConfig()
	state.Enrolled = len(config) > 0
	state.Domain = config["domain"]
	state.Realm = config["realm"]
	if server := config["server"]; server != "" {
		state.Servers = append(state.Servers, server)
	}
	if !state.Enrolled {
		// A host outside a domain is a valid state, not missing data.
		return state
	}

	state.SSSDRunning = unitActive(ctx, "sssd.service")
	state.ClockSkewSeconds, state.TimeSynchronized = clockState(ctx)
	return state
}

// PrivilegedIdentity uzupelnia stan o data wymagajace roota.
type PrivilegedIdentity struct {
	HostPrincipal     string
	KeytabKVNO        *uint32
	CacheAgeSeconds   *uint64
	SSSDOnline        *bool
	ConfigIssues      []string
	UnavailableReason string
}

// Merge joins the result from the helper into the state read without
// privileges.
func (s IdentityState) Merge(privileged PrivilegedIdentity) IdentityState {
	s.HostPrincipal = privileged.HostPrincipal
	s.KeytabKVNO = privileged.KeytabKVNO
	s.CacheAgeSeconds = privileged.CacheAgeSeconds
	s.SSSDOnline = privileged.SSSDOnline
	s.ConfigIssues = privileged.ConfigIssues
	s.UnavailableReason = privileged.UnavailableReason
	return s
}

// parseIPAConfig reads /etc/ipa/default.conf. The presence of the file is the
// only certain local proof that the host was joined to a domain.
func parseIPAConfig() map[string]string {
	file, err := os.Open(ipaConfigPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	config := map[string]string{}
	for line := range iterLines(ipaConfigPath) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		config[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return config
}

func unitActive(ctx context.Context, unit string) bool {
	result := runCommand(ctx, 10*time.Second, "/usr/bin/systemctl", "is-active", "--quiet", unit)
	return result.Ran && result.ExitCode == 0
}

// sssdOnline asks SSSD about the state of the connection to the domain. A
// non-zero code without a result

// sssdCacheAge zwraca wiek pliku cache. Rosnacy wiek przy hoscie offline

// hostKeytab reads the host principal and the key version number. A KVNO
// mismatch

// clockState reads the drift of the clock. Kerberos stops working at a
// difference of minutes, so this value is an early warning.
func clockState(ctx context.Context) (skew *float64, synchronized bool) {
	result := runCommand(ctx, 15*time.Second, "/usr/bin/chronyc", "-c", "tracking")
	if !result.Ran || result.ExitCode != 0 {
		return nil, false
	}
	// Format -c to wartosci rozdzielone przecinkami; pole 5 to odchylenie
	// systemowe w sekundach, a pole 1 to adres zrodla.
	fields := strings.Split(strings.TrimSpace(result.Stdout), ",")
	if len(fields) < 6 {
		return nil, false
	}
	if parsed, err := strconv.ParseFloat(fields[4], 64); err == nil {
		skew = &parsed
	}
	synchronized = fields[1] != "" && fields[1] != "0.0.0.0"
	return skew, synchronized
}
