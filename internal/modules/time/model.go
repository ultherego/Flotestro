// Package hosttime describes the host clock and its synchronisation.
//
// The package name deliberately differs from the directory: the directory
// names the module the way the document does (internal/modules/time), and
// the package cannot be called "time", because it would shadow the standard
// library in every file that uses it - including this one.
//
// Time is an assumption the rest of the panel stands on: Kerberos rejects
// tickets outside the window, mTLS rejects certificates not yet valid, and
// a journal from a host with a skewed clock sorts in the wrong order. That
// is why the module measures the offset instead of only showing that the
// time daemon runs.
package hosttime

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Tool and configuration paths.
const (
	TimedatectlPath = "/usr/bin/timedatectl"
	ChronycPath     = "/usr/bin/chronyc"
	ZoneDir         = "/usr/share/zoneinfo"

	// TimesyncdDir holds the panel settings for systemd-timesyncd.
	TimesyncdDir  = "/etc/systemd/timesyncd.conf.d"
	TimesyncdFile = TimesyncdDir + "/90-flotestro.conf"

	// PanelSourceDir is the directory the panel creates on a host where
	// chrony includes none of its own. A sources directory, not a
	// configuration one: it accepts only servers, so the panel file cannot
	// change anything else about chrony.
	PanelSourceDir = "/etc/chrony/sources.d"
	// EnableHeader marks the line the panel appends to the main file.
	EnableHeader = "# Added by Flotestro: time sources directory managed by the panel."

	// FileHeader marks the panel file. Without it the next operation would
	// not know which servers the panel set and which the host
	// administrator.
	FileHeader = "# Managed by Flotestro. Manual changes will not survive the next operation."
)

// Time daemon names. The name says who keeps the clock on this host.
const (
	DaemonChrony    = "chrony"
	DaemonTimesyncd = "systemd-timesyncd"
)

// Kinds of the directory chrony includes. The difference is not cosmetic:
// any directive may be written into a configuration directory and the
// daemon must be reloaded, while a sources directory accepts only servers
// and can be reloaded without breaking synchronisation.
const (
	KindConfiguration = "confdir"
	KindSources       = "sourcedir"
)

// ChronyMainConfigurations lists the places where distributions keep the
// main chrony file. The panel does not rewrite it - it reads it to learn
// which directory the daemon really includes.
var ChronyMainConfigurations = []string{
	"/etc/chrony/chrony.conf",
	"/etc/chrony.conf",
}

// ServerLimit bounds the number of servers in one change. A few sources
// give resilience against one bad one; a few dozen give nothing but
// traffic.
const ServerLimit = 8

// StepThresholdSeconds sets the offset the panel treats as a time step.
//
// A second is a practical boundary, not a theoretical one: below it the
// time daemons slew the clock smoothly, above it they step it - and then
// databases, tokens and certificates see a clock that went backwards.
const StepThresholdSeconds = 1.0

// Source is one time server seen by the daemon.
type Source struct {
	Address string `json:"address"`
	// Mode distinguishes a server, a peer and a hardware clock.
	Mode string `json:"mode,omitempty"`
	// State says whether the daemon uses this source or rejected it.
	State string `json:"state,omitempty"`
	// Nil fields mean a measurement that does not exist - not zero.
	Stratum       *uint32  `json:"stratum"`
	PollSeconds   *int     `json:"poll_seconds"`
	Reachability  string   `json:"reachability,omitempty"`
	LastRxSeconds *int64   `json:"last_rx_seconds"`
	OffsetSeconds *float64 `json:"offset_seconds"`
	ErrorSeconds  *float64 `json:"error_seconds"`
}

// Server is a configuration entry, not a working source.
//
// The distinction matters in diagnosis: a server written into the
// configuration that does not answer does not appear on the daemon's source
// list - and without this list it would look non-existent instead of
// unreachable.
type Server struct {
	Address string `json:"address"`
	// Source names the file the entry comes from.
	Source string `json:"source,omitempty"`
	// Pool marks an entry expanded to many addresses.
	Pool bool `json:"pool,omitempty"`
	// Managed marks an entry written by the panel.
	Managed bool `json:"managed"`
}

// Probe is the result of one SNTP query requested by the panel.
type Probe struct {
	Server string `json:"server"`
	// Address is the address the server answered from.
	Address       string   `json:"address,omitempty"`
	Reachable     bool     `json:"reachable"`
	Stratum       *uint32  `json:"stratum"`
	OffsetSeconds *float64 `json:"offset_seconds"`
	DelaySeconds  *float64 `json:"delay_seconds"`
	LeapStatus    string   `json:"leap_status,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// Snapshot is the picture of the host clock.
type Snapshot struct {
	// Now is the host time read at collection. The panel compares it with
	// its own clock, so it must come from the host, not from the server.
	Now      time.Time `json:"now"`
	Timezone string    `json:"timezone,omitempty"`
	// UTCOffsetSeconds is the zone offset, not a clock error.
	UTCOffsetSeconds *int `json:"utc_offset_seconds"`
	// RTCInLocalTime marks a hardware clock in local time. Such a host
	// boots with a wrong clock after a daylight saving change.
	RTCInLocalTime *bool `json:"rtc_in_local_time"`
	NTPEnabled     *bool `json:"ntp_enabled"`
	Synchronized   *bool `json:"synchronized"`
	// Service names the time daemon, Unit - its systemd unit.
	Service       string `json:"service,omitempty"`
	Unit          string `json:"unit,omitempty"`
	ServiceActive *bool  `json:"service_active"`

	ReferenceName         string     `json:"reference_name,omitempty"`
	Stratum               *uint32    `json:"stratum"`
	OffsetSeconds         *float64   `json:"offset_seconds"`
	RootDelaySeconds      *float64   `json:"root_delay_seconds"`
	RootDispersionSeconds *float64   `json:"root_dispersion_seconds"`
	FrequencyPPM          *float64   `json:"frequency_ppm"`
	LeapStatus            string     `json:"leap_status,omitempty"`
	LastSyncAt            *time.Time `json:"last_sync_at,omitempty"`

	Sources    []Source `json:"sources,omitempty"`
	Configured []Server `json:"configured_servers,omitempty"`
	Probes     []Probe  `json:"probes,omitempty"`

	// Managed is the content of the panel file, ManagedPath its path. An
	// empty path means a host on which the panel has nowhere to write the
	// change.
	Managed     string `json:"managed_config,omitempty"`
	ManagedPath string `json:"managed_path,omitempty"`
	// WriteReason says why the panel will not change the time
	// configuration here.
	WriteReason string `json:"write_reason,omitempty"`
	// ConfigPath is the daemon's main file. The panel does not rewrite it;
	// it is shown so the operator knows what the change does not concern.
	ConfigPath string `json:"config_path,omitempty"`
	// CanAddSourceDir says the host can be brought to a writable state
	// with one appended line - but only with the operator's explicit
	// consent.
	CanAddSourceDir bool `json:"can_add_source_dir,omitempty"`

	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// IsSynchronized says whether the host is synchronised. An unknown state is
// not false here: no answer from the daemon is a different situation than
// its "no".
func (s Snapshot) IsSynchronized() bool {
	return s.Synchronized != nil && *s.Synchronized
}

var zoneName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+_-]*(/[A-Za-z0-9+_.-]+){0,2}$`)
var hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)

// ValidateZone checks a time zone name.
//
// The name goes to the command and to a path in /usr/share/zoneinfo, so it
// cannot be a relative path or contain anything but a zone name.
func ValidateZone(zone string) error {
	if zone == "" {
		return fmt.Errorf("the time zone is empty")
	}
	if len(zone) > 64 {
		return fmt.Errorf("the zone name is longer than 64 characters")
	}
	if strings.Contains(zone, "..") {
		return fmt.Errorf("the zone name %q leaves the zone directory", zone)
	}
	if !zoneName.MatchString(zone) {
		return fmt.Errorf("invalid zone name %q", zone)
	}
	return nil
}

// ZonePath returns the zone file in the zone directory.
func ZonePath(zone string) string {
	return ZoneDir + "/" + zone
}

// ValidateServer checks a time server address.
//
// The address goes into the configuration file as a whole line, so it must
// not contain whitespace or a newline: the entry "a\niburst offline" would
// be a different directive than the one the operator approved.
func ValidateServer(address string) error {
	if address == "" {
		return fmt.Errorf("the time server address is empty")
	}
	if len(address) > 253 {
		return fmt.Errorf("the address %q is longer than 253 characters", address)
	}
	if net.ParseIP(address) != nil {
		return nil
	}
	if !hostName.MatchString(address) {
		return fmt.Errorf("%q is neither an IP address nor a host name", address)
	}
	return nil
}

// ValidateServers checks the whole server list.
func ValidateServers(servers []string) error {
	if len(servers) == 0 {
		return fmt.Errorf("the change names no time server")
	}
	if len(servers) > ServerLimit {
		return fmt.Errorf("the panel accepts at most %d time servers", ServerLimit)
	}
	seen := map[string]bool{}
	for _, server := range servers {
		if err := ValidateServer(server); err != nil {
			return err
		}
		if seen[server] {
			return fmt.Errorf("the server %q repeats on the list", server)
		}
		seen[server] = true
	}
	return nil
}

// ComposeTimesyncd composes the settings file for systemd-timesyncd.
func ComposeTimesyncd(servers []string) (string, error) {
	if err := ValidateServers(servers); err != nil {
		return "", err
	}
	return FileHeader + "\n[Time]\nNTP=" + strings.Join(servers, " ") + "\n", nil
}

// ComposeChrony composes the file with servers for chrony.
//
// A sources directory accepts only server directives, so no header is
// written there: the file is then owned by its name, not by a comment.
func ComposeChrony(servers []string, kind string) (string, error) {
	if err := ValidateServers(servers); err != nil {
		return "", err
	}
	lines := make([]string, 0, len(servers)+1)
	if kind != KindSources {
		lines = append(lines, FileHeader)
	}
	for _, server := range servers {
		// iburst shortens the first synchronisation from many minutes to a
		// few seconds; without it the operator stares at "not synchronised"
		// and does not know whether the change worked.
		lines = append(lines, "server "+server+" iburst")
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// EnableEntry composes the lines the panel appends to the main chrony file
// when the host includes no directory.
//
// This is the only place where the panel touches somebody else's
// configuration, and it touches it only by appending: it changes or removes
// nothing already there, and the appended directory accepts servers only.
// The operator must consent to this separately - without consent the host
// stays read-only and says why.
func EnableEntry() string {
	return "\n" + EnableHeader + "\nsourcedir " + PanelSourceDir + "\n"
}

// HasEnableEntry says whether the panel has already appended its directory.
func HasEnableEntry(configuration string) bool {
	dir, _ := DropInDir(configuration)
	return dir == PanelSourceDir
}

// ChronyFileName returns the panel file name in a directory of the given
// kind.
func ChronyFileName(kind string) string {
	if kind == KindSources {
		return "flotestro.sources"
	}
	return "90-flotestro.conf"
}
