// Package security describes the protective state of a host: mandatory
// access control, auditing, the boot mode and what the host exposes to the
// outside.
//
// The module gathers facts, not judgements. The judgement - compliance with
// a profile - is made in the panel, because the checks are versioned there
// and the whole fleet is visible there. A host that judged itself would need
// new rules on every policy change, and nobody could say whether two hosts
// were judged the same way.
package security

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Paths the state is read from.
const (
	SELinuxDir       = "/sys/fs/selinux"
	EnforceFile      = SELinuxDir + "/enforce"
	MACConfiguration = "/etc/selinux/config"
	AppArmorFile     = "/sys/module/apparmor/parameters/enabled"
	AppArmorProfiles = "/sys/kernel/security/apparmor/profiles"
	FIPSFile         = "/proc/sys/crypto/fips_enabled"
	LockdownFile     = "/sys/kernel/security/lockdown"
	EFIDir           = "/sys/firmware/efi"
	EFIVarsDir       = "/sys/firmware/efi/efivars"
	SetenforcePath   = "/usr/sbin/setenforce"
	// Augenrules assembles the rules from the rules.d directory and loads
	// them into the kernel. This is the path auditd itself provides: the
	// daemon unit on some distributions refuses a manual restart.
	AugenrulesPath = "/usr/sbin/augenrules"
	AuditctlPath   = "/usr/sbin/auditctl"
	// Audit rules live in files only root can read - and a file written
	// but not loaded describes an audit that does not exist.
	AuditRulesDir  = "/etc/audit/rules.d"
	AuditRulesFile = "/etc/audit/audit.rules"
	SSPath         = "/usr/bin/ss"
	SSPathAlt      = "/usr/sbin/ss"

	// SecureBootVariable is the name of the EFI variable holding the secure
	// boot state. The suffix is the identifier of the global EFI namespace.
	SecureBootVariable = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
)

// Mandatory access control systems.
const (
	SystemSELinux  = "selinux"
	SystemAppArmor = "apparmor"
)

// SELinux modes.
const (
	ModeEnforcing  = "enforcing"
	ModePermissive = "permissive"
	ModeDisabled   = "disabled"
)

// Mandatory describes the host's mandatory access control.
//
// The running mode and the configured mode are two fields, because they
// differ at times: a host switched by hand to permissive returns to
// enforcing after a reboot, and a host with "SELINUX=enforcing" in the file
// and SELinux disabled in the kernel looks protected but is not.
type Mandatory struct {
	System         string `json:"system,omitempty"`
	Mode           string `json:"mode,omitempty"`
	ConfiguredMode string `json:"configured_mode,omitempty"`
	Policy         string `json:"policy,omitempty"`
	// AppArmor profiles are counted separately: a profile in complain mode
	// does not protect, it only records.
	ProfilesEnforcing *int `json:"profiles_enforcing"`
	ProfilesComplain  *int `json:"profiles_complain"`
	// Reason says why the state was not determined or why no MAC system
	// protects the host.
	Reason string `json:"reason,omitempty"`
}

// Protects says whether the host has working mandatory access control.
func (m Mandatory) Protects() bool {
	switch m.System {
	case SystemSELinux:
		return m.Mode == ModeEnforcing
	case SystemAppArmor:
		return m.ProfilesEnforcing != nil && *m.ProfilesEnforcing > 0
	}
	return false
}

// Audit describes the state of the audit daemon.
//
// Loaded rules and configured rules are two fields, because they differ at
// times: a rules file written but not loaded describes an audit that does
// not exist, and the rule count alone does not say whether the kernel knows
// them.
type Audit struct {
	Present bool  `json:"present"`
	Active  *bool `json:"active"`
	// RulesLoaded is the number of rules the kernel knows; RulesConfigured -
	// the number of rules in files. A nil pointer means a read that failed,
	// not an absence of rules.
	RulesLoaded     *int   `json:"rules_loaded"`
	RulesConfigured *int   `json:"rules_configured"`
	Reason          string `json:"reason,omitempty"`
}

// Socket reach. The panel does not rule whether a service is visible from
// the internet - neither the host nor the panel knows that: a private
// address may be reachable across the whole company network, and a public
// one may sit behind an edge firewall. So what is visible gets named:
// whether the socket stands on the loopback, on a specific host address, or
// on all interfaces at once.
const (
	ReachLoopback      = "loopback"
	ReachHostNetwork   = "host-network"
	ReachAllInterfaces = "all-interfaces"
)

// Listener is one listening socket on the host.
type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process,omitempty"`
	PID      uint32 `json:"pid,omitempty"`
	// Reach names the socket reach. A service on the loopback and the same
	// service on a host address are two different situations - but neither
	// is automatically "visible from the internet".
	Reach string `json:"reach"`
}

// BeyondLoopback says whether the socket stands outside the loopback.
func (l Listener) BeyondLoopback() bool { return l.Reach != ReachLoopback && l.Reach != "" }

// Snapshot is the picture of the host's protective state.
type Snapshot struct {
	MAC   Mandatory `json:"mac"`
	Audit Audit     `json:"audit"`
	// Nil fields mean an undetermined state, not a disabled one.
	FIPSEnabled *bool `json:"fips_enabled"`
	SecureBoot  *bool `json:"secure_boot"`
	// SecureBootReason says why there is no secure boot state - most often
	// because the host boots in BIOS mode and the question makes no sense.
	SecureBootReason string `json:"secure_boot_reason,omitempty"`
	Lockdown         string `json:"lockdown,omitempty"`
	// Listening is the list of listening sockets, ListeningKnown says
	// whether it could be read at all.
	Listening      []Listener `json:"listening,omitempty"`
	ListeningKnown bool       `json:"listening_known"`
	// OwnersKnown says whether the sockets carry an owner. Without root the
	// socket list is complete but nameless - and those are two different
	// answers.
	OwnersKnown bool `json:"owners_known"`
	// Missing lists the facts that could not be gathered, with the reason.
	// The checks turn them into an undetermined state with a reason code
	// instead of guessing a value.
	Missing map[string]string `json:"missing,omitempty"`

	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// BeyondLoopback lists the sockets standing outside the loopback.
func (s Snapshot) BeyondLoopback() []Listener {
	var beyond []Listener
	for _, socket := range s.Listening {
		if socket.BeyondLoopback() {
			beyond = append(beyond, socket)
		}
	}
	return beyond
}

// ByReach counts the sockets in every reach class.
func (s Snapshot) ByReach() map[string]int {
	counts := map[string]int{}
	for _, socket := range s.Listening {
		counts[socket.Reach]++
	}
	return counts
}

// ValidateMode checks the SELinux mode ordered by the panel.
//
// The panel switches between enforcing and permissive, because both changes
// work immediately and both can be reverted the same way. It does not set
// SELinux to disabled: to come back, the host needs the whole filesystem
// relabelled and a reboot, and that is not an operation the panel can
// promise.
func ValidateMode(mode string) error {
	switch mode {
	case ModeEnforcing, ModePermissive:
		return nil
	case ModeDisabled:
		return fmt.Errorf("the panel does not disable SELinux: coming back requires relabelling the filesystem and a reboot")
	}
	return fmt.Errorf("unknown mode %q", mode)
}

// ParseEnforceMode reads /sys/fs/selinux/enforce.
func ParseEnforceMode(content string) string {
	switch strings.TrimSpace(content) {
	case "1":
		return ModeEnforcing
	case "0":
		return ModePermissive
	}
	return ""
}

// ParseSELinuxConfiguration reads /etc/selinux/config.
func ParseSELinuxConfiguration(content string) (mode, policy string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "SELINUX":
			mode = strings.TrimSpace(value)
		case "SELINUXTYPE":
			policy = strings.TrimSpace(value)
		}
	}
	return mode, policy
}

// ParseAppArmorProfiles reads /sys/kernel/security/apparmor/profiles.
//
// A row has the form "name (mode)". A profile in complain mode does not
// protect, it only records violations, so both modes are counted
// separately.
func ParseAppArmorProfiles(content string) (enforcing, complain int) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		open := strings.LastIndex(line, "(")
		close := strings.LastIndex(line, ")")
		if open < 0 || close < open {
			continue
		}
		switch strings.TrimSpace(line[open+1 : close]) {
		case "enforce":
			enforcing++
		case "complain":
			complain++
		}
	}
	return enforcing, complain
}

// ParseRulesFromFile counts the rules written in a file.
//
// Comments and empty lines are not rules; "-D" deletes all of them and is
// not one either, although it looks like an entry.
func ParseRulesFromFile(content string) int {
	rules := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "-D" {
			continue
		}
		rules++
	}
	return rules
}

// ParseRules reads the output of "auditctl -l".
func ParseRules(output string) int {
	rules := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "No rules") {
			continue
		}
		rules++
	}
	return rules
}

// ParseLockdown reads /sys/kernel/security/lockdown.
//
// The file lists all the modes, and the one in effect is in square
// brackets.
func ParseLockdown(content string) string {
	for _, field := range strings.Fields(content) {
		if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
			return strings.Trim(field, "[]")
		}
	}
	return ""
}

// ParseSecureBoot reads the SecureBoot EFI variable.
//
// The variable has five bytes: four are attributes, the last is the value.
func ParseSecureBoot(data []byte) *bool {
	if len(data) < 5 {
		return nil
	}
	enabled := data[4] == 1
	return &enabled
}

// ParseListeners reads the output of "ss -tulpnH".
//
// The columns are fixed: protocol, state, queues, local address, remote
// address and optionally the process. The local address carries the port
// after the last colon, because an IPv6 address contains colons itself.
func ParseListeners(output string) []Listener {
	var sockets []Listener
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		protocol := fields[0]
		if protocol != "tcp" && protocol != "udp" {
			continue
		}
		address, port, ok := splitAddress(fields[4])
		if !ok {
			continue
		}
		socket := Listener{
			Protocol: protocol,
			Address:  address,
			Port:     port,
			Reach:    Reach(address),
		}
		if len(fields) >= 7 {
			socket.Process, socket.PID = socketOwner(strings.Join(fields[6:], " "))
		}
		sockets = append(sockets, socket)
	}
	return sockets
}

// splitAddress splits a local address into address and port.
func splitAddress(field string) (string, int, bool) {
	colon := strings.LastIndex(field, ":")
	if colon < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(field[colon+1:])
	if err != nil {
		return "", 0, false
	}
	address := strings.Trim(field[:colon], "[]")
	// ss appends the interface name to the address after a percent sign.
	if percent := strings.Index(address, "%"); percent >= 0 {
		address = address[:percent]
	}
	return address, port, true
}

// Reach classifies the address a socket stands on.
//
// The classification ends at what the host knows about itself. "Visible
// from the internet" is a conclusion about routes and edge firewalls that
// neither the host nor the panel can draw from the address alone.
func Reach(address string) string {
	switch {
	case address == "":
		return ""
	case address == "*", address == "0.0.0.0", address == "::":
		return ReachAllInterfaces
	case strings.HasPrefix(address, "127."), address == "::1":
		return ReachLoopback
	default:
		return ReachHostNetwork
	}
}

// SocketKey identifies a socket in the helper's answer about owners.
func SocketKey(protocol, address string, port int) string {
	return protocol + "|" + address + "|" + strconv.Itoa(port)
}

// Names of the facts that cannot be read without root. The helper receives
// a list of them, not a command to run: the scope of its work is
// enumerated.
const (
	FactAppArmorProfiles = "apparmor_profiles"
	FactAuditRules       = "audit_rules"
	FactSecureBoot       = "secure_boot"
	FactSocketOwners     = "socket_owners"
)

// Owner is the process holding a socket.
type Owner struct {
	Process string `json:"process,omitempty"`
	PID     uint32 `json:"pid,omitempty"`
}

// Supplement holds the facts gathered by the helper on explicit request.
//
// A nil field means a fact that was not asked for or could not be read -
// the reason is then in Errors, under the fact name.
type Supplement struct {
	ProfilesEnforcing *int              `json:"profiles_enforcing,omitempty"`
	ProfilesComplain  *int              `json:"profiles_complain,omitempty"`
	RulesLoaded       *int              `json:"rules_loaded,omitempty"`
	RulesConfigured   *int              `json:"rules_configured,omitempty"`
	SecureBoot        *bool             `json:"secure_boot,omitempty"`
	SecureBootReason  string            `json:"secure_boot_reason,omitempty"`
	SocketOwners      map[string]Owner  `json:"socket_owners,omitempty"`
	Errors            map[string]string `json:"errors,omitempty"`
}

// socketOwner reads the users:(("name",pid=N,fd=M)) field.
func socketOwner(field string) (string, uint32) {
	open := strings.Index(field, `(("`)
	if open < 0 {
		return "", 0
	}
	rest := field[open+3:]
	name, rest, ok := strings.Cut(rest, `"`)
	if !ok {
		return "", 0
	}
	_, rest, ok = strings.Cut(rest, "pid=")
	if !ok {
		return name, 0
	}
	digits := rest
	if end := strings.IndexAny(digits, ",)"); end >= 0 {
		digits = digits[:end]
	}
	pid, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return name, 0
	}
	return name, uint32(pid)
}
