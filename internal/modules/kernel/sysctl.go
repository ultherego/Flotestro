// Package kernel describes the kernel settings and modules of a host.
//
// The module does not enumerate the whole of /proc/sys: it holds a few
// thousand keys about which the panel can say nothing sensible, and reading
// them every cycle would be a cost without an answer. The panel shows a
// profile - the set of keys somebody actually asks about - and lets the rest
// be read on request.
package kernel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Tool paths.
const (
	SysctlPath   = "/usr/sbin/sysctl"
	ModprobePath = "/usr/sbin/modprobe"
	LsmodPath    = "/usr/sbin/lsmod"
	// SysctlDir holds the panel's persistent settings. A file of its own,
	// not a shared one: a change by the panel must not rewrite what somebody
	// else set.
	SysctlDir     = "/etc/sysctl.d"
	SysctlFile    = SysctlDir + "/90-flotestro.conf"
	ModprobeDir   = "/etc/modprobe.d"
	BlacklistFile = ModprobeDir + "/90-flotestro-blacklist.conf"
	FileHeader    = "# Managed by Flotestro. Manual changes will not survive the next operation."
)

// DefaultProfile lists the keys the panel shows without being asked.
//
// This is not a list of everything that may be changed - it is a list of
// what the operator asks about most often: memory, network and process
// limits. The rest is available on request, as long as it lies within the
// allowed namespaces.
var DefaultProfile = []string{
	"vm.swappiness",
	"vm.dirty_ratio",
	"vm.max_map_count",
	"vm.overcommit_memory",
	"net.ipv4.ip_forward",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv6.conf.all.disable_ipv6",
	"net.core.somaxconn",
	"kernel.pid_max",
	"kernel.panic",
	"fs.file-max",
	"fs.inotify.max_user_watches",
}

// allowedNamespaces lists the /proc/sys branches the panel changes.
//
// Forbidding arbitrary writes matters here: /proc/sys also holds switches
// that disable kernel protections or stop the host. The panel changes what
// can be described and reverted, and leaves the rest to the host
// administrator.
var allowedNamespaces = []string{"vm.", "net.", "fs.", "kernel.", "user."}

// forbiddenKeys lists the settings the panel does not touch even though they
// belong to an allowed namespace.
var forbiddenKeys = map[string]string{
	"kernel.sysrq":                     "sysrq gives the console the right to reboot and kill processes",
	"kernel.core_pattern":              "core_pattern runs an arbitrary program on every core dump",
	"kernel.modprobe":                  "modprobe names the program run by the kernel",
	"kernel.poweroff_cmd":              "poweroff_cmd names the program run at power-off",
	"kernel.panic_on_oops":             "changing the behaviour on a kernel panic is a platform decision",
	"kernel.unprivileged_userns_clone": "disabling user namespaces breaks containers without warning",
	"kernel.kptr_restrict":             "kptr_restrict protects against leaking kernel addresses",
	"kernel.dmesg_restrict":            "dmesg_restrict protects against leaking kernel state",
}

var keyName = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_*-]+){1,8}$`)

// Setting is a single sysctl value.
type Setting struct {
	Key string `json:"key"`
	// Current is the value in effect now, Desired - the one written by the
	// panel. Different values mean a setting that waits for a reboot or was
	// changed outside the panel.
	Current string `json:"current,omitempty"`
	Desired string `json:"desired,omitempty"`
	// Source says which file sets the value persistently. Empty means the
	// kernel default, not a missing value.
	Source string `json:"source,omitempty"`
	// Managed marks a key written by the panel.
	Managed bool `json:"managed"`
}

// Module describes a kernel module.
type Module struct {
	Name string `json:"name"`
	// SizeBytes and UsedBy come from /proc/modules.
	SizeBytes uint64   `json:"size_bytes"`
	UsedBy    []string `json:"used_by,omitempty"`
	// Blacklisted marks a module blocked by the panel.
	Blacklisted bool `json:"blacklisted"`
}

// Snapshot is the picture of the host's kernel settings.
type Snapshot struct {
	Release string `json:"release,omitempty"`
	// CommandLine is the kernel command line: some settings can only be
	// changed there and only take effect after a reboot.
	CommandLine string    `json:"command_line,omitempty"`
	Settings    []Setting `json:"settings,omitempty"`
	Modules     []Module  `json:"modules,omitempty"`
	Blacklist   []string  `json:"blacklist,omitempty"`
	// Managed is the content of the panel's file.
	Managed           string    `json:"managed_config,omitempty"`
	ManagedPath       string    `json:"managed_path,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// ValidateKey checks whether the panel may set the given key.
func ValidateKey(key string) error {
	if !keyName.MatchString(key) {
		return fmt.Errorf("invalid setting name %q", key)
	}
	if reason, forbidden := forbiddenKeys[key]; forbidden {
		return fmt.Errorf("the panel does not change %s: %s", key, reason)
	}
	for _, namespace := range allowedNamespaces {
		if strings.HasPrefix(key, namespace) {
			return nil
		}
	}
	return fmt.Errorf("the panel changes settings in the branches %s; %q is outside them",
		strings.Join(allowedNamespaces, " "), key)
}

// ValidateValue checks a setting value.
//
// sysctl values are numbers or short lists of numbers; anything else points
// to an attempt to write something the kernel will not accept - or to smuggle
// a newline into the configuration file.
func ValidateValue(value string) error {
	if value == "" {
		return fmt.Errorf("the setting requires a value")
	}
	if len(value) > 128 {
		return fmt.Errorf("the value is longer than 128 characters")
	}
	for _, r := range value {
		allowed := (r >= '0' && r <= '9') || r == ' ' || r == '\t' ||
			r == '-' || r == '.' || r == ':' || r == '/' ||
			(r >= 'a' && r <= 'z')
		if !allowed {
			return fmt.Errorf("the value %q contains a disallowed character", value)
		}
	}
	return nil
}

// ComposeSysctlFile composes the content of the persistent settings file.
func ComposeSysctlFile(settings map[string]string) (string, error) {
	if len(settings) == 0 {
		return "", fmt.Errorf("the change contains no setting")
	}
	keys := make([]string, 0, len(settings))
	for key := range settings {
		if err := ValidateKey(key); err != nil {
			return "", err
		}
		if err := ValidateValue(settings[key]); err != nil {
			return "", fmt.Errorf("%s: %w", key, err)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := []string{FileHeader}
	for _, key := range keys {
		lines = append(lines, key+" = "+settings[key])
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// ParseSysctlFile reads a settings file.
func ParseSysctlFile(content string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		result[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return result
}

// ParseValues reads the output of "sysctl -n" for many keys at once.
func ParseValues(output string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// The kernel separates values with tabs; they are normalised to
		// spaces so that the comparison with the written value does not
		// depend on whitespace.
		result[strings.TrimSpace(key)] = strings.Join(strings.Fields(value), " ")
	}
	return result
}
