// Package agent holds the logic of the host agent: collecting facts, enrollment
// and handling the session with the control plane.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ultherego/flotestro/internal/modules/certificates"
	dnsmodul "github.com/ultherego/flotestro/internal/modules/dns"
	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/modules/power"
	"github.com/ultherego/flotestro/internal/modules/schedules"
	"github.com/ultherego/flotestro/internal/modules/security"
	sshmodul "github.com/ultherego/flotestro/internal/modules/ssh"
	"github.com/ultherego/flotestro/internal/modules/storage"
	czas "github.com/ultherego/flotestro/internal/modules/time"
	"github.com/ultherego/flotestro/internal/packages"
)

// SchemaVersion describes the version of the format of the inventory report
// stored in JSONB.
const SchemaVersion = "1"

// OSInfo describes the operating system of the host.
type OSInfo struct {
	Family       string `json:"family"`
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	PrettyName   string `json:"pretty_name"`
	// Codename is the name of the release (bookworm, trixie, noble). The
	// security trackers of Debian and Ubuntu speak in it and not in numbers -
	// without it there is no telling which findings concern this host.
	Codename string `json:"codename,omitempty"`
}

// Hardware describes the resources of the host.
type Hardware struct {
	CPUCores       uint32 `json:"cpu_cores"`
	MemoryBytes    uint64 `json:"memory_bytes"`
	RootFSBytes    uint64 `json:"root_fs_bytes"`
	RootFSFreeByte uint64 `json:"root_fs_free_bytes"`
	Virtualization string `json:"virtualization"`
}

// Packages sums up the state of the packages. Empty counters mean a state that
// was not determined, not zero: a failed read is not a fact about the host.
type Packages struct {
	Manager            string  `json:"manager"`
	Installed          *uint32 `json:"installed,omitempty"`
	Upgradable         *uint32 `json:"upgradable,omitempty"`
	SecurityUpgradable *uint32 `json:"security_upgradable,omitempty"`
	// InstalledDigest and InstalledCount describe the full package list the
	// inventory does not carry: the panel compares the digest with its own copy
	// and knows when its list stopped describing the host. Without it a missing
	// row in the panel database would look like a host without vulnerabilities.
	InstalledDigest   string  `json:"installed_digest,omitempty"`
	InstalledCount    *uint32 `json:"installed_count,omitempty"`
	InstalledReason   string  `json:"installed_unavailable_reason,omitempty"`
	UnavailableReason string  `json:"unavailable_reason,omitempty"`
}

// Health holds the signals sent in the heartbeat. Empty indicators mean a state
// that was not determined and are not sent to the control plane.
type Health struct {
	FailedUnits            *uint32
	RebootRequired         *bool
	Load1Milli             uint32
	RootFSUsedPercent      uint32
	UptimeSeconds          uint64
	PendingUpdates         *uint32
	PendingSecurityUpdates *uint32
}

// Facts is the full inventory report of the host.
type Facts struct {
	Hostname  string   `json:"hostname"`
	MachineID string   `json:"machine_id"`
	BootID    string   `json:"boot_id"`
	OS        OSInfo   `json:"os"`
	Hardware  Hardware `json:"hardware"`
	Packages  Packages `json:"packages"`
	// Repositories is the list of the package sources. An empty list and a list
	// that was not read are two different answers, so the picture carries its own
	// marker and reason.
	Repositories *packages.RepositoryImage `json:"repositories,omitempty"`
	Capabilities Capabilities              `json:"capabilities"`
	FailedUnits  []string                  `json:"failed_units"`
	// Empty fields mean the state could not be determined.
	FailedUnitsKnown bool           `json:"failed_units_known"`
	RebootRequired   *bool          `json:"reboot_required,omitempty"`
	Identity         IdentityState  `json:"identity"`
	LocalAccounts    []LocalAccount `json:"local_accounts,omitempty"`
	Interfaces       []string       `json:"network_interfaces"`
	// Containers is the summary of the container engine. Empty means a host
	// without an engine or an engine that was not queried - unavailable_reason
	// tells them apart.
	Containers *docker.Summary `json:"containers,omitempty"`
	// Network is the picture of the interfaces and the routes from the kernel. A
	// missing value means a cycle in which the state was not collected.
	Network *network.Snapshot `json:"network,omitempty"`
	// Files is the state of the files the panel has written on this host.
	Files *files.Snapshot `json:"files,omitempty"`
	// Kernel holds the kernel settings and the list of modules.
	Kernel *kernel.Snapshot `json:"kernel,omitempty"`
	// Security is the protection state of the host: MAC, the audit, the boot mode
	// and what the host exposes to the outside.
	Security *security.Snapshot `json:"security,omitempty"`
	// Backup is what can be said about the copies without credentials: what the
	// host can make them with. The state of the repository needs a password, so
	// it is an operation and not inventory.
	Backup *BackupState `json:"backup,omitempty"`
	// Certificates is the picture of the certificates the panel asked about and
	// of those the host watches on its own. The module does not search the disk,
	// so an empty list means the named files are missing, not a host without
	// certificates.
	Certificates *certificates.Snapshot `json:"certificates,omitempty"`
	// Power is the boot state of the host: the boot_id, the uptime and what holds
	// a shutdown back.
	Power *power.Snapshot `json:"power,omitempty"`
	// Time is the time of the host and the state of its synchronization. A
	// shifted clock breaks Kerberos and mTLS, so it is a fact about the host and
	// not a curiosity.
	Time *czas.Snapshot `json:"time,omitempty"`
	// SSH is the configuration of the sshd server.
	SSH *sshmodul.Snapshot `json:"ssh,omitempty"`
	// Storage is the picture of the disk space of the host.
	Storage *storage.Snapshot `json:"storage,omitempty"`
	// Firewall is the state of the firewall of the host.
	Firewall *firewall.Snapshot `json:"firewall,omitempty"`
	// DNS is the state of the resolver of the host.
	DNS *dnsmodul.Snapshot `json:"dns,omitempty"`
	// Schedules are the recurring jobs of the host. A missing value means a host
	// without cron or a read that failed - the unavailable_reason field inside
	// the snapshot tells them apart.
	Schedules   *schedules.Snapshot `json:"schedules,omitempty"`
	CollectedAt time.Time           `json:"collected_at"`
}

// Revision computes a stable revision from the content of the report. An
// identical host state gives an identical revision, so the server does not
// store another row without changes.
func (f Facts) Revision() (string, []byte, error) {
	// The timestamp must not affect the revision.
	stable := f
	stable.CollectedAt = time.Time{}
	payload, err := json.Marshal(stable)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(payload)
	full, err := json.Marshal(f)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(sum[:16]), full, nil
}

// MachineID returns the stable identifier of the machine.
func MachineID() (string, error) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id, nil
			}
		}
	}
	return "", os.ErrNotExist
}

// BootID changes at every restart of the host and ends the reboot phase.
func BootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ReadOSInfo reads /etc/os-release and the kernel version.
func ReadOSInfo() OSInfo {
	info := OSInfo{Architecture: runtime.GOARCH}
	release := parseKeyValueFile("/etc/os-release")
	info.Distribution = release["ID"]
	info.Version = firstNonEmpty(release["VERSION_ID"], release["VERSION"])
	info.PrettyName = release["PRETTY_NAME"]
	info.Codename = firstNonEmpty(release["VERSION_CODENAME"], release["UBUNTU_CODENAME"])
	info.Family = osFamily(release)

	if kernel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(kernel))
	}
	return info
}

// osFamily maps a distribution to a family of adapters and not to a marketing
// name.
func osFamily(release map[string]string) string {
	candidates := append([]string{release["ID"]}, strings.Fields(release["ID_LIKE"])...)
	for _, candidate := range candidates {
		switch candidate {
		case "debian", "ubuntu":
			return "debian"
		case "fedora", "rhel", "centos":
			return "rhel"
		case "suse", "opensuse":
			return "suse"
		case "arch":
			return "arch"
		}
	}
	return firstNonEmpty(release["ID"], "unknown")
}

// ReadHardware reads the resources of the host only from /proc and statfs.
func ReadHardware() Hardware {
	hw := Hardware{CPUCores: uint32(runtime.NumCPU())}
	for line := range iterLines("/proc/meminfo") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					hw.MemoryBytes = kb * 1024
				}
			}
			break
		}
	}
	total, free := rootFilesystem()
	hw.RootFSBytes, hw.RootFSFreeByte = total, free
	hw.Virtualization = detectVirtualization()
	return hw
}

func rootFilesystem() (total, free uint64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, 0
	}
	return stat.Blocks * uint64(stat.Bsize), stat.Bavail * uint64(stat.Bsize)
}

func detectVirtualization() string {
	data, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ReadHealth collects the heartbeat signals without starting child processes.
// The values that need a process come from the last inventory cycle.
func ReadHealth(cached Facts) Health {
	health := Health{
		RebootRequired:         cached.RebootRequired,
		PendingUpdates:         cached.Packages.Upgradable,
		PendingSecurityUpdates: cached.Packages.SecurityUpgradable,
	}
	if cached.FailedUnitsKnown {
		count := uint32(len(cached.FailedUnits))
		health.FailedUnits = &count
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			if load, err := strconv.ParseFloat(fields[0], 64); err == nil {
				health.Load1Milli = uint32(load * 1000)
			}
		}
	}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			if uptime, err := strconv.ParseFloat(fields[0], 64); err == nil {
				health.UptimeSeconds = uint64(uptime)
			}
		}
	}
	if total, free := rootFilesystem(); total > 0 {
		health.RootFSUsedPercent = uint32((total - free) * 100 / total)
	}
	return health
}

// runtimeDir is a directory writable for the user of the agent. System tools
// such as dnf need HOME and the XDG directories; the agent has no home
// directory, so without it they end with an error that is easy to mistake for a
// substantive result.
var runtimeDir = os.TempDir()

// SetRuntimeDir points at the working directory for the tools that are started.
func SetRuntimeDir(dir string) error {
	if dir == "" {
		return nil
	}
	for _, sub := range []string{"", "state", "cache", "config"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return err
		}
	}
	runtimeDir = dir
	return nil
}

// commandResult separates the fact that a process ran from its result. The exit
// code means something only when the process really ran.
type commandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Ran      bool
	Err      error
}

// Reason describes the reason why the value could not be determined.
func (r commandResult) Reason() string {
	switch {
	case r.Err != nil && !r.Ran:
		return r.Err.Error()
	case strings.TrimSpace(r.Stderr) != "":
		return fmt.Sprintf("code %d: %s", r.ExitCode, firstLine(r.Stderr))
	default:
		return fmt.Sprintf("code %d", r.ExitCode)
	}
}

// runCommand starts a process with a fixed path and an array of arguments.
// sh -c is never used, so the content of the data cannot become a command.
// LC_ALL=C stabilizes the output that has to be parsed.
func runCommand(ctx context.Context, timeout time.Duration, path string, args ...string) commandResult {
	if !isExecutable(path) {
		return commandResult{ExitCode: -1, Err: fmt.Errorf("%s: %w", path, os.ErrNotExist)}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = []string{
		"LC_ALL=C",
		"LANG=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"DEBIAN_FRONTEND=noninteractive",
		"HOME=" + runtimeDir,
		"XDG_STATE_HOME=" + filepath.Join(runtimeDir, "state"),
		"XDG_CACHE_HOME=" + filepath.Join(runtimeDir, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(runtimeDir, "config"),
	}

	err := cmd.Run()
	result := commandResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1, Err: err}

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		result.Ran, result.ExitCode = true, 0
	case errors.As(err, &exitErr):
		// The process ran and returned the code itself, so the code means
		// something.
		result.Ran, result.ExitCode = true, exitErr.ExitCode()
	}
	if cmdCtx.Err() != nil {
		// An exceeded timeout is not a substantive result.
		result.Ran = false
	}
	return result
}

func firstLine(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return strings.TrimSpace(text[:index])
	}
	return strings.TrimSpace(text)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parseKeyValueFile(path string) map[string]string {
	result := map[string]string{}
	for line := range iterLines(path) {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		result[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return result
}

func iterLines(path string) func(func(string) bool) {
	return func(yield func(string) bool) {
		file, err := os.Open(path)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if !yield(scanner.Text()) {
				return
			}
		}
	}
}

func networkInterfaces() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if entry.Name() != "lo" {
			names = append(names, filepath.Base(entry.Name()))
		}
	}
	return names
}
