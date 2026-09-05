// Package agent zawiera logike agenta hosta: zbieranie faktow, enrollment
// i obsluge sesji z control plane.
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

// SchemaVersion opisuje wersje formatu raportu inventory zapisywanego w JSONB.
const SchemaVersion = "1"

// OSInfo opisuje system operacyjny hosta.
type OSInfo struct {
	Family       string `json:"family"`
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	PrettyName   string `json:"pretty_name"`
}

// Hardware opisuje zasoby hosta.
type Hardware struct {
	CPUCores       uint32 `json:"cpu_cores"`
	MemoryBytes    uint64 `json:"memory_bytes"`
	RootFSBytes    uint64 `json:"root_fs_bytes"`
	RootFSFreeByte uint64 `json:"root_fs_free_bytes"`
	Virtualization string `json:"virtualization"`
}

// Packages podsumowuje stan pakietow. Puste liczniki oznaczaja stan
// nieustalony, nie zero: nieudany odczyt nie jest faktem o hoscie.
type Packages struct {
	Manager            string  `json:"manager"`
	Installed          *uint32 `json:"installed,omitempty"`
	Upgradable         *uint32 `json:"upgradable,omitempty"`
	SecurityUpgradable *uint32 `json:"security_upgradable,omitempty"`
	UnavailableReason  string  `json:"unavailable_reason,omitempty"`
}

// Health to sygnaly wysylane w heartbeacie. Wskazniki puste oznaczaja stan
// nieustalony i nie sa wysylane do control plane.
type Health struct {
	FailedUnits            *uint32
	RebootRequired         *bool
	Load1Milli             uint32
	RootFSUsedPercent      uint32
	UptimeSeconds          uint64
	PendingUpdates         *uint32
	PendingSecurityUpdates *uint32
}

// Facts to pelny raport inventory hosta.
type Facts struct {
	Hostname  string   `json:"hostname"`
	MachineID string   `json:"machine_id"`
	BootID    string   `json:"boot_id"`
	OS        OSInfo   `json:"os"`
	Hardware  Hardware `json:"hardware"`
	Packages  Packages `json:"packages"`
	// Repositories jest lista zrodel pakietow. Pusta lista i lista
	// nieodczytana to dwie rozne odpowiedzi, wiec obraz niesie swoj wlasny
	// znacznik i powod.
	Repositories *packages.ObrazRepozytoriow `json:"repositories,omitempty"`
	Capabilities Capabilities                `json:"capabilities"`
	FailedUnits  []string                    `json:"failed_units"`
	// Puste pola oznaczaja, ze stanu nie udalo sie ustalic.
	FailedUnitsKnown bool           `json:"failed_units_known"`
	RebootRequired   *bool          `json:"reboot_required,omitempty"`
	Identity         IdentityState  `json:"identity"`
	LocalAccounts    []LocalAccount `json:"local_accounts,omitempty"`
	Interfaces       []string       `json:"network_interfaces"`
	// Containers jest podsumowaniem silnika kontenerow. Puste oznacza host
	// bez silnika albo silnik nieodpytany - rozroznia je unavailable_reason.
	Containers *docker.Summary `json:"containers,omitempty"`
	// Network jest obrazem interfejsow i tras z jadra. Brak wartosci oznacza
	// cykl, w ktorym stanu nie zbierano.
	Network *network.Snapshot `json:"network,omitempty"`
	// Files jest stanem plikow, ktore panel zapisal na tym hoscie.
	Files *files.Snapshot `json:"files,omitempty"`
	// Kernel jest ustawieniami jadra i lista modulow.
	Kernel *kernel.Snapshot `json:"kernel,omitempty"`
	// Security jest stanem ochronnym hosta: MAC, audyt, tryb rozruchu
	// i to, czym host wystaje na zewnatrz.
	Security *security.Snapshot `json:"security,omitempty"`
	// Certificates jest obrazem certyfikatow, o ktore panel prosil, oraz
	// tych, ktorych host pilnuje sam. Modul nie przeszukuje dysku, wiec pusta
	// lista oznacza brak wskazanych plikow, a nie host bez certyfikatow.
	Certificates *certificates.Snapshot `json:"certificates,omitempty"`
	// Power jest stanem startu hosta: boot_id, czas dzialania i to, co
	// wstrzymuje wylaczenie.
	Power *power.Snapshot `json:"power,omitempty"`
	// Time jest czasem hosta i stanem jego synchronizacji. Przesuniety zegar
	// psuje Kerberosa i mTLS, wiec jest faktem o hoscie, a nie ciekawostka.
	Time *czas.Snapshot `json:"time,omitempty"`
	// SSH jest konfiguracja serwera sshd.
	SSH *sshmodul.Snapshot `json:"ssh,omitempty"`
	// Storage jest obrazem przestrzeni dyskowej hosta.
	Storage *storage.Snapshot `json:"storage,omitempty"`
	// Firewall jest stanem zapory hosta.
	Firewall *firewall.Snapshot `json:"firewall,omitempty"`
	// DNS jest stanem resolvera hosta.
	DNS *dnsmodul.Snapshot `json:"dns,omitempty"`
	// Schedules to zadania cykliczne hosta. Brak wartosci oznacza host bez
	// crona albo odczyt, ktory sie nie powiodl - rozroznia je pole
	// unavailable_reason w srodku migawki.
	Schedules   *schedules.Snapshot `json:"schedules,omitempty"`
	CollectedAt time.Time           `json:"collected_at"`
}

// Revision liczy stabilna rewizje z tresci raportu. Identyczny stan hosta daje
// identyczna rewizje, wiec serwer nie zapisuje kolejnego wiersza bez zmian.
func (f Facts) Revision() (string, []byte, error) {
	// Znacznik czasu nie moze wplywac na rewizje.
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

// MachineID zwraca stabilny identyfikator maszyny.
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

// BootID zmienia sie przy kazdym restarcie hosta i konczy faze reboot.
func BootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ReadOSInfo czyta /etc/os-release i wersje jadra.
func ReadOSInfo() OSInfo {
	info := OSInfo{Architecture: runtime.GOARCH}
	release := parseKeyValueFile("/etc/os-release")
	info.Distribution = release["ID"]
	info.Version = firstNonEmpty(release["VERSION_ID"], release["VERSION"])
	info.PrettyName = release["PRETTY_NAME"]
	info.Family = osFamily(release)

	if kernel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(kernel))
	}
	return info
}

// osFamily mapuje dystrybucje na rodzine adapterow, a nie na marketingowa nazwe.
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

// ReadHardware czyta zasoby hosta wylacznie z /proc i statfs.
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

// ReadHealth zbiera sygnaly heartbeatu bez uruchamiania procesow potomnych.
// Wartosci wymagajace procesu pochodza z ostatniego cyklu inventory.
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

// runtimeDir jest katalogiem zapisywalnym dla uzytkownika agenta. Narzedzia
// systemowe takie jak dnf potrzebuja HOME i katalogow XDG; agent nie ma
// katalogu domowego, wiec bez tego koncza sie bledem, ktory latwo pomylic
// z wynikiem merytorycznym.
var runtimeDir = os.TempDir()

// SetRuntimeDir wskazuje katalog roboczy dla uruchamianych narzedzi.
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

// commandResult oddziela fakt uruchomienia procesu od jego wyniku. Kod wyjscia
// ma znaczenie wylacznie wtedy, gdy proces faktycznie sie wykonal.
type commandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Ran      bool
	Err      error
}

// Reason opisuje powod, dla ktorego nie udalo sie ustalic wartosci.
func (r commandResult) Reason() string {
	switch {
	case r.Err != nil && !r.Ran:
		return r.Err.Error()
	case strings.TrimSpace(r.Stderr) != "":
		return fmt.Sprintf("kod %d: %s", r.ExitCode, firstLine(r.Stderr))
	default:
		return fmt.Sprintf("kod %d", r.ExitCode)
	}
}

// runCommand uruchamia proces ze stala sciezka i tablica argumentow.
// Nigdy nie uzywamy sh -c, wiec tresc danych nie moze stac sie poleceniem.
// LC_ALL=C stabilizuje output, ktory musimy parsowac.
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
		// Proces sie wykonal i sam zwrocil kod, wiec kod cos znaczy.
		result.Ran, result.ExitCode = true, exitErr.ExitCode()
	}
	if cmdCtx.Err() != nil {
		// Przekroczony timeout nie jest wynikiem merytorycznym.
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
