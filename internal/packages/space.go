package packages

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The space a package change needs is not one number.

// The purposes of a space fact: what the bytes on that path are for.
const (
	SpaceDownload = "download"
	SpaceInstall  = "install"
	SpaceBoot     = "boot"
)

// The bases of an estimate. The needed bytes are only as good as where they
// come from, and the operator is to know that before trusting them.
const (
	// BasisDownloadSize: the sizes of the archives from the package index.
	BasisDownloadSize = "download_size"
	// BasisInstalledSize: the growth of the installed size, package by
	// package, from the metadata of the candidate and the installed version.
	BasisInstalledSize = "installed_size"
	// BasisDownloadOnly: the installed size could not be read, so the size of the
	// archives stands in - a lower bound, because the archives are compressed.
	BasisDownloadOnly = "download_only"
	// BasisBootFiles: the files the running kernel keeps in /boot; a new
	// kernel of the same host needs about as much.
	BasisBootFiles = "boot_files"
	// BasisUnknown: nothing could be measured. Such a fact is reported and
	// never judged - an unknown size is not zero.
	BasisUnknown = "unknown"
)

// SpaceFact says how much a path needs and how much its file system has.
type SpaceFact struct {
	Path string `json:"path"`
	// Filesystem is the mount point the path lives on. Facts about paths on
	// the same mount point share its free space and are judged together.
	Filesystem     string `json:"filesystem"`
	AvailableBytes uint64 `json:"available_bytes"`
	NeededBytes    uint64 `json:"needed_bytes"`
	Purpose        string `json:"purpose"`
	Basis          string `json:"basis"`
}

// Known says whether the needed bytes were measured at all.
func (f SpaceFact) Known() bool {
	return f.Basis != BasisUnknown && f.Basis != ""
}

// ErrNoSpace means a file system the change writes to does not have the bytes
// the change needs.
var ErrNoSpace = errors.New("not enough free space")

// The headroom over the bytes a plan counts.
const (
	spaceHeadroomPercent        = 5
	spaceHeadroomMinimum uint64 = 64 << 20
)

// spaceHeadroom is the margin a change of the given size has to leave.
func spaceHeadroom(needed uint64) uint64 {
	headroom := needed * spaceHeadroomPercent / 100
	if headroom < spaceHeadroomMinimum {
		return spaceHeadroomMinimum
	}
	return headroom
}

// SpaceShortfall judges the facts of a plan.
func SpaceShortfall(facts []SpaceFact) error {
	type demand struct {
		needed    uint64
		available uint64
		paths     []string
	}
	demands := map[string]*demand{}
	var order []string
	for _, fact := range facts {
		if !fact.Known() || fact.Filesystem == "" {
			continue
		}
		entry, seen := demands[fact.Filesystem]
		if !seen {
			entry = &demand{available: fact.AvailableBytes}
			demands[fact.Filesystem] = entry
			order = append(order, fact.Filesystem)
		}
		entry.needed += fact.NeededBytes
		entry.paths = append(entry.paths, fact.Path)
	}
	sort.Strings(order)
	for _, filesystem := range order {
		entry := demands[filesystem]
		required := entry.needed + spaceHeadroom(entry.needed)
		if required <= entry.available {
			continue
		}
		return fmt.Errorf("%w on %s (%s): %s needed with the headroom, %s available",
			ErrNoSpace, filesystem, strings.Join(entry.paths, ", "),
			FormatBytes(required), FormatBytes(entry.available))
	}
	return nil
}

// FormatBytes writes a size the way a person reads it.
func FormatBytes(size uint64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	value := float64(size)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value /= unit
		if value < unit || suffix == "TiB" {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%d B", size)
}

// spaceFact measures a path.
func spaceFact(path, purpose string, needed uint64, basis string) SpaceFact {
	existing := nearestExisting(path)
	return SpaceFact{
		Path:           path,
		Filesystem:     mountPointOf(existing),
		AvailableBytes: diskAvailable(existing),
		NeededBytes:    needed,
		Purpose:        purpose,
		Basis:          basis,
	}
}

// nearestExisting walks up from the path to the first directory that exists.
func nearestExisting(path string) string {
	for {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			return path
		}
		path = parent
	}
}

// mountPointOf finds the mount point of a path: the highest ancestor on the
// same device.
func mountPointOf(path string) string {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return ""
	}
	device := stat.Dev
	mount := path
	for {
		parent := filepath.Dir(mount)
		if parent == mount {
			return mount
		}
		if err := unix.Stat(parent, &stat); err != nil || stat.Dev != device {
			return mount
		}
		mount = parent
	}
}

// spaceNeeds is what an adapter learnt about the sizes of a plan.
type spaceNeeds struct {
	download      uint64
	downloadKnown bool
	// install is the growth of the installed files; its basis says how
	// trustworthy the number is.
	install      uint64
	installBasis string
	// kernel says whether a kernel package is in the plan.
	kernel bool
}

// spaceFacts assembles the facts of a plan from what the adapter measured
// and the paths of its manager.
func spaceFacts(cacheDir, databaseDir string, needs spaceNeeds) []SpaceFact {
	downloadBasis := BasisUnknown
	if needs.downloadKnown {
		downloadBasis = BasisDownloadSize
	}
	facts := []SpaceFact{
		spaceFact(cacheDir, SpaceDownload, needs.download, downloadBasis),
	}

	installBasis := needs.installBasis
	if installBasis == "" {
		installBasis = BasisUnknown
	}
	install := spaceFact(installRoot, SpaceInstall, needs.install, installBasis)
	facts = append(facts, install)

	// The package database grows with every transaction, but by how much nobody
	// publishes.
	database := spaceFact(databaseDir, SpaceInstall, 0, BasisUnknown)
	if database.Filesystem != install.Filesystem {
		facts = append(facts, database)
	}

	if needs.kernel {
		size, known := bootFilesSize(bootDir, runningKernelRelease())
		basis := BasisUnknown
		if known {
			basis = BasisBootFiles
		}
		facts = append(facts, spaceFact(bootDir, SpaceBoot, size, basis))
	}
	return facts
}

// The paths every family shares.
const (
	installRoot = "/usr"
	bootDir     = "/boot"
)

// runningKernelRelease is the release of the running kernel, or nothing
// when it cannot be read.
func runningKernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return strings.TrimRight(string(uts.Release[:]), "\x00")
}

// bootFilesSize sums up the files of the running kernel in the boot directory:
// its image, its initramfs, its symbol map.
func bootFilesSize(dir, release string) (uint64, bool) {
	if release == "" {
		return 0, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, false
	}
	var total uint64
	found := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.Contains(entry.Name(), release) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		total += uint64(info.Size())
		found = true
	}
	return total, found
}

// KernelPackage recognises a kernel by the name of its package in the given
// family.
func KernelPackage(manager, name string) bool {
	switch manager {
	case "apt":
		// linux-image-6.1.0-25-amd64 and the metapackages linux-image-amd64,
		// linux-image-generic; the headers and the tools stay in /usr.
		return strings.HasPrefix(name, "linux-image-")
	case "dnf":
		// kernel and kernel-core carry the image; the variants - kernel-rt-core,
		// kernel-debug-core, kernel-64k-core - do the same under their own names.
		return name == "kernel" || name == "kernel-core" ||
			strings.HasPrefix(name, "kernel-") && strings.HasSuffix(name, "-core")
	case "pacman":
		return pacmanKernelPackage(name)
	}
	return false
}

// anyKernel says whether a kernel of the family is among the changes.
func anyKernel(manager string, changes []Change) bool {
	for _, change := range changes {
		if KernelPackage(manager, change.Name) {
			return true
		}
	}
	return false
}

// growth sums up how much the named packages grow: the installed size of the
// candidate over the installed size of what is there now.
func growth(names []string, candidate, current map[string]uint64) (uint64, bool) {
	var total uint64
	for _, name := range names {
		size, ok := candidate[name]
		if !ok {
			return 0, false
		}
		if installed := current[name]; size > installed {
			total += size - installed
		}
	}
	return total, true
}

// installNeeds fills the install part of the needs from the growth or,
// when the growth is not known, from the download size.
func installNeeds(needs *spaceNeeds, grown uint64, known bool) {
	switch {
	case known:
		needs.install, needs.installBasis = grown, BasisInstalledSize
	case needs.downloadKnown:
		needs.install, needs.installBasis = needs.download, BasisDownloadOnly
	default:
		needs.installBasis = BasisUnknown
	}
}

// ParseHumanSize reads a size the tools print for people: "12 M", "1. 2 GiB",
// "345 k", "512 B".
func ParseHumanSize(text string) (uint64, bool) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 || len(fields) > 2 {
		return 0, false
	}
	number, unit := fields[0], ""
	if len(fields) == 2 {
		unit = fields[1]
	} else {
		// "12M" without a space: split the trailing letters off.
		index := strings.LastIndexAny(number, "0123456789.")
		if index < 0 {
			return 0, false
		}
		number, unit = number[:index+1], number[index+1:]
	}
	value, err := strconv.ParseFloat(number, 64)
	if err != nil || value < 0 {
		return 0, false
	}
	multiplier, ok := sizeMultipliers[strings.TrimSuffix(strings.ToLower(unit), "b")]
	if !ok {
		return 0, false
	}
	// "inf M" and "nan k" pass strconv as numbers, and a product past the largest
	// integer has no defined conversion: each came out as a size that was neither
	// refused nor real.
	total := value * float64(multiplier)
	if math.IsNaN(total) || math.IsInf(total, 0) || total >= math.MaxUint64 {
		return 0, false
	}
	return uint64(total), true
}

// sizeMultipliers maps the letter of a unit, with any "B" or "iB" trimmed,
// to its multiplier.
var sizeMultipliers = map[string]uint64{
	"": 1, "k": 1 << 10, "ki": 1 << 10, "m": 1 << 20, "mi": 1 << 20,
	"g": 1 << 30, "gi": 1 << 30, "t": 1 << 40, "ti": 1 << 40,
}
