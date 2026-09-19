package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

// InstalledPackage describes one installed package in the form that is enough
// to correlate it with the security tracker of a distribution.
type InstalledPackage struct {
	Name string `json:"name"`
	// SourceName and SourceVersion are the source package.
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`

	// Epoch is empty when the package has none.
	Epoch        string `json:"epoch,omitempty"`
	Version      string `json:"version"`
	Release      string `json:"release,omitempty"`
	Architecture string `json:"architecture,omitempty"`

	SourceRPM string `json:"source_rpm,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	// RepositoryID says where the package came from. Empty means the host did not
	// record it - not that the package comes from outside the repositories.
	RepositoryID string `json:"repository_id,omitempty"`
	ModuleStream string `json:"module_stream,omitempty"`
	// Origin is the address of the repository the installed version comes from,
	// and OriginClass is its classification.
	Origin      string `json:"origin,omitempty"`
	OriginClass string `json:"origin_class,omitempty"`
}

// The classes of the origin of a package.
const (
	OriginDistribution = "vendor_distribution"
	OriginThirdParty   = "third_party_repository"
	OriginLocal        = "local_package"
	OriginUnknown      = "origin_unknown"
)

// EVR assembles the version in the form the RPM comparison uses.
func (p InstalledPackage) EVR() string {
	version := p.Version
	if p.Epoch != "" && p.Epoch != "0" {
		version = p.Epoch + ":" + version
	}
	if p.Release != "" {
		version += "-" + p.Release
	}
	return version
}

// DebVersion assembles the version in the form the Debian comparison uses.
func (p InstalledPackage) DebVersion() string {
	version := p.Version
	if p.Epoch != "" {
		version = p.Epoch + ":" + version
	}
	if p.Release != "" {
		version += "-" + p.Release
	}
	return version
}

// InstalledList is the image of the packages of a host.
type InstalledList struct {
	Manager  string             `json:"manager"`
	Packages []InstalledPackage `json:"packages,omitempty"`
	// Digest identifies the content of the list.
	Digest string `json:"digest"`
	Count  int    `json:"count"`
	// ObservedAt is the moment of the read; a correlation without the age of the
	// data makes no sense, because there is no telling what the answer concerns.
	ObservedAt time.Time `json:"observed_at"`
	// UnavailableReason says why the list is missing.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Digest computes the digest of the package list in its canonical form.
const listCanonicalisationVersion = 2

// Digest computes the digest of a package list.
func Digest(pkgs []InstalledPackage) string {
	copied := make([]InstalledPackage, len(pkgs))
	copy(copied, pkgs)
	sort.Slice(copied, func(i, j int) bool {
		if copied[i].Name != copied[j].Name {
			return copied[i].Name < copied[j].Name
		}
		if copied[i].Architecture != copied[j].Architecture {
			return copied[i].Architecture < copied[j].Architecture
		}
		return copied[i].EVR() < copied[j].EVR()
	})

	sum := sha256.New()
	sum.Write([]byte("flotestro/packages/v" + strconv.Itoa(listCanonicalisationVersion) + "\n"))
	for _, pkg := range copied {
		sum.Write([]byte(strings.Join([]string{
			pkg.Name, pkg.Epoch, pkg.Version, pkg.Release,
			pkg.Architecture, pkg.SourceName, pkg.SourceVersion,
			pkg.OriginClass,
		}, "\x1f")))
		sum.Write([]byte{'\n'})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// Installed reads the full package list of a host. The read does not require
// root: the dpkg database and the RPM database are readable by everyone.
func Installed(ctx context.Context, manager string) InstalledList {
	list := InstalledList{Manager: manager, ObservedAt: time.Now().UTC()}
	switch manager {
	case "apt":
		list.Packages, list.UnavailableReason = installedAPT(ctx)
	case "dnf":
		list.Packages, list.UnavailableReason = installedRPM(ctx)
	case PacmanName:
		list.Packages, list.UnavailableReason = installedPacman(ctx)
	default:
		list.UnavailableReason = "this package manager cannot list installed packages"
	}
	list.Count = len(list.Packages)
	list.Digest = Digest(list.Packages)
	return list
}

// installedAPT reads the dpkg database together with the source packages.
func installedAPT(ctx context.Context) ([]InstalledPackage, string) {
	// The source:Version field is empty when the source version equals the binary
	// one; dpkg-query fills it in only when they differ, so we fill it in
	// ourselves.
	format := `${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\t` +
		`${source:Package}\t${source:Version}\n`
	var pkgs []InstalledPackage
	result := runLines(ctx, 2*time.Minute, func(line string) {
		if pkg, ok := DpkgQueryLine(line); ok {
			pkgs = append(pkgs, pkg)
		}
	}, "/usr/bin/dpkg-query", "-W", "-f", format)
	if !result.Complete() {
		return nil, result.unreadable("dpkg-query")
	}
	if len(pkgs) == 0 {
		return nil, "dpkg-query returned an empty list"
	}
	// The origin is read in one call for every package: a separate question
	// about each of four hundred would be four hundred processes.
	FillAPTOrigin(ctx, pkgs)
	return pkgs, ""
}

// DpkgQueryLine reads one tab-separated row of the dpkg database as
// installedAPT asks for it.
func DpkgQueryLine(line string) (InstalledPackage, bool) {
	fields := strings.Split(line, "\t")
	if len(fields) < 6 {
		return InstalledPackage{}, false
	}
	// A package removed with its configuration left behind is not installed: its
	// code no longer lies on the host, so it is not vulnerable either.
	if strings.TrimSpace(fields[0]) != "installed" {
		return InstalledPackage{}, false
	}
	pkg := InstalledPackage{
		Name:          strings.TrimSpace(fields[1]),
		Version:       strings.TrimSpace(fields[2]),
		Architecture:  strings.TrimSpace(fields[3]),
		SourceName:    strings.TrimSpace(fields[4]),
		SourceVersion: strings.TrimSpace(fields[5]),
	}
	if pkg.Name == "" || pkg.Version == "" {
		return InstalledPackage{}, false
	}
	if pkg.SourceName == "" {
		pkg.SourceName = pkg.Name
	}
	if pkg.SourceVersion == "" {
		pkg.SourceVersion = pkg.Version
	}
	return pkg, true
}

// FillAPTOrigin writes to the packages the repository the installed version
// came from.
func FillAPTOrigin(ctx context.Context, pkgs []InstalledPackage) {
	if len(pkgs) == 0 {
		return
	}
	names := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		names = append(names, pkg.Name)
	}
	// The blocks are read as they arrive: the answer for a whole host is the
	// longest output the inventory ever takes, and only its distillate is kept.
	reader := newAPTPolicyReader()
	result := runLines(ctx, 3*time.Minute, reader.line,
		"/usr/bin/apt-cache", append([]string{"policy"}, names...)...)
	if !result.Complete() {
		// Missing knowledge about the origin stays missing knowledge: the correlator
		// treats such packages as undetermined rather than as packages of the
		// distribution.
		return
	}
	origin := reader.done()
	for i := range pkgs {
		if entry, known := origin[pkgs[i].Name]; known {
			pkgs[i].Origin = entry.Origin
			pkgs[i].OriginClass = entry.Class
		} else {
			pkgs[i].OriginClass = OriginUnknown
		}
	}
}

// OriginEntry describes the source of the installed version of a package.
type OriginEntry struct {
	Origin string
	Class  string
}

// ParseAPTPolicy reads the output of "apt-cache policy" for many packages.
func ParseAPTPolicy(output string) map[string]OriginEntry {
	reader := newAPTPolicyReader()
	for _, line := range strings.Split(output, "\n") {
		reader.line(line)
	}
	return reader.done()
}

// aptPolicyReader turns the blocks of "apt-cache policy" into origins as the
// lines arrive, so the answer for a whole host never exists at once.
type aptPolicyReader struct {
	result      map[string]OriginEntry
	name        string
	installed   string
	inInstalled bool
	fromVersion OriginEntry
	fromPackage OriginEntry
}

func newAPTPolicyReader() *aptPolicyReader {
	return &aptPolicyReader{result: map[string]OriginEntry{}}
}

// closeBlock records what the block that has just ended says about its package.
func (r *aptPolicyReader) closeBlock() {
	if r.name == "" || r.installed == "" || r.installed == "(none)" {
		return
	}
	switch {
	case r.fromVersion.Class != "" && r.fromVersion.Class != OriginLocal:
		r.result[r.name] = r.fromVersion
	case r.fromPackage.Class != "":
		// A withdrawn version: the package still belongs to the repository it came
		// from, even though that version of it is no longer there.
		r.result[r.name] = r.fromPackage
	case r.fromVersion.Class != "":
		r.result[r.name] = r.fromVersion
	default:
		r.result[r.name] = OriginEntry{Class: OriginUnknown}
	}
}

func (r *aptPolicyReader) line(line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}
	// The header of a block: "name:" at the left edge.
	if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
		r.closeBlock()
		r.name = strings.TrimSuffix(trimmed, ":")
		if colon := strings.Index(r.name, ":"); colon > 0 {
			// A multi-architecture package carries an architecture suffix.
			r.name = r.name[:colon]
		}
		r.installed, r.inInstalled = "", false
		r.fromVersion, r.fromPackage = OriginEntry{}, OriginEntry{}
		return
	}
	if r.name == "" {
		return
	}
	if strings.HasPrefix(trimmed, "Installed:") {
		r.installed = strings.TrimSpace(strings.TrimPrefix(trimmed, "Installed:"))
		return
	}
	fields := strings.Fields(trimmed)
	if strings.HasPrefix(trimmed, "***") {
		r.inInstalled = len(fields) >= 2 && fields[1] == r.installed
		return
	}
	switch {
	case len(fields) >= 2 && onlyDigits(fields[0]):
		// A source line: the priority, the address, the suite, the component.
		entry := APTSourceClass(trimmed)
		if r.inInstalled && r.fromVersion.Class == "" {
			r.fromVersion = entry
		}
		if entry.Class == OriginDistribution ||
			(entry.Class == OriginThirdParty && r.fromPackage.Class == "") {
			r.fromPackage = entry
		}
	case len(fields) >= 2 && onlyDigits(fields[len(fields)-1]):
		// The line of a further version: from this point on the sources
		// concern it rather than the installed version.
		r.inInstalled = false
	}
}

// done closes the last block and hands over what was read.
func (r *aptPolicyReader) done() map[string]OriginEntry {
	r.closeBlock()
	r.name = ""
	return r.result
}

// onlyDigits says whether a string consists of digits alone.
func onlyDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// distributionAddresses recognises the repositories of the vendor.
var distributionAddresses = []string{
	"debian.org", "debian.net", "ubuntu.com", "canonical.com", "raspbian.org",
}

// APTSourceClass classifies a source line from "apt-cache policy".
func APTSourceClass(row string) OriginEntry {
	fields := strings.Fields(row)
	if len(fields) < 2 {
		return OriginEntry{Class: OriginUnknown}
	}
	address := fields[1]
	if strings.Contains(address, "/var/lib/dpkg/status") {
		// A version known from the state file alone: the package arrived from
		// outside the repositories - by hand or from a local build.
		return OriginEntry{Origin: address, Class: OriginLocal}
	}
	for _, vendor := range distributionAddresses {
		if strings.Contains(address, vendor) {
			return OriginEntry{Origin: address, Class: OriginDistribution}
		}
	}
	return OriginEntry{Origin: address, Class: OriginThirdParty}
}

// installedRPM reads the RPM database in the full NEVRA form.
func installedRPM(ctx context.Context) ([]InstalledPackage, string) {
	format := `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\n`
	var pkgs []InstalledPackage
	result := runLines(ctx, 2*time.Minute, func(line string) {
		if pkg, ok := RPMQueryLine(line); ok {
			pkgs = append(pkgs, pkg)
		}
	}, rpmPath, "-qa", "--qf", format)
	if !result.Complete() {
		return nil, result.unreadable("rpm -qa")
	}
	if len(pkgs) == 0 {
		return nil, "rpm -qa returned an empty list"
	}
	return pkgs, ""
}

// RPMQueryLine reads one tab-separated row of the RPM database as
// installedRPM asks for it.
func RPMQueryLine(line string) (InstalledPackage, bool) {
	fields := strings.Split(line, "\t")
	if len(fields) < 7 {
		return InstalledPackage{}, false
	}
	pkg := InstalledPackage{
		Name:         strings.TrimSpace(fields[0]),
		Epoch:        strings.TrimSpace(fields[1]),
		Version:      strings.TrimSpace(fields[2]),
		Release:      strings.TrimSpace(fields[3]),
		Architecture: strings.TrimSpace(fields[4]),
		SourceRPM:    strings.TrimSpace(fields[5]),
		Vendor:       strings.TrimSpace(fields[6]),
	}
	if pkg.Name == "" || pkg.Version == "" {
		return InstalledPackage{}, false
	}
	// EPOCHNUM gives "0" also when the package has no epoch; we record that as a
	// missing epoch, because that is how the advisories speak about it.
	if pkg.Epoch == "0" || pkg.Epoch == "(none)" {
		pkg.Epoch = ""
	}
	if pkg.Vendor == "(none)" {
		pkg.Vendor = ""
	}
	pkg.SourceName, pkg.SourceVersion = SourceFromSourceRPM(pkg.SourceRPM)
	return pkg, true
}

// SourceFromSourceRPM extracts the name and the version of the source out of
// the name of the source file.
func SourceFromSourceRPM(sourceRPM string) (name, version string) {
	file := strings.TrimSuffix(strings.TrimSpace(sourceRPM), ".src.rpm")
	if file == "" || file == "(none)" {
		return "", ""
	}
	last := strings.LastIndex(file, "-")
	if last <= 0 {
		return file, ""
	}
	release := file[last+1:]
	rest := file[:last]
	secondLast := strings.LastIndex(rest, "-")
	if secondLast <= 0 {
		return rest, release
	}
	return rest[:secondLast], rest[secondLast+1:] + "-" + release
}
