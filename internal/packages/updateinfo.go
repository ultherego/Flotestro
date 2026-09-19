package packages

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Advisory is a vendor finding known to the host from the metadata of its
// repositories.
type Advisory struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title,omitempty"`
	// CVEIDs are gathered from the description and from the references: the
	// vendor gives them in both places and not always in the same one.
	CVEIDs []string `json:"cve_ids,omitempty"`
	// Packages lists the versions that close the finding.
	Packages []AdvisoryPackage `json:"packages,omitempty"`
	IssuedAt *time.Time        `json:"issued_at,omitempty"`
}

// AdvisoryPackage is one version of a package that closes a finding.
type AdvisoryPackage struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture,omitempty"`
	// EVR is the full version with the epoch, if the vendor gave one.
	EVR string `json:"evr"`
}

// TypeSecurity marks a security finding. The remaining types - bug fixes and
// new features - are not vulnerabilities and must not reach the assessment.
const TypeSecurity = "security"

// cvePattern catches CVE identifiers anywhere in a description.
var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// ReasonAdvisoriesUnreadable is the typed reason the panel reads when the
// host's own metadata could not be turned into findings.
const ReasonAdvisoriesUnreadable = "host_advisories_unreadable"

// Advisories reads the vendor findings known to the host.
func Advisories(ctx context.Context, manager string,
	installed []InstalledPackage) ([]Advisory, string) {
	if manager != "dnf" {
		// APT has no updateinfo: for Debian and Ubuntu the panel fetches the
		// findings straight from the tracker of the vendor.
		return nil, ""
	}
	// --cacheonly, like every other dnf call of this module: the findings are
	// read from the metadata the host already has, never fetched here.
	// Every advisory the vendor ever published is in that answer; each block is
	// narrowed as it closes, so the ones this host does not carry never pile up.
	present := installedSet(installed)
	var kept []Advisory
	reader := newUpdateinfoReader(func(advisory Advisory) {
		if narrowed, ok := narrowAdvisory(advisory, present); ok {
			kept = append(kept, narrowed)
		}
	})
	result := runLines(ctx, 5*time.Minute, reader.line,
		dnfPath, "--cacheonly", "updateinfo", "info", "--all", "--with-cve")
	if !result.Complete() {
		// A typed reason, because the panel judges coverage by it: a shell
		// message there reads as a host nobody assessed, with no code to act on.
		return nil, ReasonAdvisoriesUnreadable + ": " + result.Reason()
	}
	reader.done()
	return kept, ""
}

// NarrowToInstalled keeps the security findings that concern the packages
// really present on this host.
func NarrowToInstalled(advisories []Advisory, installed []InstalledPackage) []Advisory {
	if len(installed) == 0 {
		return nil
	}
	present := installedSet(installed)
	var result []Advisory
	for _, advisory := range advisories {
		if narrowed, ok := narrowAdvisory(advisory, present); ok {
			result = append(result, narrowed)
		}
	}
	return result
}

// installedSet indexes the packages of the host by name and architecture.
func installedSet(installed []InstalledPackage) map[string]bool {
	present := make(map[string]bool, 2*len(installed))
	for _, pkg := range installed {
		present[pkg.Name+"\x1f"+pkg.Architecture] = true
		present[pkg.Name+"\x1fnoarch"] = present[pkg.Name+"\x1fnoarch"] || pkg.Architecture == "noarch"
	}
	return present
}

// narrowAdvisory keeps a finding only where it concerns a package this host
// really carries, and only where it is a security finding.
func narrowAdvisory(advisory Advisory, present map[string]bool) (Advisory, bool) {
	// Bug fixes and new features are not vulnerabilities and must not
	// reach the security assessment.
	if advisory.Type != TypeSecurity || len(present) == 0 {
		return Advisory{}, false
	}
	var matching []AdvisoryPackage
	for _, pkg := range advisory.Packages {
		if present[pkg.Name+"\x1f"+pkg.Architecture] {
			matching = append(matching, pkg)
		}
	}
	if len(matching) == 0 {
		return Advisory{}, false
	}
	advisory.Packages = matching
	return advisory, true
}

// ParseUpdateinfo reads the block format of "dnf updateinfo info".
func ParseUpdateinfo(output string) []Advisory {
	var advisories []Advisory
	reader := newUpdateinfoReader(func(advisory Advisory) {
		advisories = append(advisories, advisory)
	})
	for _, line := range strings.Split(output, "\n") {
		reader.line(line)
	}
	reader.done()
	return advisories
}

// updateinfoReader turns the blocks of "dnf updateinfo info" into findings as
// the lines arrive and hands each one over the moment its block closes.
type updateinfoReader struct {
	emit       func(Advisory)
	current    *Advisory
	inPackages bool
}

func newUpdateinfoReader(emit func(Advisory)) *updateinfoReader {
	return &updateinfoReader{emit: emit}
}

func (r *updateinfoReader) flush() {
	if r.current != nil && r.current.ID != "" {
		r.current.CVEIDs = unique(r.current.CVEIDs)
		r.emit(*r.current)
	}
	r.current, r.inPackages = nil, false
}

// done closes the last block; a file that ends without a blank line still has
// one finding in it.
func (r *updateinfoReader) done() { r.flush() }

func (r *updateinfoReader) line(line string) {
	if strings.TrimSpace(line) == "" {
		r.flush()
		return
	}
	key, value, ok := splitRow(line)
	if !ok {
		return
	}
	indented := line[0] == ' ' || line[0] == '\t'

	if key == "Name" && !indented {
		r.flush()
		r.current = &Advisory{ID: value}
		return
	}
	if r.current == nil {
		return
	}

	switch {
	case key == "" && r.inPackages:
		// A further package of the collection: a line without a key
		// continues the list.
		if pkg, ok := ParseNEVRA(value); ok {
			r.current.Packages = append(r.current.Packages, pkg)
		}
		return
	case key == "Packages" && indented:
		r.inPackages = true
		if pkg, ok := ParseNEVRA(value); ok {
			r.current.Packages = append(r.current.Packages, pkg)
		}
		return
	case indented:
		// A nested key: it does not describe the finding, but it can carry
		// a CVE in the title of a reference.
		r.inPackages = false
		r.current.CVEIDs = append(r.current.CVEIDs, cvePattern.FindAllString(value, -1)...)
		return
	}

	r.inPackages = false
	switch key {
	case "Title":
		if r.current.Title == "" {
			r.current.Title = value
		}
	case "Type":
		r.current.Type = strings.ToLower(value)
	case "Severity":
		r.current.Severity = FedoraSeverity(value)
	case "Issued":
		if moment, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
			momentUTC := moment.UTC()
			r.current.IssuedAt = &momentUTC
		}
	}
	// A CVE appears in the description, in the title of a reference or in both:
	// we gather them from the whole block instead of trusting one place.
	r.current.CVEIDs = append(r.current.CVEIDs, cvePattern.FindAllString(value, -1)...)
}

// splitRow divides a row into a key and a value.
func splitRow(line string) (key, value string, ok bool) {
	colon := strings.Index(line, ":")
	if colon < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:colon])
	value = strings.TrimSpace(line[colon+1:])
	return key, value, true
}

// ParseNEVRA reads the file name of a package in the form
// name-version-release.
func ParseNEVRA(entry string) (AdvisoryPackage, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return AdvisoryPackage{}, false
	}
	dot := strings.LastIndex(entry, ".")
	if dot <= 0 {
		return AdvisoryPackage{}, false
	}
	architecture := entry[dot+1:]
	rest := entry[:dot]

	last := strings.LastIndex(rest, "-")
	if last <= 0 {
		return AdvisoryPackage{}, false
	}
	release := rest[last+1:]
	rest = rest[:last]

	secondLast := strings.LastIndex(rest, "-")
	if secondLast <= 0 {
		return AdvisoryPackage{}, false
	}
	version := rest[secondLast+1:]
	name := rest[:secondLast]
	if name == "" || version == "" || release == "" {
		return AdvisoryPackage{}, false
	}
	return AdvisoryPackage{
		Name: name, Architecture: architecture, EVR: version + "-" + release,
	}, true
}

// FedoraSeverity translates the severity of the vendor into a uniform
// vocabulary.
func FedoraSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "urgent":
		return "critical"
	case "important", "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low", "minor":
		return "low"
	}
	// "None" is not a severity: it is a missing severity and is to stay one.
	return ""
}

// unique removes the repetitions, keeping the alphabetical order.
func unique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]bool{}
	var result []string
	for _, value := range values {
		if set[value] {
			continue
		}
		set[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
