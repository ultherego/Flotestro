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
	result := run(ctx, 5*time.Minute, dnfPath, "--cacheonly", "updateinfo", "info", "--all", "--with-cve")
	if !result.Ran || result.ExitCode != 0 {
		// A typed reason, because the panel judges coverage by it: a shell
		// message there reads as a host nobody assessed, with no code to act on.
		return nil, ReasonAdvisoriesUnreadable + ": " + result.Reason()
	}
	return NarrowToInstalled(ParseUpdateinfo(result.Stdout), installed), ""
}

// NarrowToInstalled keeps the security findings that concern the packages
// really present on this host.
func NarrowToInstalled(advisories []Advisory, installed []InstalledPackage) []Advisory {
	if len(installed) == 0 {
		return nil
	}
	present := map[string]bool{}
	for _, pkg := range installed {
		present[pkg.Name+"\x1f"+pkg.Architecture] = true
		present[pkg.Name+"\x1fnoarch"] = present[pkg.Name+"\x1fnoarch"] || pkg.Architecture == "noarch"
	}

	var result []Advisory
	for _, advisory := range advisories {
		// Bug fixes and new features are not vulnerabilities and must not
		// reach the security assessment.
		if advisory.Type != TypeSecurity {
			continue
		}
		var matching []AdvisoryPackage
		for _, pkg := range advisory.Packages {
			if present[pkg.Name+"\x1f"+pkg.Architecture] {
				matching = append(matching, pkg)
			}
		}
		if len(matching) == 0 {
			continue
		}
		advisory.Packages = matching
		result = append(result, advisory)
	}
	return result
}

// ParseUpdateinfo reads the block format of "dnf updateinfo info".
func ParseUpdateinfo(output string) []Advisory {
	var advisories []Advisory
	var current *Advisory
	inPackages := false

	flush := func() {
		if current != nil && current.ID != "" {
			current.CVEIDs = unique(current.CVEIDs)
			advisories = append(advisories, *current)
		}
		current, inPackages = nil, false
	}

	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		key, value, ok := splitRow(line)
		if !ok {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'

		if key == "Name" && !indented {
			flush()
			current = &Advisory{ID: value}
			continue
		}
		if current == nil {
			continue
		}

		switch {
		case key == "" && inPackages:
			// A further package of the collection: a line without a key
			// continues the list.
			if pkg, ok := ParseNEVRA(value); ok {
				current.Packages = append(current.Packages, pkg)
			}
			continue
		case key == "Packages" && indented:
			inPackages = true
			if pkg, ok := ParseNEVRA(value); ok {
				current.Packages = append(current.Packages, pkg)
			}
			continue
		case indented:
			// A nested key: it does not describe the finding, but it can carry
			// a CVE in the title of a reference.
			inPackages = false
			current.CVEIDs = append(current.CVEIDs, cvePattern.FindAllString(value, -1)...)
			continue
		}

		inPackages = false
		switch key {
		case "Title":
			if current.Title == "" {
				current.Title = value
			}
		case "Type":
			current.Type = strings.ToLower(value)
		case "Severity":
			current.Severity = FedoraSeverity(value)
		case "Issued":
			if moment, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
				momentUTC := moment.UTC()
				current.IssuedAt = &momentUTC
			}
		}
		// A CVE appears in the description, in the title of a reference or in both:
		// we gather them from the whole block instead of trusting one place.
		current.CVEIDs = append(current.CVEIDs, cvePattern.FindAllString(value, -1)...)
	}
	flush()
	return advisories
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
