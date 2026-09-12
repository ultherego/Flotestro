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
//
// These are facts rather than an assessment: the host says which findings its
// vendor released and which versions of packages close them. Whether they
// concern this host is settled by the panel - just as with every other
// module.
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

// Advisories reads the vendor findings known to the host.
//
// For dnf they are in the repository metadata the host has anyway: that is the
// settling source for Fedora, because it speaks about versions from the same
// repositories the host takes packages from.
func Advisories(ctx context.Context, manager string,
	installed []InstalledPackage) ([]Advisory, string) {
	if manager != "dnf" {
		// APT has no updateinfo: for Debian and Ubuntu the panel fetches the
		// findings straight from the tracker of the vendor.
		return nil, ""
	}
	// --all: the findings already applied as well. The panel compares the
	// versions anyway, and a list of the pending ones alone would depend on
	// when the host last refreshed its metadata.
	result := run(ctx, 5*time.Minute, dnfPath, "updateinfo", "info", "--all", "--with-cve")
	if !result.Ran || result.ExitCode != 0 {
		return nil, "dnf updateinfo: " + result.Reason()
	}
	return NarrowToInstalled(ParseUpdateinfo(result.Stdout), installed), ""
}

// NarrowToInstalled keeps the security findings that concern the packages
// really present on this host.
//
// The full list of findings of a release is thousands of entries times dozens
// of packages each - and most of them concern things the host does not have.
// The narrowing here is the scope of the correlation rather than a saving: the
// panel assesses what lies on the host.
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
//
// The format is columnar: the key of a finding stands at the left edge, and
// nested keys - in the references and in the package collection - are
// indented. The distinction matters, because the names repeat: the "Type" of a
// finding says "security" and the "Type" of a reference says "bugzilla".
// Without it every finding with a reference loses its type and drops out of
// the assessment.
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
		// A CVE appears in the description, in the title of a reference or in
		// both: we gather them from the whole block instead of trusting one
		// place.
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
// name-version-release.arch.
//
// The name may contain dashes, so we read from the end: the architecture after
// the last dot, then the release and the version after the last two dashes.
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
