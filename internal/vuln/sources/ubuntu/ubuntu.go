// Package ubuntu reads the OVAL data of Canonical.
//
// This is the settling source for Ubuntu hosts. Canonical publishes a
// separate file for every release, and in it definitions per CVE: which
// source package is vulnerable and in which version it was fixed. The
// versions are backported, so by the upstream numbering they look
// vulnerable.
//
// What this source does not say and what the panel does not pretend to know
// from it:
//
// The pocket. A fix released in esm-apps or esm-infra requires an Ubuntu Pro
// subscription, and the file records the pocket in the comment of a criterion
// alone. The panel treats it like any other vendor fix: "the vendor released
// it" is the vendor_fix axis, and "it can be taken from a repository of this
// host" is a separate axis that stays undetermined without the repository
// metadata. Neither of them promises more than the panel has checked.
//
// The kernel. OVAL settles the kernel by the version of the one currently
// running. The panel assesses installed packages, so an old kernel lying next
// to the running one gets a finding as well. That is deliberate: a vulnerable
// file on disk is vulnerable, and "is it running" is a question a package
// assessment does not answer.
package ubuntu

import (
	"compress/bzip2"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/vuln"
	"github.com/ultherego/flotestro/internal/vuln/version"
)

// Provider is the name of the source written down with every finding.
const Provider = "ubuntu"

// DefaultURL points at the directory with the OVAL data.
const DefaultURL = "https://security-metadata.canonical.com/oval/"

// The limits of a fetch. The file of one release is more than a dozen
// megabytes compressed and around two hundred decompressed; a substantially
// larger answer means we are fetching something other than we think - or that
// somebody planted a bomb.
const (
	MaxCompressedSize = 256 << 20
	MaxSize           = 2 << 30
)

// ErrNotModified means a feed unchanged since the last fetch.
var ErrNotModified = fmt.Errorf("the feed has not changed since the last fetch")

// Source fetches and parses the OVAL data of Canonical.
type Source struct {
	Base   string
	Client *http.Client
}

// New creates the source.
func New(address string, limit time.Duration) *Source {
	if address == "" {
		address = DefaultURL
	}
	if !strings.HasSuffix(address, "/") {
		address += "/"
	}
	if limit <= 0 {
		limit = 10 * time.Minute
	}
	return &Source{Base: address, Client: &http.Client{Timeout: limit}}
}

func (z *Source) Name() string { return Provider }

// Fetch pulls the data for the named releases and glues them into one
// snapshot.
//
// Canonical publishes a file per release, so there are as many fetches as the
// fleet has releases. A release Canonical does not publish does not reach the
// snapshot - and rightly so: a host of such a release is to get the reason "a
// release outside the feed" rather than a silent zero findings.
func (z *Source) Fetch(ctx context.Context, releases []string,
	etag string) (vuln.Snapshot, []vuln.Advisory, error) {
	snapshot := vuln.Snapshot{Provider: Provider}
	list := append([]string(nil), releases...)
	sort.Strings(list)

	etags := ParseETags(etag)
	updated := map[string]string{}
	var advisories []vuln.Advisory
	var covered, unchanged []string
	var newest time.Time
	var changed, fetchedAny bool
	for _, release := range list {
		result, err := z.fetchRelease(ctx, release, etags[release])
		if err != nil {
			return snapshot, nil, err
		}
		if result.releaseMissing {
			continue
		}
		fetchedAny = true
		if result.unchanged {
			unchanged = append(unchanged, release)
			updated[release] = etags[release]
			covered = append(covered, release)
			continue
		}
		changed = true
		advisories = append(advisories, result.advisories...)
		updated[release] = result.etag
		covered = append(covered, release)
		if result.modified.After(newest) {
			newest = result.modified
		}
	}

	if !fetchedAny {
		return snapshot, nil, fmt.Errorf("none of the releases %v has OVAL data", list)
	}
	if !changed {
		return snapshot, nil, ErrNotModified
	}
	// There is one snapshot and it has to be complete: the releases that
	// answered "no changes" are fetched once more unconditionally. Otherwise
	// we would write a snapshot without their findings and their hosts would
	// look clean.
	for _, release := range unchanged {
		result, err := z.fetchRelease(ctx, release, "")
		if err != nil {
			return snapshot, nil, err
		}
		if result.releaseMissing {
			continue
		}
		advisories = append(advisories, result.advisories...)
		updated[release] = result.etag
		if result.modified.After(newest) {
			newest = result.modified
		}
	}

	SortAdvisories(advisories)
	snapshot.Releases = covered
	snapshot.ETag = JoinETags(updated)
	snapshot.Digest = Digest(advisories)
	snapshot.AdvisoryCount = len(advisories)
	snapshot.FetchedAt = time.Now().UTC()
	if !newest.IsZero() {
		moment := newest.UTC()
		snapshot.SourceModifiedAt = &moment
	}
	return snapshot, advisories, nil
}

// releaseResult is one fetch of one release file.
type releaseResult struct {
	advisories     []vuln.Advisory
	etag           string
	modified       time.Time
	unchanged      bool
	releaseMissing bool
}

// fetchRelease pulls and parses the file of one release.
func (z *Source) fetchRelease(ctx context.Context, release, etag string) (releaseResult, error) {
	var result releaseResult
	address := z.Base + "com.ubuntu." + release + ".cve.oval.xml.bz2"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return result, err
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	request.Header.Set("User-Agent", "flotestro-vuln/1")

	response, err := z.Client.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusNotModified:
		result.unchanged = true
		return result, nil
	case http.StatusNotFound, http.StatusGone:
		// Canonical does not publish this release. That is not a fetch
		// error: it is the answer "we do not cover this release".
		result.releaseMissing = true
		return result, nil
	case http.StatusOK:
	default:
		return result, fmt.Errorf("OVAL %s answered %s", release, response.Status)
	}
	result.etag = response.Header.Get("ETag")
	if modified := response.Header.Get("Last-Modified"); modified != "" {
		if moment, err := http.ParseTime(modified); err == nil {
			result.modified = moment
		}
	}

	// Two counters, because there are two sizes: the compressed one guards
	// the link, the decompressed one guards memory. An archive of a few
	// megabytes can decompress into gigabytes, and a stream cut in half would
	// look like the whole thing.
	compressed := &byteCounter{source: io.LimitReader(response.Body, MaxCompressedSize+1)}
	decompressed := &byteCounter{
		source: io.LimitReader(bzip2.NewReader(compressed), MaxSize+1),
	}
	advisories, err := Parse(decompressed, release)
	if compressed.read > MaxCompressedSize {
		return result, fmt.Errorf("the OVAL data %s exceed %d bytes when fetched",
			release, MaxCompressedSize)
	}
	if decompressed.read > MaxSize {
		return result, fmt.Errorf("the OVAL data %s exceed %d bytes when decompressed",
			release, MaxSize)
	}
	if err != nil {
		return result, fmt.Errorf("OVAL %s: %w", release, err)
	}
	result.advisories = advisories
	return result, nil
}

// byteCounter counts how much was really read from the stream.
type byteCounter struct {
	source io.Reader
	read   int64
}

func (l *byteCounter) Read(buffer []byte) (int, error) {
	n, err := l.source.Read(buffer)
	l.read += int64(n)
	return n, err
}

// The elements of an OVAL document that settle anything. We do not read the
// rest: the document also describes the tests of the system family and of the
// release, and the panel knows those from the inventory of the host.
type definition struct {
	Class    string   `xml:"class,attr"`
	Metadata metadata `xml:"metadata"`
	Criteria criteria `xml:"criteria"`
}

type metadata struct {
	Title       string        `xml:"title"`
	Description string        `xml:"description"`
	References  []reference   `xml:"reference"`
	Advisory    advisoryEntry `xml:"advisory"`
}

type reference struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
}

type advisoryEntry struct {
	Severity string   `xml:"severity"`
	Date     string   `xml:"public_date"`
	CVE      cveEntry `xml:"cve"`
}

type cveEntry struct {
	Priority string `xml:"priority,attr"`
}

// criteria are a tree: a kernel definition has criteria nested several
// levels deep, one per kernel variant.
type criteria struct {
	Criteria  []criteria  `xml:"criteria"`
	Criterion []criterion `xml:"criterion"`
}

type criterion struct {
	TestRef string `xml:"test_ref,attr"`
}

type testEntry struct {
	ID      string   `xml:"id,attr"`
	Comment string   `xml:"comment,attr"`
	State   stateRef `xml:"state"`
}

type stateRef struct {
	Ref string `xml:"state_ref,attr"`
}

type stateEntry struct {
	ID    string `xml:"id,attr"`
	EVR   *value `xml:"evr"`
	Value *value `xml:"value"`
}

type value struct {
	Operation string `xml:"operation,attr"`
	Content   string `xml:",chardata"`
}

// correlationTest is what is left of an OVAL test after the translation into
// the language of the panel: whose package it is and which state says the
// fixed version.
type correlationTest struct {
	pkg    string
	state  string
	kernel bool
}

// definitionEntry is a definition after slimming down.
//
// The definitions come in the document before the tests, so we have to keep
// them until the end of the file - and as a whole they do not fit in the
// memory of the panel: the descriptions of one release alone are well over a
// hundred megabytes, because Canonical appends to each of them update
// instructions for dozens of kernel variants. We keep from a definition only
// what reaches the finding.
type definitionEntry struct {
	cve      string
	severity string
	data     string
	title    string
	tests    []string
}

// slim leaves from a definition what the panel really writes down.
func slim(entry definition) definitionEntry {
	result := definitionEntry{
		severity: Severity(entry.Metadata.Advisory.CVE.Priority, entry.Metadata.Advisory.Severity),
		data:     strings.TrimSpace(entry.Metadata.Advisory.Date),
		title:    shortened(withoutInstructions(entry.Metadata.Description)),
		tests:    collectTests(entry.Criteria),
	}
	if result.title == "" {
		result.title = shortened(entry.Metadata.Title)
	}
	for _, ref := range entry.Metadata.References {
		if strings.EqualFold(ref.Source, "CVE") {
			result.cve = strings.ToValidUTF8(ref.RefID, "")
			break
		}
	}
	return result
}

// Parse reads the OVAL data of one release and returns the findings of the
// panel.
//
// As a stream, because the file of a release is around two hundred megabytes
// once decompressed. The definitions come in the document before the tests
// and the states, so the join is made at the end - we keep from a definition
// only what it needs.
func Parse(source io.Reader, release string) ([]vuln.Advisory, error) {
	decoder := xml.NewDecoder(source)
	var definitions []definitionEntry
	tests := map[string]correlationTest{}
	states := map[string]string{}
	closed := false

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "definition":
				var entry definition
				if err := decoder.DecodeElement(&entry, &element); err != nil {
					return nil, err
				}
				if entry.Class == "vulnerability" {
					definitions = append(definitions, slim(entry))
				}
			case "dpkginfo_test", "variable_test":
				var entry testEntry
				if err := decoder.DecodeElement(&entry, &element); err != nil {
					return nil, err
				}
				kernel := element.Name.Local == "variable_test"
				if kernel && !strings.Contains(entry.Comment, "kernel") {
					continue
				}
				// The name of the source package is in the comment of the
				// test: the OVAL structure carries only binary packages in
				// the object, and Canonical tracks security by the source.
				pkg := inQuotes(entry.Comment)
				if pkg == "" {
					continue
				}
				tests[entry.ID] = correlationTest{pkg: pkg, state: entry.State.Ref, kernel: kernel}
			case "dpkginfo_state", "variable_state":
				var entry stateEntry
				if err := decoder.DecodeElement(&entry, &element); err != nil {
					return nil, err
				}
				if version := stateVersion(entry); version != "" {
					states[entry.ID] = version
				}
			}
		case xml.EndElement:
			if element.Name.Local == "oval_definitions" {
				closed = true
			}
		}
	}

	// A document cut in half simply ends with no further token. Without this
	// check the panel would get half the data as the whole thing and treat
	// the missing findings as non-existent.
	if !closed {
		return nil, fmt.Errorf("the OVAL document was cut before the closing")
	}

	advisories := join(definitions, tests, states, release)
	// Date we cannot read are not empty data. Were Canonical to change the
	// shape of the document, the panel is to say "error" rather than show a
	// fleet without vulnerabilities.
	if len(definitions) > 0 && len(advisories) == 0 {
		return nil, fmt.Errorf("the OVAL document has %d definitions, none of which settles anything",
			len(definitions))
	}
	SortAdvisories(advisories)
	return advisories, nil
}

// stateVersion extracts the fixed version out of an OVAL state.
//
// We understand only the comparison "less than": that is how Canonical writes
// "fixed from this version". We do not guess any other operator - a state we
// do not understand is left without a version and the package comes out as
// vulnerable without a fix rather than as fixed.
func stateVersion(entry stateEntry) string {
	for _, field := range []*value{entry.EVR, entry.Value} {
		if field == nil || field.Operation != "less than" {
			continue
		}
		if version := strings.TrimSpace(field.Content); version != "" {
			return strings.ToValidUTF8(version, "")
		}
	}
	return ""
}

// packageState is the finding for one source package in one CVE.
type packageState struct {
	status  string
	version string
}

// join joins the definitions with the tests and the states into findings of
// the panel.
func join(definitions []definitionEntry, tests map[string]correlationTest,
	states map[string]string, release string) []vuln.Advisory {
	var advisories []vuln.Advisory
	for _, entry := range definitions {
		if entry.cve == "" {
			continue
		}

		pkgStates := map[string]packageState{}
		for _, ref := range entry.tests {
			test, ok := tests[ref]
			if !ok {
				continue
			}
			version := states[test.state]
			// A kernel criterion without a version does not speak about a
			// vulnerability, only about which kernel variant is running.
			if test.kernel && version == "" {
				continue
			}
			status := vuln.StatusOpen
			if version != "" {
				status = vuln.StatusFixed
			}
			pkgStates[test.pkg] = merge(pkgStates[test.pkg], packageState{status, version})
		}

		for pkg, state := range pkgStates {
			advisories = append(advisories, advisoryFor(entry, release, pkg, state))
		}
	}
	return advisories
}

// merge settles two findings about the same package in one CVE.
//
// One CVE can describe the same package in several pockets: in the main one
// without a fix, in esm-apps with one. The fix wins - the vendor released it.
// When there are several versions we take the lowest: it is from that one
// that the package carries the fix, so a host with a higher version is fixed
// in every pocket.
func merge(previous, current packageState) packageState {
	if previous.status == "" {
		return current
	}
	if previous.status != vuln.StatusFixed {
		return current
	}
	if current.status != vuln.StatusFixed {
		return previous
	}
	if version.CompareDeb(current.version, previous.version) < 0 {
		return current
	}
	return previous
}

// collectTests walks down the tree of criteria and gathers the references to
// the tests.
func collectTests(tree criteria) []string {
	var refs []string
	for _, entry := range tree.Criterion {
		if entry.TestRef != "" {
			refs = append(refs, entry.TestRef)
		}
	}
	for _, branch := range tree.Criteria {
		refs = append(refs, collectTests(branch)...)
	}
	return refs
}

// advisoryFor assembles one finding of the panel.
func advisoryFor(entry definitionEntry, release, pkg string, state packageState) vuln.Advisory {
	result := vuln.Advisory{
		Provider: Provider, AdvisoryID: entry.cve, CVEIDs: []string{entry.cve},
		Distribution: "ubuntu", Release: release,
		SourcePackage:  strings.ToValidUTF8(pkg, ""),
		Status:         state.status,
		FixedVersion:   state.version,
		VendorSeverity: entry.severity,
		Title:          entry.title,
		URL:            "https://ubuntu.com/security/" + entry.cve,
	}
	if moment, err := time.Parse(time.RFC3339, entry.data); err == nil {
		momentUTC := moment.UTC()
		result.PublishedAt = &momentUTC
	}
	return result
}

// Severity translates the priority of Canonical into a vendor severity.
//
// "untriaged" is not a severity: it is a missing severity and is to stay one.
// A vendor that has not scored yet has not said "negligible".
func Severity(priority, severity string) string {
	for _, candidate := range []string{priority, severity} {
		switch strings.ToLower(strings.TrimSpace(candidate)) {
		case "critical":
			return "critical"
		case "high":
			return "high"
		case "medium":
			return "medium"
		case "low":
			return "low"
		case "negligible":
			return "negligible"
		}
	}
	return ""
}

// SortAdvisories puts the findings in an order independent of the order of
// the fetch: the digest has to be the same for the same data.
func SortAdvisories(advisories []vuln.Advisory) {
	sort.Slice(advisories, func(i, j int) bool {
		if advisories[i].SourcePackage != advisories[j].SourcePackage {
			return advisories[i].SourcePackage < advisories[j].SourcePackage
		}
		if advisories[i].Release != advisories[j].Release {
			return advisories[i].Release < advisories[j].Release
		}
		return advisories[i].AdvisoryID < advisories[j].AdvisoryID
	})
}

// Digest computes the digest of the canonical form of the findings.
func Digest(advisories []vuln.Advisory) string {
	sum := sha256.New()
	sum.Write([]byte("flotestro/vuln/ubuntu/v1\n"))
	for _, advisoryFor := range advisories {
		sum.Write([]byte(strings.Join([]string{
			advisoryFor.SourcePackage, advisoryFor.Release, advisoryFor.AdvisoryID,
			advisoryFor.Status, advisoryFor.FixedVersion, advisoryFor.VendorSeverity,
		}, "\x1f")))
		sum.Write([]byte{'\n'})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// ParseETags reads the ETags written down with the previous snapshot.
//
// There is one snapshot and as many files as releases - so one field holds a
// map "release=etag". An entry that does not have that shape is not guessed
// at: worse than fetching too much is not fetching a change.
func ParseETags(etag string) map[string]string {
	etags := map[string]string{}
	for _, entry := range strings.Fields(etag) {
		release, tag, ok := strings.Cut(entry, "=")
		if !ok || release == "" || tag == "" {
			continue
		}
		etags[release] = tag
	}
	return etags
}

// JoinETags writes the etags of the releases into one field of the snapshot.
func JoinETags(etags map[string]string) string {
	releases := make([]string, 0, len(etags))
	for release := range etags {
		releases = append(releases, release)
	}
	sort.Strings(releases)
	entries := make([]string, 0, len(releases))
	for _, release := range releases {
		tag := etags[release]
		// An etag with a space would fall apart into two entries when read
		// back. We skip it: an unconditional fetch is a cheaper mistake than
		// a conditional fetch with a wrong value.
		if tag == "" || strings.ContainsAny(tag, " \t\n") {
			continue
		}
		entries = append(entries, release+"="+tag)
	}
	return strings.Join(entries, " ")
}

// inQuotes returns the first text in apostrophes.
func inQuotes(text string) string {
	start := strings.Index(text, "'")
	if start < 0 {
		return ""
	}
	rest := text[start+1:]
	end := strings.Index(rest, "'")
	if end <= 0 {
		return ""
	}
	return strings.ToValidUTF8(rest[:end], "")
}

// withoutInstructions cuts the update instructions out of a description.
//
// Canonical appends to the description a list of packages to install - for
// every kernel variant separately. That is an instruction rather than a
// description of the vulnerability, and after trimming to three hundred
// characters only half of the first command would be left of it.
func withoutInstructions(description string) string {
	if cut := strings.Index(description, "Update Instructions:"); cut >= 0 {
		description = description[:cut]
	}
	return description
}

// shortened trims a description to 300 characters rather than bytes.
func shortened(description string) string {
	description = strings.ToValidUTF8(strings.TrimSpace(description), "")
	runes := []rune(description)
	if len(runes) > 300 {
		return string(runes[:300])
	}
	return description
}
