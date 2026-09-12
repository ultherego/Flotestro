// Package debian reads the security tracker of Debian.
//
// This is the settling source for Debian hosts: it says which version of a
// source package carries the fix in a given release. Those versions are
// backported, so by the upstream numbering they look vulnerable - and no
// range from an upstream feed covers them.
package debian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/vuln"
)

// Provider is the name of the source written down with every finding.
const Provider = "debian"

// DefaultURL points at the full dump of the tracker.
const DefaultURL = "https://security-tracker.debian.org/tracker/data/json"

// MaxSize limits the fetch. The dump is a few dozen megabytes; a
// substantially larger answer means we are fetching something other than we
// think.
const MaxSize = 512 << 20

// ErrNotModified means a feed unchanged since the last fetch.
var ErrNotModified = fmt.Errorf("the feed has not changed since the last fetch")

// Source fetches and parses the dump of the tracker.
type Source struct {
	URL    string
	Client *http.Client
}

// New creates the source.
func New(address string, limit time.Duration) *Source {
	if address == "" {
		address = DefaultURL
	}
	if limit <= 0 {
		limit = 10 * time.Minute
	}
	return &Source{URL: address, Client: &http.Client{Timeout: limit}}
}

func (z *Source) Name() string { return Provider }

// releaseEntry is the description of one release in a tracker finding.
type releaseEntry struct {
	Status       string `json:"status"`
	Urgency      string `json:"urgency"`
	FixedVersion string `json:"fixed_version"`
	// NoDSA marks a vulnerability the vendor does not intend to fix in this
	// release. That is not the same as a missing fix: it is a decision.
	NoDSA       string `json:"nodsa"`
	NoDSAReason string `json:"nodsa_reason"`
}

// cveEntry is one finding for a source package.
type cveEntry struct {
	Description string                  `json:"description"`
	Scope       string                  `json:"scope"`
	Releases    map[string]releaseEntry `json:"releases"`
}

// Fetch pulls the dump and turns it into findings for the named releases.
//
// We filter by the releases of the fleet, because the full dump describes
// more than a dozen releases and several hundred thousand findings - and the
// panel needs the ones that concern the hosts it really has.
func (z *Source) Fetch(ctx context.Context, releases []string,
	etag string) (vuln.Snapshot, []vuln.Advisory, error) {
	snapshot := vuln.Snapshot{Provider: Provider, Releases: releases}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, z.URL, nil)
	if err != nil {
		return snapshot, nil, err
	}
	// A conditional fetch: the dump changes a few times a day and is a few
	// dozen megabytes. Fetching it every cycle without need is a cost the
	// other side bears as well.
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	// We do not set the Accept-Encoding header ourselves: when the client
	// does, the library stops decompressing the answer and a gzip stream
	// reaches the parser. Left to the library, the compression works and is
	// decompressed transparently.
	request.Header.Set("User-Agent", "flotestro-vuln/1")

	response, err := z.Client.Do(request)
	if err != nil {
		return snapshot, nil, err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotModified {
		return snapshot, nil, ErrNotModified
	}
	if response.StatusCode != http.StatusOK {
		return snapshot, nil, fmt.Errorf("the tracker answered %s", response.Status)
	}
	snapshot.ETag = response.Header.Get("ETag")
	if modified := response.Header.Get("Last-Modified"); modified != "" {
		if moment, err := http.ParseTime(modified); err == nil {
			momentUTC := moment.UTC()
			snapshot.SourceModifiedAt = &momentUTC
		}
	}

	// We read one byte more than allowed: were the answer larger, the cut
	// stream would end in the middle of the data. The parser would report an
	// error then, but not every error can be told from a syntax error - and a
	// dump trimmed in half is to look like what it is.
	counter := &byteCounter{source: io.LimitReader(response.Body, MaxSize+1)}
	advisories, err := Parse(counter, releases)
	if counter.read > MaxSize {
		return snapshot, nil, fmt.Errorf(
			"the tracker dump exceeds %d bytes - this is not the dump we expect",
			MaxSize)
	}
	if err != nil {
		return snapshot, nil, err
	}
	snapshot.Digest = Digest(advisories)
	snapshot.AdvisoryCount = len(advisories)
	snapshot.FetchedAt = time.Now().UTC()
	return snapshot, advisories, nil
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

// Parse reads the dump as a stream and returns the findings for the named
// releases.
//
// As a stream, because the dump is a few dozen megabytes: read into memory as
// a whole it would cost a multiple of that size once decoded.
func Parse(source io.Reader, releases []string) ([]vuln.Advisory, error) {
	wanted := map[string]bool{}
	for _, release := range releases {
		wanted[release] = true
	}

	decoder := json.NewDecoder(source)
	opening, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("the tracker dump: %w", err)
	}
	if opening != json.Delim('{') {
		return nil, fmt.Errorf("the tracker dump starts with %v rather than with an object", opening)
	}

	var advisories []vuln.Advisory
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		pkg, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("the tracker dump: an unexpected key %v", key)
		}
		var entries map[string]cveEntry
		if err := decoder.Decode(&entries); err != nil {
			return nil, fmt.Errorf("package %s: %w", pkg, err)
		}
		for cveName, entry := range entries {
			for release, description := range entry.Releases {
				if !wanted[release] {
					continue
				}
				advisories = append(advisories, advisoryFromEntry(pkg, cveName, release, description, entry))
			}
		}
	}

	// The closing of the object and the end of the stream are checked
	// explicitly. A stream cut in half simply ends with no further key - the
	// loop exits silently, and the panel gets half the dump as the full thing
	// and treats the missing findings as non-existent.
	closing, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("the tracker dump was cut before the closing: %w", err)
	}
	if closing != json.Delim('}') {
		return nil, fmt.Errorf("the tracker dump ends with %v rather than with the closing of the object", closing)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("the tracker dump carries data after the closing of the object")
	}

	sort.Slice(advisories, func(i, j int) bool {
		if advisories[i].SourcePackage != advisories[j].SourcePackage {
			return advisories[i].SourcePackage < advisories[j].SourcePackage
		}
		if advisories[i].Release != advisories[j].Release {
			return advisories[i].Release < advisories[j].Release
		}
		return advisories[i].AdvisoryID < advisories[j].AdvisoryID
	})
	return advisories, nil
}

// advisoryFromEntry translates one tracker entry into a finding of the panel.
func advisoryFromEntry(pkg, cveName, release string, description releaseEntry, entry cveEntry) vuln.Advisory {
	advisory := vuln.Advisory{
		Provider: Provider, AdvisoryID: cveName, CVEIDs: []string{cveName},
		Distribution: "debian", Release: release, SourcePackage: pkg,
		VendorSeverity: Severity(description.Urgency),
		Title:          shortened(entry.Description),
		URL:            "https://security-tracker.debian.org/tracker/" + cveName,
	}
	advisory.Status, advisory.FixedVersion = Status(description)
	// The versions and identifiers are cleaned as well: the dump is text from
	// outside, and a single bad byte must not topple the whole import.
	advisory.FixedVersion = strings.ToValidUTF8(advisory.FixedVersion, "")
	advisory.SourcePackage = strings.ToValidUTF8(advisory.SourcePackage, "")
	advisory.AdvisoryID = strings.ToValidUTF8(advisory.AdvisoryID, "")
	return advisory
}

// Status translates the state of a tracker entry into the state of a finding.
//
// The tracker has three states and one trap: "resolved" with the fixed
// version "0" does not mean "fixed in version zero" but "this release was
// never vulnerable". Treating that as a version would give a vulnerability on
// every host, because every version is greater than zero.
func Status(description releaseEntry) (string, string) {
	switch description.Status {
	case "resolved":
		if description.FixedVersion == "" || description.FixedVersion == "0" {
			return vuln.StatusNotAffected, ""
		}
		return vuln.StatusFixed, description.FixedVersion
	case "open":
		if description.NoDSA != "" || description.NoDSAReason != "" {
			// The vendor settled that it will not release a fix in this
			// release. That is an answer rather than a missing answer - and
			// the host is still vulnerable.
			return vuln.StatusDeferred, ""
		}
		return vuln.StatusOpen, ""
	case "undetermined":
		return vuln.StatusUnderInvestigation, ""
	}
	return vuln.StatusUnderInvestigation, ""
}

// Severity translates the urgency of the tracker into a vendor severity.
func Severity(urgency string) string {
	switch strings.ToLower(strings.TrimSpace(urgency)) {
	case "high", "high**":
		return "high"
	case "medium", "medium**":
		return "medium"
	case "low", "low**":
		return "low"
	case "unimportant":
		return "unimportant"
	case "end-of-life":
		return "end-of-life"
	}
	// "not yet assigned" is not a severity: it is a missing severity and is
	// to stay one.
	return ""
}

// Digest computes the digest of the canonical form of the findings.
//
// The canonicalisation is explicit: the same data have to give the same
// digest, otherwise the panel would start a new snapshot on every fetch and
// recompute the whole fleet.
func Digest(advisories []vuln.Advisory) string {
	sum := sha256.New()
	sum.Write([]byte("flotestro/vuln/debian/v1\n"))
	for _, advisory := range advisories {
		sum.Write([]byte(strings.Join([]string{
			advisory.SourcePackage, advisory.Release, advisory.AdvisoryID,
			advisory.Status, advisory.FixedVersion, advisory.VendorSeverity,
		}, "\x1f")))
		sum.Write([]byte{'\n'})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// shortened trims a description to 300 characters rather than bytes.
//
// Cutting by bytes splits a multi-byte character in half and leaves a
// sequence that cannot be written to the database: the whole import then
// ended with an encoding error and the panel was left without a feed. The
// descriptions of the tracker are in English, but they quote names and
// punctuation from outside ASCII.
func shortened(description string) string {
	description = strings.ToValidUTF8(strings.TrimSpace(description), "")
	runes := []rune(description)
	if len(runes) > 300 {
		return string(runes[:300])
	}
	return description
}
