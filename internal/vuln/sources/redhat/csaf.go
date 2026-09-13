// Package redhat reads the CSAF/VEX date of Red Hat.
//
// This is the settling source for RHEL hosts. Red Hat publishes one VEX
// document per CVE and says three things in it at once: which products are
// vulnerable, which ones it does not concern and in which version of a
// package the fix is.
//
// We read the base RHEL alone. The EUS, AUS and E4S streams have fixes of
// their own and are available only to some customers, and the layered
// products (OpenShift, RHEM) are separate package distributions. A finding
// from such a stream would describe a host the panel does not have in front
// of it.
//
// AlmaLinux, Rocky and CentOS Stream are deliberately not supported here:
// their packages carry version numbers of their own, so the findings of Red
// Hat would speak about something else. Until the panel reads their own
// sources, their hosts are to get the reason "feed missing" - that is a more
// honest answer than somebody else's assessment.
package redhat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/vuln"
	"github.com/ultherego/flotestro/internal/vuln/version"
)

// Provider is the name of the source written down with every finding.
const Provider = "redhat"

// Distribution is the name of the distribution these findings hold for.
const Distribution = "rhel"

type documentHeader struct {
	Title    string `json:"title"`
	Tracking struct {
		ID                 string `json:"id"`
		InitialReleaseDate string `json:"initial_release_date"`
	} `json:"tracking"`
	AggregateSeverity struct {
		Text string `json:"text"`
	} `json:"aggregate_severity"`
}

type branch struct {
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Product  product  `json:"product"`
	Branches []branch `json:"branches"`
}

type product struct {
	ProductID string `json:"product_id"`
	Helper    struct {
		CPE string `json:"cpe"`
	} `json:"product_identification_helper"`
}

type relationship struct {
	Category        string `json:"category"`
	FullProductName struct {
		ProductID string `json:"product_id"`
	} `json:"full_product_name"`
	ProductReference string `json:"product_reference"`
	RelatesTo        string `json:"relates_to_product_reference"`
}

// Advisories translates one VEX document into findings of the panel.
//
// It takes the named releases of the base RHEL alone. The filter is here
// rather than higher up because of the size: a CVE document that touches
// every product of the vendor is dozens of megabytes and several hundred
// thousand identifiers. Read into memory as a whole it would cost a multiple
// of that size, so we read it as a stream and reject foreign products at
// once.
func Advisories(document []byte, releases map[string]bool) ([]vuln.Advisory, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	opening, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("the VEX document: %w", err)
	}
	if opening != json.Delim('{') {
		return nil, fmt.Errorf("the VEX document starts with %v rather than with an object", opening)
	}

	var header documentHeader
	products := map[string]string{}
	streams := map[string]string{}
	treeRead := false
	var result []vuln.Advisory

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		mergeKey, _ := token.(string)
		switch mergeKey {
		case "document":
			if err := decoder.Decode(&header); err != nil {
				return nil, fmt.Errorf("the header of the document: %w", err)
			}
		case "product_tree":
			if err := readTree(decoder, releases, products, streams); err != nil {
				return nil, err
			}
			treeRead = true
		case "vulnerabilities":
			// The product tree comes in the document before the
			// vulnerabilities and it alone says which release an identifier
			// concerns. A document in another order is rejected rather than
			// guessed at.
			if !treeRead {
				return nil, fmt.Errorf("the VEX document has vulnerabilities before the product tree")
			}
			gathered, err := readVulnerabilities(decoder, header, products, streams)
			if err != nil {
				return nil, err
			}
			result = append(result, gathered...)
		default:
			if err := skip(decoder); err != nil {
				return nil, err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("the VEX document was cut before the closing: %w", err)
	}
	return result, nil
}

// readTree reads the product tree: which product is which release and which
// compound identifier belongs to which stream.
func readTree(decoder *json.Decoder, releases map[string]bool,
	products, streams map[string]string) error {
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('{') {
		return fmt.Errorf("the product tree is not an object")
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		mergeKey, _ := token.(string)
		switch mergeKey {
		case "branches":
			// There are a few hundred branches and they carry the CPEs - those
			// we read as a whole.
			var branches []branch
			if err := decoder.Decode(&branches); err != nil {
				return fmt.Errorf("the product branches: %w", err)
			}
			for _, entry := range branches {
				collectReleases(entry, releases, products)
			}
		case "relationships":
			if err := readRelationships(decoder, products, streams); err != nil {
				return err
			}
		default:
			if err := skip(decoder); err != nil {
				return err
			}
		}
	}
	// The closing of the tree object.
	_, err = decoder.Token()
	return err
}

// readRelationships binds packages to products, skipping foreign products at
// once.
//
// A large document holds more than ten thousand relationships and most of
// them concern layered products. Keeping all of them in memory only to reject
// them right away is what the panel cannot afford.
func readRelationships(decoder *json.Decoder, products, streams map[string]string) error {
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('[') {
		return fmt.Errorf("the product relationships are not a list")
	}
	for decoder.More() {
		var entry relationship
		if err := decoder.Decode(&entry); err != nil {
			return fmt.Errorf("a product relationship: %w", err)
		}
		if entry.FullProductName.ProductID == "" || entry.RelatesTo == "" {
			continue
		}
		if products[entry.RelatesTo] == "" {
			continue
		}
		streams[entry.FullProductName.ProductID] = entry.RelatesTo
	}
	_, err = decoder.Token()
	return err
}

// readVulnerabilities assembles the findings of every vulnerability in the
// document.
func readVulnerabilities(decoder *json.Decoder, header documentHeader,
	products, streams map[string]string) ([]vuln.Advisory, error) {
	opening, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if opening != json.Delim('[') {
		return nil, fmt.Errorf("the vulnerabilities are not a list")
	}
	severity := strings.ToLower(strings.TrimSpace(header.AggregateSeverity.Text))
	var result []vuln.Advisory
	for decoder.More() {
		gathered, err := readVulnerability(decoder, header, severity, products, streams)
		if err != nil {
			return nil, err
		}
		result = append(result, gathered...)
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return result, nil
}

// productState is one product identifier with the state the vendor assigned
// to it.
type productState struct {
	id     string
	status string
}

// readVulnerability assembles the findings of one vulnerability.
//
// The keys of the document run alphabetically, so the product states arrive
// before the remediations and before the title. We gather the states first -
// already filtered down to the base RHEL - and settle them only once the
// whole object has been read.
func readVulnerability(decoder *json.Decoder, header documentHeader, severity string,
	products, streams map[string]string) ([]vuln.Advisory, error) {
	opening, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if opening != json.Delim('{') {
		return nil, fmt.Errorf("a vulnerability is not an object")
	}

	var cveNumber, title, releaseDate string
	var states []productState
	errata := map[string]string{}
	noFixPlanned := map[string]bool{}

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		mergeKey, _ := token.(string)
		switch mergeKey {
		case "cve":
			if err := decoder.Decode(&cveNumber); err != nil {
				return nil, err
			}
		case "title":
			if err := decoder.Decode(&title); err != nil {
				return nil, err
			}
		case "release_date":
			if err := decoder.Decode(&releaseDate); err != nil {
				return nil, err
			}
		case "product_status":
			gathered, err := readStates(decoder, products, streams)
			if err != nil {
				return nil, err
			}
			states = append(states, gathered...)
		case "remediations":
			if err := readRemediations(decoder, products, streams, errata, noFixPlanned); err != nil {
				return nil, err
			}
		default:
			if err := skip(decoder); err != nil {
				return nil, err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}

	cveNumber = strings.ToValidUTF8(strings.TrimSpace(cveNumber), "")
	if cveNumber == "" || len(states) == 0 {
		return nil, nil
	}
	if title == "" {
		title = header.Title
	}
	return assemble(states, cveNumber, shortened(title), severity, releaseDate,
		header, products, streams, errata, noFixPlanned), nil
}

// readStates reads the product states, leaving the base RHEL alone.
func readStates(decoder *json.Decoder, products, streams map[string]string) ([]productState, error) {
	opening, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if opening != json.Delim('{') {
		return nil, fmt.Errorf("the product states are not an object")
	}
	var gathered []productState
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		mergeKey, _ := token.(string)
		status := ""
		switch mergeKey {
		case "fixed":
			status = vuln.StatusFixed
		case "known_affected":
			status = vuln.StatusOpen
		case "under_investigation":
			status = vuln.StatusUnderInvestigation
		}
		// The "not affected" state is not written down: the correlator makes
		// no finding out of it anyway, and the vendor lists thousands of
		// packages per CVE in it.
		if status == "" {
			if err := skip(decoder); err != nil {
				return nil, err
			}
			continue
		}
		ids, err := readIdentifiers(decoder, products, streams)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			gathered = append(gathered, productState{id: id, status: status})
		}
	}
	_, err = decoder.Token()
	return gathered, err
}

// readIdentifiers reads the list of product identifiers and keeps the ones
// that concern the releases under consideration.
func readIdentifiers(decoder *json.Decoder, products, streams map[string]string) ([]string, error) {
	opening, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if opening != json.Delim('[') {
		return nil, fmt.Errorf("the product list is not a list")
	}
	var result []string
	for decoder.More() {
		var id string
		if err := decoder.Decode(&id); err != nil {
			return nil, err
		}
		if ours(id, products, streams) {
			result = append(result, id)
		}
	}
	_, err = decoder.Token()
	return result, err
}

// readRemediations reads the remediations, keeping the errata and the "we
// will not fix it" decisions.
func readRemediations(decoder *json.Decoder, products, streams map[string]string,
	errata map[string]string, noFixPlanned map[string]bool) error {
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('[') {
		return fmt.Errorf("the remediations are not a list")
	}
	for decoder.More() {
		remediationOpening, err := decoder.Token()
		if err != nil {
			return err
		}
		if remediationOpening != json.Delim('{') {
			return fmt.Errorf("a remediation is not an object")
		}
		var category, address string
		var ids []string
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			mergeKey, _ := token.(string)
			switch mergeKey {
			case "category":
				if err := decoder.Decode(&category); err != nil {
					return err
				}
			case "url":
				if err := decoder.Decode(&address); err != nil {
					return err
				}
			case "product_ids":
				ids, err = readIdentifiers(decoder, products, streams)
				if err != nil {
					return err
				}
			default:
				if err := skip(decoder); err != nil {
					return err
				}
			}
		}
		if _, err := decoder.Token(); err != nil {
			return err
		}
		switch category {
		case "vendor_fix":
			for _, id := range ids {
				errata[id] = address
			}
		case "no_fix_planned":
			for _, id := range ids {
				noFixPlanned[id] = true
			}
		}
	}
	_, err = decoder.Token()
	return err
}

// ours says whether a product identifier concerns the release we are
// reading.
func ours(id string, products, streams map[string]string) bool {
	if streams[id] != "" {
		return true
	}
	productID, _, ok := strings.Cut(id, ":")
	return ok && products[productID] != ""
}

// skip jumps over a value the panel does not read.
//
// The descriptions and the CVSS scores alone are most of the volume of the
// document, and they add nothing to the answer "is this package
// vulnerable".
func skip(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') && token != json.Delim('[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return nil
}

// mergeKey points unambiguously at a package in a release: we merge the
// findings from several streams of the same release by it.
type mergeKey struct {
	release string
	pkg     string
}

// assemble settles the gathered product states into findings of the panel.
func assemble(states []productState, cveNumber, title, severity, releaseDate string,
	header documentHeader, products, streams map[string]string,
	errata map[string]string, noFixPlanned map[string]bool) []vuln.Advisory {
	published := date(releaseDate, header.Tracking.InitialReleaseDate)
	gathered := map[mergeKey]vuln.Advisory{}
	for _, state := range states {
		release, pkg, version, ok := split(state.id, products, streams)
		if !ok {
			continue
		}
		status := state.status
		if status == vuln.StatusOpen && noFixPlanned[state.id] {
			// The vendor settled that it will not release a fix. That is an
			// answer rather than a missing answer - and the host is still
			// vulnerable.
			status = vuln.StatusDeferred
		}
		current := vuln.Advisory{
			Provider: Provider, AdvisoryID: cveNumber, CVEIDs: []string{cveNumber},
			Distribution: Distribution, Release: release,
			// The RPM family correlates by the binary package: a Red Hat
			// finding speaks about a specific version to install rather than
			// about a source.
			SourcePackage: pkg, BinaryPackage: pkg,
			FixedVersion: version, Status: status, VendorSeverity: severity,
			Title: title, URL: link(errata[state.id], cveNumber),
			PublishedAt: published,
		}
		if number := erratumNumber(errata[state.id]); number != "" {
			current.AdvisoryID = number
		}
		put(gathered, mergeKey{release, pkg}, current)
	}

	result := make([]vuln.Advisory, 0, len(gathered))
	for _, advisory := range gathered {
		result = append(result, advisory)
	}
	return result
}

// put merges the findings about the same package in the same release.
//
// One release has several streams (BaseOS, AppStream) and several
// architectures, and the fix is released in each of them separately - with
// the same version number, because the vendor builds it once. The fix wins,
// and of several versions the lowest one: it is from that one that the
// package carries the fix, so a host with a higher version is fixed.
func put(gathered map[mergeKey]vuln.Advisory, where mergeKey, current vuln.Advisory) {
	previous, ok := gathered[where]
	if !ok {
		gathered[where] = current
		return
	}
	if previous.Status != vuln.StatusFixed {
		gathered[where] = current
		return
	}
	if current.Status != vuln.StatusFixed {
		return
	}
	if version.CompareRPM(current.FixedVersion, previous.FixedVersion) < 0 {
		gathered[where] = current
	}
}

// split translates a product identifier into the release, the package and
// the version.
//
// The identifier has two shapes: "product:package" for a vulnerability
// without a fix and "stream:NEVRA" for a fixed version.
//
// The architecture is not written down. The vendor builds the fix once and
// releases it under the same number for every architecture, so a finding per
// architecture would be the same sentence said five times.
func split(id string, products, streams map[string]string) (string, string, string, bool) {
	productID, rest, ok := strings.Cut(id, ":")
	if !ok || rest == "" {
		return "", "", "", false
	}
	// A compound identifier points at the stream through a relationship; a
	// simple one points at the product directly.
	reference := productID
	if target, ok := streams[id]; ok {
		reference = target
	}
	release := products[reference]
	if release == "" {
		return "", "", "", false
	}
	// Container components carry an image path in their name rather than a
	// system package - the panel does not have them on the package list of a
	// host.
	if strings.Contains(rest, "/") {
		return "", "", "", false
	}
	if !strings.Contains(rest, ":") {
		return release, strings.ToValidUTF8(rest, ""), "", true
	}
	name, arch, version, ok := SplitNEVRA(rest)
	if !ok || arch == "src" {
		// A source package is not installed on the host, so a finding about
		// it has nothing to concern.
		return "", "", "", false
	}
	return release, name, version, true
}

// SplitNEVRA breaks "name-epoch:version-release.arch" into parts.
func SplitNEVRA(nevra string) (string, string, string, bool) {
	dot := strings.LastIndex(nevra, ".")
	if dot <= 0 {
		return "", "", "", false
	}
	arch := nevra[dot+1:]
	rest := nevra[:dot]

	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return "", "", "", false
	}
	left, right := rest[:colon], rest[colon+1:]
	dash := strings.LastIndex(left, "-")
	if dash <= 0 || right == "" {
		return "", "", "", false
	}
	name, epoch := left[:dash], left[dash+1:]
	version := right
	// The epoch is written down the way the host writes it: zero is the
	// default and does not belong to the version number.
	if epoch != "" && epoch != "0" {
		version = epoch + ":" + version
	}
	return strings.ToValidUTF8(name, ""), strings.ToValidUTF8(arch, ""),
		strings.ToValidUTF8(version, ""), true
}

// collectReleases walks down the product tree and records the release of
// every product that is a base RHEL of the releases under consideration.
func collectReleases(entry branch, releases map[string]bool, products map[string]string) {
	if entry.Product.ProductID != "" {
		if release := ReleaseFromCPE(entry.Product.Helper.CPE); release != "" {
			if len(releases) == 0 || releases[release] {
				products[entry.Product.ProductID] = release
			}
		}
	}
	for _, branches := range entry.Branches {
		collectReleases(branches, releases, products)
	}
}

// ReleaseFromCPE returns the release of the base RHEL, or empty when the CPE
// describes another product.
//
// The base RHEL carries "enterprise_linux" in its CPE. The extended streams
// (rhel_eus, rhel_aus, rhel_e4s, rhel_tus) have names of their own and fixes
// of their own - a host that has not bought them must not be assessed with
// them.
func ReleaseFromCPE(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return ""
	}
	if parts[2] != "redhat" || parts[3] != "enterprise_linux" {
		return ""
	}
	version := parts[4]
	if major, _, ok := strings.Cut(version, "."); ok {
		version = major
	}
	if version == "" {
		return ""
	}
	for _, c := range version {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return version
}

// erratumNumber extracts the identifier of an erratum out of a vendor link.
func erratumNumber(url string) string {
	cut := strings.LastIndex(url, "/")
	if cut < 0 {
		return ""
	}
	number := url[cut+1:]
	if !strings.HasPrefix(number, "RHSA-") && !strings.HasPrefix(number, "RHBA-") &&
		!strings.HasPrefix(number, "RHEA-") {
		return ""
	}
	return strings.ToValidUTF8(number, "")
}

// link points at the erratum of the vendor, and when there is none - at the
// CVE page.
func link(errata, cveNumber string) string {
	if errata != "" {
		return strings.ToValidUTF8(errata, "")
	}
	return "https://access.redhat.com/security/cve/" + cveNumber
}

// shortened trims a title to 300 characters rather than bytes.
func shortened(title string) string {
	title = strings.ToValidUTF8(strings.TrimSpace(title), "")
	runes := []rune(title)
	if len(runes) > 300 {
		return string(runes[:300])
	}
	return title
}

// date reads the first readable date of the ones given.
func date(candidates ...string) *time.Time {
	for _, candidate := range candidates {
		moment, err := time.Parse(time.RFC3339, strings.TrimSpace(candidate))
		if err != nil {
			continue
		}
		momentUTC := moment.UTC()
		return &momentUTC
	}
	return nil
}
