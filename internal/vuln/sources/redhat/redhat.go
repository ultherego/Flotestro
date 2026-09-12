package redhat

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/ultherego/flotestro/internal/vuln"
)

// DefaultURL points at the VEX directory of Red Hat.
const DefaultURL = "https://security.access.redhat.com/data/csaf/v2/vex/"

// DefaultDirectory is the place where the panel keeps the findings it has
// read between cycles.
const DefaultDirectory = "/var/lib/flotestro/vuln/redhat"

// The limits of a fetch.
const (
	// MaxArchive limits a full fetch. The archive is around three hundred
	// megabytes; a substantially larger one means we are fetching something
	// other than we think.
	MaxArchive = 2 << 30
	// MaxFile limits a single VEX document. CVE documents that touch every
	// product of the vendor are dozens of megabytes each - and they are
	// genuine.
	MaxFile = 256 << 20
	// MaxDocuments limits the number of files in the archive.
	MaxDocuments = 500000
	// ChangesForFullFetch says above how many changed files it is cheaper to
	// take the whole archive than to pull them one by one.
	ChangesForFullFetch = 3000
)

// ErrNotModified means a feed unchanged since the last fetch.
var ErrNotModified = fmt.Errorf("the feed has not changed since the last fetch")

// Source reads the CSAF/VEX data of Red Hat and keeps them between cycles.
//
// It is the only source of the panel that has a memory, and it has one out of
// necessity: the full data are a three hundred megabyte archive and some
// sixty thousand files, while the vendor publishes changes by the dozen a
// day. Fetching the whole thing every cycle would be a cost the other side
// bears as well.
type Source struct {
	Base      string
	Directory string
	Client    *http.Client

	// loaded says whether the memory of the source is already filled. Source
	// is called from a single goroutine of the scheduler, so there is no lock
	// here.
	loaded  bool
	mark    time.Time
	archive string
	// releases says which releases the records were built for. The data are
	// filtered while reading, so a fleet that has gained a new release has to
	// read it again - otherwise its hosts would look clean.
	releases map[string]bool
}

// New creates the source.
func New(address, directory string, limit time.Duration) *Source {
	if address == "" {
		address = DefaultURL
	}
	if !strings.HasSuffix(address, "/") {
		address += "/"
	}
	if directory == "" {
		directory = DefaultDirectory
	}
	if limit <= 0 {
		limit = 30 * time.Minute
	}
	return &Source{Base: address, Directory: directory, Client: &http.Client{Timeout: limit}}
}

func (z *Source) Name() string { return Provider }

// Fetch returns the findings for the named releases of the base RHEL.
func (z *Source) Fetch(ctx context.Context, releases []string,
	etag string) (vuln.Snapshot, []vuln.Advisory, error) {
	snapshot := vuln.Snapshot{Provider: Provider}

	wanted := map[string]bool{}
	for _, release := range releases {
		if release != "" {
			wanted[release] = true
		}
	}
	if len(wanted) == 0 {
		return snapshot, nil, fmt.Errorf("no releases to fetch")
	}
	if !covers(z.releases, wanted) {
		z.releases = wanted
		z.loaded = false
		z.mark = time.Time{}
	}

	first := !z.loaded
	full, err := z.load(ctx)
	if err != nil {
		return snapshot, nil, err
	}
	// A full fetch in the same call rules out a second one: otherwise an
	// archive older than the change threshold would have itself fetched over
	// and over.
	changedCount, err := z.increment(ctx, !full)
	if err != nil {
		return snapshot, nil, err
	}
	if changedCount == 0 && !first {
		return snapshot, nil, ErrNotModified
	}
	if err := z.saveState(); err != nil {
		return snapshot, nil, err
	}

	advisories, covered, err := z.collect()
	if err != nil {
		return snapshot, nil, err
	}

	SortAdvisories(advisories)
	snapshot.Releases = intersection(covered, releases)
	snapshot.Digest = Digest(advisories)
	snapshot.AdvisoryCount = len(advisories)
	snapshot.FetchedAt = time.Now().UTC()
	if !z.mark.IsZero() {
		moment := z.mark.UTC()
		snapshot.SourceModifiedAt = &moment
	}
	return snapshot, advisories, nil
}

// intersection returns the releases the panel really has something to assess
// with.
func intersection(covered map[string]bool, releases []string) []string {
	var result []string
	for _, release := range releases {
		if covered[release] {
			result = append(result, release)
		}
	}
	sort.Strings(result)
	return result
}

// sourceState is what survives a restart of the panel.
type sourceState struct {
	Archive string    `json:"archive"`
	Mark    time.Time `json:"mark"`
	// Releases says which releases the findings were written for. A memory
	// built for a narrower set is not an incomplete memory - it is a memory
	// of something else, and it has to be built again.
	Releases []string `json:"releases"`
}

// covers says whether the first set of releases contains the second.
func covers(have, want map[string]bool) bool {
	if len(have) == 0 {
		return false
	}
	for release := range want {
		if !have[release] {
			return false
		}
	}
	return true
}

// releaseSet turns a list of releases into a set.
func releaseSet(releases []string) map[string]bool {
	set := map[string]bool{}
	for _, release := range releases {
		if release != "" {
			set[release] = true
		}
	}
	return set
}

// releaseList turns a set of releases into a sorted list.
func releaseList(set map[string]bool) []string {
	list := make([]string, 0, len(set))
	for release := range set {
		list = append(list, release)
	}
	sort.Strings(list)
	return list
}

// load fills the memory of the source: from disk, and when there is none -
// from the archive.
//
// It returns whether it reached for the full archive.
func (z *Source) load(ctx context.Context) (bool, error) {
	if z.loaded {
		return false, nil
	}
	if err := os.MkdirAll(z.documentDirectory(), 0o750); err != nil {
		return false, err
	}

	state, err := z.readState()
	if err != nil {
		return false, err
	}
	if state.Archive != "" && covers(releaseSet(state.Releases), z.releases) && z.hasDocuments() {
		z.archive, z.mark = state.Archive, state.Mark
		z.loaded = true
		return false, nil
	}
	if err := z.fullFetch(ctx); err != nil {
		return false, err
	}
	z.loaded = true
	return true, nil
}

// documentDirectory points at the place for the findings that were read.
func (z *Source) documentDirectory() string {
	return filepath.Join(z.Directory, "documents")
}

// hasDocuments says whether there are any findings read on disk.
func (z *Source) hasDocuments() bool {
	wpisy, err := os.ReadDir(z.documentDirectory())
	return err == nil && len(wpisy) > 0
}

// fullFetch pulls and unpacks the archive of every document.
func (z *Source) fullFetch(ctx context.Context) error {
	name, err := z.text(ctx, "archive_latest.txt")
	if err != nil {
		return fmt.Errorf("the name of the archive: %w", err)
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("archive_latest.txt points at %q", name)
	}

	// The archive is from the day it carries in its name rather than from
	// today. A mark taken from the moment of the fetch would call everything
	// the vendor published since the archive was assembled read - that is,
	// pass over a week of changes in silence. The increment pulls the rest.
	before := ArchiveDate(name)

	// A full fetch starts from a clean directory: a document the vendor has
	// withdrawn must not survive in the records as a finding.
	if err := os.RemoveAll(z.documentDirectory()); err != nil {
		return err
	}
	if err := os.MkdirAll(z.documentDirectory(), 0o750); err != nil {
		return err
	}

	response, err := z.get(ctx, name)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	counter := &byteCounter{source: io.LimitReader(response.Body, MaxArchive+1)}
	decompressed, err := zstd.NewReader(counter)
	if err != nil {
		return err
	}
	defer decompressed.Close()

	reader := tar.NewReader(decompressed)
	documents := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("the archive %s: %w", name, err)
		}
		if header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".json") {
			continue
		}
		if header.Size > MaxFile {
			return fmt.Errorf("the document %s has %d bytes", header.Name, header.Size)
		}
		documents++
		if documents > MaxDocuments {
			return fmt.Errorf("the archive has more than %d documents", MaxDocuments)
		}
		content, err := io.ReadAll(io.LimitReader(reader, MaxFile))
		if err != nil {
			return err
		}
		if err := z.accept(documentPath(header.Name), content); err != nil {
			return err
		}
	}
	if counter.read > MaxArchive {
		return fmt.Errorf("the archive exceeds %d bytes", MaxArchive)
	}
	if documents == 0 {
		return fmt.Errorf("the archive %s has not a single document", name)
	}
	z.archive, z.mark = name, before
	return nil
}

// ArchiveDate reads the date out of the name of an archive
// ("csaf_vex_2026-08-30.tar.zst").
//
// When the name does not carry one we return the zero time: the increment
// then walks the whole list of changes, which is an expensive but true
// answer.
func ArchiveDate(name string) time.Time {
	for _, part := range strings.FieldsFunc(name, func(c rune) bool {
		return c == '_' || c == '.'
	}) {
		if moment, err := time.Parse("2006-01-02", part); err == nil {
			return moment.UTC()
		}
	}
	return time.Time{}
}

// increment pulls the files changed since the last fetch.
func (z *Source) increment(ctx context.Context, mayArchive bool) (int, error) {
	changedFiles, newest, err := z.changedFiles(ctx, "changes.csv")
	if err != nil {
		return 0, err
	}
	deleted, _, err := z.changedFiles(ctx, "deletions.csv")
	if err != nil {
		return 0, err
	}
	if len(changedFiles) == 0 && len(deleted) == 0 {
		return 0, nil
	}
	// With a large number of changes fetching the archive is cheaper for both
	// sides than several thousand separate requests.
	if len(changedFiles) > ChangesForFullFetch && mayArchive {
		if err := z.fullFetch(ctx); err != nil {
			return 0, err
		}
		return len(changedFiles), nil
	}

	for _, path := range deleted {
		if err := z.remove(path); err != nil {
			return 0, err
		}
	}
	for _, path := range changedFiles {
		content, err := z.file(ctx, path)
		if err != nil {
			return 0, err
		}
		if content == nil {
			// The file disappeared between the listing and the fetch: that
			// is not an error, it means the vendor withdrew it.
			if err := z.remove(path); err != nil {
				return 0, err
			}
			continue
		}
		if err := z.accept(path, content); err != nil {
			return 0, err
		}
	}
	if !newest.IsZero() {
		z.mark = newest
	}
	return len(changedFiles) + len(deleted), nil
}

// accept translates one document and writes its findings to disk.
//
// To disk rather than into memory: the findings for one RHEL release alone
// are close to a million and keeping them between cycles would cost the panel
// several hundred megabytes only for something to change once a day.
func (z *Source) accept(path string, content []byte) error {
	advisories, err := Advisories(content, z.releases)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(advisories) == 0 {
		// A document that says nothing about the base RHEL takes up no
		// space: most of them are like that.
		return z.remove(path)
	}
	encoded, err := json.Marshal(advisories)
	if err != nil {
		return err
	}
	target := filepath.Join(z.documentDirectory(), filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	return os.WriteFile(target, encoded, 0o640)
}

// remove deletes the findings read from one document.
func (z *Source) remove(path string) error {
	err := os.Remove(filepath.Join(z.documentDirectory(), filepath.FromSlash(path)))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// collect reads from disk every finding and the releases they describe.
func (z *Source) collect() ([]vuln.Advisory, map[string]bool, error) {
	covered := map[string]bool{}
	var result []vuln.Advisory
	years, err := os.ReadDir(z.documentDirectory())
	if err != nil {
		return nil, nil, err
	}
	for _, year := range years {
		if !year.IsDir() {
			continue
		}
		directory := filepath.Join(z.documentDirectory(), year.Name())
		files, err := os.ReadDir(directory)
		if err != nil {
			return nil, nil, err
		}
		for _, file := range files {
			content, err := os.ReadFile(filepath.Join(directory, file.Name()))
			if err != nil {
				return nil, nil, err
			}
			var advisories []vuln.Advisory
			if err := json.Unmarshal(content, &advisories); err != nil {
				// A damaged record must not pretend to be the whole thing:
				// half the data looks exactly like no vulnerabilities.
				return nil, nil, fmt.Errorf("%s/%s: %w", year.Name(), file.Name(), err)
			}
			for _, advisory := range advisories {
				covered[advisory.Release] = true
			}
			result = append(result, advisories...)
		}
	}
	return result, covered, nil
}

// changedFiles reads the list of changed files newer than the mark of the
// source.
func (z *Source) changedFiles(ctx context.Context, name string) ([]string, time.Time, error) {
	content, err := z.text(ctx, name)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", name, err)
	}
	return Changes(strings.NewReader(content), z.mark)
}

// Changes reads a "file,date" listing and returns the files newer than the
// mark.
func Changes(source io.Reader, after time.Time) ([]string, time.Time, error) {
	reader := csv.NewReader(source)
	reader.FieldsPerRecord = -1
	newest := time.Time{}
	var files []string
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, time.Time{}, err
		}
		if len(row) < 2 {
			continue
		}
		moment, err := time.Parse(time.RFC3339, strings.TrimSpace(row[1]))
		if err != nil {
			continue
		}
		if moment.After(newest) {
			newest = moment.UTC()
		}
		if !after.IsZero() && !moment.After(after) {
			continue
		}
		path := documentPath(strings.TrimSpace(row[0]))
		if path == "" {
			continue
		}
		files = append(files, path)
	}
	return files, newest, nil
}

// documentPath reduces a path from the archive or the listing to the form
// "year/cve-....json".
//
// The name comes from outside, so we accept nothing that does not look
// exactly like a VEX document: a year and a CVE file. Everything else is
// rejected rather than straightened out - a path we do not understand is not
// a path we are allowed to guess at.
func documentPath(name string) string {
	name = filepath.ToSlash(strings.TrimSpace(name))
	parts := strings.Split(name, "/")
	if len(parts) < 2 {
		return ""
	}
	year, file := parts[len(parts)-2], parts[len(parts)-1]
	if len(year) != 4 || !onlyDigits(year) {
		return ""
	}
	if !strings.HasPrefix(file, "cve-") || !strings.HasSuffix(file, ".json") {
		return ""
	}
	if strings.ContainsAny(file, `\:`) || strings.Contains(file, "..") {
		return ""
	}
	return year + "/" + file
}

// onlyDigits says whether a string consists of digits alone.
func onlyDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// file fetches one VEX document. It returns nil when the vendor has
// withdrawn it.
func (z *Source) file(ctx context.Context, path string) ([]byte, error) {
	response, err := z.get(ctx, path)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(io.LimitReader(response.Body, MaxFile))
}

// text fetches a small helper file.
func (z *Source) text(ctx context.Context, name string) (string, error) {
	response, err := z.get(ctx, name)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, MaxFile))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// get makes a request to the data directory of the vendor.
func (z *Source) get(ctx context.Context, name string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, z.Base+name, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "flotestro-vuln/1")
	response, err := z.Client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("%s answered %s", name, response.Status)
	}
	return response, nil
}

// readState reads the state written down at the previous fetch.
func (z *Source) readState() (sourceState, error) {
	var state sourceState
	content, err := os.ReadFile(filepath.Join(z.Directory, "state.json"))
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(content, &state); err != nil {
		// A damaged state must not block the source: worse than fetching
		// everything again is fetching nothing.
		return sourceState{}, nil
	}
	return state, nil
}

// saveState persists the state of the source.
func (z *Source) saveState() error {
	if err := os.MkdirAll(z.Directory, 0o750); err != nil {
		return err
	}
	state, err := json.Marshal(sourceState{
		Archive: z.archive, Mark: z.mark, Releases: releaseList(z.releases),
	})
	if err != nil {
		return err
	}
	// The state is written through a temporary file and a rename: an
	// interrupted write must not leave the panel with a state it cannot
	// read.
	temporary := filepath.Join(z.Directory, "state.json.tmp")
	if err := os.WriteFile(temporary, state, 0o640); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(z.Directory, "state.json"))
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

// SortAdvisories puts the findings in an order independent of the order they
// were read in: the digest has to be the same for the same data.
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
	sum.Write([]byte("flotestro/vuln/redhat/v1\n"))
	for _, advisory := range advisories {
		sum.Write([]byte(strings.Join([]string{
			advisory.SourcePackage, advisory.Release, advisory.AdvisoryID,
			advisory.Status, advisory.FixedVersion, advisory.VendorSeverity,
		}, "\x1f")))
		sum.Write([]byte{'\n'})
	}
	return hex.EncodeToString(sum.Sum(nil))
}
