package redhat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChangesTakeOnlyNewerFiles(t *testing.T) {
	listing := `"2026/cve-2026-0003.json","2026-09-06T08:35:48+00:00"
"2026/cve-2026-0002.json","2026-09-05T10:00:00+00:00"
"2025/cve-2025-0001.json","2026-08-01T10:00:00+00:00"
`
	after, _ := time.Parse(time.RFC3339, "2026-09-05T00:00:00Z")
	files, newest, err := Changes(strings.NewReader(listing), after)
	if err != nil {
		t.Fatalf("the list of changes: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("files to fetch = %v", files)
	}
	if !newest.Equal(time.Date(2026, 9, 6, 8, 35, 48, 0, time.UTC)) {
		t.Fatalf("newest mark = %s", newest)
	}
	// A zero mark means "we have nothing": we then take the whole listing.
	all, _, err := Changes(strings.NewReader(listing), time.Time{})
	if err != nil || len(all) != 3 {
		t.Fatalf("the whole listing = %v (%v)", all, err)
	}
}

func TestTheDocumentPathDoesNotLeaveTheDirectory(t *testing.T) {
	cases := map[string]string{
		"2026/cve-2026-0001.json":          "2026/cve-2026-0001.json",
		"./2026/cve-2026-0001.json":        "2026/cve-2026-0001.json",
		"csaf/v2/vex/2026/cve-2026-1.json": "2026/cve-2026-1.json",
		"../../etc/passwd.json":            "",
		"/etc/passwd.json":                 "",
		"2026/cve-2026-0001.txt":           "",
		"cve-2026-0001.json":               "",
		"2026/../../etc/cve-x.json":        "",
		"changes.csv":                      "",
	}
	for input, want := range cases {
		if got := documentPath(input); got != want {
			t.Errorf("%q -> %q, want %q", input, got, want)
		}
	}
}

func TestTheArchiveDateComesFromTheName(t *testing.T) {
	moment := ArchiveDate("csaf_vex_2026-08-30.tar.zst")
	if !moment.Equal(time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("archive date = %s", moment)
	}
	// A name without a date is to give the zero time rather than today:
	// otherwise the panel would call everything it has never seen read.
	if !ArchiveDate("csaf_vex_latest.tar.zst").IsZero() {
		t.Fatal("a name without a date gave a non-zero mark")
	}
}

func TestTheRecordsSurviveARestart(t *testing.T) {
	directory := t.TempDir()
	source := New("", directory, time.Minute)
	source.releases = map[string]bool{"9": true}
	if err := source.accept("2026/cve-2026-1234.json", []byte(vexSample)); err != nil {
		t.Fatalf("reading the document: %v", err)
	}
	source.archive = "csaf_vex_2026-08-30.tar.zst"
	source.mark = time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	if err := source.saveState(); err != nil {
		t.Fatalf("writing the state: %v", err)
	}
	first, _, err := source.collect()
	if err != nil {
		t.Fatalf("reading the findings: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("the records hold not a single finding")
	}

	second := New("", directory, time.Minute)
	state, err := second.readState()
	if err != nil {
		t.Fatalf("reading the state: %v", err)
	}
	if state.Archive != source.archive || !state.Mark.Equal(source.mark) {
		t.Fatalf("the state after a restart = %+v", state)
	}
	if !covers(releaseSet(state.Releases), map[string]bool{"9": true}) {
		t.Fatalf("the state does not say which releases the records were built for: %+v", state)
	}
	second.releases = map[string]bool{"9": true}
	after, covered, err := second.collect()
	if err != nil {
		t.Fatalf("reading after a restart: %v", err)
	}
	if len(after) != len(first) || !covered["9"] {
		t.Fatalf("after a restart findings = %d, releases = %v", len(after), covered)
	}
}

func TestADocumentWithoutRHELTakesNoSpace(t *testing.T) {
	directory := t.TempDir()
	source := New("", directory, time.Minute)
	// A document about the nine read for the ten has nothing to say.
	source.releases = map[string]bool{"10": true}
	if err := source.accept("2026/cve-2026-1234.json", []byte(vexSample)); err != nil {
		t.Fatalf("reading the document: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "documents", "2026", "cve-2026-1234.json")); !os.IsNotExist(err) {
		t.Fatal("a document without findings took space in the records")
	}
}

func TestDamagedRecordsDoNotPretendToBeTheFullThing(t *testing.T) {
	directory := t.TempDir()
	source := New("", directory, time.Minute)
	source.releases = map[string]bool{"9": true}
	if err := source.accept("2026/cve-2026-1234.json", []byte(vexSample)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "documents", "2026", "cve-2026-9999.json"),
		[]byte("[{cut"), 0o640); err != nil {
		t.Fatal(err)
	}
	// Half the data would look like the whole thing and the host would come
	// out clean, so damaged records are a fetch error rather than a smaller
	// set.
	if _, _, err := source.collect(); err == nil {
		t.Fatal("damaged records went through as the whole thing")
	}
}

func TestAMemoryForNarrowerReleasesIsNotEnough(t *testing.T) {
	// A memory built for the nine does not describe the ten - and must not be
	// called complete, because the hosts of the new release would look clean.
	if covers(map[string]bool{"9": true}, map[string]bool{"9": true, "10": true}) {
		t.Error("a narrower set of releases was called sufficient")
	}
	if !covers(map[string]bool{"9": true, "10": true}, map[string]bool{"9": true}) {
		t.Error("a wider set of releases was called insufficient")
	}
	if covers(nil, map[string]bool{"9": true}) {
		t.Error("an empty memory was called sufficient")
	}
}

func TestWeReadOnlyTheNamedReleases(t *testing.T) {
	advisories, err := Advisories([]byte(vexSample), map[string]bool{"10": true})
	if err != nil {
		t.Fatalf("reading the document: %v", err)
	}
	if len(advisories) != 0 {
		t.Fatalf("a document about the nine gave %d findings for the ten", len(advisories))
	}
	nine, err := Advisories([]byte(vexSample), map[string]bool{"9": true})
	if err != nil {
		t.Fatalf("reading the document: %v", err)
	}
	if len(nine) == 0 {
		t.Fatal("a document about the nine gave not a single finding")
	}
}
