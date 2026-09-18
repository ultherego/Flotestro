package files

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) VersionStore {
	t.Helper()
	return VersionStore{Root: t.TempDir(), KeepPerPath: 3, MaxBytes: 1 << 20}
}

// TestAKeptVersionComesBackByteForByte guards the promise the contract of
// file.ensure makes: a previous version is kept and can be put back
// exactly - the bytes and the inode, not the bytes alone.
func TestAKeptVersionComesBackByteForByte(t *testing.T) {
	store := testStore(t)
	content := []byte("key = first\nkey2 = \x01\x02 binary\n")
	current := File{Path: "/etc/app.conf", Exists: true, Mode: "0640", Owner: "root", Group: "adm"}

	kept, err := store.Keep("/etc/app.conf", current, content, "task-1")
	if err != nil {
		t.Fatalf("keeping: %v", err)
	}
	if kept.SHA256 != Fingerprint(content) || kept.SizeBytes != int64(len(content)) {
		t.Fatalf("the version was filed under the wrong name: %+v", kept)
	}

	version, restored, err := store.Lookup("/etc/app.conf", kept.SHA256)
	if err != nil {
		t.Fatalf("looking up: %v", err)
	}
	if string(restored) != string(content) {
		t.Errorf("the content came back changed: %q", restored)
	}
	if version.Mode != "0640" || version.Owner != "root" || version.Group != "adm" {
		t.Errorf("the inode was not kept with the content: %+v", version)
	}
	if version.OrderedBy != "task-1" {
		t.Errorf("the version does not say which order displaced it: %+v", version)
	}
}

// TestAnUnknownDigestIsRefused guards the difference between a rollback
// and an undo: the operator names a content, and a host that does not have
// it says so instead of putting back the newest copy.
func TestAnUnknownDigestIsRefused(t *testing.T) {
	store := testStore(t)
	if _, err := store.Keep("/etc/app.conf", File{Exists: true}, []byte("first\n"), ""); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.Lookup("/etc/app.conf", Fingerprint([]byte("never written here\n")))
	if !errors.Is(err, ErrNoSuchVersion) {
		t.Fatalf("a digest the host never kept gave %v", err)
	}
	// A path with no versions at all answers the same way rather than with
	// a directory error the panel would have to interpret.
	if _, _, err := store.Lookup("/etc/other.conf", Fingerprint([]byte("x"))); !errors.Is(err, ErrNoSuchVersion) {
		t.Fatalf("a file with no versions gave %v", err)
	}
}

// TestACorruptedCopyIsNotWrittenBack guards the check on the way out: a
// copy whose bytes no longer hash to the digest it is filed under is not
// content anybody approved.
func TestACorruptedCopyIsNotWrittenBack(t *testing.T) {
	store := testStore(t)
	kept, err := store.Keep("/etc/app.conf", File{Exists: true}, []byte("first\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(store.directory("/etc/app.conf"))
	for _, entry := range entries {
		if entry.Name() == kept.Entry {
			if err := os.WriteFile(filepath.Join(store.directory("/etc/app.conf"), entry.Name()),
				[]byte("something else\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, _, err := store.Lookup("/etc/app.conf", kept.SHA256); !errors.Is(err, ErrVersionCorrupted) {
		t.Fatalf("a changed copy gave %v", err)
	}
}

// TestTheCountBoundDropsTheOldest guards the bound that keeps a host from
// filling the partition its own state lives on.
func TestTheCountBoundDropsTheOldest(t *testing.T) {
	store := testStore(t)
	var first string
	for _, line := range []string{"one\n", "two\n", "three\n", "four\n"} {
		kept, err := store.Keep("/etc/app.conf", File{Exists: true}, []byte(line), "")
		if err != nil {
			t.Fatal(err)
		}
		if line == "one\n" {
			first = kept.SHA256
		}
	}
	versions := store.List("/etc/app.conf")
	if len(versions) != 3 {
		t.Fatalf("the store keeps %d versions, want 3", len(versions))
	}
	if _, _, err := store.Lookup("/etc/app.conf", first); !errors.Is(err, ErrNoSuchVersion) {
		t.Error("the oldest version survived the count bound")
	}
	// The newest is the first in the list: the panel shows them in that
	// order and must not have to sort them itself.
	if versions[0].SHA256 != Fingerprint([]byte("four\n")) {
		t.Errorf("the list does not start with the newest version: %+v", versions[0])
	}
}

// TestTheByteBoundDropsTheOldestAcrossFiles guards the second bound: one
// file rewritten with large content stays inside its own count and would
// still fill the disk.
func TestTheByteBoundDropsTheOldestAcrossFiles(t *testing.T) {
	store := VersionStore{Root: t.TempDir(), KeepPerPath: 10, MaxBytes: 2048}
	large := make([]byte, 1000)
	for i := range large {
		large[i] = 'a'
	}
	oldest, err := store.Keep("/etc/one.conf", File{Exists: true}, large, "")
	if err != nil {
		t.Fatal(err)
	}
	large[0] = 'b'
	if _, err := store.Keep("/etc/two.conf", File{Exists: true}, large, ""); err != nil {
		t.Fatal(err)
	}
	large[0] = 'c'
	if _, err := store.Keep("/etc/three.conf", File{Exists: true}, large, ""); err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.Lookup("/etc/one.conf", oldest.SHA256); !errors.Is(err, ErrNoSuchVersion) {
		t.Error("the oldest copy in the store survived the byte bound")
	}
	if len(store.List("/etc/three.conf")) != 1 {
		t.Error("the newest copy was dropped instead of the oldest")
	}
}

// TestTheSameContentIsKeptOnce guards that a version is addressed by its
// content: two entries with one digest would make "restore this version"
// ambiguous.
func TestTheSameContentIsKeptOnce(t *testing.T) {
	store := testStore(t)
	for i := 0; i < 3; i++ {
		if _, err := store.Keep("/etc/app.conf", File{Exists: true}, []byte("same\n"), ""); err != nil {
			t.Fatal(err)
		}
	}
	if versions := store.List("/etc/app.conf"); len(versions) != 1 {
		t.Fatalf("the same content is kept %d times", len(versions))
	}
}

// TestTheDigestOfASecretVersionIsNotReported guards the boundary of the
// secret store: the host keeps the copy, so a rollback does not need the
// store again, but it does not put a fingerprint of a secret value into
// the panel's database.
func TestTheDigestOfASecretVersionIsNotReported(t *testing.T) {
	store := testStore(t)
	current := File{Path: "/etc/token.conf", Exists: true, Mode: "0600", FromSecret: true}
	kept, err := store.Keep("/etc/token.conf", current, []byte("s3cret\n"), "task-9")
	if err != nil {
		t.Fatal(err)
	}

	reported := store.Reported("/etc/token.conf")
	if len(reported) != 1 {
		t.Fatalf("the host does not report that it kept anything: %+v", reported)
	}
	if reported[0].SHA256 != "" {
		t.Error("the digest of content from the secret store was reported")
	}
	if !reported[0].FromSecret || reported[0].KeptAt.IsZero() {
		t.Errorf("the reported version says nothing about itself: %+v", reported[0])
	}
	// The host itself still finds the copy by its digest: the restore does
	// not need the secret store to be reachable.
	if _, content, err := store.Lookup("/etc/token.conf", kept.SHA256); err != nil ||
		string(content) != "s3cret\n" {
		t.Errorf("the host cannot put back the version it kept: %q, %v", content, err)
	}
}

// TestTheStoreIsReadableByRootAlone guards the reason keeping content from
// the secret store is safe at all: the copy has the protection the file
// itself had.
func TestTheStoreIsReadableByRootAlone(t *testing.T) {
	store := testStore(t)
	if _, err := store.Keep("/etc/app.conf", File{Exists: true}, []byte("first\n"), ""); err != nil {
		t.Fatal(err)
	}
	directory := store.directory("/etc/app.conf")
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("the directory of the store has the mode %v", info.Mode().Perm())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		details, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if details.Mode().Perm() != 0o600 {
			t.Errorf("%s has the mode %v", entry.Name(), details.Mode().Perm())
		}
	}
}
