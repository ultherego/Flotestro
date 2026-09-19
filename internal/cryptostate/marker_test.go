package cryptostate

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secondReplica is a control plane started against the same database with a
// state directory of its own: another process, another volume, one
// installation record.
func secondReplica(t *testing.T, storage *memoryStorage) Options {
	t.Helper()
	dir := t.TempDir()
	return Options{
		Storage: storage, Provider: newFakeProvider(), CADir: dir,
		LegacyKeyPath: filepath.Join(dir, "secrets.key"),
	}
}

func openFatalWith(t *testing.T, o Options, code string, stranger Stranger) *FatalError {
	t.Helper()
	_, err := Open(context.Background(), o)
	var fatal *FatalError
	if !errors.As(err, &fatal) {
		t.Fatalf("open = %v, want a fatal %s", err, code)
	}
	if fatal.Code != code {
		t.Fatalf("open failed with %s (%s), want %s", fatal.Code, fatal.Reason, code)
	}
	if fatal.Stranger != stranger {
		t.Fatalf("the refusal blames %q, want %q (%s)", fatal.Stranger, stranger, fatal.Reason)
	}
	return fatal
}

// The first start names the state directory, and every start afterwards
// reads that name rather than writing it again.
func TestTheStateDirectoryNamesItsInstallation(t *testing.T) {
	l := newLab(t)
	record := l.open(t).Record()

	data, err := os.ReadFile(MarkerPath(l.dir))
	if err != nil {
		t.Fatalf("the first start left no marker: %v", err)
	}
	if strings.TrimSpace(string(data)) != record.InstallationID {
		t.Fatalf("the marker says %q, the installation is %s", strings.TrimSpace(string(data)), record.InstallationID)
	}
	info, err := os.Stat(MarkerPath(l.dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the marker has mode %v, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(MarkerPath(l.dir) + ".new"); !errors.Is(err, fs.ErrNotExist) {
		t.Error("the temporary file of the marker was left behind")
	}

	// The ordinary restart: the same installation, nothing created, the
	// marker untouched.
	again := l.open(t)
	if again.Record().InstallationID != record.InstallationID {
		t.Fatal("the restart made another installation")
	}
	if l.storage.inserts != 1 {
		t.Fatalf("inserts = %d, want 1", l.storage.inserts)
	}
}

// Chapter 21: --scale control-plane=2 with separate state volumes. The
// second replica finds the installation record of the first and a state
// directory that holds nothing of it, and refuses rather than making itself
// a second CA and a second secret store key for one installation.
func TestAReplicaWithItsOwnStateVolumeIsRefused(t *testing.T) {
	l := newLab(t)
	record := l.open(t).Record()

	second := secondReplica(t, l.storage)
	fatal := openFatalWith(t, second, CodeInstallationMismatch, StrangerStateDirectory)
	if !strings.Contains(fatal.Reason, record.InstallationID) {
		t.Errorf("the refusal does not name the installation of the database: %s", fatal.Reason)
	}
	if !strings.Contains(fatal.Reason, second.CADir) {
		t.Errorf("the refusal does not name the state directory: %s", fatal.Reason)
	}
	// Nothing was created in the directory of the replica that was refused.
	entries, err := os.ReadDir(second.CADir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the refused replica left %d file(s) in its state directory", len(entries))
	}
	if second.Provider.HasMaterial() {
		t.Fatal("the refused replica made itself a key")
	}
	if l.storage.inserts != 1 {
		t.Fatalf("inserts = %d: the refused replica recorded an installation", l.storage.inserts)
	}
}

// The state directory of one installation next to the database of another:
// the mixture a restore from two backups produces. The directory is the
// stranger, because the database is what the fleet and the secrets follow.
func TestAStateDirectoryOfAnotherInstallationIsRefused(t *testing.T) {
	first := newLab(t)
	firstRecord := first.open(t).Record()
	other := newLab(t)
	otherRecord := other.open(t).Record()

	// The directory and the provider of the second installation, pointed at
	// the database of the first.
	mixed := Options{
		Storage: first.storage, Provider: other.provider,
		CADir: other.dir, LegacyKeyPath: other.legacy,
	}
	fatal := openFatalWith(t, mixed, CodeInstallationMismatch, StrangerStateDirectory)
	if !strings.Contains(fatal.Reason, otherRecord.InstallationID) ||
		!strings.Contains(fatal.Reason, firstRecord.InstallationID) {
		t.Errorf("the refusal does not name both installations: %s", fatal.Reason)
	}
}

// A state directory with a history against a database that describes no
// installation: an empty or a restored-from-before database under a
// directory that is somebody's. Here the database is the stranger, and
// initialising over it would make a second installation out of one set of
// keys.
func TestAnEmptyDatabaseUnderAKnownStateDirectoryIsRefused(t *testing.T) {
	l := newLab(t)
	record := l.open(t).Record()

	emptied := l.options()
	emptied.Storage = &memoryStorage{}
	fatal := openFatalWith(t, emptied, CodeInstallationMismatch, StrangerDatabase)
	if !strings.Contains(fatal.Reason, record.InstallationID) {
		t.Errorf("the refusal does not name the installation of the state directory: %s", fatal.Reason)
	}
}

// An installation from before the marker: its directory holds the key and
// the CA and says nothing about which installation they are. Every other
// check answers that question, so the start is ordinary and the directory is
// named on the way out.
func TestAnInstallationFromBeforeTheMarkerIsNamed(t *testing.T) {
	l := newLab(t)
	record := l.open(t).Record()
	if err := os.Remove(MarkerPath(l.dir)); err != nil {
		t.Fatal(err)
	}

	again := l.open(t)
	if again.Record().InstallationID != record.InstallationID {
		t.Fatal("the start made another installation")
	}
	data, err := os.ReadFile(MarkerPath(l.dir))
	if err != nil {
		t.Fatalf("the start did not name the state directory: %v", err)
	}
	if strings.TrimSpace(string(data)) != record.InstallationID {
		t.Fatalf("the marker says %q, the installation is %s", strings.TrimSpace(string(data)), record.InstallationID)
	}
}

// A marker that is there and says nothing is not read as "no marker": a
// truncated write must not let a start treat the directory as fresh.
func TestAnEmptyMarkerStopsTheStart(t *testing.T) {
	l := newLab(t)
	l.open(t)
	if err := os.WriteFile(MarkerPath(l.dir), []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), l.options()); err == nil {
		t.Fatal("a start with an empty marker succeeded")
	}
}

// The first start of an installation that does not exist yet stays what it
// is: an installation being created, with nothing to compare against.
func TestAFirstStartAgainstAnEmptyDatabaseIsAnInitialisation(t *testing.T) {
	l := newLab(t)
	runtime := l.open(t)
	if !runtime.Report(context.Background()).Initialised {
		t.Fatal("the first start did not report itself as an initialisation")
	}
}
