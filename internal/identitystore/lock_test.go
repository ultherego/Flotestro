package identitystore

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The agent daemon, the relay daemon and the operator's CLI all commit into one
// directory. Two of them at once used to be enough to lose a host's identity:
// the staging directory of one was removed by the Clean the other runs at the
// end of its commit, and both used one name for the symlink temp, so one could
// publish the other's generation under its own rename. Every writer takes the
// lock now, and this holds them to it.
func TestConcurrentCommitsEachLeaveAWholeGeneration(t *testing.T) {
	store, ca, _ := storeWithIdentity(t)
	root := store.Dir()
	const writers = 6

	var wait sync.WaitGroup
	failures := make(chan error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		generation := generation(t, ca, testHost)
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if _, err := store.Commit(generation); err != nil {
				failures <- err
			}
		}()
	}
	close(start)
	wait.Wait()
	close(failures)
	for err := range failures {
		t.Fatalf("a commit made beside the others failed: %v", err)
	}

	// Whichever of them went last, the host has an identity and it reads.
	current, err := store.Current()
	if err != nil {
		t.Fatalf("the host has no identity after six commits at once: %v", err)
	}
	if len(current.Certificate.Certificate) == 0 || current.HostID != testHost {
		t.Fatalf("the identity in force is not the host's: %+v", current.HostID)
	}

	// And nothing is left half-written: no staging directory, no leftover
	// symlink temp of an interrupted move.
	entries, err := os.ReadDir(filepath.Join(root, GenerationsDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if name := entry.Name(); len(name) > 0 && name[0] == '.' {
			t.Errorf("a temporary generation was left behind: %s", name)
		}
	}
	rootEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range rootEntries {
		if entry.Name() != nextName && len(entry.Name()) > len(nextName) &&
			entry.Name()[:len(nextName)] == nextName {
			t.Errorf("a temporary symlink was left behind: %s", entry.Name())
		}
	}
}

// A file of the previous layout that is there and cannot be read is not the
// same thing as a host with no identity, and answering "none" to it sent the
// operator to enroll a host that already had one.
func TestAnUnreadableLegacyIdentityIsAnErrorAndNotAnAbsence(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, "state"))
	legacy := t.TempDir()

	// Nothing there at all: no identity, no error.
	moved, err := store.Migrate(filepath.Join(legacy, "agent.key"),
		filepath.Join(legacy, "agent.pem"), filepath.Join(legacy, "trust.pem"))
	if moved || err != nil {
		t.Fatalf("an empty directory gave moved=%v err=%v", moved, err)
	}

	// A key that cannot be read - here a directory in its place, which fails
	// for any user rather than only for one that is not root.
	if err := os.Mkdir(filepath.Join(legacy, "agent.key"), 0o700); err != nil {
		t.Fatal(err)
	}
	moved, err = store.Migrate(filepath.Join(legacy, "agent.key"),
		filepath.Join(legacy, "agent.pem"), filepath.Join(legacy, "trust.pem"))
	if moved {
		t.Fatal("an unreadable identity was reported as moved")
	}
	if err == nil {
		t.Fatal("an unreadable identity of the previous layout was reported as no identity at all")
	}
}
