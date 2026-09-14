package packages

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// lockCheckBudget bounds the lock check. The scenario of chapter 23 is a
// refusal that does not hang: apt-get itself waits up to two minutes for a
// busy lock, and a check that waited with it would freeze the whole job.
const lockCheckBudget = 2 * time.Second

// holdLock takes the lock the way dpkg and rpm do: an exclusive flock on the
// file, held until the end of the test. The adapter opens the file through
// a descriptor of its own, and flock locks belong to the open file
// description, so the lock is really contended rather than re-entered.
func holdLock(t *testing.T, path string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	})
}

// swapLockFiles points an adapter at files in a temporary directory standing
// in for /var/lib/dpkg or /var/lib/rpm, and restores the real list afterwards.
func swapLockFiles(t *testing.T, list *[]string, paths ...string) {
	t.Helper()
	saved := *list
	*list = paths
	t.Cleanup(func() { *list = saved })
}

// timed runs the check and fails the test when it did not come back within
// the budget: a check that blocks is the bug the scenario is about.
func timed(t *testing.T, what string, run func()) {
	t.Helper()
	started := time.Now()
	run()
	if elapsed := time.Since(started); elapsed > lockCheckBudget {
		t.Fatalf("%s took %s; the lock check has to come back at once", what, elapsed)
	}
}

// TestLockHeldSeesTheFrontendLock is the scenario of a local administrator in
// the middle of "apt install": the panel's operation is refused with the
// typed code, names the lock, and does not queue behind it.
func TestLockHeldSeesTheFrontendLock(t *testing.T) {
	dpkg := t.TempDir()
	frontend := filepath.Join(dpkg, "lock-frontend")
	holdLock(t, frontend)
	// The other files exist and are free: the refusal has to come from the
	// one that is really held, not from every file the list names.
	free := filepath.Join(dpkg, "lock")
	if err := os.WriteFile(free, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	swapLockFiles(t, &aptLockFiles, free, frontend)

	apt := &APT{}
	timed(t, "LockHeld", func() {
		held, path := apt.LockHeld()
		if !held {
			t.Fatal("a held frontend lock was not seen")
		}
		if path != frontend {
			t.Fatalf("the lock reported was %s, expected %s", path, frontend)
		}
	})

	// The transaction itself refuses before it starts anything, with the
	// code the panel shows and the error the callers recognise as a refusal
	// rather than a broken transaction.
	timed(t, "Upgrade", func() {
		apply, err := apt.Upgrade(context.Background(), Options{})
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("Upgrade under a held lock: %v, expected %v", err, ErrLocked)
		}
		// The literal is deliberate: the code is part of the job result
		// contract, and renaming the constant must not pass unnoticed.
		if code, _ := ErrorCodeOf(err); code != "package_manager_locked" {
			t.Fatalf("code = %q, expected package_manager_locked", code)
		}
		if !Refused(err) {
			t.Fatal("a held lock is a refusal, not a failed transaction")
		}
		if len(apply.Applied) != 0 {
			t.Fatalf("the refused transaction reports %d applied packages", len(apply.Applied))
		}
	})

	// A metadata refresh takes the same lock and is refused the same way.
	timed(t, "Refresh", func() {
		if err := apt.Refresh(context.Background()); !errors.Is(err, ErrLocked) {
			t.Fatalf("Refresh under a held lock: %v, expected %v", err, ErrLocked)
		}
	})
}

// TestAFreeLockDoesNotRefuseTheChange guards the other side: the check
// must not turn every transaction away. A free file is free, and a file the
// process cannot open is "not checked" rather than "held" - a missing
// directory must not block the host for good.
func TestAFreeLockDoesNotRefuseTheChange(t *testing.T) {
	dpkg := t.TempDir()
	free := filepath.Join(dpkg, "lock-frontend")
	if err := os.WriteFile(free, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dpkg, "does-not-exist", "lock")

	timed(t, "lockHeld", func() {
		if held, checked := lockHeld(free); held || !checked {
			t.Fatalf("a free lock: held=%v checked=%v", held, checked)
		}
		if held, checked := lockHeld(missing); held || checked {
			t.Fatalf("a missing lock file: held=%v checked=%v, expected neither", held, checked)
		}
	})

	swapLockFiles(t, &aptLockFiles, free, missing)
	if held, path := (&APT{}).LockHeld(); held {
		t.Fatalf("a free lock was reported as held at %s", path)
	}
	// The lock the check took to look must be gone: the check may not leave
	// the file locked behind itself, or the administrator's next apt call
	// would wait for the panel.
	if held, _ := lockHeld(free); held {
		t.Fatal("the check left the lock held")
	}
}

// TestTheRPMLockIsSeenTheSameWay checks the dnf adapter against the same
// scenario: the lock file differs, the refusal does not.
func TestTheRPMLockIsSeenTheSameWay(t *testing.T) {
	rpm := t.TempDir()
	lock := filepath.Join(rpm, ".rpm.lock")
	holdLock(t, lock)
	swapLockFiles(t, &dnfLockFiles, lock)

	dnf := &DNF{}
	timed(t, "LockHeld", func() {
		held, path := dnf.LockHeld()
		if !held || path != lock {
			t.Fatalf("held=%v path=%s, expected the lock at %s", held, path, lock)
		}
	})
	timed(t, "Upgrade", func() {
		_, err := dnf.Upgrade(context.Background(), Options{})
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("Upgrade under a held lock: %v, expected %v", err, ErrLocked)
		}
		if code, _ := ErrorCodeOf(err); code != "package_manager_locked" {
			t.Fatalf("code = %q, expected package_manager_locked", code)
		}
	})
}
