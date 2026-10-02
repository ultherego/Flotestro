package packages

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A POSIX record lock is what APT takes on /var/lib/dpkg/lock-frontend, and on
// Linux a flock test cannot see one. Measured on agent-debian on 02.10: with the
// POSIX lock held by another process, flock acquired the file. So this is the
// case the probe exists for, and it needs a second process, because POSIX locks
// belong to the process and this one would see its own as free.
func TestAPosixLockHeldByAnotherProcessIsSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock-frontend")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if held, checked := lockHeld(path); !checked || held {
		t.Fatalf("an unlocked file reads as held=%v checked=%v", held, checked)
	}

	ready, release := holdPosixLock(t, path)
	<-ready
	held, checked := lockHeld(path)
	release()
	if !checked {
		t.Fatal("the probe could not answer about a file it had just read")
	}
	if !held {
		t.Error("a POSIX lock held by another process was not seen; a transaction " +
			"would start beside the one already running")
	}
}

func TestAFlockHeldByAnotherProcessIsSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// flock is per open file description, so one taken here is visible to a
	// separate open of the same path in this process.
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN) }()
	if held, checked := lockHeld(path); !checked || !held {
		t.Errorf("a flock was not seen: held=%v checked=%v", held, checked)
	}
}

// A file nobody can open is not a file with no lock: the second value says the
// probe could not answer, and the caller must not read that as "free".
func TestAFileThatCannotBeOpenedIsNotAnAnswer(t *testing.T) {
	if held, checked := lockHeld(filepath.Join(t.TempDir(), "absent")); checked || held {
		t.Errorf("a missing file answered held=%v checked=%v", held, checked)
	}
}

// holdPosixLock takes the POSIX lock in a separate process and returns a channel
// closed once it is held, plus the way to let it go.
func holdPosixLock(t *testing.T, path string) (<-chan struct{}, func()) {
	t.Helper()
	// The second process is this same test binary, re-executed with the variable
	// TestMain looks for: it then holds the lock and runs no test, so the suite
	// gains no scenario and no skip. A skip the gate cannot classify is a failed
	// gate, and a helper is not a scenario.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), lockHelperVar+"="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	failed := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := stdout.Read(buf)
		if n > 0 && strings.HasPrefix(string(buf[:n]), "held") {
			close(ready)
			return
		}
		failed <- string(buf[:n])
		close(ready)
	}()
	return ready, func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		select {
		case what := <-failed:
			t.Errorf("the second process never took the lock, so this test proved "+
				"nothing: %q", what)
		default:
		}
	}
}

// lockHelperVar turns this binary into the process that holds the lock.
const lockHelperVar = "FLOTESTRO_LOCK_HELPER"

func TestMain(m *testing.M) {
	path := os.Getenv(lockHelperVar)
	if path == "" {
		os.Exit(m.Run())
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stdout, "open: %v", err)
		os.Exit(1)
	}
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart, Start: 0, Len: 0}
	if err := unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock); err != nil {
		fmt.Fprintf(os.Stdout, "lock: %v", err)
		os.Exit(1)
	}
	fmt.Fprint(os.Stdout, "held")
	select {} // until the parent lets go
}
