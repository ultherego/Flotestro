package helper

import (
	"errors"
	"os/exec"
	"testing"
)

// A tool that did not run has no status, and an absent status must not be read
// as a zero. Three defects in two days had that one shape: a filesystem check
// nobody performed confirmed a repair, a lock nobody could probe counted as
// absent, and a package cache that was never prepared counted as ready.
func TestAToolThatDidNotRunHasNoStatus(t *testing.T) {
	t.Run("it ended well", func(t *testing.T) {
		code, ran, reason := ranWith(nil)
		if code != 0 || !ran || reason != "" {
			t.Errorf("ranWith(nil) = %d, %v, %q; want 0, true, \"\"", code, ran, reason)
		}
	})

	t.Run("it ran and ended badly", func(t *testing.T) {
		// /bin/sh is on every host this helper runs on, so a missing one is a
		// failure of the test environment and not a reason to skip.
		err := exec.Command("/bin/sh", "-c", "exit 4").Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running a command that exits 4 gave %v, want an exit status", err)
		}
		code, ran, reason := ranWith(err)
		if !ran {
			t.Fatal("a tool that ended with a status was reported as not having run")
		}
		if code != 4 {
			t.Errorf("code = %d, want 4", code)
		}
		if reason != "" {
			t.Errorf("reason = %q over a tool that ran", reason)
		}
	})

	t.Run("it did not run at all", func(t *testing.T) {
		// The error of a command that never started is not an *exec.ExitError,
		// and that is the whole distinction this function exists for.
		code, ran, reason := ranWith(errors.New("fork/exec /usr/sbin/fsck: no such file or directory"))
		if ran {
			t.Fatal("a tool that never started was reported as having run")
		}
		if code != 0 {
			t.Errorf("code = %d over a tool that did not run", code)
		}
		if reason == "" {
			t.Error("nothing said why the tool did not run, so no message can name it")
		}
	})
}
