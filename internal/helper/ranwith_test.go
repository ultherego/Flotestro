package helper

import (
	"context"
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
			t.Errorf("ranWith(nil) = %d, %v, %q", code, ran, reason)
		}
	})

	t.Run("it ran and ended badly", func(t *testing.T) {
		err := exec.Command("sh", "-c", "exit 4").Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Skip("this host did not give an exit status to read")
		}
		code, ran, _ := ranWith(err)
		if !ran {
			t.Fatal("a tool that ended with a status was reported as not having run")
		}
		if code != 4 {
			t.Errorf("code = %d, want 4", code)
		}
	})

	t.Run("it did not run at all", func(t *testing.T) {
		err := exec.Command("/nonexistent/flotestro-probe").Run()
		if err == nil {
			t.Skip("this host has a binary where none was expected")
		}
		code, ran, reason := ranWith(err)
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

	t.Run("the deadline passed", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := exec.CommandContext(ctx, "sh", "-c", "exit 0").Run()
		if err == nil {
			t.Skip("the cancelled context did not stop the command on this host")
		}
		if _, ran, reason := ranWith(err); ran && reason == "" {
			// A killed process does carry a status on some systems; what must
			// not happen is "ran, status zero, nothing to say".
			t.Error("a command stopped by its context looked like one that ended well")
		}
	})
}
