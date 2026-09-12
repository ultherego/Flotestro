package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunCommandTellsAResultFromAnExecutionError(t *testing.T) {
	ctx := context.Background()

	t.Run("a process that finished successfully", func(t *testing.T) {
		result := runCommand(ctx, 5*time.Second, "/bin/true")
		if !result.Ran || result.ExitCode != 0 {
			t.Fatalf("Ran=%v ExitCode=%d, expected true/0", result.Ran, result.ExitCode)
		}
	})

	t.Run("a process that returned an error code", func(t *testing.T) {
		// A non-zero code from a process that ran is a result, not a failure.
		result := runCommand(ctx, 5*time.Second, "/bin/false")
		if !result.Ran {
			t.Fatal("the process ran and Ran=false")
		}
		if result.ExitCode != 1 {
			t.Fatalf("ExitCode=%d, expected 1", result.ExitCode)
		}
	})

	t.Run("a missing binary", func(t *testing.T) {
		result := runCommand(ctx, 5*time.Second, "/there/is/no/such/program")
		if result.Ran {
			t.Fatal("a program that does not exist was taken for one that ran")
		}
		if result.Err == nil {
			t.Fatal("no error for a program that does not exist")
		}
	})

	t.Run("an exceeded timeout", func(t *testing.T) {
		// A timeout is not a substantive result, even though the process returns
		// a code.
		result := runCommand(ctx, 100*time.Millisecond, "/bin/sleep", "5")
		if result.Ran {
			t.Fatal("a process interrupted by the timeout was taken for one that ran")
		}
	})
}

func TestRunCommandSetsAWritableHome(t *testing.T) {
	dir := t.TempDir()
	if err := SetRuntimeDir(dir); err != nil {
		t.Fatalf("the working directory: %v", err)
	}
	t.Cleanup(func() { runtimeDir = os.TempDir() })

	// Tools such as dnf create files in HOME and XDG. The agent has no home
	// directory, so the absence of those variables used to end in an error taken
	// for a result.
	result := runCommand(context.Background(), 5*time.Second, "/usr/bin/env")
	if !result.Ran {
		t.Skip("/usr/bin/env is missing")
	}
	for _, want := range []string{
		"HOME=" + dir,
		"XDG_STATE_HOME=" + filepath.Join(dir, "state"),
		"XDG_CACHE_HOME=" + filepath.Join(dir, "cache"),
	} {
		if !strings.Contains(result.Stdout, want) {
			t.Errorf("%s is missing from the environment of the process", want)
		}
	}
	for _, sub := range []string{"state", "cache", "config"} {
		if info, err := os.Stat(filepath.Join(dir, sub)); err != nil || !info.IsDir() {
			t.Errorf("the directory %s was not created", sub)
		}
	}
}

func TestInterpretNeedsRestarting(t *testing.T) {
	cases := []struct {
		name   string
		result commandResult
		want   *bool
	}{
		{
			name:   "code 0 means no restart is needed",
			result: commandResult{Ran: true, ExitCode: 0, Stdout: "Reboot should not be necessary.\n"},
			want:   boolPtr(false),
		},
		{
			name:   "code 1 with an answer means a restart is required",
			result: commandResult{Ran: true, ExitCode: 1, Stdout: "Core libraries or services have been updated.\n"},
			want:   boolPtr(true),
		},
		{
			// This is a regression: dnf without a writable HOME ends with code 1
			// and stays silent on stdout. That used to be reported as "a restart
			// is required" on every Fedora host.
			name: "code 1 without an answer is an error, not a result",
			result: commandResult{
				Ran: true, ExitCode: 1, Stdout: "",
				Stderr: "filesystem error: cannot create directories: Permission denied",
			},
			want: nil,
		},
		{
			name:   "the process did not run",
			result: commandResult{Ran: false, ExitCode: -1},
			want:   nil,
		},
		{
			name:   "an unknown exit code",
			result: commandResult{Ran: true, ExitCode: 127, Stdout: "something"},
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := interpretNeedsRestarting(tc.result)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("an undetermined state was expected, got %v", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("%v was expected, got an undetermined state", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("got %v, expected %v", *got, *tc.want)
			}
		})
	}
}

func TestCommandResultReasonDescribesTheError(t *testing.T) {
	result := commandResult{
		Ran: true, ExitCode: 1,
		Stderr: "filesystem error: cannot create directories: Permission denied\na further line",
	}
	reason := result.Reason()
	if !strings.Contains(reason, "code 1") {
		t.Errorf("the reason does not contain the exit code: %q", reason)
	}
	if !strings.Contains(reason, "Permission denied") {
		t.Errorf("the reason does not contain the content of the error: %q", reason)
	}
	if strings.Contains(reason, "a further line") {
		t.Errorf("the reason should be a single line: %q", reason)
	}
}
