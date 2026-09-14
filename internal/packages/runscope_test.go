package packages

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/helper/runscope"
)

// The scope of a package transaction is a prefix in front of the tool - the
// systemd-run invocation the helper builds. The tests stand a script in for
// systemd-run: it records what it was given, drops its own flags and starts
// the tool, so the assertion is on the argv that reached the process.

// scopeShim writes the stand-in for systemd-run and a tool for it to start.
// The shim records its whole argument array in a file, one argument per
// line, so an argument with a space in it is seen as one argument.
func scopeShim(t *testing.T) (shim, tool, record string) {
	t.Helper()
	directory := t.TempDir()
	record = filepath.Join(directory, "argv")
	shim = filepath.Join(directory, "systemd-run")
	tool = filepath.Join(directory, "tool")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + record + "\"\n" +
		"while [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n"
	if err := os.WriteFile(shim, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho \"the tool ran: $*\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return shim, tool, record
}

// scopedContext carries the prefix of a scope, the way the helper records it
// for a request with limits.
func scopedContext(shim string) context.Context {
	prefix := []string{shim, "--scope", "--quiet", "--unit=flotestro-op-test", "--"}
	return runscope.With(context.Background(), func(argv []string) []string {
		return runscope.Prefixed(prefix, argv)
	})
}

func TestAPackageCommandRunsUnderTheScopeOfTheContext(t *testing.T) {
	shim, tool, record := scopeShim(t)
	result := runCommand(scopedContext(shim), time.Minute, "", tool, "--noconfirm", "-Syu", "a b")
	if !result.Ran || result.ExitCode != 0 {
		t.Fatalf("the scoped command did not run: %+v", result)
	}
	if !strings.Contains(result.Stdout, "the tool ran: --noconfirm -Syu a b") {
		t.Errorf("the tool did not get its arguments: %q", result.Stdout)
	}
	recorded, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the scope was not started: %v", err)
	}
	want := strings.Join([]string{
		"--scope", "--quiet", "--unit=flotestro-op-test", "--", tool, "--noconfirm", "-Syu", "a b",
	}, "\n") + "\n"
	if string(recorded) != want {
		t.Errorf("the scope got the argv %q\nexpected %q", recorded, want)
	}
}

func TestAPackageCommandRunsBareWithoutAScope(t *testing.T) {
	_, tool, record := scopeShim(t)
	result := runCommand(context.Background(), time.Minute, "", tool, "-Qu")
	if !result.Ran || result.ExitCode != 0 {
		t.Fatalf("the bare command did not run: %+v", result)
	}
	if !strings.Contains(result.Stdout, "the tool ran: -Qu") {
		t.Errorf("the tool did not get its arguments: %q", result.Stdout)
	}
	if _, err := os.Stat(record); err == nil {
		t.Error("the scope was started for a context without one")
	}
}

// A scope cleared in the context is a bare run as well: the helper clears it
// for a request without limits, so that nothing recorded higher up leaks in.
func TestAClearedScopeIsABareRun(t *testing.T) {
	shim, tool, record := scopeShim(t)
	ctx := runscope.With(scopedContext(shim), nil)
	result := runCommand(ctx, time.Minute, "", tool, "-Qu")
	if !result.Ran || result.ExitCode != 0 {
		t.Fatalf("the bare command did not run: %+v", result)
	}
	if _, err := os.Stat(record); err == nil {
		t.Error("the scope was started although the context cleared it")
	}
}

// The transaction with progress is the other place a tool starts; it takes
// the scope the same way, so an upgrade is not left out of it.
func TestATransactionWithProgressRunsUnderTheScope(t *testing.T) {
	shim, tool, record := scopeShim(t)
	result := runWithProgress(scopedContext(shim), time.Minute, nil, false, tool, "upgrade", "-y")
	if !result.Ran || result.ExitCode != 0 {
		t.Fatalf("the scoped transaction did not run: %+v", result)
	}
	if !strings.Contains(result.Stdout, "the tool ran: upgrade -y") {
		t.Errorf("the tool did not get its arguments: %q", result.Stdout)
	}
	recorded, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the scope was not started: %v", err)
	}
	if !strings.HasPrefix(string(recorded), "--scope\n--quiet\n--unit=flotestro-op-test\n--\n"+tool+"\n") {
		t.Errorf("the scope got the argv %q", recorded)
	}
}

// The tool is checked before the scope is asked for: a missing manager is
// reported as such, not as a failure of systemd-run.
func TestAMissingToolIsReportedBeforeTheScope(t *testing.T) {
	shim, _, record := scopeShim(t)
	result := runCommand(scopedContext(shim), time.Minute, "", filepath.Join(t.TempDir(), "absent"))
	if result.Ran || result.Err == nil || !strings.Contains(result.Err.Error(), "the tool is missing") {
		t.Fatalf("a missing tool gave %+v", result)
	}
	if _, err := os.Stat(record); err == nil {
		t.Error("the scope was started for a missing tool")
	}
}
