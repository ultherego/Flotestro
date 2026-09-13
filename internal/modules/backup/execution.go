package backup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ErrInterrupted means an operation interrupted before the end.
//
// An interrupted backup is neither a failed nor a successful backup: it is
// a state that has to be stated directly. The repository may have writes
// started, and the restore directory - half the files.
var ErrInterrupted = errors.New("the operation was interrupted before completion")

// toolEnvironment assembles the variables for the tool process.
//
// The credentials go exactly this way, not in the arguments: the command
// line is readable in /proc by every user of the host, and the environment
// - only by the process owner.
func toolEnvironment(order Order, passwordVariable string) []string {
	environment := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"HOME=" + workingDir(),
		"TMPDIR=" + workingDir(),
	}
	if len(order.Password) > 0 && passwordVariable != "" {
		environment = append(environment, passwordVariable+"="+string(order.Password))
	}
	for name, value := range order.Environment {
		environment = append(environment, name+"="+string(value))
	}
	return environment
}

// workingDir points at a directory writable by the tool process.
var workingDir = func() string { return os.TempDir() }

// SetWorkingDir points at the working directory of the backup tools.
func SetWorkingDir(dir string) {
	if dir == "" {
		return
	}
	workingDir = func() string { return dir }
}

// commandResult separates the fact of starting the process from its
// result.
type commandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Ran      bool
	Err      error
}

// Reason describes a failure in a way readable in the task result.
//
// The credentials are already masked by whoever runs the command: the
// reason goes into the task result, and from there into the panel
// database.
func (r commandResult) Reason() string {
	if r.Err != nil && !r.Ran {
		return r.Err.Error()
	}
	description := strings.TrimSpace(r.Stderr)
	if description == "" {
		description = strings.TrimSpace(r.Stdout)
	}
	if description == "" {
		return fmt.Sprintf("code %d", r.ExitCode)
	}
	// The last lines say what happened; the beginning is at times the tool
	// banner.
	lines := strings.Split(description, "\n")
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	return fmt.Sprintf("code %d: %s", r.ExitCode, strings.Join(lines, " / "))
}

// run executes the tool and returns its output.
//
// Never through a shell and always as an argument array: a path name in a
// backup definition cannot become a command. The stdout lines go to the
// progress receiver as they come, because a backup takes long, and the
// operator is meant to see that something is happening - not the end alone.
func run(ctx context.Context, path string, arguments []string,
	environment []string, secrets [][]byte, lineFunc func(string)) commandResult {
	return runInDir(ctx, "", path, arguments, environment, secrets, lineFunc)
}

// runInDir runs the tool in the given working directory.
//
// Borg unpacks an archive into the current directory of the process, not
// into a directory given as an argument - so the restore target directory
// is part of the invocation here, not of the command text.
func runInDir(ctx context.Context, dir, path string, arguments []string,
	environment []string, secrets [][]byte, lineFunc func(string)) commandResult {
	cmd := exec.CommandContext(ctx, path, arguments...)
	cmd.Env = environment
	cmd.Dir = dir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return commandResult{Err: err}
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return commandResult{Err: err}
	}

	var collected strings.Builder
	var mu sync.Mutex
	reading := make(chan struct{})
	go func() {
		defer close(reading)
		scanner := bufio.NewScanner(stdout)
		// A restic progress line with a file list can be long; the default
		// scanner buffer would cut it and break the JSON parsing.
		scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			if collected.Len() < MaxOutput*2 {
				collected.WriteString(line)
				collected.WriteString("\n")
			}
			mu.Unlock()
			if lineFunc != nil {
				lineFunc(line)
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()

	<-reading
	err = cmd.Wait()

	result := commandResult{Ran: true}
	mu.Lock()
	result.Stdout = Limit(Mask(collected.String(), secrets))
	mu.Unlock()
	result.Stderr = Limit(Mask(stderr.String(), secrets))
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.Ran = false
			result.Err = err
		}
	}
	// An interruption has its own reason: a process killed by the time
	// limit or by cancelling the task leaves a state nobody knows, and
	// silence here would look like an ordinary tool failure.
	if ctx.Err() != nil {
		result.Err = fmt.Errorf("%w: %v", ErrInterrupted, ctx.Err())
	}
	return result
}

// orderSecrets gathers the values that must not be in the output.
func orderSecrets(order Order) [][]byte {
	secrets := make([][]byte, 0, len(order.Environment)+1)
	if len(order.Password) > 0 {
		secrets = append(secrets, order.Password)
	}
	for _, value := range order.Environment {
		secrets = append(secrets, value)
	}
	return secrets
}

// exists says whether the file is on the host.
func exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
