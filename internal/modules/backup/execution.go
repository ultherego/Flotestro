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

	"github.com/ultherego/flotestro/internal/platform/process"
)

// ErrInterrupted means an operation interrupted before the end.
var ErrInterrupted = errors.New("the operation was interrupted before completion")

// ErrRepositoryAbsent means the repository is not there yet: the tool found
// nothing to open at the address it was given.
var ErrRepositoryAbsent = errors.New("the repository does not exist yet")

// repositoryAbsent reads the tool's own words for "there is nothing here".
func repositoryAbsent(output string) bool {
	text := strings.ToLower(output)
	for _, phrase := range []string{
		// restic
		"unable to open config file",
		"repository does not exist",
		"config file does not exist",
		// borg
		"does not exist",
		"repository not found",
		"is not a valid repository",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

// toolEnvironment assembles the variables for the tool process.
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
func run(ctx context.Context, path string, arguments []string,
	environment []string, secrets [][]byte, lineFunc func(string)) commandResult {
	return runInDir(ctx, "", path, arguments, environment, secrets, lineFunc)
}

// runInDir runs the tool in the given working directory.
func runInDir(ctx context.Context, dir, path string, arguments []string,
	environment []string, secrets [][]byte, lineFunc func(string)) commandResult {
	// The tool runs behind the resource scope the context asks for, when the
	// helper put one there; the working directory and the environment are those
	// of the tool either way, the scope adds nothing of its own.
	argv := process.Apply(ctx, append([]string{path}, arguments...))
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
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
	// An interruption has its own reason: a process killed by the time limit or
	// by cancelling the task leaves a state nobody knows, and silence here would
	// look like an ordinary tool failure.
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
