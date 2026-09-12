package packages

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Progress describes the progress of a package transaction.
//
// The step and the percentage are separate, because the tools give different
// things: apt knows the percentage of the whole operation, dnf numbers the
// steps. An undetermined value is not turned into zero - zero steps would look
// like no work at all.
type Progress struct {
	Step    uint32
	Total   uint32
	Percent *uint32
	Message string
}

// ProgressFunc receives the progress. The calls are already limited in
// frequency, so the receiver does not have to throttle them.
type ProgressFunc func(Progress)

// minimumProgressInterval limits the stream to a pace a person can read. Apt
// can print several hundred changes of the percentage per second; each of them
// would cost a notification all the way to the browser.
const minimumProgressInterval = 400 * time.Millisecond

// dnfStep recognises the progress lines of dnf. The description column is
// padded to a fixed width, so between the description and the percentage there
// is sometimes one space and sometimes a dozen - the pattern anchors on the
// percentage column rather than on the gap:
//
//	[1/6] Verify package files              100% | 166.0   B/s | ...
//	[3/6] Upgrading tcpdump-14:4.99.6-2.fc4 100% |  36.0 MiB/s | ...
var dnfStep = regexp.MustCompile(`^\[\s*(\d+)/(\d+)\]\s+(.+?)\s+\d{1,3}%`)

// dnfStepWithoutPercent handles the steps printed without a progress column.
var dnfStepWithoutPercent = regexp.MustCompile(`^\[\s*(\d+)/(\d+)\]\s+(.+?)\s*$`)

// throttler lets the progress through no more often than every
// minimumProgressInterval, but does not lose the last state.
type throttler struct {
	mu       sync.Mutex
	receiver ProgressFunc
	last     time.Time
}

func (d *throttler) send(p Progress, now time.Time) {
	if d == nil || d.receiver == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.last) < minimumProgressInterval {
		return
	}
	d.last = now
	d.receiver(p)
}

// runWithProgress starts a tool and reports the progress along the way.
//
// Apt gets a status descriptor of its own (APT::Status-Fd). That is its own
// machine channel of progress - parsing the bars from a terminal would give a
// result that depends on the width of the window and on the locale.
func runWithProgress(ctx context.Context, timeout time.Duration, progress ProgressFunc,
	statusFd bool, path string, args ...string) commandResult {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return commandResult{ExitCode: -1, Err: errorf("%s: the tool is missing", path)}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Env = environment()

	throttle := &throttler{receiver: progress}
	var wait sync.WaitGroup

	stdout := &limitedBuffer{limit: maxOutput}
	stderr := &limitedBuffer{limit: maxOutput}

	// The outputs are read line by line so that the progress arrives along the
	// way rather than only once the tool has finished.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return commandResult{ExitCode: -1, Err: err}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return commandResult{ExitCode: -1, Err: err}
	}

	if statusFd {
		reader, writer, err := os.Pipe()
		if err != nil {
			return commandResult{ExitCode: -1, Err: err}
		}
		// ExtraFiles starts at descriptor 3.
		cmd.ExtraFiles = []*os.File{writer}
		wait.Add(1)
		go func() {
			defer wait.Done()
			defer reader.Close()
			readAPTStatus(reader, throttle)
		}()
		defer writer.Close()
	}

	if err := cmd.Start(); err != nil {
		return commandResult{ExitCode: -1, Err: err}
	}
	if statusFd {
		// The parent has to close its end, otherwise the reader never sees the
		// end of the stream.
		_ = cmd.ExtraFiles[0].Close()
	}

	wait.Add(2)
	go func() { defer wait.Done(); readOutput(stdoutPipe, stdout, throttle) }()
	go func() { defer wait.Done(); readOutput(stderrPipe, stderr, throttle) }()

	// The readers have to finish before Wait: Wait closes the pipes, so called
	// earlier it would cut the output that has not been read yet.
	wait.Wait()
	runErr := cmd.Wait()

	result := commandResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1, Err: runErr}
	switch {
	case runErr == nil:
		result.Ran, result.ExitCode = true, 0
	default:
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.Ran, result.ExitCode = true, exitErr.ExitCode()
		}
	}
	if cmdCtx.Err() != nil {
		result.Ran = false
	}
	return result
}

// readOutput gathers the output and recognises the steps of dnf along the
// way.
func readOutput(r io.Reader, buffer *limitedBuffer, throttle *throttler) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		buffer.WriteLine(line)
		if progress, ok := dnfStepFrom(line); ok {
			throttle.send(progress, time.Now())
		}
	}
}

// dnfStepFrom reads the number of a step out of a progress line of dnf.
func dnfStepFrom(line string) (Progress, bool) {
	match := dnfStep.FindStringSubmatch(line)
	if match == nil {
		match = dnfStepWithoutPercent.FindStringSubmatch(line)
	}
	if match == nil {
		return Progress{}, false
	}
	step, err := strconv.ParseUint(match[1], 10, 32)
	if err != nil {
		return Progress{}, false
	}
	total, err := strconv.ParseUint(match[2], 10, 32)
	if err != nil || total == 0 {
		return Progress{}, false
	}
	return Progress{
		Step:    uint32(step),
		Total:   uint32(total),
		Message: strings.TrimSpace(match[3]),
	}, true
}

// readAPTStatus reads the machine progress channel of apt.
//
// The format is "kind:package:percentage:description". The dlstatus kind
// covers the download, pmstatus the installation itself; the operator cares
// about both, because both phases can take a while.
func readAPTStatus(r io.Reader, throttle *throttler) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 8<<10), 256<<10)
	for scanner.Scan() {
		if progress, ok := aptStatus(scanner.Text()); ok {
			throttle.send(progress, time.Now())
		}
	}
}

// aptStatus reads one line of the status channel of apt.
func aptStatus(line string) (Progress, bool) {
	parts := strings.SplitN(line, ":", 4)
	if len(parts) < 4 {
		return Progress{}, false
	}
	kind := parts[0]
	if kind != "pmstatus" && kind != "dlstatus" {
		return Progress{}, false
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	if err != nil {
		return Progress{}, false
	}
	percent := uint32(value)
	description := strings.TrimSpace(parts[3])
	if kind == "dlstatus" {
		description = "Downloading: " + description
	}
	return Progress{Percent: &percent, Message: description}, true
}

// readAPTStatusForTest exposes the parser of the apt status to the tests
// without the throttling: a test is to check the reading of the format rather
// than the pace of the reports.
func readAPTStatusForTest(r io.Reader, throttle *throttler) {
	throttle.mu.Lock()
	throttle.last = time.Time{}
	throttle.mu.Unlock()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if p, ok := aptStatus(scanner.Text()); ok {
			throttle.receiver(p)
		}
	}
}
