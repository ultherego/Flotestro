package sudoers

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// visudoCandidates are the places the checker lives. A service PATH rarely
// carries the sbin directories, so the paths come first and the PATH last.
var visudoCandidates = []string{"/usr/sbin/visudo", "/usr/local/sbin/visudo", "/sbin/visudo"}

// visudoTimeout bounds the run: the checker reads the files and exits.
const visudoTimeout = 15 * time.Second

// The bounds on what the checker's message may carry into the inventory.
const (
	maxCheckerLines  = 8
	maxCheckerLength = 200
)

// runSyntaxCheck is the seam the tests replace; on a host it runs visudo.
var runSyntaxCheck = runVisudo

// runVisudo runs "visudo -c" and reports what happened: the tool, the status
// and the message. It states facts and never decides whether the host passes.
func runVisudo(now time.Time) *SyntaxCheck {
	check := &SyntaxCheck{CheckedAt: now.UTC()}
	tool, err := findVisudo()
	if err != nil {
		check.Reason = "visudo was not found on this host: " + err.Error()
		return check
	}
	check.Tool, check.Available = tool, true

	ctx, cancel := context.WithTimeout(context.Background(), visudoTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, tool, "-c")
	// A fixed environment keeps the diagnostics in one language and one form,
	// whatever the host's locale is.
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	check.Output = sanitizeCheckerOutput(string(output))

	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		check.Reason = "visudo did not finish within " + visudoTimeout.String()
	case err == nil:
		check.Ran = true
	case errors.As(err, &exit) && exit.ExitCode() >= 0:
		check.Ran, check.ExitCode = true, exit.ExitCode()
	default:
		// The tool is there and did not run: that says nothing about the files.
		check.Reason = "visudo did not run: " + err.Error()
	}
	return check
}

// findVisudo names the checker of this host.
func findVisudo() (string, error) {
	for _, candidate := range visudoCandidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return exec.LookPath("visudo")
}

// checkerDiagnostic matches the lines the checker writes about the files. The
// other lines are the policy it echoes back around the error, and those name
// accounts, hosts and commands.
var checkerDiagnostic = regexp.MustCompile(`(?i)(parsed OK|syntax error|parse error|unknown defaults|` +
	`is invalid|unable to |cannot |no such file|not found|permission denied|>>>)`)

// sanitizeCheckerOutput keeps the checker's diagnostics and drops the policy
// lines it quotes: the panel needs the file and the line, not their contents.
func sanitizeCheckerOutput(output string) string {
	kept := make([]string, 0, maxCheckerLines)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !checkerDiagnostic.MatchString(line) {
			continue
		}
		if runes := []rune(line); len(runes) > maxCheckerLength {
			line = string(runes[:maxCheckerLength]) + "…"
		}
		kept = append(kept, line)
		if len(kept) == maxCheckerLines {
			break
		}
	}
	return strings.Join(kept, "\n")
}
