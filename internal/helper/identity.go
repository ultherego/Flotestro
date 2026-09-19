package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// probeIdentity reads the privileged part of the domain state: the host
// keytab, the SSSD cache database and the SSSD offline policy in sssd.
func (s *Server) probeIdentity(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.IdentityProbeRequest) *helperv1.HelperResponse {
	result := &helperv1.IdentityProbeResult{}
	var missing []string

	// Every tool below has its own short limit; the limit of the order binds them
	// together, so a stuck SSSD does not hold the connection for all of them in a
	// row.
	ctx, cancel := deadline(ctx, request, 2*time.Minute, 10*time.Minute)
	defer cancel()

	principal, kvno, err := readHostKeytab(ctx)
	switch {
	case err != nil:
		missing = append(missing, "keytab: "+err.Error())
	default:
		result.HostPrincipal = principal
		result.KeytabKvno = kvno
	}

	if age, err := sssdCacheAge(action.GetDomain()); err != nil {
		missing = append(missing, "cache SSSD: "+err.Error())
	} else {
		result.CacheAgeSeconds = age
	}

	online, issues, err := sssdStatus(ctx, action.GetDomain())
	switch {
	case err != nil:
		missing = append(missing, "sssctl: "+err.Error())
	default:
		result.SssdOnline = online
		result.ConfigIssues = issues
	}

	// The offline policy is a file read, not a tool run, so a stuck SSSD cannot
	// hide it; its own reason travels inside the message because a half-read
	// policy is still worth showing next to what is unknown.
	policy := readSSSDOfflinePolicy(action.GetDomain())
	result.SssdOfflinePolicy = sssdOfflinePolicyToProto(policy)
	if policy.UnavailableReason != "" {
		missing = append(missing, "sssd.conf: "+policy.UnavailableReason)
	}

	if len(missing) > 0 {
		// Missing parts of the data are not an error of the operation: the
		// reason is reported so that the operator knows what is unknown and why.
		result.UnavailableReason = strings.Join(missing, "; ")
	}

	s.log.Info("the identity state of the host was read",
		"task_id", request.GetTaskId(), "principal", result.GetHostPrincipal(),
		"missing", len(missing))
	return &helperv1.HelperResponse{Accepted: true, IdentityResult: result}
}

// readHostKeytab reads the host principal and the key version number. A KVNO
// mismatch between the host and the directory means Kerberos will stop working.
func readHostKeytab(ctx context.Context) (principal string, kvno *uint32, err error) {
	const keytabPath = "/etc/krb5.keytab"
	if _, statErr := os.Stat(keytabPath); statErr != nil {
		return "", nil, fmt.Errorf("%s is missing", keytabPath)
	}
	stdout, _, err := runIdentityTool(ctx, 15*time.Second, "klist", "-k", keytabPath)
	if err != nil {
		return "", nil, err
	}
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "host/") {
			continue
		}
		principal = fields[1]
		if parsed, parseErr := strconv.ParseUint(fields[0], 10, 32); parseErr == nil {
			value := uint32(parsed)
			kvno = &value
		}
		return principal, kvno, nil
	}
	return "", nil, fmt.Errorf("the keytab contains no host principal")
}

// sssdCacheAge returns the age of the cache database. A growing age on a host
// cut off from the directory means the access policies grow older and older.
func sssdCacheAge(domain string) (*uint64, error) {
	if domain == "" {
		return nil, fmt.Errorf("the domain name is missing")
	}
	path := filepath.Join("/var/lib/sss/db", "cache_"+domain+".ldb")
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s is missing", path)
	}
	age := uint64(time.Since(info.ModTime()).Seconds())
	return &age, nil
}

// sssdStatus asks SSSD about the connection state and checks the configuration.
func sssdStatus(ctx context.Context, domain string) (*bool, []string, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("the domain name is missing")
	}
	stdout, _, err := runIdentityTool(ctx, 20*time.Second, "sssctl", "domain-status", domain, "--online")
	if err != nil {
		return nil, nil, err
	}

	var online *bool
	lower := strings.ToLower(stdout)
	switch {
	case strings.Contains(lower, "online"):
		value := true
		online = &value
	case strings.Contains(lower, "offline"):
		value := false
		online = &value
	}

	issues := parseConfigCheck(ctx)
	return online, issues, nil
}

// parseConfigCheck reads the result of the SSSD configuration check. The tool
// ends its output with the summary line "Issues identified by validators: N".
func parseConfigCheck(ctx context.Context) []string {
	output, _, err := runIdentityTool(ctx, 20*time.Second, "sssctl", "config-check")
	if err != nil {
		return nil
	}

	const summaryPrefix = "issues identified by validators:"
	var (
		details []string
		total   = -1
	)
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, summaryPrefix) {
			if parsed, parseErr := strconv.Atoi(strings.TrimSpace(
				trimmed[len(summaryPrefix):])); parseErr == nil {
				total = parsed
			}
			continue
		}
		if strings.Contains(lower, "error") || strings.Contains(lower, "warning") ||
			strings.HasPrefix(lower, "[rule") {
			details = append(details, trimmed)
		}
	}

	// A summary saying zero is binding: a lack of details does not then mean
	// that something was not read.
	if total == 0 {
		return nil
	}
	return details
}

// runIdentityTool runs a tool from a fixed list of paths with nothing on its
// standard input.
func runIdentityTool(ctx context.Context, timeout time.Duration, tool string, args ...string) (string, string, error) {
	stdout, stderr, err := identityToolRunner(ctx, timeout, nil, tool, args...)
	var exit *exitStatusError
	if errors.As(err, &exit) {
		// A query tool that printed its answer and then complained is believed for
		// the answer: klist lists the keytab and exits with a warning about a
		// missing default, and the listing is the point.
		return stdout, stderr, nil
	}
	return stdout, stderr, err
}

// runIdentityToolWithInput runs a tool with the given text on its standard
// input, for a tool that takes a credential on its prompt rather than in argv.
func runIdentityToolWithInput(ctx context.Context, timeout time.Duration, input string,
	tool string, args ...string) (string, string, error) {
	return identityToolRunner(ctx, timeout, strings.NewReader(input), tool, args...)
}

// runIdentityToolStrict runs a tool whose exit code is the verdict.
func runIdentityToolStrict(ctx context.Context, timeout time.Duration, tool string, args ...string) (string, string, error) {
	return identityToolRunner(ctx, timeout, nil, tool, args...)
}

// exitStatusError says the tool ended with a non-zero code; the lenient runner
// returns it alongside a result, the strict one treats it as the failure it
// is.
type exitStatusError struct {
	tool   string
	code   int
	stderr string
}

func (e *exitStatusError) Error() string {
	return fmt.Sprintf("%s: exit status %d: %s", e.tool, e.code, firstLineOf(e.stderr))
}

// identityToolRunner is the seam the tests replace: the join and the leave
// call real directory tools, and a unit test has neither a directory nor the
// right to change the host running it.
var identityToolRunner = execIdentityTool

// execIdentityTool runs the tool. A nil input leaves the tool without a
// standard input, so a tool that prompts fails at once instead of waiting.
func execIdentityTool(ctx context.Context, timeout time.Duration, input io.Reader,
	tool string, args ...string) (string, string, error) {
	path := ""
	for _, candidate := range []string{"/usr/bin/" + tool, "/usr/sbin/" + tool, "/sbin/" + tool} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			path = candidate
			break
		}
	}
	if path == "" {
		return "", "", fmt.Errorf("the tool %s is missing", tool)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/var/lib/flotestro-helper"}
	if input != nil {
		cmd.Stdin = input
		// A password prompt reads the controlling terminal first and falls back to
		// standard input only without one.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}

	err := cmd.Run()
	if cmdCtx.Err() != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("the time was exceeded")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && stdout.Len() > 0 {
		// The tool may have returned a result despite a non-zero code. The result
		// goes back with the code, and the caller decides which one it believes.
		return stdout.String(), stderr.String(),
			&exitStatusError{tool: tool, code: exitErr.ExitCode(), stderr: stderr.String()}
	}
	if err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("%s: %v", tool, firstLineOf(stderr.String()))
	}
	return stdout.String(), stderr.String(), nil
}

func firstLineOf(text string) string {
	trimmed := strings.TrimSpace(text)
	if index := strings.IndexByte(trimmed, '\n'); index >= 0 {
		return strings.TrimSpace(trimmed[:index])
	}
	if trimmed == "" {
		return "no details"
	}
	return trimmed
}
