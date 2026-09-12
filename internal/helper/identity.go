package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// probeIdentity reads the privileged part of the domain state: the host keytab
// and the SSSD cache database. The agent has no access to them and should not
// have one.
func (s *Server) probeIdentity(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.IdentityProbeRequest) *helperv1.HelperResponse {
	result := &helperv1.IdentityProbeResult{}
	var missing []string

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

// parseConfigCheck reads the result of the SSSD configuration check.
//
// The tool ends its output with the summary line "Issues identified by
// validators: N". Counting it as a problem would turn an "everything is fine"
// report into a warning, so the summary serves only to decide whether to return
// any details at all.
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

// runIdentityTool runs a tool from a fixed list of paths. The name never comes
// from the request, so it cannot point at an arbitrary program.
func runIdentityTool(ctx context.Context, timeout time.Duration, tool string, args ...string) (string, string, error) {
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

	err := cmd.Run()
	if cmdCtx.Err() != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("the time was exceeded")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && stdout.Len() > 0 {
		// The tool may have returned a result despite a non-zero code.
		return stdout.String(), stderr.String(), nil
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
