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

// probeIdentity odczytuje uprzywilejowana czesc stanu domeny: keytab hosta
// i baze cache SSSD. Agent nie ma do nich dostepu i nie powinien go miec.
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
		// Brak czesci danych nie jest bledem operacji: raportujemy powod,
		// zeby operator wiedzial, czego nie wiadomo i dlaczego.
		result.UnavailableReason = strings.Join(missing, "; ")
	}

	s.log.Info("odczytano stan tozsamosci hosta",
		"task_id", request.GetTaskId(), "principal", result.GetHostPrincipal(),
		"braki", len(missing))
	return &helperv1.HelperResponse{Accepted: true, IdentityResult: result}
}

// readHostKeytab odczytuje principal hosta i numer wersji klucza. Rozjazd KVNO
// miedzy hostem a katalogiem oznacza, ze Kerberos przestanie dzialac.
func readHostKeytab(ctx context.Context) (principal string, kvno *uint32, err error) {
	const keytabPath = "/etc/krb5.keytab"
	if _, statErr := os.Stat(keytabPath); statErr != nil {
		return "", nil, fmt.Errorf("brak %s", keytabPath)
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
	return "", nil, fmt.Errorf("keytab nie zawiera principala hosta")
}

// sssdCacheAge zwraca wiek bazy cache. Rosnacy wiek przy hoscie odcietym od
// katalogu oznacza, ze polityki dostepu sa coraz starsze.
func sssdCacheAge(domain string) (*uint64, error) {
	if domain == "" {
		return nil, fmt.Errorf("brak nazwy domeny")
	}
	path := filepath.Join("/var/lib/sss/db", "cache_"+domain+".ldb")
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("brak %s", path)
	}
	age := uint64(time.Since(info.ModTime()).Seconds())
	return &age, nil
}

// sssdStatus pyta SSSD o stan polaczenia i sprawdza konfiguracje.
func sssdStatus(ctx context.Context, domain string) (*bool, []string, error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("brak nazwy domeny")
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

// parseConfigCheck czyta wynik kontroli konfiguracji SSSD.
//
// Narzedzie konczy wyjscie linia podsumowania "Issues identified by
// validators: N". Zliczanie jej jako problemu zamienialoby raport "wszystko
// w porzadku" w ostrzezenie, wiec podsumowanie sluzy wylacznie do decyzji,
// czy w ogole zwracac szczegoly.
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

	// Podsumowanie mowiace o zerze jest wiazace: brak szczegolow nie oznacza
	// wtedy, ze czegos nie odczytalismy.
	if total == 0 {
		return nil
	}
	return details
}

// runIdentityTool uruchamia narzedzie z ustalonej listy sciezek. Nazwa nigdy
// nie pochodzi z zadania, wiec nie moze wskazac dowolnego programu.
func runIdentityTool(ctx context.Context, timeout time.Duration, tool string, args ...string) (string, string, error) {
	path := ""
	for _, candidate := range []string{"/usr/bin/" + tool, "/usr/sbin/" + tool, "/sbin/" + tool} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			path = candidate
			break
		}
	}
	if path == "" {
		return "", "", fmt.Errorf("brak narzedzia %s", tool)
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
		return stdout.String(), stderr.String(), fmt.Errorf("przekroczony czas")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && stdout.Len() > 0 {
		// Narzedzie moglo zwrocic wynik mimo niezerowego kodu.
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
		return "brak szczegolow"
	}
	return trimmed
}
