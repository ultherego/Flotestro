package helper

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// The SSSD configuration and its drop-in directory. The main file is readable
// by root only, which is the whole reason this parser lives in the helper and
// not in the agent.
const (
	sssdConfPath      = "/etc/sssd/sssd.conf"
	sssdConfDropInDir = "/etc/sssd/conf.d"
)

// The defaults SSSD applies when a key is absent from the domain section.
// They are facts about SSSD, not measurements, so a value taken from here is
// always named in Defaulted.
const (
	sssdDefaultCacheCredentials       = false
	sssdDefaultOfflineExpirationDays  = uint32(0)
	sssdDefaultEntryCacheTimeoutSecs  = uint32(5400)
	sssdDefaultStorePasswordIfOffline = false
)

// sssdOfflinePolicy is the parsed offline behaviour of one SSSD domain. A nil
// field is a value that could not be read; the reason says why. The panel
// judges what the values mean, the helper only reports them.
type sssdOfflinePolicy struct {
	CacheCredentials                 *bool
	OfflineCredentialsExpirationDays *uint32
	EntryCacheTimeoutSeconds         *uint32
	StorePasswordIfOffline           *bool
	// Defaulted names the keys absent from the configuration that took the
	// SSSD default, by their sssd.conf name.
	Defaulted []string
	// UnavailableReason explains every value left nil.
	UnavailableReason string
}

// readSSSDOfflinePolicy reads the offline policy of the domain from the
// system configuration. Nothing is executed: the file says what SSSD would
// do, and that is the fact the panel needs.
func readSSSDOfflinePolicy(domain string) sssdOfflinePolicy {
	return parseSSSDOfflinePolicy(domain, sssdConfPath, sssdConfDropInDir)
}

// parseSSSDOfflinePolicy reads the [domain/<name>] section from the main file
// and the drop-in snippets, the snippets in name order overriding the main
// file the way SSSD merges them, and extracts the offline keys.
func parseSSSDOfflinePolicy(domain, mainPath, dropInDir string) sssdOfflinePolicy {
	if strings.TrimSpace(domain) == "" {
		return sssdOfflinePolicy{UnavailableReason: "the domain name is missing"}
	}

	section, found, err := readSSSDDomainSection(domain, mainPath, dropInDir)
	if err != nil {
		return sssdOfflinePolicy{UnavailableReason: err.Error()}
	}
	if !found {
		return sssdOfflinePolicy{UnavailableReason: fmt.Sprintf(
			"no [domain/%s] section in %s", domain, mainPath)}
	}

	var policy sssdOfflinePolicy
	var problems []string
	defaulted := func(key string) { policy.Defaulted = append(policy.Defaulted, key) }
	unparsable := func(key, value string) {
		problems = append(problems, fmt.Sprintf("%s has an unreadable value %q", key, value))
	}

	if value, ok := section["cache_credentials"]; !ok {
		policy.CacheCredentials = boolPtr(sssdDefaultCacheCredentials)
		defaulted("cache_credentials")
	} else if parsed, ok := parseSSSDBool(value); ok {
		policy.CacheCredentials = &parsed
	} else {
		unparsable("cache_credentials", value)
	}

	if value, ok := section["offline_credentials_expiration"]; !ok {
		policy.OfflineCredentialsExpirationDays = uint32Ptr(sssdDefaultOfflineExpirationDays)
		defaulted("offline_credentials_expiration")
	} else if parsed, ok := parseSSSDUint(value); ok {
		policy.OfflineCredentialsExpirationDays = &parsed
	} else {
		unparsable("offline_credentials_expiration", value)
	}

	if value, ok := section["entry_cache_timeout"]; !ok {
		policy.EntryCacheTimeoutSeconds = uint32Ptr(sssdDefaultEntryCacheTimeoutSecs)
		defaulted("entry_cache_timeout")
	} else if parsed, ok := parseSSSDUint(value); ok {
		policy.EntryCacheTimeoutSeconds = &parsed
	} else {
		unparsable("entry_cache_timeout", value)
	}

	if value, ok := section["krb5_store_password_if_offline"]; !ok {
		policy.StorePasswordIfOffline = boolPtr(sssdDefaultStorePasswordIfOffline)
		defaulted("krb5_store_password_if_offline")
	} else if parsed, ok := parseSSSDBool(value); ok {
		policy.StorePasswordIfOffline = &parsed
	} else {
		unparsable("krb5_store_password_if_offline", value)
	}

	policy.UnavailableReason = strings.Join(problems, "; ")
	return policy
}

// readSSSDDomainSection collects the keys of the domain section across the
// main file and the drop-ins. A missing main file is an error - SSSD without
// a configuration is not a domain client - while a missing drop-in
// directory is the ordinary case.
func readSSSDDomainSection(domain, mainPath, dropInDir string) (map[string]string, bool, error) {
	section := map[string]string{}
	found, err := mergeSSSDDomainSection(section, domain, mainPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, fmt.Errorf("%s is missing", mainPath)
		}
		return nil, false, fmt.Errorf("%s: %v", mainPath, err)
	}

	for _, path := range sssdDropIns(dropInDir) {
		// A snippet that cannot be read must not silently hide keys it may
		// set: the whole policy is then unknown rather than half-true.
		dropInFound, err := mergeSSSDDomainSection(section, domain, path)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %v", path, err)
		}
		found = found || dropInFound
	}
	return section, found, nil
}

// sssdDropIns lists the snippets SSSD would read: the *.conf files of the
// directory, not hidden, in name order.
func sssdDropIns(dir string) []string {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		paths = append(paths, filepath.Join(dir, name))
	}
	sort.Strings(paths)
	return paths
}

// mergeSSSDDomainSection adds the keys of [domain/<name>] from one file to
// the map, later files overriding earlier ones. The section name is compared
// without regard to case: SSSD treats domain names that way.
func mergeSSSDDomainSection(into map[string]string, domain, path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	wanted := "domain/" + strings.TrimSpace(domain)
	found := false
	inSection := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				// A broken header ends the section: keys after it belong to
				// nothing SSSD would apply either.
				inSection = false
				continue
			}
			name := strings.TrimSpace(line[1:end])
			inSection = strings.EqualFold(name, wanted)
			found = found || inSection
			continue
		}
		if !inSection {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		into[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return found, nil
}

// parseSSSDBool accepts what SSSD's own confdb accepts: true or false in any
// letter case. Anything else is an unreadable value, not a false.
func parseSSSDBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// parseSSSDUint reads a non-negative integer. A negative number or text is
// unreadable rather than zero, because zero has its own meaning here.
func parseSSSDUint(value string) (uint32, bool) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(parsed), true
}

// sssdOfflinePolicyToProto carries the parsed policy over the wire without
// filling any hole: a nil field stays unset.
func sssdOfflinePolicyToProto(policy sssdOfflinePolicy) *helperv1.SssdOfflinePolicy {
	return &helperv1.SssdOfflinePolicy{
		CacheCredentials:                 policy.CacheCredentials,
		OfflineCredentialsExpirationDays: policy.OfflineCredentialsExpirationDays,
		EntryCacheTimeoutSeconds:         policy.EntryCacheTimeoutSeconds,
		Krb5StorePasswordIfOffline:       policy.StorePasswordIfOffline,
		Defaulted:                        policy.Defaulted,
		UnavailableReason:                policy.UnavailableReason,
	}
}

func boolPtr(value bool) *bool       { return &value }
func uint32Ptr(value uint32) *uint32 { return &value }
