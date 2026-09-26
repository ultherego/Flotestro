package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// EnvDatabaseMode declares what kind of database this installation runs
// against. It is declared and never guessed. The deployment used to infer it
// from whether a DSN file happened to be there, so an installation meant for a
// database somebody else runs could come up pointing at a local server nobody
// started - or generate a password for one and persist the address of it.
const EnvDatabaseMode = "FLOTESTRO_DATABASE_MODE"

// EnvAllowInsecureDatabase lets a laboratory run an external database without
// TLS. It exists so the refusal below has one visible way round it instead of
// several invisible ones.
const EnvAllowInsecureDatabase = "FLOTESTRO_LAB_ALLOW_INSECURE_DB"

// DatabaseMode is quickstart or external.
type DatabaseMode string

const (
	// DatabaseModeQuickstart is the database this deployment starts itself: one
	// host, an internal network, and a trial that has to come up on the first
	// command.
	DatabaseModeQuickstart DatabaseMode = "quickstart"
	// DatabaseModeExternal is a database somebody else runs. The panel then
	// holds the connection to what an installation of that kind promises: a
	// verified server and a writer.
	DatabaseModeExternal DatabaseMode = "external"
)

// ParseDatabaseMode reads the mode from configuration. An empty value is the
// quickstart, because that is what an installation with nothing set is.
func ParseDatabaseMode(value string) (DatabaseMode, error) {
	switch DatabaseMode(strings.ToLower(strings.TrimSpace(value))) {
	case "", DatabaseModeQuickstart:
		return DatabaseModeQuickstart, nil
	case DatabaseModeExternal:
		return DatabaseModeExternal, nil
	}
	return "", fmt.Errorf("%s has to be quickstart or external, not %q", EnvDatabaseMode, value)
}

// DatabaseModeSetting reads the declared mode.
func DatabaseModeSetting() (DatabaseMode, error) {
	return ParseDatabaseMode(os.Getenv(EnvDatabaseMode))
}

// CheckDatabaseDSN holds the connection to what the declared mode promises.
// The DSN itself never reaches an error message: it carries the password.
func CheckDatabaseDSN(mode DatabaseMode, dsn string) error {
	if mode != DatabaseModeExternal {
		return nil
	}
	settings, err := dsnSettings(dsn)
	if err != nil {
		return err
	}
	insecure := strings.EqualFold(os.Getenv(EnvAllowInsecureDatabase), "true")
	switch settings["sslmode"] {
	case "verify-full":
	case "":
		if !insecure {
			return fmt.Errorf("the DSN names no sslmode; a database somebody else runs is reached with "+
				"sslmode=verify-full, or with %s=true if this is a laboratory", EnvAllowInsecureDatabase)
		}
	default:
		if !insecure {
			return fmt.Errorf("the DSN asks for sslmode=%s; a database somebody else runs is reached with "+
				"verify-full, which checks the certificate against the name it was reached by - anything "+
				"less accepts a server that merely answers. Set %s=true only in a laboratory",
				settings["sslmode"], EnvAllowInsecureDatabase)
		}
	}
	// A pooler or a replica handed a write silently loses it or refuses it late.
	// Asked for here, the connection goes to a writer or does not open.
	if attrs := settings["target_session_attrs"]; attrs != "read-write" && !insecure {
		if attrs == "" {
			return fmt.Errorf("the DSN names no target_session_attrs; add target_session_attrs=read-write " +
				"so the panel connects to a writer and not to a standby that accepts the connection and " +
				"refuses every change")
		}
		return fmt.Errorf("the DSN asks for target_session_attrs=%s; the panel writes, so it needs read-write", attrs)
	}
	return nil
}

// DatabaseTrustsSystemRoots says whether an external DSN leaves the root
// certificates to the system store. It is not an error - a public authority is
// a reasonable choice - but it is worth one line at the start.
func DatabaseTrustsSystemRoots(mode DatabaseMode, dsn string) bool {
	if mode != DatabaseModeExternal {
		return false
	}
	settings, err := dsnSettings(dsn)
	if err != nil {
		return false
	}
	return settings["sslrootcert"] == ""
}

// dsnSettings reads the parameters of a DSN in either form the drivers take:
// a URL, or a list of key=value pairs.
func dsnSettings(dsn string) (map[string]string, error) {
	settings := map[string]string{}
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return nil, fmt.Errorf("the DSN is empty")
	}
	if strings.HasPrefix(trimmed, "postgres://") || strings.HasPrefix(trimmed, "postgresql://") {
		parsed, err := url.Parse(trimmed)
		if err != nil {
			// The message carries no DSN: it holds the password.
			return nil, fmt.Errorf("the DSN is not a valid URL")
		}
		for key, values := range parsed.Query() {
			if len(values) > 0 {
				settings[strings.ToLower(key)] = values[len(values)-1]
			}
		}
		settings["host"] = parsed.Hostname()
		return settings, nil
	}
	for _, field := range strings.Fields(trimmed) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		settings[strings.ToLower(key)] = strings.Trim(value, "'\"")
	}
	return settings, nil
}
