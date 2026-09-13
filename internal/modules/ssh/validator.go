package ssh

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The account pattern allows the "user@host" form and the asterisk, because
// that is how AllowUsers works in sshd - and that is its whole syntax.
var accountPattern = regexp.MustCompile(`^[A-Za-z0-9_.*?@-]{1,64}$`)

// sshd boolean values. "prohibit-password" is neither yes nor no, so the
// values are kept as text and checked against a list.
var (
	booleanValues = map[string]bool{"yes": true, "no": true}
	rootValues    = map[string]bool{
		"yes": true, "no": true, "prohibit-password": true, "forced-commands-only": true,
	}
)

// Validate checks a configuration change before the write.
func Validate(settings Settings) error {
	if settings.Port != "" {
		port, err := strconv.Atoi(settings.Port)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("port %q is outside the range 1-65535", settings.Port)
		}
	}
	if settings.PermitRootLogin != "" && !rootValues[settings.PermitRootLogin] {
		return fmt.Errorf("unsupported PermitRootLogin value %q", settings.PermitRootLogin)
	}
	for name, value := range map[string]string{
		"PasswordAuthentication":       settings.PasswordAuthentication,
		"PubkeyAuthentication":         settings.PubkeyAuthentication,
		"KbdInteractiveAuthentication": settings.KbdInteractive,
	} {
		if value != "" && !booleanValues[value] {
			return fmt.Errorf("%s accepts yes or no, not %q", name, value)
		}
	}
	if settings.MaxAuthTries != "" {
		tries, err := strconv.Atoi(settings.MaxAuthTries)
		if err != nil || tries < 1 || tries > 100 {
			return fmt.Errorf("MaxAuthTries %q is outside the range 1-100", settings.MaxAuthTries)
		}
	}
	for _, list := range [][]string{settings.AllowUsers, settings.DenyUsers} {
		for _, entry := range list {
			if !accountPattern.MatchString(entry) {
				return fmt.Errorf("invalid account pattern %q", entry)
			}
		}
	}
	for _, group := range settings.AllowGroups {
		if !accountPattern.MatchString(group) {
			return fmt.Errorf("invalid group name %q", group)
		}
	}
	return nil
}

// CutsOffAllMethods says whether at least one authentication method remains
// after the change.
//
// A server nobody can log into by any method is not secured - it is
// unavailable. These are not the same, and the panel must not turn one into
// the other by oversight.
func CutsOffAllMethods(desired Settings, state Snapshot) bool {
	value := func(wanted, current string) string {
		if wanted != "" {
			return wanted
		}
		return current
	}
	password := value(desired.PasswordAuthentication, state.PasswordAuthentication)
	pubkey := value(desired.PubkeyAuthentication, state.PubkeyAuthentication)
	interactive := value(desired.KbdInteractive, state.KbdInteractive)
	// GSSAPI is left to the state: the panel does not set it, but a
	// domain-joined host may rely on it.
	gssapi := state.GSSAPIAuthentication

	for _, method := range []string{password, pubkey, interactive, gssapi} {
		if strings.EqualFold(method, "yes") {
			return false
		}
	}
	return true
}
