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

// PanelDirectives reads the directives the panel's own file sets. The file is
// written by ComposeDropIn, so every line of it that is not the header is one
// directive and its value.
func PanelDirectives(content string) map[string]string {
	directives := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		directives[key] = strings.TrimSpace(value)
	}
	return directives
}

// CutsOffAllMethods says whether at least one authentication method remains
// after the change.
//
// A field the order leaves out does not mean "keep": the panel's file is
// replaced whole, so a directive the order omits and the panel's current file
// sets is removed from the host. What the server applies afterwards comes from
// the rest of its configuration and from the defaults this build of sshd was
// compiled with - neither of which the panel may invent. Such a value is
// unknown, and an unknown is not a way in: it cannot be the method that saves
// a change from locking everybody out.
func CutsOffAllMethods(desired Settings, state Snapshot) bool {
	managed := PanelDirectives(state.Managed)
	value := func(directive, wanted, current string) string {
		if wanted != "" {
			return wanted
		}
		if _, setByThePanel := managed[directive]; setByThePanel {
			return ""
		}
		return current
	}
	password := value("PasswordAuthentication", desired.PasswordAuthentication, state.PasswordAuthentication)
	pubkey := value("PubkeyAuthentication", desired.PubkeyAuthentication, state.PubkeyAuthentication)
	interactive := value("KbdInteractiveAuthentication", desired.KbdInteractive, state.KbdInteractive)
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
