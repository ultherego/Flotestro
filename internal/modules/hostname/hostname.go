// Package hostname holds the rules of renaming a host: what a name may look
// like and how the entries of /etc/hosts follow the rename. The panel
// validates an order with the same code the helper checks it with, so an
// order the host would refuse is refused already when it is placed.
package hostname

import (
	"fmt"
	"regexp"
	"strings"
)

// HostsPath is the file that maps names to addresses locally.
const HostsPath = "/etc/hosts"

// BackupPath keeps the content of /etc/hosts from before the first rename
// by the panel. It is written once and never overwritten: the file from
// before the panel touched anything is the one an administrator wants back.
const BackupPath = "/etc/hosts.flotestro-before"

// maxLength is the limit the kernel sets on a hostname (HOST_NAME_MAX);
// a fully qualified name has the same limit in practice.
const maxLength = 64

// label matches one RFC 1123 label: letters, digits and hyphens, neither at
// the start nor at the end, at most 63 characters.
var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate rejects a name that cannot be a hostname.
//
// Upper-case letters are refused rather than folded: hostnamectl would
// lower them and the host would end up with a name other than the one the
// operator approved. A trailing dot is refused for the same reason.
func Validate(name string) error {
	if name == "" {
		return fmt.Errorf("the hostname is empty")
	}
	if len(name) > maxLength {
		return fmt.Errorf("the hostname is longer than %d characters", maxLength)
	}
	if strings.ToLower(name) != name {
		return fmt.Errorf("the hostname %q has upper-case letters; the host would lower them", name)
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return fmt.Errorf("localhost is not a name of a host")
	}
	for _, part := range strings.Split(name, ".") {
		if !label.MatchString(part) {
			return fmt.Errorf("invalid hostname %q: the label %q is not an RFC 1123 label", name, part)
		}
	}
	return nil
}

// ValidatePretty rejects a pretty name the tool would refuse or that would
// break the record it is written to.
func ValidatePretty(pretty string) error {
	if strings.ContainsAny(pretty, "\n\r\x00") {
		return fmt.Errorf("the pretty hostname must not contain a newline")
	}
	if len(pretty) > 255 {
		return fmt.Errorf("the pretty hostname is longer than 255 characters")
	}
	return nil
}

// Short returns the first label of a name: the part the kernel reports as
// the short hostname.
func Short(name string) string {
	short, _, _ := strings.Cut(name, ".")
	return short
}

// RewriteHosts replaces the old hostname with the new one in the entries of
// /etc/hosts that name it.
//
// Only the name fields are touched, never the address and never a comment,
// and only whole names are replaced: a host called "db" must not turn
// "db-backup" into something else. The short forms of both names are
// treated as well, because distributions write the short name next to the
// full one on the same line. The rewrite is idempotent: content that no
// longer names the old hostname comes back unchanged.
func RewriteHosts(content, previous, current string) (string, bool) {
	if previous == "" || previous == current {
		return content, false
	}
	replacements := map[string]string{previous: current}
	// The short form follows the long one: distributions write the short
	// name next to the full one on the same line. A short old name is the
	// full old name and is already covered.
	if short := Short(previous); short != previous && Short(current) != short {
		replacements[short] = Short(current)
	}

	lines := strings.Split(content, "\n")
	changed := false
	for index, line := range lines {
		text, comment, hasComment := strings.Cut(line, "#")
		fields := strings.Fields(text)
		if len(fields) < 2 {
			continue
		}
		touched := false
		seen := map[string]bool{}
		names := make([]string, 0, len(fields)-1)
		for _, name := range fields[1:] {
			if replacement, found := replacements[name]; found {
				name = replacement
				touched = true
			}
			if seen[name] {
				// Two names collapsing into one after the rewrite leave
				// one entry, not a duplicate.
				touched = true
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
		if !touched {
			continue
		}
		rebuilt := fields[0] + "\t" + strings.Join(names, " ")
		if hasComment {
			rebuilt += " #" + comment
		}
		lines[index] = rebuilt
		changed = true
	}
	if !changed {
		return content, false
	}
	return strings.Join(lines, "\n"), true
}
