package files

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// Validator describes a content check before the write.
//
// A check makes sense only when it concerns what the file really means:
// JSON with a syntax error is not loaded by any service, and a systemd unit
// file with a typo in a section name is silently ignored. A validator the
// host does not have is not a reason to write without checking - it is a
// reason to say so directly.
type Validator struct {
	Name string
	// Command checks the file on the host. Empty means a built-in
	// validator, run without starting anything.
	Command []string
	// BuiltIn checks the content in memory.
	BuiltIn func(content string) error
}

// validators lists the known checks. The key is the name used in the
// order.
var validators = map[string]Validator{
	"json": {Name: "json", BuiltIn: validateJSON},
	"ini":  {Name: "ini", BuiltIn: validateINI},
	"systemd-unit": {
		Name:    "systemd-unit",
		Command: []string{"/usr/bin/systemd-analyze", "verify"},
	},
	"nginx": {
		Name: "nginx",
		// nginx checks the whole configuration, not a single file: a
		// fragment without context is not a valid configuration by itself.
		Command: []string{"/usr/sbin/nginx", "-t"},
	},
	"chrony": {
		Name:    "chrony",
		Command: []string{"/usr/sbin/chronyd", "-Q", "-f"},
	},
}

// SelectValidator picks the check for a path when the order did not name
// one.
func SelectValidator(path, requested string) (Validator, bool, error) {
	if requested != "" {
		validator, known := validators[requested]
		if !known {
			return Validator{}, false, fmt.Errorf("unknown validator %q", requested)
		}
		return validator, true, nil
	}
	switch {
	case strings.HasSuffix(path, ".json"):
		return validators["json"], true, nil
	case strings.HasPrefix(path, "/etc/systemd/system/") &&
		(strings.HasSuffix(path, ".service") || strings.HasSuffix(path, ".timer")):
		return validators["systemd-unit"], true, nil
	case strings.HasPrefix(path, "/etc/nginx/"):
		return validators["nginx"], true, nil
	case strings.HasPrefix(filepath.Base(path), "chrony"):
		return validators["chrony"], true, nil
	}
	return Validator{}, false, nil
}

// validateJSON checks the JSON syntax.
func validateJSON(content string) error {
	var target any
	if err := json.Unmarshal([]byte(content), &target); err != nil {
		return fmt.Errorf("the file is not valid JSON: %w", err)
	}
	return nil
}

// validateINI checks the basic syntax of key-value files.
//
// No full parser is pretended: what breaks files most often is checked - a
// row that is neither a section, nor a comment, nor an assignment.
func validateINI(content string) error {
	for number, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			continue
		}
		if !strings.Contains(trimmed, "=") {
			return fmt.Errorf("row %d is neither an assignment nor a section: %q", number+1, trimmed)
		}
	}
	return nil
}
