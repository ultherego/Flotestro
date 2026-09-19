package logs

import (
	"errors"
	"regexp"
	"strings"
)

// ErrBootID means the value is not a boot identifier.
var ErrBootID = errors.New("not a boot identifier: thirty-two hex digits, with or without dashes")

// hex32 is the bare form of a boot identifier as the journal spells it.
var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// NormalizeBootID brings a boot identifier to the form journalctl takes after
// --boot: thirty-two lowercase hex digits without dashes.
func NormalizeBootID(raw string) (string, error) {
	value := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", ""))
	if !hex32.MatchString(value) {
		return "", ErrBootID
	}
	return value, nil
}
