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

// NormalizeBootID brings a boot identifier to the form journalctl takes
// after --boot: thirty-two lowercase hex digits without dashes. The kernel
// prints the same identifier with dashes in /proc/sys/kernel/random/boot_id
// and the Power tab shows that form; the journal lists it bare. Either
// spelling is accepted, and anything else is refused rather than passed on
// to journalctl, which would read a wrong value as "no such boot" and
// answer with nothing - or, for an empty one, with every boot.
func NormalizeBootID(raw string) (string, error) {
	value := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", ""))
	if !hex32.MatchString(value) {
		return "", ErrBootID
	}
	return value, nil
}
