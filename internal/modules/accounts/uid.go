// Package accounts holds what the inventory, the control plane and the root
// helper have to agree on about local accounts: which identifiers belong to
// people and which to the system, which groups are root by another name, and
package accounts

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// LoginDefsPath is the file useradd itself reads for the ranges.
const LoginDefsPath = "/etc/login.defs"

// The fallback range. The values match the settings of the distributions
// the fleet runs; they apply only when the file is missing or says nothing.
const (
	DefaultUIDMin       = 1000
	DefaultUIDMax       = 60000
	DefaultSystemUIDMax = 999
)

// UIDRange is the range of identifiers that belong to the accounts of people,
// as the host's login.
type UIDRange struct {
	Min int64
	Max int64
	// SystemMax is SYS_UID_MAX: useradd --system allocates below it.
	SystemMax int64
	// Source says where the values came from: the path of the file, or
	// "defaults" when the file was unreadable or silent.
	Source string
}

// DefaultUIDRange is the range assumed where login.defs says nothing.
func DefaultUIDRange() UIDRange {
	return UIDRange{Min: DefaultUIDMin, Max: DefaultUIDMax, SystemMax: DefaultSystemUIDMax, Source: "defaults"}
}

// LoadUIDRange reads the range from the host's login.defs.
func LoadUIDRange() UIDRange {
	return ParseUIDRange(LoginDefsPath)
}

// ParseUIDRange reads the range from the given file. The path is a parameter
// so the classification can be checked without touching the system.
func ParseUIDRange(path string) UIDRange {
	file, err := os.Open(path)
	if err != nil {
		return DefaultUIDRange()
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	uidRange := ParseLoginDefs(strings.Join(lines, "\n"))
	if uidRange.Source != "defaults" {
		uidRange.Source = path
	}
	return uidRange
}

// ParseLoginDefs reads UID_MIN, UID_MAX and SYS_UID_MAX from the content of a
// login.
func ParseLoginDefs(content string) UIDRange {
	uidRange := DefaultUIDRange()
	found := false
	for _, line := range strings.Split(content, "\n") {
		if before, _, commented := strings.Cut(line, "#"); commented {
			line = before
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || value < 0 {
			continue
		}
		switch fields[0] {
		case "UID_MIN":
			uidRange.Min, found = value, true
		case "UID_MAX":
			uidRange.Max, found = value, true
		case "SYS_UID_MAX":
			uidRange.SystemMax, found = value, true
		}
	}
	if uidRange.Max < uidRange.Min {
		return DefaultUIDRange()
	}
	if found {
		uidRange.Source = "login.defs"
	}
	return uidRange
}

// IsSystem says whether an identifier belongs to the system rather than
// to a person.
func (r UIDRange) IsSystem(uid int64) bool {
	return uid < r.Min || uid > r.Max
}
