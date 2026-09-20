package packages

import (
	"strings"
	"unicode"
)

// The direction of a change in the plan. Every element of a plan carries one:
// the operator approves "openssl goes up to 3.
const (
	ActionInstall   = "install"
	ActionUpgrade   = "upgrade"
	ActionDowngrade = "downgrade"
	ActionRemove    = "remove"
)

// changeAction names the direction of a version change of the manager's
// family.
func changeAction(manager, current, candidate string) string {
	switch {
	case current == "" && candidate == "":
		return ""
	case current == "":
		return ActionInstall
	case candidate == "":
		return ActionRemove
	}
	var order int
	if manager == "apt" {
		order = CompareDebVersions(candidate, current)
	} else {
		order = CompareRPMVersions(candidate, current)
	}
	if order < 0 {
		return ActionDowngrade
	}
	return ActionUpgrade
}

// CompareDebVersions orders two Debian versions the way dpkg does
// (deb-version(7)): the epoch numerically, then the upstream and the revision.
func CompareDebVersions(a, b string) int {
	epochA, restA := splitEpoch(a)
	epochB, restB := splitEpoch(b)
	if order := compareNumeric(epochA, epochB); order != 0 {
		return order
	}
	upstreamA, revisionA := splitDebRevision(restA)
	upstreamB, revisionB := splitDebRevision(restB)
	if order := compareDebPart(upstreamA, upstreamB); order != 0 {
		return order
	}
	return compareDebPart(revisionA, revisionB)
}

func splitEpoch(version string) (epoch, rest string) {
	if index := strings.IndexByte(version, ':'); index >= 0 {
		return version[:index], version[index+1:]
	}
	return "0", version
}

// splitDebRevision cuts the Debian revision off at the last hyphen; a
// version without a hyphen has no revision.
func splitDebRevision(version string) (upstream, revision string) {
	if index := strings.LastIndexByte(version, '-'); index >= 0 {
		return version[:index], version[index+1:]
	}
	return version, ""
}

// debOrder is the weight of one character in a non-digit run: a tilde before
// the end of the string, the end before letters, letters before everything
// else, and within a class the byte value.
func debOrder(c byte, present bool) int {
	switch {
	case !present:
		return 0
	case c == '~':
		return -1
	case unicode.IsLetter(rune(c)):
		return int(c)
	default:
		return int(c) + 256
	}
}

func compareDebPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// The non-digit run.
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ca, cb byte
			presentA, presentB := i < len(a) && !isDigit(a[i]), j < len(b) && !isDigit(b[j])
			if presentA {
				ca = a[i]
			}
			if presentB {
				cb = b[j]
			}
			if order := debOrder(ca, presentA) - debOrder(cb, presentB); order != 0 {
				if order < 0 {
					return -1
				}
				return 1
			}
			if presentA {
				i++
			}
			if presentB {
				j++
			}
		}
		// The digit run.
		startA, startB := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if order := compareNumeric(a[startA:i], b[startB:j]); order != 0 {
			return order
		}
	}
	return 0
}

// CompareRPMVersions orders two EVR strings the way rpm does (rpmvercmp): the
// epoch numerically, then the version and the release by their segments.
func CompareRPMVersions(a, b string) int {
	epochA, restA := splitEpoch(a)
	epochB, restB := splitEpoch(b)
	if order := compareNumeric(epochA, epochB); order != 0 {
		return order
	}
	versionA, releaseA := splitDebRevision(restA)
	versionB, releaseB := splitDebRevision(restB)
	if order := rpmvercmp(versionA, versionB); order != 0 {
		return order
	}
	return rpmvercmp(releaseA, releaseB)
}

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Separators are skipped; a tilde and a caret are ordered on their
		// own before anything else is looked at.
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		tildeA, tildeB := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if tildeA || tildeB {
			if !tildeA {
				return 1
			}
			if !tildeB {
				return -1
			}
			i++
			j++
			continue
		}
		caretA, caretB := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if caretA || caretB {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case !caretA:
				return 1
			case !caretB:
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		startA, startB := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		segmentA, segmentB := a[startA:i], b[startB:j]
		if segmentB == "" {
			// The segments are of different kinds: a number beats letters.
			if numeric {
				return 1
			}
			return -1
		}
		var order int
		if numeric {
			order = compareNumeric(segmentA, segmentB)
		} else {
			order = strings.Compare(segmentA, segmentB)
		}
		if order != 0 {
			return order
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

// compareNumeric orders two digit strings by value, whatever their leading
// zeros and their length; an empty string is zero.
func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }
