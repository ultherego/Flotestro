// Package version compares package versions by the rules of their own
// managers.
//
// This is the place where a silent error with serious consequences is
// easiest to make. Package versions are not SemVer and cannot be compared
// lexically: "1.10" is newer than "1.9", "1.0~rc1" older than "1.0", and the
// epoch in "1:2.0" beats anything without an epoch. A wrong answer in this
// direction means a vulnerability considered fixed - that is, a host the
// panel calls safe.
package version

import (
	"strconv"
	"strings"
)

// CompareDeb compares versions by the Debian rule (deb-version(7)).
//
// It returns a negative number, zero or a positive one - just like
// dpkg --compare-versions.
func CompareDeb(a, b string) int {
	epochA, upstreamA, revisionA := splitDeb(a)
	epochB, upstreamB, revisionB := splitDeb(b)

	if result := compareNumbers(epochA, epochB); result != 0 {
		return result
	}
	if result := compareDebPart(upstreamA, upstreamB); result != 0 {
		return result
	}
	return compareDebPart(revisionA, revisionB)
}

// splitDeb divides a version into the epoch, the upstream part and the
// Debian revision.
func splitDeb(version string) (epoch int, upstream, revision string) {
	version = strings.TrimSpace(version)
	if colon := strings.Index(version, ":"); colon >= 0 {
		// An unreadable epoch is treated as zero: such a spelling does not
		// come from dpkg and has no right to win a comparison.
		epoch, _ = strconv.Atoi(version[:colon])
		version = version[colon+1:]
	}
	if dash := strings.LastIndex(version, "-"); dash >= 0 {
		return epoch, version[:dash], version[dash+1:]
	}
	return epoch, version, ""
}

func compareNumbers(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareDebPart compares one part of a Debian version.
//
// The algorithm is exactly the one from dpkg: alternately we compare
// non-numeric fragments by a character order of their own and numeric
// fragments as numbers. A tilde is smaller than everything, including the
// end of the string - which is why "1.0~rc1" is older than "1.0".
func compareDebPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// A non-numeric fragment.
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			charA, charB := 0, 0
			if i < len(a) {
				charA = debOrder(a[i])
			}
			if j < len(b) {
				charB = debOrder(b[j])
			}
			if charA != charB {
				return compareNumbers(charA, charB)
			}
			i++
			j++
		}
		// Leading zeroes do not change the value of a number.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		startA, startB := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		digitsA, digitsB := a[startA:i], b[startB:j]
		if len(digitsA) != len(digitsB) {
			return compareNumbers(len(digitsA), len(digitsB))
		}
		if result := strings.Compare(digitsA, digitsB); result != 0 {
			return result
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// debOrder gives characters the order used by dpkg.
//
// A tilde is smaller than empty space, letters come before the remaining
// characters and everything else after them - by the ASCII code shifted so
// that it does not fall between the letters.
func debOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case isDigit(c):
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	default:
		return int(c) + 256
	}
}
