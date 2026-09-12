package version

import (
	"strings"
)

// CompareRPM compares full RPM versions in the EVR form
// (epoch:version-release).
//
// It returns a negative number, zero or a positive one - just like rpmvercmp
// from librpm.
func CompareRPM(a, b string) int {
	epochA, versionA, releaseA := splitEVR(a)
	epochB, versionB, releaseB := splitEVR(b)

	if result := CompareRPMSegment(epochA, epochB); result != 0 {
		return result
	}
	if result := CompareRPMSegment(versionA, versionB); result != 0 {
		return result
	}
	// The release is compared only when both sides carry one: an advisory
	// often gives the version alone, and then "2.4.6" and "2.4.6-1" mean the
	// same question rather than two different versions.
	if releaseA == "" || releaseB == "" {
		return 0
	}
	return CompareRPMSegment(releaseA, releaseB)
}

// splitEVR divides an RPM version into the epoch, the version and the
// release.
func splitEVR(evr string) (epoch, version, release string) {
	evr = strings.TrimSpace(evr)
	epoch = "0"
	if colon := strings.Index(evr, ":"); colon >= 0 {
		epoch = evr[:colon]
		if strings.TrimSpace(epoch) == "" {
			epoch = "0"
		}
		evr = evr[colon+1:]
	}
	if dash := strings.Index(evr, "-"); dash >= 0 {
		return epoch, evr[:dash], evr[dash+1:]
	}
	return epoch, evr, ""
}

// CompareRPMSegment implements rpmvercmp for one segment of a version.
//
// The librpm algorithm: strings are split into runs of digits, runs of
// letters and the rest; separators are skipped, a run of digits is always
// newer than a run of letters, and a tilde is smaller than everything. The
// "^" character marks an intermediate version and is greater than the end of
// the string but smaller than any other character.
func CompareRPMSegment(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Separators are skipped on both sides.
		for i < len(a) && !isAlphanumeric(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlphanumeric(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		// A tilde: smaller than everything, including the end of the string.
		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			switch {
			case i >= len(a) || a[i] != '~':
				return 1
			case j >= len(b) || b[j] != '~':
				return -1
			}
			i++
			j++
			continue
		}
		// A caret: greater than the end of the string, smaller than any other
		// character.
		if (i < len(a) && a[i] == '^') || (j < len(b) && b[j] == '^') {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case a[i] != '^':
				return 1
			case b[j] != '^':
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
			for i < len(a) && isLetter(a[i]) {
				i++
			}
			for j < len(b) && isLetter(b[j]) {
				j++
			}
		}
		segmentA, segmentB := a[startA:i], b[startB:j]
		if segmentB == "" {
			// A run of digits is always newer than a run of letters.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			segmentA = strings.TrimLeft(segmentA, "0")
			segmentB = strings.TrimLeft(segmentB, "0")
			if len(segmentA) != len(segmentB) {
				if len(segmentA) > len(segmentB) {
					return 1
				}
				return -1
			}
		}
		if result := strings.Compare(segmentA, segmentB); result != 0 {
			if result > 0 {
				return 1
			}
			return -1
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

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAlphanumeric(c byte) bool { return isDigit(c) || isLetter(c) }
