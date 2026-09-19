package packages

import (
	"strings"
)

// maxReasonLength limits the message in the result of a job.
const maxReasonLength = 400

// errorMarkers recognise the lines that carry the cause.
var errorMarkers = []string{
	"error", "e: ", "problem", "failed", "failure", "cannot", "conflict",
	"no match", "nothing provides", "sub-process", "unmet dependencies",
}

// errorDescription picks from the output of a tool the lines that really say
// what went wrong.
func errorDescription(stderr, stdout string) string {
	lines := append(usefulLines(stderr), usefulLines(stdout)...)
	if len(lines) == 0 {
		return ""
	}

	// The line with an error marker and what follows it: dnf writes "Error:
	// Transaction failed" and the details only below.
	for i, line := range lines {
		if hasErrorMarker(line) {
			return joinLines(lines[i:])
		}
	}
	// Without a marker what counts is the end of the output rather than the
	// beginning.
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return joinLines(lines)
}

// usefulLines sifts out the progress bars and the empty lines.
func usefulLines(text string) []string {
	var result []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || progressLine(line) {
			continue
		}
		result = append(result, line)
	}
	return result
}

// progressLine recognises a progress bar. Dnf builds it out of percentages and
// columns separated by a vertical bar; apt uses brackets with percentages.
func progressLine(line string) bool {
	if strings.Contains(line, "%") && strings.Contains(line, "|") {
		return true
	}
	// Lines of the sort "Progress: [ 12%]" and "(Reading database ... 45%".
	trimmed := strings.TrimLeft(line, "([ ")
	return strings.HasPrefix(trimmed, "Progress") || strings.HasPrefix(trimmed, "Reading database")
}

func hasErrorMarker(line string) bool {
	lower := strings.ToLower(line)
	for _, marker := range errorMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// joinLines builds the lines into one sentence and trims it to the limit.
func joinLines(lines []string) string {
	text := strings.Join(lines, " / ")
	if len(text) > maxReasonLength {
		// The trim is visible: a cut message without a mark could look like
		// the full text of the error.
		return text[:maxReasonLength] + "…"
	}
	return text
}

// brokenDownloadSymptoms recognise the failures that have exactly one correct
// answer: the fetched file is damaged and has to be fetched again.
var brokenDownloadSymptoms = []string{
	"cannot be verified",
	"failed to verify",
	"checksum",
	"digest mismatch",
	"hash sum mismatch",
	"corrupted",
	"is corrupt",
	"unexpected end of file",
	"is not the expected size",
	"package does not match intended download",
	// pacman: a package file that fails its check.
	"invalid or corrupted package",
}

// BrokenDownload says whether the transaction failed because of a damaged file
// in the cache.
func BrokenDownload(stderr, stdout string) bool {
	text := strings.ToLower(stderr + "\n" + stdout)
	for _, symptom := range brokenDownloadSymptoms {
		if strings.Contains(text, symptom) {
			return true
		}
	}
	return false
}
