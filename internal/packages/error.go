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

// trailingLines is how much of the end of an output stands for it when no line
// carries a marker.
const trailingLines = 3

// errorDescription picks from the output of a tool the lines that really say
// what went wrong. It walks the streams instead of splitting them: a failed
// transaction writes megabytes, and only a sentence of it is ever shown.
func errorDescription(stderr, stdout string) string {
	var found []string
	var tail [trailingLines]string
	count := 0

	forEachUsefulLine(stderr, stdout, func(line string) bool {
		// The line with an error marker and what follows it: dnf writes "Error:
		// Transaction failed" and the details only below.
		if len(found) > 0 || hasErrorMarker(line) {
			found = append(found, line)
			return joinedLength(found) <= maxReasonLength
		}
		tail[count%trailingLines] = line
		count++
		return true
	})

	if len(found) > 0 {
		return joinLines(found)
	}
	// Without a marker what counts is the end of the output rather than the
	// beginning.
	kept := make([]string, 0, trailingLines)
	for i := max(count-trailingLines, 0); i < count; i++ {
		kept = append(kept, tail[i%trailingLines])
	}
	return joinLines(kept)
}

// forEachUsefulLine walks the lines of both streams in order, skipping the
// progress bars and the empty lines, until the caller has seen enough.
func forEachUsefulLine(stderr, stdout string, visit func(string) bool) {
	for _, text := range [2]string{stderr, stdout} {
		if !forEachUsefulLineIn(text, visit) {
			return
		}
	}
}

// forEachUsefulLineIn walks one stream. It returns false when the caller
// stopped it.
func forEachUsefulLineIn(text string, visit func(string) bool) bool {
	for rest := text; rest != ""; {
		var raw string
		raw, rest, _ = strings.Cut(rest, "\n")
		line := strings.TrimSpace(raw)
		if line == "" || progressLine(line) {
			continue
		}
		if !visit(line) {
			return false
		}
	}
	return true
}

// lastUsefulLines keeps the last lines of a stream without ever holding all of
// them: a failed transaction writes far more than a result shows.
func lastUsefulLines(text string, count int) []string {
	if count <= 0 {
		return nil
	}
	ring := make([]string, count)
	seen := 0
	forEachUsefulLineIn(text, func(line string) bool {
		ring[seen%count] = line
		seen++
		return true
	})
	kept := make([]string, 0, min(seen, count))
	for i := max(seen-count, 0); i < seen; i++ {
		kept = append(kept, ring[i%count])
	}
	return kept
}

// joinedLength is how long the lines gathered so far read as one sentence.
func joinedLength(lines []string) int {
	total := 3 * (len(lines) - 1)
	for _, line := range lines {
		total += len(line)
	}
	return total
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
