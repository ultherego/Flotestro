package adminapi

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The CSV exports of the list screens.

// exportRowLimit is the most rows one export carries.
const exportRowLimit = 50000

// exportFlushEvery is how many rows accumulate before they are handed to the
// socket: a file of the whole fleet reaches the browser as it is written, not
// once it is complete.
const exportFlushEvery = 500

// The markers in the first cell of the last row of a file that did not
// reach its end.
const (
	exportTruncatedMarker = "truncated"
	exportErrorMarker     = "error"
)

// exportFileName names a file after the list and the day it was taken:
// flotestro-hosts-2026-09-15.
func exportFileName(list string, now time.Time) string {
	return "flotestro-" + list + "-" + now.UTC().Format("2006-01-02") + ".csv"
}

// exportFormat reads the format parameter of a list request: JSON by default,
// CSV on request, and a refusal for anything else - a typo in the format is
// not a reason to answer with JSON as if nothing was asked.
func exportFormat(w http.ResponseWriter, r *http.Request) (asCSV bool, ok bool) {
	switch format := r.URL.Query().Get("format"); format {
	case "", "json":
		return false, true
	case "csv":
		return true, true
	default:
		problem(w, http.StatusBadRequest, "invalid_format", "format must be json or csv")
		return false, false
	}
}

// exportPartialError is what rows returns when the list behind the file ended
// before its last row for a reason the list itself named - a sweep out of its
// time budget.
type exportPartialError struct {
	reason string
}

func (e exportPartialError) Error() string {
	return "the export stops before the last row: " + e.reason
}

// partialHeader says that an export does not describe the whole list it stands
// for.
const partialHeader = "X-Flotestro-Partial"

// markPartial says, before the first row is written, that the numbers in the
// file describe a part of the fleet.
func markPartial(w http.ResponseWriter) {
	w.Header().Set(partialHeader, "true")
}

// writeCSV streams one export.
func (s *Server) writeCSV(w http.ResponseWriter, r *http.Request, filename string, columns []string,
	rows func(yield func(cells []string) bool) error) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	writer := csv.NewWriter(w)
	if err := writer.Write(columns); err != nil {
		return
	}
	count := 0
	stopped := false
	err := rows(func(cells []string) bool {
		if stopped {
			return false
		}
		if count >= exportRowLimit {
			_ = writer.Write(exportMarkerRow(len(columns), exportTruncatedMarker,
				"the export stops at "+strconv.Itoa(exportRowLimit)+" rows; narrow the filter"))
			stopped = true
			return false
		}
		guarded := make([]string, len(cells))
		for i, cell := range cells {
			guarded[i] = csvText(cell)
		}
		if err := writer.Write(guarded); err != nil {
			stopped = true
			return false
		}
		count++
		if count%exportFlushEvery == 0 {
			writer.Flush()
			if writer.Error() != nil {
				stopped = true
				return false
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		return true
	})
	var cut exportPartialError
	switch {
	case errors.As(err, &cut) && !stopped:
		_ = writer.Write(exportMarkerRow(len(columns), exportTruncatedMarker, cut.Error()))
		stopped = true
	case err != nil && !stopped:
		s.log.Warn("the CSV export broke off", "path", r.URL.Path, "rows", count, "err", err)
		_ = writer.Write(exportMarkerRow(len(columns), exportErrorMarker,
			"the export broke off before its end; ask for it again"))
		stopped = true
	}
	writer.Flush()
	// The trailer travels after the last chunk: a file that ended with a marker
	// row is flagged for a reader that looks at the headers rather than at the
	// last row.
	if stopped {
		w.Header().Set(http.TrailerPrefix+partialHeader, "true")
	}
}

// exportMarkerRow is the last row of a file that did not reach its end: the
// marker in the first cell, the explanation in the second, and the width of an
// ordinary row so the file still parses.
func exportMarkerRow(width int, marker, message string) []string {
	row := make([]string, width)
	row[0] = marker
	if width > 1 {
		row[1] = message
	}
	return row
}

// csvText keeps a cell from becoming a formula.
func csvText(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		if _, err := strconv.ParseFloat(value, 64); err == nil {
			return value
		}
		return "'" + value
	}
	return value
}

// formatTime renders a timestamp for a cell: RFC 3339 in UTC, and empty
// for a moment that never came.
func formatTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

// csvInstant renders a timestamp that is always set.
func csvInstant(value time.Time) string {
	return formatTime(&value)
}

// csvList joins several values into one cell.
func csvList(values []string) string {
	return strings.Join(values, ";")
}

// csvBool renders a fact that may be undetermined: true, false, or empty
// for a host that has not said - unknown is not false.
func csvBool(value *bool) string {
	if value == nil {
		return ""
	}
	return strconv.FormatBool(*value)
}

// csvInt renders a count that may be undetermined.
func csvInt(value *int) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(*value)
}

// csvFloat renders a measure with the precision a sheet needs and no
// exponent.
func csvFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}
