package adminapi

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The CSV exports of the list screens.
//
// Every list the panel shows answers the same request with format=csv as
// a file: the same filters, the same scope the caller may read, and no
// page - the file is the whole list, because a spreadsheet is where an
// operator takes a list that does not fit on a screen. The columns of an
// export are fixed and named in snake_case, so a sheet or a script built
// against one file reads the next one; timestamps are RFC 3339 in UTC and
// a cell that holds several values joins them with a semicolon.
//
// The rows go from the store straight to the socket, page by page where
// the store pages, so an export of the whole fleet costs the panel the
// memory of one page. Two things end a file early, and both are said in
// the file itself, in its last row, because the status line is long sent
// by then: the cap on rows, and an error reading the store. A script that
// reads an export checks the first cell of the last row against the two
// markers before it trusts the file.

// exportRowLimit is the most rows one export carries. Beyond it the file
// ends with a truncation row rather than growing without bound: the panel
// is not a data warehouse, and an operator who needs more narrows the
// filter or asks the database.
const exportRowLimit = 50000

// exportFlushEvery is how many rows accumulate before they are handed to
// the socket: a file of the whole fleet reaches the browser as it is
// written, not once it is complete.
const exportFlushEvery = 500

// The markers in the first cell of the last row of a file that did not
// reach its end.
const (
	exportTruncatedMarker = "truncated"
	exportErrorMarker     = "error"
)

// exportFileName names a file after the list and the day it was taken:
// flotestro-hosts-2026-09-15.csv. The day is enough; two exports of one
// list on one day are told apart by the browser, which numbers them.
func exportFileName(list string, now time.Time) string {
	return "flotestro-" + list + "-" + now.UTC().Format("2006-01-02") + ".csv"
}

// exportFormat reads the format parameter of a list request: JSON by
// default, CSV on request, and a refusal for anything else - a typo in
// the format is not a reason to answer with JSON as if nothing was asked.
// The second result says whether the caller may go on.
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

// writeCSV streams one export. The columns are the header row; rows
// produces the file's rows and hands each to yield, and stops when yield
// says false - the cap is reached or the socket is gone. An error rows
// returns is written as the last row of the file and logged: the file is
// already on its way, so the caller cannot get a problem document any
// more, and a file cut short without a word would pass for a complete
// one.
//
// Every cell goes through the formula guard: a host name, a message, a
// reason - anything a host or a person typed - may begin with a character
// a spreadsheet takes as a formula.
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
	if err != nil && !stopped {
		s.log.Warn("the CSV export broke off", "path", r.URL.Path, "rows", count, "err", err)
		_ = writer.Write(exportMarkerRow(len(columns), exportErrorMarker,
			"the export broke off before its end; ask for it again"))
	}
	writer.Flush()
}

// exportMarkerRow is the last row of a file that did not reach its end:
// the marker in the first cell, the explanation in the second, and the
// width of an ordinary row so the file still parses.
func exportMarkerRow(width int, marker, message string) []string {
	row := make([]string, width)
	row[0] = marker
	if width > 1 {
		row[1] = message
	}
	return row
}

// csvText keeps a cell from becoming a formula. A host name or a message
// comes from the host, and a spreadsheet runs a cell that starts with =,
// +, - or @; a leading apostrophe makes it text again. A number is left
// alone: a negative count of days is a value, and an apostrophe would
// turn every one of them into text.
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
