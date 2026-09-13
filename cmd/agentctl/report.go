package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// The outcomes of a single check.
//
// "warn" is a finding that does not stop the host from working; "not_run"
// says that an earlier failure made the check meaningless, and the detail
// says which one.
const (
	StatusPass   = "pass"
	StatusFail   = "fail"
	StatusWarn   = "warn"
	StatusNotRun = "not_run"
)

// Check is the result of one diagnostic step.
//
// The error code is the part that matters: a person reads the detail, but
// the code is what a support bundle or a playbook compares, and it is stable
// across releases and translations.
type Check struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
	Detail    string `json:"detail,omitempty"`

	// OffsetMS is the difference between the clock of the host and the one
	// of the endpoint, positive when the host is ahead.
	OffsetMS *int64 `json:"offset_ms,omitempty"`
	// Addresses are the results of a name lookup.
	Addresses []string `json:"addresses,omitempty"`
	// Overrides lists the settings that take precedence over the file.
	Overrides []string `json:"overrides,omitempty"`
	// DaysLeft says how long the certificate of the host is still valid.
	DaysLeft *int `json:"days_left,omitempty"`
	// Available and Total count the capabilities of the host.
	Available *int `json:"available,omitempty"`
	Total     *int `json:"total,omitempty"`
}

// Report is the complete outcome of a diagnosis.
//
// Both renderers work from this one value: what the operator reads in the
// terminal and what a playbook reads from the JSON must not drift apart.
type Report struct {
	OK     bool    `json:"ok"`
	Checks []Check `json:"checks"`
}

// pass records a passed check.
func pass(name, detail string) Check {
	return Check{Name: name, Status: StatusPass, Detail: detail}
}

// fail records a failed check with its stable code.
func fail(name, code, detail string) Check {
	return Check{Name: name, Status: StatusFail, ErrorCode: code, Detail: detail}
}

// warn records a finding that does not stop the host.
func warn(name, code, detail string) Check {
	return Check{Name: name, Status: StatusWarn, ErrorCode: code, Detail: detail}
}

// notRun records a check that an earlier failure made meaningless.
func notRun(name, why string) Check {
	return Check{Name: name, Status: StatusNotRun, Detail: why}
}

// add appends a check and keeps the overall verdict current.
//
// A warning leaves the verdict alone: the host works, and somebody has to
// look at it - those are different answers.
func (r *Report) add(check Check) {
	if check.Status == StatusFail {
		r.OK = false
	}
	r.Checks = append(r.Checks, check)
}

// renderText prints one line per check for a person.
func renderText(out io.Writer, report Report) {
	for _, check := range report.Checks {
		line := fmt.Sprintf("%-16s %-7s", check.Name, check.Status)
		if check.ErrorCode != "" {
			line += " " + check.ErrorCode
		}
		if check.Detail != "" {
			line += "  " + check.Detail
		}
		fmt.Fprintln(out, line)
	}
	if report.OK {
		fmt.Fprintln(out, "Result: ok")
		return
	}
	failed := 0
	for _, check := range report.Checks {
		if check.Status == StatusFail {
			failed++
		}
	}
	fmt.Fprintf(out, "Result: %d failed\n", failed)
}

// renderJSON prints the report as it is, for a playbook or a support bundle.
func renderJSON(out io.Writer, report Report) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
