// Package ctl holds what the operator tools of a host share: the report of a
// diagnosis, the network checks against the panel, the forced-renewal limit
// and a few helpers for the text they print.
package ctl

import (
	"encoding/json"
	"fmt"
	"io"
)

// The outcomes of a single check.
const (
	StatusPass   = "pass"
	StatusFail   = "fail"
	StatusWarn   = "warn"
	StatusNotRun = "not_run"
)

// Check is the result of one diagnostic step.
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
	// DaysLeft says how long the certificate is still valid.
	DaysLeft *int `json:"days_left,omitempty"`
	// Available and Total count the capabilities of the host.
	Available *int `json:"available,omitempty"`
	Total     *int `json:"total,omitempty"`
	// FreeBytes is the space left on the filesystem of a directory.
	FreeBytes *int64 `json:"free_bytes,omitempty"`
	// UsedBytes and MaxBytes describe the fill of a bounded store, such as
	// the buffer of a relay.
	UsedBytes *int64 `json:"used_bytes,omitempty"`
	MaxBytes  *int64 `json:"max_bytes,omitempty"`
}

// Report is the complete outcome of a diagnosis.
type Report struct {
	OK     bool    `json:"ok"`
	Checks []Check `json:"checks"`
}

// Pass records a passed check.
func Pass(name, detail string) Check {
	return Check{Name: name, Status: StatusPass, Detail: detail}
}

// Fail records a failed check with its stable code.
func Fail(name, code, detail string) Check {
	return Check{Name: name, Status: StatusFail, ErrorCode: code, Detail: detail}
}

// Warn records a finding that does not stop the component.
func Warn(name, code, detail string) Check {
	return Check{Name: name, Status: StatusWarn, ErrorCode: code, Detail: detail}
}

// NotRun records a check that an earlier failure made meaningless.
func NotRun(name, why string) Check {
	return Check{Name: name, Status: StatusNotRun, Detail: why}
}

// Add appends a check and keeps the overall verdict current.
func (r *Report) Add(check Check) {
	if check.Status == StatusFail {
		r.OK = false
	}
	r.Checks = append(r.Checks, check)
}

// Find returns the check with the given name.
func (r Report) Find(name string) (Check, bool) {
	for _, check := range r.Checks {
		if check.Name == name {
			return check, true
		}
	}
	return Check{}, false
}

// RenderText prints one line per check for a person.
func RenderText(out io.Writer, report Report) {
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

// RenderJSON prints the report as it is, for a playbook or a support bundle.
func RenderJSON(out io.Writer, report Report) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
