package main

import (
	"io"

	"github.com/ultherego/flotestro/internal/ctl"
)

// The report of a diagnosis is shared with the tool of the relay: both
// answer the same questions about the path to the panel, and a playbook
// compares the same codes whichever of the two wrote them. The names below
// keep the tool reading as one piece.
const (
	StatusPass   = ctl.StatusPass
	StatusFail   = ctl.StatusFail
	StatusWarn   = ctl.StatusWarn
	StatusNotRun = ctl.StatusNotRun
)

type (
	Check  = ctl.Check
	Report = ctl.Report
)

// pass records a passed check.
func pass(name, detail string) Check { return ctl.Pass(name, detail) }

// fail records a failed check with its stable code.
func fail(name, code, detail string) Check { return ctl.Fail(name, code, detail) }

// warn records a finding that does not stop the host.
func warn(name, code, detail string) Check { return ctl.Warn(name, code, detail) }

// notRun records a check that an earlier failure made meaningless.
func notRun(name, why string) Check { return ctl.NotRun(name, why) }

// renderText prints one line per check for a person.
func renderText(out io.Writer, report Report) { ctl.RenderText(out, report) }

// renderJSON prints the report as it is, for a playbook or a support bundle.
func renderJSON(out io.Writer, report Report) error { return ctl.RenderJSON(out, report) }
