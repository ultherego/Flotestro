// Command auditverify checks an export of the audit trail without the panel.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-v":
			fmt.Fprintln(out, buildinfo.Describe("auditverify"))
			return 0
		case "help", "--help", "-h":
			usage(out)
			return 0
		}
	}
	if len(args) > 1 {
		usage(errOut)
		return 2
	}

	name := "standard input"
	if len(args) == 1 && args[0] != "-" {
		file, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintf(errOut, "auditverify: %v\n", err)
			return 2
		}
		defer file.Close()
		in = file
		name = args[0]
	}

	report, err := audit.VerifyChain(in)
	if err != nil {
		if errors.Is(err, audit.ErrChainBroken) {
			fmt.Fprintf(errOut, "%s: BROKEN: %v\n", name, err)
			if report.Count > 0 {
				fmt.Fprintf(errOut, "%s: the first %d events verified, up to event %d\n",
					name, report.Count, report.Last)
			}
			return 1
		}
		fmt.Fprintf(errOut, "auditverify: reading %s: %v\n", name, err)
		return 2
	}
	if report.Count == 0 {
		fmt.Fprintf(out, "%s: OK, no events, the chain is intact\n", name)
		return 0
	}
	fmt.Fprintf(out, "%s: OK, %d events (%d to %d), sha256_chain %s\n",
		name, report.Count, report.First, report.Last, report.SHA256Chain)
	return 0
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "usage: auditverify [file.jsonl]")
	fmt.Fprintln(out, "  Recomputes the hash chain of an audit export made with GET /api/v1/audit/export")
	fmt.Fprintln(out, "  and reports whether the file is intact. Without a file it reads standard input.")
	fmt.Fprintln(out, "  Exit status: 0 intact, 1 broken, 2 wrong invocation.")
}
