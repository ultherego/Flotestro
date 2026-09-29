// Command gatecheck judges a laboratory gate report.
//
// It reads result.json, refuses one that is incomplete or that is about
// another commit, recomputes the verdict from the evidence and prints it. The
// workflow that records the commit status runs this instead of a handful of
// jq expressions, so the rules live in one place and have tests.
//
//	gatecheck -sha <commit> [report.json]   # stdin when no file is named
//
// Stdout is two lines: the verdict, then the one line a status carries.
// Anything else goes to stderr, and a refusal is a non-zero exit.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ultherego/flotestro/internal/release"
)

func main() {
	sha := flag.String("sha", "", "the commit the report has to be about")
	flag.Parse()

	data, err := read(flag.Arg(0))
	if err != nil {
		fail(err)
	}
	report, verdict, reasons, err := release.CheckGateReport(data, *sha)
	if err != nil {
		fail(err)
	}
	for _, reason := range reasons {
		fmt.Fprintf(os.Stderr, "  - %s\n", reason)
	}
	fmt.Println(verdict)
	fmt.Println(report.Summary(verdict))
}

func read(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(1)
}
