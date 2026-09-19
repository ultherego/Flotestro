// Command relayctl operates the Flotestro relay of a site. The tool is
// deliberately separate from the daemon, just as with the agent.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/ultherego/flotestro/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	return runWithInput(args, os.Stdin, out, errOut)
}

func runWithInput(args []string, in_ io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		usage(errOut)
		return 2
	}
	switch args[0] {
	case "status":
		return statusCommand(args[1:], out, errOut)
	case "diagnose":
		return diagnoseCommand(args[1:], out, errOut)
	case "enroll":
		return enrollmentCommand(args[1:], in_, out, errOut)
	case "renew":
		return renewCommand(args[1:], out, errOut)
	case "version":
		// The version number alone is not enough when a package behaves differently
		// than it should: the first question is "which commit is this from".
		fmt.Fprintln(out, buildinfo.Describe("flotestro-relayctl"))
		return 0
	case "help", "-h", "--help":
		usage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "unknown command: %s\n", args[0])
		usage(errOut)
		return 2
	}
}

func usage(where io.Writer) {
	fmt.Fprint(where, `flotestro-relayctl - the tool of the site relay

  enroll    [--token-file FILE] [--config FILE]  registers the relay in the fleet and writes the identity
  renew     [--config FILE]                      forces a renewal of the certificate (at most once in 10 minutes)
  status    [--config FILE]                      the identity, the certificate, the centre, the buffer and the listener
  diagnose  [--json] [--config FILE]             the config, identity, DNS, TLS, clock, state directory, buffer, listener
  version                                        the version of the tool

Exit codes: 0 ready, 1 a problem to fix, 2 a usage error or a refused request.
`)
}
