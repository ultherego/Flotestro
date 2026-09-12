// Command agentctl operates the Flotestro agent on a host.
//
// The tool is deliberately separate from the daemon. An operator who is
// setting a host up or looking for the cause of silence needs an answer at
// once and without the panel - and the daemon at that moment either does not
// come up or is just trying to connect.
//
// No command changes the state of the host beyond an explicit command of the
// operator, and none prints secrets.
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
	case "config":
		return configurationCommands(args[1:], out, errOut)
	case "status":
		return statusCommand(args[1:], out, errOut)
	case "diagnose":
		return diagnoseCommand(args[1:], out, errOut)
	case "enroll":
		return enrollmentCommand(args[1:], in_, out, errOut)
	case "version":
		// The version number alone is not enough when a package behaves
		// differently than it should: the first question is "which commit is
		// this from".
		fmt.Fprintln(out, buildinfo.Opis("flotestro-agentctl"))
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
	fmt.Fprint(where, `flotestro-agentctl - the tool of the host

  enroll          [--token-file FILE]  registers the host in the fleet and writes the identity
  config validate [--config FILE]   checks the configuration file and the permissions on it
  config show     [--config FILE]   shows the settings once the defaults are filled in
  status          [--config FILE]   the identity, the certificate, the session and the helper
  diagnose        [--config FILE]   DNS, TCP, TLS, the clock, the socket and the capabilities
  version                           the version of the tool

Exit codes: 0 ready, 1 a problem to fix, 2 a usage error.
`)
}
