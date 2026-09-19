// Command agentctl operates the Flotestro agent on a host. The tool is
// deliberately separate from the daemon.
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
	case "support-bundle":
		return supportBundleCommand(args[1:], out, errOut)
	case "enroll":
		return enrollmentCommand(args[1:], in_, out, errOut)
	case "renew":
		return renewCommand(args[1:], out, errOut)
	case "identity":
		return identityCommands(args[1:], in_, out, errOut)
	case "helper-trust":
		return helperTrustCommands(args[1:], out, errOut)
	case "version":
		// The version number alone is not enough when a package behaves differently
		// than it should: the first question is "which commit is this from".
		fmt.Fprintln(out, buildinfo.Describe("flotestro-agentctl"))
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
  renew           [--config FILE]   forces a renewal of the certificate (at most once in 10 minutes)
  identity reset  --confirm HOSTNAME [--token-file FILE] [--revoke-old]
                                    replaces the identity with a recovery token from the panel;
                                    the current one is kept until the new one is verified
  identity reset  --discard-pending abandons the record of an unfinished enrollment attempt
  helper-trust show                 the host identity and the panel keys the root helper trusts (as root)
  helper-trust reset --confirm HOSTNAME
                                    forgets them, so the next session's bundle is taken afresh; for a host
                                    enrolled anew with a panel the helper does not know (as root)
  config validate [--config FILE]   checks the configuration file and the permissions on it
  config show     [--config FILE]   shows the settings once the defaults are filled in
  config migrate  [--write]         converts the environment file of the service into agent.yaml
  status          [--config FILE]   the identity, the certificate, a pending attempt, the session and the helper
  diagnose        [--json]          the config, machine-id, clock, DNS, TLS, identity, socket, capabilities
  support-bundle  [--output FILE]   writes the diagnosis, the status, the config, the journal and the
                                    identity metadata (never the key) into a tar.gz; every collector
                                    declares what it carries, and a bundle that would leak is refused
  support-bundle  --verify FILE     checks an existing bundle with the same scanner before it is sent
  version                           the version of the tool

Exit codes: 0 ready, 1 a problem to fix, 2 a usage error or a refused request.
`)
}
