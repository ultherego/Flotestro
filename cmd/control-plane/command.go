package main

import (
	"flag"
	"fmt"
	"strings"
)

// The named commands of the process.
//
// One image carries the serving control plane and the migrator, and which
// of the two a container is has to be visible in the command line of the
// deployment rather than in an environment variable somebody has to go and
// look up. A migration job runs `migrate` with the credentials of the
// migrator; the serving replicas run `serve` and do not hold DDL rights at
// all; a readiness gate and an upgrade runbook run `schema-check`, which
// changes nothing and answers with its exit status.
type command string

const (
	// commandServe runs the API, the gateway and the enrollment endpoint.
	commandServe command = "serve"
	// commandMigrate brings the schema forward and exits.
	commandMigrate command = "migrate"
	// commandSchemaCheck compares the schema with the one this binary
	// expects and exits; it writes nothing.
	commandSchemaCheck command = "schema-check"
)

// commandUsage is printed when the command word is not one of the three.
const commandUsage = "the commands are serve (the default), migrate and schema-check"

// parseCommand takes the command word off the argument list and returns the
// rest for the flag parser.
//
// A plain `flotestro-control-plane` with flags alone stays what it has
// always been - the serving process - because that is what every existing
// unit file and every laboratory script runs. A word that is not a command
// is refused rather than read as a flag: a typo in a deployment must not
// start a process that serves a fleet when it was meant to migrate a
// database.
func parseCommand(args []string) (command, []string, error) {
	if len(args) == 0 {
		return commandServe, nil, nil
	}
	first := args[0]
	if strings.HasPrefix(first, "-") {
		return commandServe, args, nil
	}
	switch command(first) {
	case commandServe, commandMigrate, commandSchemaCheck:
		return command(first), args[1:], nil
	default:
		return "", nil, fmt.Errorf("%q is not a command of the control plane; %s", first, commandUsage)
	}
}

// flagWasSet says whether the command line named a flag, as opposed to the
// flag keeping the value the environment or the built-in default gave it.
// It is how a setting that also exists as an environment variable can tell
// "the operator asked for this" from "nobody said anything".
func flagWasSet(name string) bool {
	set := false
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
