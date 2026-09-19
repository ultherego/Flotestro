package main

import (
	"flag"
	"fmt"
	"strings"
)

// The named commands of the process.
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
func flagWasSet(name string) bool {
	set := false
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
