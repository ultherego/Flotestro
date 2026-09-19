package main

import (
	"strings"
	"testing"
)

func TestParseCommandNamesTheThreeCommands(t *testing.T) {
	for _, name := range []string{"serve", "migrate", "schema-check"} {
		cmd, rest, err := parseCommand([]string{name, "-state-dir", "/var/lib/flotestro"})
		if err != nil {
			t.Fatalf("the command %q was refused: %v", name, err)
		}
		if string(cmd) != name {
			t.Fatalf("the command word %q was read as %q", name, cmd)
		}
		if len(rest) != 2 || rest[0] != "-state-dir" {
			t.Fatalf("the flags after the command were not handed on: %v", rest)
		}
	}
}

// Every unit file, installer and laboratory script that exists today runs
// the binary with flags alone, and that is the serving process.
func TestParseCommandWithoutACommandServes(t *testing.T) {
	cmd, rest, err := parseCommand(nil)
	if err != nil || cmd != commandServe || rest != nil {
		t.Fatalf("a bare invocation is not the serving process: %q %v %v", cmd, rest, err)
	}
	cmd, rest, err = parseCommand([]string{"--migrate-only"})
	if err != nil {
		t.Fatalf("the deprecated flag was refused: %v", err)
	}
	if cmd != commandServe || len(rest) != 1 || rest[0] != "--migrate-only" {
		t.Fatalf("a leading flag has to reach the flag parser untouched: %q %v", cmd, rest)
	}
}

// A typo must not start a process that serves a fleet when it was meant to
// migrate a database.
func TestParseCommandRefusesAWordThatIsNotACommand(t *testing.T) {
	_, _, err := parseCommand([]string{"migrations"})
	if err == nil {
		t.Fatal("a word that is not a command was accepted")
	}
	if !strings.Contains(err.Error(), commandUsage) {
		t.Fatalf("the refusal does not name the commands: %v", err)
	}
}
