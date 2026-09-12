// Package buildinfo says what this binary was made of.
//
// The version alone is not enough when a package behaves differently than it
// should: the first question is then "which commit is this from" and it has to
// be answerable on the host, without access to the release machine. That is
// why the commit and the build date are written into the binary just like the
// version.
//
// The version of the protocol sits next to them deliberately: it settles
// whether an old agent can talk to the panel at all, and an operator looking
// at a host should see the whole set in one place.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// The values written in when building a release through -ldflags -X.
//
// The defaults say outright that nobody wrote them in. "unknown" is better
// than a made-up value: a package built by hand is to look different from a
// release.
var (
	Version = "0.1.0"
	Commit  = ""
	Date    = ""
)

// AgentProtocol changes with every incompatible change of the contract
// between the agent and the centre.
const AgentProtocol = 1

// Describe assembles one line for the "version" command.
func Describe(name string) string {
	line := name + " " + Version
	if commit := ShortCommit(); commit != "" {
		line += " (" + commit
		if Date != "" {
			line += ", " + Date
		}
		line += ")"
	}
	return line + " [" + runtime.GOOS + "/" + runtime.GOARCH + ", " + runtime.Version() + "]"
}

// ShortCommit shortens the commit digest into a form readable in one line.
//
// When the release did not write the commit in, we try to read it from the
// build metadata: with a plain "go build" it is there and is enough to say
// what this binary was made of.
func ShortCommit() string {
	commit := Commit
	if commit == "" {
		commit = commitFromMetadata()
	}
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func commitFromMetadata() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return strings.TrimSpace(setting.Value)
		}
	}
	return ""
}
