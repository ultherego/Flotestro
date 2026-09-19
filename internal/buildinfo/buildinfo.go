// Package buildinfo says what this binary was made of.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// The values written in when building a release through -ldflags -X. The
// defaults say outright that nobody wrote them in.
var (
	Version = "0.1.0"
	Commit  = ""
	Date    = ""
)

// AgentProtocol changes with every incompatible change of the contract between
// the agent and the centre.
const AgentProtocol = 1

// AgentProtocolMin is the oldest protocol this binary still speaks.
const AgentProtocolMin = 1

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

// FullCommit returns the whole commit digest, for the record the panel keeps
// of a host: the short form is for a line on a screen, the full one is what a
// build is looked up by.
func FullCommit() string {
	if Commit != "" {
		return Commit
	}
	return commitFromMetadata()
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
