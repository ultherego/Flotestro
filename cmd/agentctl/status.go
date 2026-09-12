package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// statusCommand answers the question "what is this agent doing at all".
func statusCommand(args []string, out, errOut io.Writer) int {
	path, ok := configurationPath("status", args, errOut)
	if !ok {
		return 2
	}

	problems := 0
	cfg, err := agentconfig.Load(path)
	if err != nil {
		fmt.Fprintf(out, "Config:       ERROR (%s): %v\n", path, err)
		// Without the configuration we do not even know where to look for the
		// identity - guessing the directory would give an answer about
		// somebody else's state.
		return 1
	}
	fmt.Fprintf(out, "Config:       correct (%s)\n", path)

	identity := agent.ReadIdentity(cfg.Agent.StateDir)
	switch {
	case !identity.Present:
		fmt.Fprintf(out, "Identity:     missing (%s)\n", identity.Err)
		problems++
	default:
		fmt.Fprintf(out, "Identity:     host/%s\n", identity.HostID)
		left := time.Until(identity.NotAfter)
		switch {
		case identity.Expired:
			fmt.Fprintf(out, "Certificate:  EXPIRED %s\n",
				identity.NotAfter.UTC().Format(time.RFC3339))
			problems++
		default:
			fmt.Fprintf(out, "Certificate:  valid until %s (%s)\n",
				identity.NotAfter.UTC().Format(time.RFC3339), rounded(left))
		}
	}

	state, err := agent.ReadState(cfg.Agent.StateDir)
	switch {
	case os.IsNotExist(err):
		// A missing state file is not a failure: the agent may have just been
		// installed and have had no session at all yet.
		fmt.Fprintln(out, "Session:      no record - the agent has not opened a session yet")
	case err != nil:
		fmt.Fprintf(out, "Session:      unknown (%v)\n", err)
	case state.ConnectedAt != nil:
		fmt.Fprintf(out, "Session:      connected to %s since %s (%s)\n", state.Gateway,
			state.ConnectedAt.UTC().Format(time.RFC3339), rounded(time.Since(*state.ConnectedAt)))
	default:
		reason := state.LastError
		if reason == "" {
			reason = "no session"
		}
		since := ""
		if state.DisconnectedAt != nil {
			since = " since " + state.DisconnectedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(out, "Session:      disconnected%s: %s\n", since, reason)
		problems++
	}
	if state.LastInventoryAt != nil {
		fmt.Fprintf(out, "Inventory:    %s, revision %s\n",
			state.LastInventoryAt.UTC().Format(time.RFC3339), shortened(state.InventoryRevision))
	}

	if cfg.Agent.Mode == agentconfig.ModeReadOnly {
		// In the read-only mode the helper has no right to run: its absence is
		// then an answer rather than a fault.
		fmt.Fprintf(out, "Helper:       disabled (mode %s)\n", cfg.Agent.Mode)
	} else if err := socketWorks(cfg.Helper.Socket); err != nil {
		fmt.Fprintf(out, "Helper:       unavailable (%v)\n", err)
		problems++
	} else {
		fmt.Fprintf(out, "Helper:       the socket is ready (%s)\n", cfg.Helper.Socket)
	}

	fmt.Fprintf(out, "Agent:        %s\n", version)
	if problems > 0 {
		return 1
	}
	return 0
}

// socketWorks checks whether the helper can be connected to.
func socketWorks(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", path)
	}
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// rounded shortens a duration into a form a person can read.
func rounded(duration time.Duration) string {
	if duration < 0 {
		duration = -duration
	}
	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%dd %02dh", days, hours)
	}
	return duration.Round(time.Second).String()
}

// shortened trims a digest to a form that can be compared by eye.
func shortened(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}
