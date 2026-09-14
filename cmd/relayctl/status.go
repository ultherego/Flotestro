package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/ctl"
	"github.com/ultherego/flotestro/internal/relayconfig"
)

// statusCommand answers the question "what is this relay doing at all".
func statusCommand(args []string, out, errOut io.Writer) int {
	path, ok := configurationPath("status", args, errOut)
	if !ok {
		return 2
	}
	return status{ConfigPath: path, Now: time.Now, Identity: readIdentity,
		State: ctl.ReadRelayState, Listener: listenerWorks}.run(out)
}

// status gathers what the status touches outside the process, so that a
// test can run it on a temporary directory without a daemon.
type status struct {
	ConfigPath string
	Now        func() time.Time
	Identity   func(stateDir string) storedIdentity
	State      func(stateDir string) (ctl.RelayState, error)
	Listener   func(address string) error
}

func (s status) run(out io.Writer) int {
	problems := 0
	cfg, err := relayconfig.Load(s.ConfigPath)
	if err != nil {
		fmt.Fprintf(out, "Config:       ERROR (%s): %v\n", s.ConfigPath, err)
		// Without the configuration we do not even know where to look for
		// the identity - guessing the directory would give an answer about
		// somebody else's state.
		return 1
	}
	fmt.Fprintf(out, "Config:       correct (%s)\n", s.ConfigPath)
	fmt.Fprintf(out, "Relay:        %s, site %s\n", cfg.Relay.Name, cfg.Relay.Site)

	now := s.Now()
	identity := s.Identity(cfg.Relay.StateDir)
	switch {
	case !identity.Present:
		fmt.Fprintf(out, "Identity:     missing (%s)\n", identity.Err)
		problems++
	default:
		fmt.Fprintf(out, "Identity:     relay/%s (CN %s)\n", identity.RelayID, identity.Subject)
		until := identity.NotAfter.UTC().Format(time.RFC3339)
		if identity.Expired {
			fmt.Fprintf(out, "Certificate:  serial %s, EXPIRED %s\n", identity.Serial, until)
			problems++
		} else {
			fmt.Fprintf(out, "Certificate:  serial %s, valid until %s (%s)\n",
				identity.Serial, until, ctl.Rounded(identity.NotAfter.Sub(now)))
		}
		if len(identity.Names) > 0 {
			fmt.Fprintf(out, "Names:        %s\n", strings.Join(identity.Names, ", "))
		}
	}

	state, err := s.State(cfg.Relay.StateDir)
	switch {
	case os.IsNotExist(err):
		// A missing state file is not a failure: the relay may have just
		// been installed and not have run at all yet.
		fmt.Fprintf(out, "Centre:       no record - the relay has not run yet (gateway %s)\n",
			cfg.Upstream.GatewayURLs[0])
	case err != nil:
		fmt.Fprintf(out, "Centre:       unknown (%v)\n", err)
	default:
		describeCentre(out, state, now, &problems)
		describeBuffer(out, state, now, &problems)
		sessions := fmt.Sprintf("Sessions:     %d agents", state.Sessions)
		if state.CentreSessions != nil {
			sessions += fmt.Sprintf(" (the centre sees %d)", *state.CentreSessions)
		}
		fmt.Fprintln(out, sessions)
	}

	if err := s.Listener(cfg.Relay.Listen); err != nil {
		fmt.Fprintf(out, "Listener:     not accepting connections on %s (%v)\n", cfg.Relay.Listen, err)
		problems++
	} else {
		fmt.Fprintf(out, "Listener:     accepting connections on %s\n", cfg.Relay.Listen)
	}

	fmt.Fprintf(out, "Relay:        %s\n", version)
	if problems > 0 {
		return 1
	}
	return 0
}

// describeCentre puts the last contact with the centre into one line.
func describeCentre(out io.Writer, state ctl.RelayState, now time.Time, problems *int) {
	gateway := state.Gateway
	switch {
	case state.LastUpstreamAt == nil:
		reason := state.LastUpstreamError
		if reason == "" {
			reason = "no contact yet"
		}
		fmt.Fprintf(out, "Centre:       %s, never reached: %s\n", gateway, reason)
		*problems++
	case !state.UpstreamOK || state.LastUpstreamError != "":
		reason := state.LastUpstreamError
		if reason == "" {
			reason = "the link is down"
		}
		fmt.Fprintf(out, "Centre:       %s, unreachable since %s (%s ago): %s\n", gateway,
			state.LastUpstreamAt.UTC().Format(time.RFC3339),
			ctl.Rounded(now.Sub(*state.LastUpstreamAt)), reason)
		*problems++
	default:
		fmt.Fprintf(out, "Centre:       %s, last contact %s (%s ago)\n", gateway,
			state.LastUpstreamAt.UTC().Format(time.RFC3339),
			ctl.Rounded(now.Sub(*state.LastUpstreamAt)))
	}
}

// describeBuffer puts the fill of the buffer into one line.
//
// The oldest item is at most as old as the moment the buffer started
// filling: the relay drains it in order, so that moment bounds the wait of
// everything in it.
func describeBuffer(out io.Writer, state ctl.RelayState, now time.Time, problems *int) {
	line := fmt.Sprintf("Buffer:       %s of %s, %d items", ctl.Bytes(state.BufferBytes),
		ctl.Bytes(state.BufferMaxBytes), state.BufferedItems)
	if state.BufferedItems > 0 && state.BufferingSince != nil {
		line += fmt.Sprintf(", oldest up to %s", ctl.Rounded(now.Sub(*state.BufferingSince)))
	}
	if state.BufferDropped > 0 {
		line += fmt.Sprintf("; DROPPED %d results", state.BufferDropped)
		*problems++
	}
	fmt.Fprintln(out, line)
}

// listenerWorks checks whether the relay accepts connections on its
// address. A wildcard address is probed on the loopback: the question is
// whether the process listens, not which interface answers.
func listenerWorks(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
		if ip != nil && ip.To4() == nil {
			host = "::1"
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}
