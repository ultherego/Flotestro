// Command agent-helper carries out the operations that require root on
// behalf of the agent.
//
// The helper is activated by systemd on demand, listens on a unix socket
// alone and never connects to the network. A compromise of the agent
// therefore gives no access to root beyond what the helper explicitly
// supports.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/helper"
	"github.com/ultherego/flotestro/internal/packages"
)

func main() {
	if err := run(); err != nil {
		slog.Error("the helper ended with an error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		socketPath = flag.String("socket",
			config.Env("FLOTESTRO_HELPER_SOCKET", "/run/flotestro/helper.sock"),
			"the path of the socket when there is no socket activation")
		agentUser = flag.String("agent-user",
			config.Env("FLOTESTRO_AGENT_USER", "flotestro-agent"),
			"the user who is allowed to issue commands")
		rollback = flag.String("rollback", "",
			"carry out the recorded plan of rolling a network change back and finish")
		rollbackFirewall = flag.String("rollback-firewall", "",
			"carry out the recorded plan of rolling a firewall change back and finish")
		agentReplacement = flag.String("agent-replacement", "",
			"install the named version of the agent package and finish")
		idleTimeout = flag.Duration("idle-timeout",
			time.Duration(config.EnvInt("FLOTESTRO_HELPER_IDLE_SECONDS", 300))*time.Second,
			"the idle time after which the helper finishes its work")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	// The agent replacement mode is called by a transient systemd unit.
	// Installing the agent package stops the helper and restarts the agent,
	// so it must not run in the process that ordered it: that process would
	// not live to the end of its own transaction.
	if *agentReplacement != "" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		log.Info("the replacement of the agent", "package", *agentReplacement)
		return helper.RunAgentReplacement(ctx, *agentReplacement, log)
	}

	// The rollback mode is called by a transient systemd unit when nobody has
	// confirmed connectivity after a network change. It works without a
	// socket, without the agent and without the panel - it is the last thing
	// that works when a change cuts the host off from the world.
	if *rollbackFirewall != "" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		log.Warn("rolling the firewall change back", "plan", *rollbackFirewall)
		if err := helper.RollbackFirewall(ctx, *rollbackFirewall); err != nil {
			return err
		}
		log.Info("the firewall change was rolled back", "plan", *rollbackFirewall)
		return nil
	}

	if *rollback != "" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		log.Warn("rolling the network change back", "plan", *rollback)
		if err := helper.RollbackFromPlan(ctx, *rollback); err != nil {
			return err
		}
		log.Info("the network change was rolled back", "plan", *rollback)
		return nil
	}

	allowedUID, err := lookupUID(*agentUser)
	if err != nil {
		return err
	}

	// The helper runs as root, so the package tools use the directory of
	// root.
	if err := packages.SetRuntimeDir("/var/lib/flotestro-helper"); err != nil {
		return fmt.Errorf("the working directory of the helper: %w", err)
	}

	listener, activated, err := helper.ListenerFromSystemd()
	if err != nil {
		return err
	}
	if !activated {
		// The mode without socket activation serves the tests; the helper then
		// watches over the permissions of the socket itself so that it is not
		// available to the whole system.
		_ = os.Remove(*socketPath)
		if err := os.MkdirAll(dirOf(*socketPath), 0o755); err != nil {
			return err
		}
		listener, err = net.Listen("unix", *socketPath)
		if err != nil {
			return fmt.Errorf("the socket %s: %w", *socketPath, err)
		}
		if err := os.Chown(*socketPath, 0, int(gidOf(*agentUser))); err != nil {
			log.Warn("the group of the socket was not set", "err", err)
		}
		if err := os.Chmod(*socketPath, 0o660); err != nil {
			return err
		}
	}
	defer listener.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("the helper is ready",
		"agent_user", *agentUser, "uid", allowedUID,
		"socket_activated", activated, "protocol_version", helper.ProtocolVersion)

	// A package transaction holds the agent package for its own duration so
	// as not to replace it halfway through its own work. When it died with
	// the process, the hold stayed for good and blocked every later
	// replacement of the agent. We clean it up at the start - but only when
	// it was us who placed it.
	if released, err := packages.ReleaseAbandonedHold(ctx); err != nil {
		log.Warn("the abandoned hold on the agent package was not released", "err", err)
	} else if released {
		log.Info("the abandoned hold on the agent package was released")
	}

	// The helper finishes its work after a period of idleness. With the fleet
	// at rest not a single root process runs. The server counts the idleness
	// from the last connection and never during a job: a clock counted here
	// from the start cut a transaction that happened to be running in its
	// fifth minute.
	server := helper.NewServer(allowedUID, log)
	server.IdleTimeout = *idleTimeout
	return server.Serve(ctx, listener)
}

func lookupUID(name string) (uint32, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("the user %s: %w", name, err)
	}
	uid, err := strconv.ParseUint(entry.Uid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(uid), nil
}

func gidOf(name string) uint32 {
	entry, err := user.Lookup(name)
	if err != nil {
		return 0
	}
	gid, err := strconv.ParseUint(entry.Gid, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(gid)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
