// Command agent-helper carries out the operations that require root on behalf
// of the agent.
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
	"github.com/ultherego/flotestro/internal/helpercap"
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
		restoreFirewall = flag.Bool("restore-firewall", false,
			"rebuild the panel's own firewall table from its registry and finish")
		agentReplacement = flag.String("agent-replacement", "",
			"install the named version of the agent package and finish")
		idleTimeout = flag.Duration("idle-timeout",
			time.Duration(config.EnvInt("FLOTESTRO_HELPER_IDLE_SECONDS", 300))*time.Second,
			"the idle time after which the helper finishes its work")
		configPath = flag.String("config",
			config.Env("FLOTESTRO_HELPER_CONFIG", helpercap.DefaultConfigPath),
			"the configuration file of the helper (optional)")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	// The agent replacement mode is called by a transient systemd unit.
	if *agentReplacement != "" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		log.Info("the replacement of the agent", "package", *agentReplacement)
		return helper.RunAgentReplacement(ctx, *agentReplacement, log)
	}

	// The restore mode is called at boot by flotestro-firewall-restore.service:
	// no boot source of a distribution carries the panel's own table.
	if *restoreFirewall {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		record, err := helper.RestoreFirewallAtBoot(ctx)
		log.Info("the panel's own firewall table at boot",
			"rules", record.Rules, "reason", record.Reason, "detail", record.Detail)
		return err
	}

	// The rollback mode is called by a transient systemd unit when nobody has
	// confirmed connectivity after a network change.
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
		// sets the owner and mode of the socket, so only the agent reaches it.
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

	// A package transaction holds the agent package for its own duration so as
	// not to replace it halfway through its own work.
	if released, err := packages.ReleaseAbandonedHold(ctx); err != nil {
		log.Warn("the abandoned hold on the agent package was not released", "err", err)
	} else if released {
		log.Info("the abandoned hold on the agent package was released")
	}

	// What the last replacement kept so that the host could go back is dropped
	// once the package database holds the version that replacement ordered.
	helper.ReleaseSettledRollback(ctx, log)

	// The helper finishes its work after a period of idleness. With the fleet at
	// rest not a single root process runs.
	server := helper.NewServer(allowedUID, log)
	server.IdleTimeout = *idleTimeout

	// The capability of the panel: the keyring and the host identity are root's,
	// the replay store is root's, and the mode is the owner's decision.
	settings, err := helpercap.LoadSettings(*configPath)
	if err != nil {
		return err
	}
	replay, err := helpercap.OpenReplayStore(settings.ReplayDir)
	if err != nil {
		return fmt.Errorf("the replay store of the helper: %w", err)
	}
	defer replay.Close()
	trust := helpercap.TrustStore{Dir: settings.TrustDir, HostIDPath: settings.HostIDPath,
		RequireRoot: true, PinPath: settings.PinPath, Bootstrap: settings.Bootstrap}
	server.SetCapabilityPolicy(helpercap.NewPolicy(settings.Mode, helpercap.NewVerifier(trust, replay, log)), trust)
	hostID, _ := trust.HostID()
	keyring, skipped, _ := trust.Keyring()
	log.Info("the capability policy of the helper",
		"mode", string(settings.Mode), "mode_source", settings.Source,
		"trusted_keys", keyring.IDs(), "skipped_keys", len(skipped),
		"host_id", hostID, "trust_dir", settings.TrustDir, "replay_dir", settings.ReplayDir)
	if settings.Mode == helpercap.ModeEnforce && (keyring.Empty() || hostID == "") {
		log.Warn("enforce mode with no trusted key or no host identity: every mutating request will be refused until the panel's trust bundle reaches this host")
	}
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
