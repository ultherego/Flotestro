// Command agent-helper wykonuje operacje wymagajace roota w imieniu agenta.
//
// Helper jest aktywowany przez systemd na zadanie, nasluchuje wylacznie na
// gniezdzie unixowym i nigdy nie laczy sie z siecia. Kompromitacja agenta nie
// daje wiec dostepu do roota poza tym, co helper jawnie obsluguje.
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
		slog.Error("helper zakonczony bledem", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		socketPath = flag.String("socket",
			config.Env("FLOTESTRO_HELPER_SOCKET", "/run/flotestro/helper.sock"),
			"sciezka gniazda, gdy nie ma socket activation")
		agentUser = flag.String("agent-user",
			config.Env("FLOTESTRO_AGENT_USER", "flotestro-agent"),
			"uzytkownik, ktoremu wolno wydawac polecenia")
		rollback = flag.String("rollback", "",
			"wykonaj zapisany plan wycofania zmiany sieci i zakoncz")
		rollbackFirewall = flag.String("rollback-firewall", "",
			"wykonaj zapisany plan wycofania zmiany zapory i zakoncz")
		idleTimeout = flag.Duration("idle-timeout",
			time.Duration(config.EnvInt("FLOTESTRO_HELPER_IDLE_SECONDS", 300))*time.Second,
			"czas bezczynnosci, po ktorym helper konczy prace")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	// Tryb wycofania jest wolany przez przejsciowa jednostke systemd, gdy
	// nikt nie potwierdzil lacznosci po zmianie sieci. Dziala bez gniazda,
	// bez agenta i bez panelu - to ostatnia rzecz, ktora dziala, gdy zmiana
	// odetnie host od swiata.
	if *rollbackFirewall != "" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		log.Warn("wycofanie zmiany zapory", "plan", *rollbackFirewall)
		if err := helper.WycofajZapore(ctx, *rollbackFirewall); err != nil {
			return err
		}
		log.Info("zmiana zapory wycofana", "plan", *rollbackFirewall)
		return nil
	}

	if *rollback != "" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		log.Warn("wycofanie zmiany sieci", "plan", *rollback)
		if err := helper.WycofajZPlanu(ctx, *rollback); err != nil {
			return err
		}
		log.Info("zmiana sieci wycofana", "plan", *rollback)
		return nil
	}

	allowedUID, err := lookupUID(*agentUser)
	if err != nil {
		return err
	}

	// Helper dziala jako root, wiec narzedzia pakietowe uzywaja katalogu roota.
	if err := packages.SetRuntimeDir("/var/lib/flotestro-helper"); err != nil {
		return fmt.Errorf("katalog roboczy helpera: %w", err)
	}

	listener, activated, err := helper.ListenerFromSystemd()
	if err != nil {
		return err
	}
	if !activated {
		// Tryb bez socket activation sluzy testom; wtedy helper sam pilnuje
		// praw gniazda, zeby nie bylo dostepne dla calego systemu.
		_ = os.Remove(*socketPath)
		if err := os.MkdirAll(dirOf(*socketPath), 0o755); err != nil {
			return err
		}
		listener, err = net.Listen("unix", *socketPath)
		if err != nil {
			return fmt.Errorf("gniazdo %s: %w", *socketPath, err)
		}
		if err := os.Chown(*socketPath, 0, int(gidOf(*agentUser))); err != nil {
			log.Warn("nie ustawiono grupy gniazda", "err", err)
		}
		if err := os.Chmod(*socketPath, 0o660); err != nil {
			return err
		}
	}
	defer listener.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("helper gotowy",
		"agent_user", *agentUser, "uid", allowedUID,
		"socket_activated", activated, "protocol_version", helper.ProtocolVersion)

	// Helper konczy prace po okresie bezczynnosci. W stanie spoczynku floty
	// nie dziala zaden proces roota.
	if *idleTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go watchIdle(ctx, cancel, listener, *idleTimeout, log)
	}

	return helper.NewServer(allowedUID, log).Serve(ctx, listener)
}

// watchIdle zamyka helper, gdy przez zadany czas nikt sie nie polaczyl.
func watchIdle(ctx context.Context, cancel context.CancelFunc, listener net.Listener,
	timeout time.Duration, log *slog.Logger) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
		log.Info("koniec pracy po okresie bezczynnosci", "timeout", timeout.String())
		cancel()
		_ = listener.Close()
	}
}

func lookupUID(name string) (uint32, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("uzytkownik %s: %w", name, err)
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
