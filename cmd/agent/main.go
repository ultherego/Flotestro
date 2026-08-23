// Command agent laczy hosta z control plane Flotestro.
// Proces dziala bez uprawnien roota; mutacje beda przekazywane do helpera.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/packages"
)

func main() {
	var (
		stateDir = flag.String("state-dir",
			config.Env("FLOTESTRO_AGENT_STATE_DIR", "/var/lib/flotestro-agent"), "katalog stanu agenta")
		enrollmentURL = flag.String("enrollment-url",
			config.Env("FLOTESTRO_ENROLLMENT_URL", ""), "adres endpointu enrollmentu")
		gatewayURL = flag.String("gateway-url",
			config.Env("FLOTESTRO_GATEWAY_URL", ""), "adres gatewaya agentow")
		token = flag.String("enrollment-token",
			config.Env("FLOTESTRO_ENROLLMENT_TOKEN", ""), "token enrollmentu (tylko pierwszy start)")
		caFile = flag.String("ca-file",
			config.Env("FLOTESTRO_CA_FILE", ""), "bundle CA do bootstrapu zaufania")
		inventoryMinutes = flag.Int("inventory-minutes",
			config.EnvInt("FLOTESTRO_INVENTORY_MINUTES", 15), "odstep pelnego inventory")
		helperSocket = flag.String("helper-socket",
			config.Env("FLOTESTRO_HELPER_SOCKET", "/run/flotestro/helper.sock"),
			"gniazdo helpera roota")
		maxTasks = flag.Int("max-concurrent-tasks",
			config.EnvInt("FLOTESTRO_MAX_CONCURRENT_TASKS", 2), "limit rownoleglych zadan")
		once = flag.Bool("collect-once", false, "wypisz zebrane fakty i zakoncz")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Narzedzia systemowe potrzebuja zapisywalnego HOME. Agent nie ma katalogu
	// domowego, wiec wskazujemy im katalog stanu; bez tego dnf konczy sie
	// bledem, ktory latwo pomylic z wynikiem.
	runtimeDir := filepath.Join(*stateDir, "run")
	if err := agent.SetRuntimeDir(runtimeDir); err != nil {
		log.Error("nie przygotowano katalogu roboczego", "err", err)
		os.Exit(1)
	}
	if err := packages.SetRuntimeDir(runtimeDir); err != nil {
		log.Error("nie przygotowano katalogu roboczego adaptera pakietow", "err", err)
		os.Exit(1)
	}

	if *once {
		if err := printFacts(ctx); err != nil {
			log.Error("nie zebrano faktow", "err", err)
			os.Exit(1)
		}
		return
	}

	if *enrollmentURL == "" || *gatewayURL == "" {
		log.Error("wymagane sa --enrollment-url i --gateway-url")
		os.Exit(1)
	}

	identity, err := agent.EnsureIdentity(ctx, *stateDir, *enrollmentURL, *token, *caFile)
	if err != nil {
		log.Error("brak tozsamosci agenta", "err", err)
		os.Exit(1)
	}
	log.Info("tozsamosc agenta gotowa",
		"host_id", identity.HostID, "cert_not_after", identity.NotAfter.Format(time.RFC3339))

	// Dziennik idempotencji przezywa restart agenta: ponownie dostarczone
	// zadanie musi zwrocic poprzedni wynik, a nie wykonac mutacje drugi raz.
	journal, err := agent.NewIdempotencyJournal(filepath.Join(*stateDir, "tasks"), 24*time.Hour)
	if err != nil {
		log.Error("nie otwarto dziennika idempotencji", "err", err)
		os.Exit(1)
	}

	executor := agent.NewTaskExecutor(
		agent.NewHelperClient(*helperSocket), journal, func() agent.Facts { return agent.Facts{} }, log)

	// Uprzywilejowana czesc stanu domeny idzie przez helpera; agent nie ma
	// dostepu do keytab hosta ani bazy cache SSSD.
	agent.SetPrivilegedIdentityProbe(executor.ProbePrivilegedIdentity)
	agent.SetPrivilegedAccountProbe(executor.ProbeLocalAccounts)
	agent.SetDockerProbe(executor.ProbeDocker)
	agent.SetScheduleProbe(executor.ProbeSchedules)
	// Modul sieci sprawdza po zmianie, czy host nadal dosiega panelu.
	agent.SetGatewayURL(*gatewayURL)
	agent.SetFirewallProbe(executor.ProbeFirewall)
	agent.SetLVMProbe(executor.ProbeLVM)
	agent.SetSSHProbe(executor.ProbeSSH)

	// Certyfikat agenta jest krotkotrwaly. Bez odnawiania caly host wypadlby
	// z floty w dniu wygasniecia, bo tokenu enrollmentu juz na nim nie ma.
	odnowienia := make(chan struct{}, 1)
	go agent.KeepCertificateFresh(ctx, identity, agent.RenewalOptions{
		StateDir:   *stateDir,
		GatewayURL: *gatewayURL,
		Log:        log,
		OnRenewed: func() {
			select {
			case odnowienia <- struct{}{}:
			default:
			}
		},
	})

	if err := agent.Run(ctx, agent.SessionOptions{
		GatewayURL:         *gatewayURL,
		Identity:           identity,
		InventoryInterval:  time.Duration(*inventoryMinutes) * time.Minute,
		Executor:           executor,
		MaxConcurrentTasks: *maxTasks,
		Log:                log,
		Renewed:            odnowienia,
	}); err != nil {
		log.Error("agent zakonczony bledem", "err", err)
		os.Exit(1)
	}
}

func printFacts(ctx context.Context) error {
	facts, err := agent.Collect(ctx)
	if err != nil {
		return err
	}
	_, raw, err := facts.Revision()
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(raw, '\n'))
	return err
}
