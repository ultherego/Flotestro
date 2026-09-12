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
	"github.com/ultherego/flotestro/internal/agentconfig"
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
			config.Env("FLOTESTRO_GATEWAY_URL", ""),
			"adres gatewaya agentow; nadpisuje cala liste z pliku")
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
		// Plik YAML jest kanonicznym zrodlem ustawien; flagi i zmienne
		// srodowiskowe zostaja jako override dla obrazow i testow.
		configPath = flag.String("config",
			config.Env("FLOTESTRO_AGENT_CONFIG", agentconfig.DefaultPath),
			"plik konfiguracji agenta")
		tryb = flag.String("mode", config.Env("FLOTESTRO_AGENT_MODE", ""),
			"tryb pracy: full albo read_only")
	)
	flag.Parse()

	// Co ustawil operator, a co przyszlo z domyslnych - to rozroznienie jest
	// cala trescia pierwszenstwa: plik nie moze nadpisac tego, co ktos podal
	// jawnie, a domyslna wartosc flagi nie moze udawac decyzji.
	jawne := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { jawne[f.Name] = true })

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	// Bramy w kolejnosci priorytetu. Pusta lista znaczy "tylko to, co podano
	// flaga albo zmienna" - i wtedy wypelnia sie nizej pojedynczym adresem.
	var bramy []string

	cfg, zPliku, err := wczytajKonfiguracje(*configPath)
	if err != nil {
		log.Error("konfiguracja agenta", "plik", *configPath, "err", err)
		os.Exit(1)
	}
	if zPliku {
		zastosuj(cfg, jawne, ustawienia{
			stateDir: stateDir, enrollmentURL: enrollmentURL, gatewayURL: gatewayURL,
			bramy: &bramy, caFile: caFile, helperSocket: helperSocket,
			inventoryMinutes: inventoryMinutes, maxTasks: maxTasks, tryb: tryb,
		})
		log.Info("konfiguracja wczytana", "plik", *configPath,
			"bram", len(cfg.Connection.GatewayURLs), "tryb", *tryb)
	} else {
		// Zgodnosc wstecz: host postawiony przed wprowadzeniem pliku YAML
		// dziala dalej na zmiennych srodowiskowych. Musi jednak wiedziec,
		// ze idzie stara droga - inaczej zostanie na niej na zawsze.
		log.Warn("brak pliku konfiguracji, uzywam zmiennych srodowiskowych",
			"plik", *configPath)
	}

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

	if len(bramy) == 0 && *gatewayURL != "" {
		bramy = []string{*gatewayURL}
	}
	if *enrollmentURL == "" || len(bramy) == 0 {
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
	// Tryb obserwacji jest decyzja wlasciciela hosta, a nie brakiem
	// zdolnosci: agent raportuje fakty, ale nie wykona zadnej zmiany.
	if *tryb == agentconfig.ModeReadOnly {
		executor.UstawTrybOdczytu(true)
		log.Info("agent pracuje w trybie obserwacji", "tryb", *tryb)
	}

	// Uprzywilejowana czesc stanu domeny idzie przez helpera; agent nie ma
	// dostepu do keytab hosta ani bazy cache SSSD.
	agent.SetPrivilegedIdentityProbe(executor.ProbePrivilegedIdentity)
	agent.SetPrivilegedAccountProbe(executor.ProbeLocalAccounts)
	agent.SetDockerProbe(executor.ProbeDocker)
	agent.SetScheduleProbe(executor.ProbeSchedules)
	// Modul sieci sprawdza po zmianie, czy host nadal dosiega panelu.
	// Wystarczy jedna brama: chodzi o to, czy host w ogole ma droge do
	// centrali, a nie o to, ktora z nich obsluguje biezaca sesje.
	agent.SetGatewayURL(bramy[0])
	agent.SetFirewallProbe(executor.ProbeFirewall)
	agent.SetLVMProbe(executor.ProbeLVM)
	agent.SetSSHProbe(executor.ProbeSSH)
	agent.SetKernelProbe(executor.ProbeKernel)
	agent.SetFileProbe(executor.ProbeFiles)
	agent.SetSecurityProbe(executor.ProbeSecurity)
	agent.SetCertificateProbe(executor.ProbeCertificates)

	// Certyfikat agenta jest krotkotrwaly. Bez odnawiania caly host wypadlby
	// z floty w dniu wygasniecia, bo tokenu enrollmentu juz na nim nie ma.
	odnowienia := make(chan struct{}, 1)
	go agent.KeepCertificateFresh(ctx, identity, agent.RenewalOptions{
		StateDir: *stateDir,
		// Odnowienie idzie do bramy pierwszego wyboru. Nie jest pilne co do
		// minuty: do wygasniecia zostaje wtedy jeszcze jedna trzecia zycia
		// certyfikatu, wiec awaria tej jednej bramy nie odcina hosta.
		GatewayURL: bramy[0],
		Log:        log,
		OnRenewed: func() {
			select {
			case odnowienia <- struct{}{}:
			default:
			}
		},
	})

	if err := agent.Run(ctx, agent.SessionOptions{
		GatewayURLs:        bramy,
		Identity:           identity,
		InventoryInterval:  time.Duration(*inventoryMinutes) * time.Minute,
		Executor:           executor,
		MaxConcurrentTasks: *maxTasks,
		Log:                log,
		Renewed:            odnowienia,
		// Stan na dysku jest jedynym zrodlem, z ktorego agentctl na hoscie
		// bez panelu dowie sie, czy agent naprawde rozmawia z gatewayem.
		Stan: agent.NowyPisarzStanu(*stateDir, identity.HostID),
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

// ustawienia zbiera wskazniki do wartosci, ktore moze podac plik.
type ustawienia struct {
	stateDir         *string
	enrollmentURL    *string
	gatewayURL       *string
	bramy            *[]string
	caFile           *string
	helperSocket     *string
	inventoryMinutes *int
	maxTasks         *int
	tryb             *string
}

// wczytajKonfiguracje czyta plik YAML, jesli istnieje.
//
// Brak pliku nie jest bledem: host postawiony przed jego wprowadzeniem ma
// dzialac dalej. Plik, ktory jest i jest zly, bledem jest - agent, ktory
// wystartowal z domyslnymi ustawieniami zamiast z zapisanych, laczylby sie
// gdzie indziej niz operator zapisal.
func wczytajKonfiguracje(sciezka string) (agentconfig.Config, bool, error) {
	if sciezka == "" {
		return agentconfig.Config{}, false, nil
	}
	if _, err := os.Stat(sciezka); err != nil {
		if os.IsNotExist(err) {
			return agentconfig.Config{}, false, nil
		}
		return agentconfig.Config{}, false, err
	}
	cfg, err := agentconfig.Load(sciezka)
	if err != nil {
		return agentconfig.Config{}, false, err
	}
	if err := cfg.CheckBootstrapCA(); err != nil {
		return agentconfig.Config{}, false, err
	}
	return cfg, true, nil
}

// zastosuj wpisuje wartosci z pliku tam, gdzie nikt nie podal wlasnych.
//
// Pierwszenstwo: jawna flaga > zmienna srodowiskowa > plik > domyslne.
func zastosuj(cfg agentconfig.Config, jawne map[string]bool, cel ustawienia) {
	ustaw := func(flaga, zmienna string, wartosc string, docelowy *string) {
		if wartosc == "" || jawne[flaga] || os.Getenv(zmienna) != "" {
			return
		}
		*docelowy = wartosc
	}
	ustaw("state-dir", "FLOTESTRO_AGENT_STATE_DIR", cfg.Agent.StateDir, cel.stateDir)
	ustaw("enrollment-url", "FLOTESTRO_ENROLLMENT_URL", cfg.Connection.EnrollmentURL, cel.enrollmentURL)
	// Lista bram jest priorytetowa i idzie do agenta w calosci: przelaczenie
	// na brame zapasowa nie moze byc reczna czynnoscia operatora w chwili
	// awarii centrali. Jawna flaga albo zmienna srodowiskowa zastepuje cala
	// liste - kto podaje jeden adres, ten chce dokladnie jego.
	if len(cfg.Connection.GatewayURLs) > 0 {
		ustaw("gateway-url", "FLOTESTRO_GATEWAY_URL", cfg.Connection.GatewayURLs[0], cel.gatewayURL)
		if !jawne["gateway-url"] && os.Getenv("FLOTESTRO_GATEWAY_URL") == "" {
			*cel.bramy = append([]string{}, cfg.Connection.GatewayURLs...)
		}
	}
	ustaw("ca-file", "FLOTESTRO_CA_FILE", cfg.Connection.BootstrapCA, cel.caFile)
	ustaw("helper-socket", "FLOTESTRO_HELPER_SOCKET", cfg.Helper.Socket, cel.helperSocket)
	ustaw("mode", "FLOTESTRO_AGENT_MODE", cfg.Agent.Mode, cel.tryb)

	if !jawne["inventory-minutes"] && os.Getenv("FLOTESTRO_INVENTORY_MINUTES") == "" {
		*cel.inventoryMinutes = int(cfg.Agent.InventoryInterval / time.Minute)
	}
	if !jawne["max-concurrent-tasks"] && os.Getenv("FLOTESTRO_MAX_CONCURRENT_TASKS") == "" {
		*cel.maxTasks = cfg.Agent.MaxConcurrentTasks
	}
}
