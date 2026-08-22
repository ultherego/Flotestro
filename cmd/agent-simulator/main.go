// Command agent-simulator utrzymuje wiele symulowanych agentow wobec
// prawdziwego control plane.
//
// Dokument stawia symulator floty przed dashboardem: warunkiem wyjscia etapu
// agenta jest 2000 jednoczesnych sesji bezczynnych, a etapu skalowania 10 000.
// Bez symulatora nie da sie tego zmierzyc inaczej niz na produkcji.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/config"
)

// stats zbiera przebieg symulacji.
type stats struct {
	enrolled  atomic.Int64
	connected atomic.Int64
	failed    atomic.Int64
	reconnect atomic.Int64
}

func main() {
	if err := run(); err != nil {
		slog.Error("symulator zakonczony bledem", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		count    = flag.Int("count", 100, "liczba symulowanych agentow")
		prefix   = flag.String("prefix", "sim", "prefiks nazw hostow")
		stateDir = flag.String("state-dir",
			config.Env("FLOTESTRO_SIM_STATE_DIR", "/var/tmp/flotestro-sim"),
			"katalog tozsamosci symulowanych agentow")
		enrollmentURL = flag.String("enrollment-url", config.Env("FLOTESTRO_ENROLLMENT_URL", ""),
			"adres endpointu enrollmentu")
		gatewayURL = flag.String("gateway-url", config.Env("FLOTESTRO_GATEWAY_URL", ""),
			"adres gatewaya agentow")
		token = flag.String("enrollment-token", config.Env("FLOTESTRO_ENROLLMENT_TOKEN", ""),
			"token enrollmentu")
		caFile = flag.String("ca-file", config.Env("FLOTESTRO_CA_FILE", ""), "bundle CA")
		rampUp = flag.Duration("ramp-up", 30*time.Second,
			"czas rozlozenia startu agentow; jednoczesny start calej floty to lawina")
		duration = flag.Duration("duration", 0, "czas trwania symulacji; zero oznacza bez limitu")
		report   = flag.Duration("report-interval", 15*time.Second, "odstep raportow")
		verbose  = flag.Bool("verbose", false, "logi pojedynczych agentow")
	)
	flag.Parse()

	if *enrollmentURL == "" || *gatewayURL == "" {
		return fmt.Errorf("wymagane sa --enrollment-url i --gateway-url")
	}
	if *count <= 0 {
		return fmt.Errorf("liczba agentow musi byc dodatnia")
	}

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	agentLog := slog.New(slog.NewTextHandler(io.Discard, nil))
	if *verbose {
		agentLog = log
	}
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return fmt.Errorf("katalog stanu: %w", err)
	}

	counters := &stats{}
	go reportLoop(ctx, counters, *count, *report)

	var wg sync.WaitGroup
	// Start jest rozlozony w czasie: jednoczesne polaczenie calej floty jest
	// dokladnie tym uderzeniem, przed ktorym broni sie control plane.
	interval := time.Duration(0)
	if *rampUp > 0 && *count > 1 {
		interval = *rampUp / time.Duration(*count)
	}

	for index := 0; index < *count; index++ {
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			simulate(ctx, index, *prefix, *stateDir, *enrollmentURL, *gatewayURL,
				*token, *caFile, counters, agentLog)
		}(index)
	}

	wg.Wait()
	printSummary(counters, *count)
	return nil
}

// simulate utrzymuje jednego agenta o syntetycznej tozsamosci.
func simulate(ctx context.Context, index int, prefix, stateDir, enrollmentURL, gatewayURL,
	token, caFile string, counters *stats, log *slog.Logger) {
	hostname := fmt.Sprintf("%s-%05d", prefix, index)
	// Identyfikator maszyny jest stabilny miedzy uruchomieniami symulatora,
	// wiec ponowny start nie tworzy nowych hostow we flocie.
	sum := sha256.Sum256([]byte(hostname))
	machineID := hex.EncodeToString(sum[:16])

	identity, err := agent.EnsureIdentityFor(ctx, agent.IdentityRequest{
		StateDir:        stateDir + "/" + hostname,
		EnrollmentURL:   enrollmentURL,
		Token:           token,
		BootstrapCAPath: caFile,
		MachineID:       machineID,
		Hostname:        hostname,
		OSFamily:        "debian",
		OSVersion:       "13",
		Architecture:    runtime.GOARCH,
	})
	if err != nil {
		counters.failed.Add(1)
		log.Error("enrollment symulowanego agenta nie powiodl sie",
			"hostname", hostname, "err", err)
		return
	}
	counters.enrolled.Add(1)

	facts := syntheticFacts(hostname, machineID)
	counters.connected.Add(1)
	defer counters.connected.Add(-1)

	err = agent.Run(ctx, agent.SessionOptions{
		GatewayURL:   gatewayURL,
		Identity:     identity,
		CollectFacts: func(context.Context) (agent.Facts, error) { return facts, nil },
		// Symulowany agent nie wykonuje zadan mutujacych; celem jest pomiar
		// kosztu samych sesji i inventory.
		InventoryInterval:  30 * time.Minute,
		MaxConcurrentTasks: 1,
		Log:                log,
	})
	if err != nil && ctx.Err() == nil {
		counters.reconnect.Add(1)
	}
}

// syntheticFacts buduje wiarygodne, ale rozne fakty dla kazdego agenta.
// Identyczne fakty dawalyby te sama rewizje inventory i ukrywaly koszt zapisu.
func syntheticFacts(hostname, machineID string) agent.Facts {
	sum := sha256.Sum256([]byte(machineID))
	seed := int(sum[0])<<8 | int(sum[1])

	installed := uint32(400 + seed%600)
	upgradable := uint32(seed % 40)
	return agent.Facts{
		Hostname:  hostname,
		MachineID: machineID,
		BootID:    hex.EncodeToString(sum[16:]),
		OS: agent.OSInfo{
			Family: "debian", Distribution: "debian", Version: "13",
			Kernel: "6.12.0-sim", Architecture: runtime.GOARCH,
			PrettyName: "Debian GNU/Linux 13 (symulacja)",
		},
		Hardware: agent.Hardware{
			CPUCores:       uint32(2 + seed%6),
			MemoryBytes:    uint64(2+seed%14) << 30,
			RootFSBytes:    40 << 30,
			RootFSFreeByte: uint64(10+seed%25) << 30,
			Virtualization: "flotestro-simulator",
		},
		Packages: agent.Packages{
			Manager: "apt", Installed: &installed, Upgradable: &upgradable,
		},
		Capabilities:     agent.Capabilities{Systemd: true, APT: true, Journald: true},
		FailedUnitsKnown: true,
		Interfaces:       []string{"eth0"},
		CollectedAt:      time.Now().UTC(),
	}
}

func reportLoop(ctx context.Context, counters *stats, target int, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var memory runtime.MemStats
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runtime.ReadMemStats(&memory)
			fmt.Printf("polaczonych %d/%d | enrollment %d | bledow %d | reconnect %d | goroutines %d | RSS symulatora %.0f MiB\n",
				counters.connected.Load(), target, counters.enrolled.Load(),
				counters.failed.Load(), counters.reconnect.Load(),
				runtime.NumGoroutine(), float64(memory.Sys)/1048576)
		}
	}
}

func printSummary(counters *stats, target int) {
	fmt.Printf("\npodsumowanie: cel %d | zarejestrowanych %d | bledow %d | reconnect %d\n",
		target, counters.enrolled.Load(), counters.failed.Load(), counters.reconnect.Load())
}
