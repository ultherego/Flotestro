// Command agent-simulator keeps many simulated agents against a real control
// plane.
//
// The document puts the fleet simulator before the dashboard: the exit
// condition of the agent stage is 2000 concurrent idle sessions, and of the
// scaling stage 10 000. Without the simulator there is no measuring that
// other than in production.
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

// stats gathers the course of the simulation.
type stats struct {
	enrolled  atomic.Int64
	connected atomic.Int64
	failed    atomic.Int64
	reconnect atomic.Int64
}

func main() {
	if err := run(); err != nil {
		slog.Error("the simulator ended with an error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		count    = flag.Int("count", 100, "the number of simulated agents")
		prefix   = flag.String("prefix", "sim", "the prefix of the host names")
		stateDir = flag.String("state-dir",
			config.Env("FLOTESTRO_SIM_STATE_DIR", "/var/tmp/flotestro-sim"),
			"the directory of the identities of the simulated agents")
		enrollmentURL = flag.String("enrollment-url", config.Env("FLOTESTRO_ENROLLMENT_URL", ""),
			"the address of the enrollment endpoint")
		gatewayURL = flag.String("gateway-url", config.Env("FLOTESTRO_GATEWAY_URL", ""),
			"the address of the agent gateway")
		token = flag.String("enrollment-token", config.Env("FLOTESTRO_ENROLLMENT_TOKEN", ""),
			"the enrollment token")
		caFile = flag.String("ca-file", config.Env("FLOTESTRO_CA_FILE", ""), "the CA bundle")
		rampUp = flag.Duration("ramp-up", 30*time.Second,
			"the time the start of the agents is spread over; starting the whole fleet at once is an avalanche")
		duration = flag.Duration("duration", 0, "how long the simulation lasts; zero means without a limit")
		report   = flag.Duration("report-interval", 15*time.Second, "the interval of the reports")
		verbose  = flag.Bool("verbose", false, "the logs of individual agents")
	)
	flag.Parse()

	if *enrollmentURL == "" || *gatewayURL == "" {
		return fmt.Errorf("--enrollment-url and --gateway-url are required")
	}
	if *count <= 0 {
		return fmt.Errorf("the number of agents has to be positive")
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
		return fmt.Errorf("the state directory: %w", err)
	}

	counters := &stats{}
	go reportLoop(ctx, counters, *count, *report)

	var wg sync.WaitGroup
	// The start is spread over time: the whole fleet connecting at once is
	// exactly the blow the control plane defends itself against.
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

// simulate keeps one agent with a synthetic identity.
func simulate(ctx context.Context, index int, prefix, stateDir, enrollmentURL, gatewayURL,
	token, caFile string, counters *stats, log *slog.Logger) {
	hostname := fmt.Sprintf("%s-%05d", prefix, index)
	// The machine identifier is stable between runs of the simulator, so a
	// restart does not create new hosts in the fleet.
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
		log.Error("the enrollment of a simulated agent failed",
			"hostname", hostname, "err", err)
		return
	}
	counters.enrolled.Add(1)

	facts := syntheticFacts(hostname, machineID)
	counters.connected.Add(1)
	defer counters.connected.Add(-1)

	err = agent.Run(ctx, agent.SessionOptions{
		GatewayURLs:  []string{gatewayURL},
		Identity:     identity,
		CollectFacts: func(context.Context) (agent.Facts, error) { return facts, nil },
		// A simulated agent carries out no mutating jobs; the goal is to
		// measure the cost of the sessions and the inventory alone.
		InventoryInterval:  30 * time.Minute,
		MaxConcurrentTasks: 1,
		Log:                log,
	})
	if err != nil && ctx.Err() == nil {
		counters.reconnect.Add(1)
	}
}

// syntheticFacts builds believable but different facts for every agent.
// Identical facts would give the same inventory revision and hide the cost of
// the write.
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
			PrettyName: "Debian GNU/Linux 13 (simulation)",
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
		Capabilities: agent.Capabilities{
			{Name: agent.CapSystemd, Version: 1, Available: true},
			{Name: agent.CapAPT, Version: 1, Available: true, Features: map[string]bool{"repair": true}},
			{Name: agent.CapJournald, Version: 1, Available: true},
		},
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
			fmt.Printf("connected %d/%d | enrolled %d | errors %d | reconnects %d | goroutines %d | RSS of the simulator %.0f MiB\n",
				counters.connected.Load(), target, counters.enrolled.Load(),
				counters.failed.Load(), counters.reconnect.Load(),
				runtime.NumGoroutine(), float64(memory.Sys)/1048576)
		}
	}
}

func printSummary(counters *stats, target int) {
	fmt.Printf("\nsummary: target %d | registered %d | errors %d | reconnects %d\n",
		target, counters.enrolled.Load(), counters.failed.Load(), counters.reconnect.Load())
}
