// Command agent-simulator keeps many simulated agents against a real control
// plane.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/metrics"
)

// stats gathers the course of the simulation.
type stats struct {
	enrolled  atomic.Int64
	connected atomic.Int64
	failed    atomic.Int64
	reconnect atomic.Int64
	// raised counts the sessions started since the last storm dropped the
	// fleet; it is the numerator of the reconnect rate.
	raised atomic.Int64
}

// simulation is what every simulated agent needs to know about the run.
type simulation struct {
	prefix        string
	stateDir      string
	enrollmentURL string
	gatewayURL    string
	token         string
	caFile        string
	// storm says whether an agent raises its session again after it is cut.
	storm     bool
	stormRamp time.Duration
	fleet     *fleet
}

// fleet holds the live sessions so a storm can cut all of them at once.
type fleet struct {
	mu   sync.Mutex
	drop map[int]context.CancelFunc
	// round counts the storms; an agent compares it to tell a session the
	// storm cut from one that failed by itself.
	round atomic.Int64
}

func newFleet() *fleet { return &fleet{drop: map[int]context.CancelFunc{}} }

func (f *fleet) join(index int, cancel context.CancelFunc) {
	f.mu.Lock()
	f.drop[index] = cancel
	f.mu.Unlock()
}

func (f *fleet) leave(index int) {
	f.mu.Lock()
	delete(f.drop, index)
	f.mu.Unlock()
}

// sweep cuts every live session at once and returns how many it cut.
func (f *fleet) sweep() int {
	f.round.Add(1)
	f.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(f.drop))
	for _, cancel := range f.drop {
		cancels = append(cancels, cancel)
	}
	f.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return len(cancels)
}

// stormConfig is the shape of one reconnect storm.
type stormConfig struct {
	every  time.Duration
	rounds int
	ramp   time.Duration
	settle time.Duration
	// metricsURL is the panel's exposition; the criterion is judged by the
	// panel's own numbers, not by the simulator's.
	metricsURL   string
	metricsToken string
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

		stormEvery = flag.Duration("storm-interval", 0,
			"how often the whole fleet is dropped and raised again; zero raises no storm")
		stormRounds = flag.Int("storm-rounds", 0,
			"how many storms to raise; zero means until the simulation ends")
		stormRamp = flag.Duration("storm-ramp", 0,
			"the time the fleet's return after a storm is spread over; zero takes the ramp-up")
		stormSettle = flag.Duration("storm-settle", 30*time.Second,
			"how long past the ramp the fleet is given to come back before the round is reported")
		metricsURL = flag.String("metrics-url", config.Env("FLOTESTRO_METRICS_URL", ""),
			"the panel's exposition, read after every storm")
		metricsToken = flag.String("metrics-token", config.Env("FLOTESTRO_METRICS_TOKEN", ""),
			"the bearer token for the exposition; the environment variable keeps it out of the process list")
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
	sim := simulation{
		prefix: *prefix, stateDir: *stateDir, enrollmentURL: *enrollmentURL,
		gatewayURL: *gatewayURL, token: *token, caFile: *caFile, fleet: newFleet(),
	}
	if *stormEvery > 0 {
		ramp := *stormRamp
		if ramp <= 0 {
			ramp = *rampUp
		}
		sim.storm, sim.stormRamp = true, ramp
		go stormLoop(ctx, sim.fleet, counters, stormConfig{
			every: *stormEvery, rounds: *stormRounds, ramp: ramp, settle: *stormSettle,
			metricsURL: *metricsURL, metricsToken: *metricsToken,
		})
	}
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
			simulate(ctx, index, sim, counters, agentLog)
		}(index)
	}

	wg.Wait()
	printSummary(counters, *count)
	// A run in which nothing enrolled ended in failure, not in an empty
	// measurement: a script that waits for the fleet reads the exit code.
	if ctx.Err() == nil && counters.enrolled.Load() == 0 {
		return fmt.Errorf("none of the %d agents enrolled; see the errors above", *count)
	}
	return nil
}

// simulate keeps one agent with a synthetic identity. In storm mode it raises
// its session again, after a jittered pause, every time the session is cut.
func simulate(ctx context.Context, index int, sim simulation, counters *stats, log *slog.Logger) {
	hostname := fmt.Sprintf("%s-%05d", sim.prefix, index)
	// The machine identifier is stable between runs of the simulator, so a
	// restart does not create new hosts in the fleet.
	sum := sha256.Sum256([]byte(hostname))
	machineID := hex.EncodeToString(sum[:16])

	identity, err := agent.EnsureIdentityFor(ctx, agent.IdentityRequest{
		StateDir:        sim.stateDir + "/" + hostname,
		EnrollmentURL:   sim.enrollmentURL,
		Token:           sim.token,
		BootstrapCAPath: sim.caFile,
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
	for ctx.Err() == nil {
		round := sim.fleet.round.Load()
		sessionCtx, cancel := context.WithCancel(ctx)
		sim.fleet.join(index, cancel)
		counters.connected.Add(1)
		counters.raised.Add(1)

		err := agent.Run(sessionCtx, agent.SessionOptions{
			GatewayURLs:  []string{sim.gatewayURL},
			Identity:     identity,
			CollectFacts: func(context.Context) (agent.Facts, error) { return facts, nil },
			// A simulated agent carries out no mutating jobs; the goal is to
			// measure the cost of the sessions and the inventory alone.
			InventoryInterval:  30 * time.Minute,
			MaxConcurrentTasks: 1,
			Log:                log,
		})

		counters.connected.Add(-1)
		sim.fleet.leave(index)
		cancel()

		// A session the storm cut is not a session that failed; counting it as
		// one would make the storm look like an outage of the panel.
		cut := sim.fleet.round.Load() != round
		if err != nil && ctx.Err() == nil && !cut {
			counters.reconnect.Add(1)
		}
		if !sim.storm || ctx.Err() != nil {
			return
		}
		// The return is spread over the ramp: a fleet that comes back in the
		// same instant measures the simulator rather than the panel.
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(sim.stormRamp)):
		}
	}
}

// jitter spreads one agent's return over the window.
func jitter(window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	return rand.N(window)
}

// stormLoop drops the whole fleet and measures its return: how fast the
// sessions come back, and what the panel itself says while they do.
func stormLoop(ctx context.Context, live *fleet, counters *stats, cfg stormConfig) {
	ticker := time.NewTicker(cfg.every)
	defer ticker.Stop()

	for round := 1; cfg.rounds <= 0 || round <= cfg.rounds; round++ {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		before := counters.connected.Load()
		counters.raised.Store(0)
		started := time.Now()
		dropped := live.sweep()
		fmt.Printf("storm %d: %d sessions dropped; the fleet returns over %s\n",
			round, dropped, cfg.ramp)

		// The fleet is back when as many sessions stand as stood before the
		// drop, or when the ramp and the settling time have gone by without it.
		deadline := started.Add(cfg.ramp + cfg.settle)
		for time.Now().Before(deadline) && counters.connected.Load() < before {
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
		elapsed := time.Since(started)
		raised := counters.raised.Load()
		rate := 0.0
		if elapsed > 0 {
			rate = float64(raised) / elapsed.Seconds()
		}
		fmt.Printf("storm %d: %d/%d sessions back in %s, %d raised (%.1f per second), errors %d\n",
			round, counters.connected.Load(), before, elapsed.Round(time.Millisecond),
			raised, rate, counters.reconnect.Load())
		printPanelMetrics(ctx, cfg.metricsURL, cfg.metricsToken)
	}
}

// panelSeries are the panel's own numbers the acceptance criteria name: the
// resident set, the descriptors against their limit, the collector's pauses,
// the CPU, and what the fleet's return cost in enrollments and renewals.
var panelSeries = []string{
	"flotestro_agent_sessions_active",
	"flotestro_process_resident_bytes",
	"flotestro_process_open_fds",
	"flotestro_process_max_fds",
	"flotestro_process_cpu_seconds_total",
	"flotestro_goroutines",
	"flotestro_gc_pause_seconds_p99",
	"flotestro_agent_reconnect_total",
	"flotestro_enrollment_pending",
	"flotestro_agent_renewal_total",
}

// printPanelMetrics prints what the panel says about itself after a storm.
func printPanelMetrics(ctx context.Context, url, token string) {
	if url == "" {
		return
	}
	values, err := readPanelMetrics(ctx, url, token)
	if err != nil {
		fmt.Printf("  the panel's own numbers could not be read: %v\n", err)
		return
	}
	parts := make([]string, 0, len(panelSeries))
	for _, name := range panelSeries {
		value, ok := values[name]
		if !ok {
			// A series the panel does not expose is a number nobody knows,
			// which is not the same as a number that is zero.
			parts = append(parts, name+"=unknown")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%g", name, value))
	}
	fmt.Printf("  panel: %s\n", strings.Join(parts, " "))
}

// readPanelMetrics sums every series of a family in the panel's exposition.
func readPanelMetrics(ctx context.Context, url, token string) (map[string]float64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the panel answered %s", response.Status)
	}

	values := map[string]float64{}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		series, raw, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil {
			continue
		}
		name, _, _ := strings.Cut(series, "{")
		values[name] += value
	}
	return values, scanner.Err()
}

// syntheticFacts builds believable but different facts for every agent.
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

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fmt.Printf("connected %d/%d | enrolled %d | errors %d | reconnects %d | goroutines %d | simulator RSS %s\n",
				counters.connected.Load(), target, counters.enrolled.Load(),
				counters.failed.Load(), counters.reconnect.Load(),
				runtime.NumGoroutine(), residentSet())
		}
	}
}

// residentSet is the simulator's own resident set as the host measures it.
// The runtime's own bookkeeping is not that number, here no more than in the
// panel.
func residentSet() string {
	resident := metrics.ReadFootprint().ResidentBytes
	if resident == nil {
		return "unknown"
	}
	return fmt.Sprintf("%.0f MiB", float64(*resident)/1048576)
}

func printSummary(counters *stats, target int) {
	fmt.Printf("\nsummary: target %d | registered %d | errors %d | reconnects %d | simulator RSS %s\n",
		target, counters.enrolled.Load(), counters.failed.Load(),
		counters.reconnect.Load(), residentSet())
}
