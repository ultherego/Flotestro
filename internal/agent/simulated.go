package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helper"
)

// SimulatedHost is the machine a simulated agent works on: the kernel
// settings it holds, and the time a change takes. The executor on top of it is
// the real one, so a task goes through the same checks, claims, journal and
// verification as on a host; only the root helper is replaced.
type SimulatedHost struct {
	// Latency is how long a change takes; zero means no delay.
	Latency time.Duration

	mu     sync.Mutex
	sysctl map[string]string
}

// NewSimulatedExecutor builds the executor of a simulated agent over host.
func NewSimulatedExecutor(host *SimulatedHost, stateDir string, facts func() Facts,
	log *slog.Logger) (*TaskExecutor, error) {
	journal, err := NewIdempotencyJournal(stateDir, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	client := newHelperClientWithDial(func(context.Context) (net.Conn, error) {
		near, far := net.Pipe()
		go host.serve(far)
		return near, nil
	})
	executor := NewTaskExecutor(client, journal, facts, log)
	executor.verifyReaders = &hostReaders{sysctl: host.readSysctl}
	return executor, nil
}

// Sysctl returns what the host holds under key.
func (h *SimulatedHost) Sysctl(key string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	value, ok := h.sysctl[key]
	return value, ok
}

func (h *SimulatedHost) readSysctl(key string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sysctl[key], nil
}

// serve answers one request the way the helper does; what it does not know it
// accepts without changing anything.
func (h *SimulatedHost) serve(conn net.Conn) {
	defer conn.Close()
	var request helperv1.HelperRequest
	if err := helper.ReadMessage(conn, &request); err != nil {
		return
	}
	response := &helperv1.HelperResponse{Accepted: true, Final: true}
	if kernel := request.GetKernel(); kernel != nil &&
		kernel.GetOperation() == helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE {
		if h.Latency > 0 {
			time.Sleep(h.Latency)
		}
		h.mu.Lock()
		if h.sysctl == nil {
			h.sysctl = map[string]string{}
		}
		applied := make([]string, 0, len(kernel.GetSettings()))
		for key, value := range kernel.GetSettings() {
			h.sysctl[key] = value
			applied = append(applied, key)
		}
		h.mu.Unlock()
		response.KernelResult = &helperv1.KernelResult{Message: "simulated", AppliedRuntime: applied}
	}
	_ = helper.WriteMessage(conn, response)
}

// SimulatedFacts builds believable but different facts for every agent; a working
// one also has the kernel capability its changes need.
func SimulatedFacts(hostname, machineID string, working bool) Facts {
	sum := sha256.Sum256([]byte(machineID))
	seed := int(sum[0])<<8 | int(sum[1])

	installed := uint32(400 + seed%600)
	upgradable := uint32(seed % 40)
	capabilities := Capabilities{
		{Name: CapSystemd, Version: 1, Available: true},
		{Name: CapAPT, Version: 1, Available: true, Features: map[string]bool{"repair": true}},
		{Name: CapJournald, Version: 1, Available: true},
	}
	if working {
		capabilities = append(capabilities, Capability{Name: CapKernel, Version: 1, Available: true})
	}
	return Facts{
		Hostname:  hostname,
		MachineID: machineID,
		BootID:    hex.EncodeToString(sum[16:]),
		OS: OSInfo{
			Family: "debian", Distribution: "debian", Version: "13",
			Kernel: "6.12.0-sim", Architecture: runtime.GOARCH,
			PrettyName: "Debian GNU/Linux 13 (simulation)",
		},
		Hardware: Hardware{
			CPUCores:       uint32(2 + seed%6),
			MemoryBytes:    uint64(2+seed%14) << 30,
			RootFSBytes:    40 << 30,
			RootFSFreeByte: uint64(10+seed%25) << 30,
			Virtualization: "flotestro-simulator",
		},
		Packages: Packages{
			Manager: "apt", Installed: &installed, Upgradable: &upgradable,
		},
		Capabilities:     capabilities,
		FailedUnitsKnown: true,
		Interfaces:       []string{"eth0"},
		CollectedAt:      time.Now().UTC(),
	}
}
