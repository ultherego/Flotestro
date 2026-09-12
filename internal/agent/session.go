package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/endpoints"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
)

// SessionOptions configures the connection of the agent to the control plane.
type SessionOptions struct {
	// GatewayURLs are the gateways in order of priority. The agent keeps one
	// active session but knows the whole list: switching to a standby gateway
	// must not be a manual action of the operator at the moment the centre
	// fails.
	GatewayURLs       []string
	Identity          *Identity
	InventoryInterval time.Duration
	Executor          *TaskExecutor
	// CollectFacts allows synthetic facts to be substituted. The fleet simulator
	// does not read a real host, because a thousand agents on one machine would
	// report the same state.
	CollectFacts func(context.Context) (Facts, error)
	// MaxConcurrentTasks limits the number of tasks performed in parallel. The
	// host must not be flooded with work by the control plane.
	MaxConcurrentTasks int
	Log                *slog.Logger
	// Renewed signals a renewal of the certificate. The session then ends at
	// once so that the next one goes with the new identity; waiting for a natural
	// break would mean working on a certificate that has just been replaced.
	Renewed <-chan struct{}
	// State writes to disk what is happening with the agent. Without it the
	// diagnostic tool on the host sees only the identity files and cannot answer
	// whether the agent really talks to the panel.
	State *StateWriter

	// gatewayURL is the gateway chosen for this one session. It does not come
	// from the configuration but from the gateway manager, so it is not a public
	// field.
	gatewayURL string
}

const (
	minBackoff = 2 * time.Second
	maxBackoff = 5 * time.Minute
)

// Run keeps the connection to the gateway and resumes it with backoff and
// jitter. A failure of the control plane must not cause an avalanche of
// reconnects from the whole fleet.
func Run(ctx context.Context, opts SessionOptions) error {
	manager := endpoints.New(opts.GatewayURLs, minBackoff, maxBackoff)
	if len(manager.Gateways()) == 0 {
		return errors.New("the agent has no gateway to connect to")
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		gateway, err := manager.Choose(time.Now())
		if err != nil {
			// A revoked identity is not a failure of the link. The agent stops
			// knocking and leaves the reason where the operator of the host will
			// look: further attempts repair nothing, and enrollment is a decision
			// of a human, not a side effect of a reconnect.
			opts.Log.Error("the connection was stopped", "err", err)
			opts.State.Disconnected(err.Error(), time.Now())
			return err
		}
		if gateway == nil {
			// Every gateway still has a retry window. The wait goes until the
			// nearest one instead of spinning in a loop.
			waiting := manager.UntilNext(time.Now())
			opts.Log.Info("all the gateways are in their retry window",
				"in", waiting.Round(time.Second).String())
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(waiting):
			}
			continue
		}

		// The client is created at every connection, because the identity may
		// change in the meantime: a renewed certificate has to come into use
		// without restarting the agent.
		client := agentv1connect.NewAgentServiceClient(
			newHTTP2Client(opts.Identity),
			gateway.URL,
			// The Connect protocol does not support full duplex, so the
			// bidirectional stream travels over gRPC on top of HTTP/2.
			connect.WithGRPC(),
		)
		start := time.Now()
		session := opts
		session.gatewayURL = gateway.URL
		err = runSession(ctx, client, session)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			opts.Log.Warn("the session ended", "gateway", gateway.URL, "err", err)
			opts.State.Disconnected(err.Error(), time.Now())
		} else {
			opts.State.Disconnected("", time.Now())
		}

		switch {
		case errors.Is(err, errIdentityRenewed):
			// A break after a certificate renewal is not an error of the gateway:
			// the next connection goes with the new identity and to the same
			// place.
			manager.Success(gateway.URL, time.Now())
			continue
		case time.Since(start) > time.Minute:
			// A session that worked for longer than a minute is not a symptom of
			// an error loop - even when it ended with a break.
			manager.Success(gateway.URL, time.Now())
			if err == nil {
				continue
			}
		}

		class := endpoints.Classify(err)
		manager.Error(gateway.URL, class, time.Now())
		if class == endpoints.ClassConfiguration {
			// A bad configuration does not repair itself with a retry, so it is
			// named directly and where it can be seen without the panel.
			opts.Log.Error("the gateway refused the connection because of the configuration",
				"gateway", gateway.URL, "err", err,
				"hint", "check bootstrap_ca_file and the name in gateway_urls")
		}
	}
}

// errIdentityRenewed ends the session after a certificate renewal. The next
// connection already goes with the new identity.
var errIdentityRenewed = errors.New("the identity of the agent was renewed")

func runSession(ctx context.Context, client agentv1connect.AgentServiceClient,
	opts SessionOptions) (result error) {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A certificate renewal ends the session: the next one is to go with the new
	// identity. The break of the stream then looks like an ordinary error, so the
	// reason is swapped on the way out - Run is not to wait before reconnecting.
	renewed := make(chan struct{})
	if opts.Renewed != nil {
		go func() {
			select {
			case <-opts.Renewed:
				close(renewed)
				cancel()
			case <-sessionCtx.Done():
			}
		}()
	}
	defer func() {
		select {
		case <-renewed:
			result = errIdentityRenewed
		default:
		}
	}()

	stream := client.Connect(sessionCtx)
	defer func() { _ = stream.CloseRequest() }()

	// The address the host reaches the panel with is determined once per session
	// and passed to the network module: it is what decides which interface is the
	// management channel, and therefore which change must not be made without a
	// warning.
	localAddress := panelAddress(opts.gatewayURL)

	collect := opts.CollectFacts
	if collect == nil {
		collect = func(ctx context.Context) (Facts, error) {
			return CollectFrom(ctx, localAddress)
		}
	}

	facts, err := collect(sessionCtx)
	if err != nil {
		return err
	}
	revision, _, err := facts.Revision()
	if err != nil {
		return err
	}

	if err := stream.Send(&agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
			AgentVersion:      Version,
			BootId:            facts.BootID,
			Capabilities:      capabilitiesToProto(facts.Capabilities),
			InventoryRevision: revision,
			LocalAddress:      localAddress,
		}},
	}); err != nil {
		return err
	}

	first, err := stream.Receive()
	if err != nil {
		return err
	}
	sessionConfig := first.GetSessionConfig()
	if sessionConfig == nil {
		return errors.New("the server did not send back the session configuration")
	}
	heartbeatInterval := time.Duration(sessionConfig.GetHeartbeatSeconds()) * time.Second
	if heartbeatInterval <= 0 {
		heartbeatInterval = 60 * time.Second
	}
	jitterWindow := time.Duration(sessionConfig.GetHeartbeatJitterSeconds()) * time.Second

	opts.Log.Info("the session was established",
		"host_id", opts.Identity.HostID, "heartbeat", heartbeatInterval.String())
	opts.State.Connected(opts.gatewayURL, time.Now())

	// Send is not safe for concurrent calls.
	var sendMu sync.Mutex
	send := func(msg *agentv1.AgentMessage) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(msg)
	}

	sendInventory := func(f Facts) error {
		rev, raw, err := f.Revision()
		if err != nil {
			return err
		}
		if err := send(&agentv1.AgentMessage{
			Payload: &agentv1.AgentMessage_Inventory{Inventory: inventoryToProto(f, rev, raw)},
		}); err != nil {
			return err
		}
		opts.State.Inventory(rev, time.Now())
		return nil
	}

	if err := sendInventory(facts); err != nil {
		return err
	}

	// The facts are read by the task executor while checking the preconditions
	// and updated by the inventory cycle, so they need synchronization.
	var factsMu sync.RWMutex
	cachedFacts := facts
	currentFacts := func() Facts {
		factsMu.RLock()
		defer factsMu.RUnlock()
		return cachedFacts
	}
	updateFacts := func(fresh Facts) {
		factsMu.Lock()
		cachedFacts = fresh
		factsMu.Unlock()
	}
	if opts.Executor != nil {
		opts.Executor.facts = currentFacts
		// The progress travels in the same stream as the results. A send error is
		// not escalated: losing the preview must not interrupt an operation in
		// progress. The journal preview travels in the same stream as the results.
		opts.Executor.logLines = func(lines *agentv1.TaskLogLines) {
			if err := send(&agentv1.AgentMessage{
				Payload: &agentv1.AgentMessage_TaskLogLines{TaskLogLines: lines},
			}); err != nil {
				opts.Log.Debug("the journal preview was not sent",
					"task_id", lines.GetTaskId(), "err", err)
			}
		}
		// A secret is fetched with a separate call, at the moment the operation
		// runs. The value then lives in the memory of the host and is written
		// nowhere - neither in the journal of the agent nor in the result of the
		// task.
		opts.Executor.secrets = func(ctx context.Context, taskID, name string, version int) ([]byte, error) {
			response, err := client.FetchSecret(ctx, connect.NewRequest(&agentv1.FetchSecretRequest{
				TaskId: taskID, SecretName: name, SecretVersion: uint32(version),
			}))
			if err != nil {
				return nil, err
			}
			value := response.Msg.GetValue()
			// The panel gives the digest of what it issued: this checks that
			// exactly that arrived and not content damaged on the way.
			if digest := response.Msg.GetSha256(); digest != "" && digest != valueDigest(value) {
				return nil, errors.New("the digest of the fetched secret does not match the one given by the panel")
			}
			return value, nil
		}
		opts.Executor.progress = func(p *agentv1.TaskProgress) {
			if err := send(&agentv1.AgentMessage{
				Payload: &agentv1.AgentMessage_TaskProgress{TaskProgress: p},
			}); err != nil {
				opts.Log.Debug("the progress of the task was not sent",
					"task_id", p.GetTaskId(), "err", err)
			}
		}
	}

	// The slots are counted separately for every resource class: a long package
	// read must not take the whole pool and stop the operations that last
	// milliseconds.
	slots := newBudget(opts.MaxConcurrentTasks)
	// The resource locks are a second layer next to the budget: the budget says
	// how many tasks the host can carry, and the locks - which of them cannot
	// run side by side.
	resources := newLocks()

	receiveErr := make(chan error, 1)
	reportError := func(err error) {
		select {
		case receiveErr <- err:
		default:
		}
	}

	// The inventory collection runs next to the receive loop: a heavy read must
	// not stop the acceptance of tasks.
	inventory := newCollector()
	go func() {
		collectScope := func(ctx context.Context, modules []string) (Facts, error) {
			if len(modules) == 0 {
				return collect(ctx)
			}
			// A partial refresh enters the previous picture: a module outside the
			// scope is to stay as it was and not disappear.
			return CollectModules(ctx, localAddress, currentFacts(), modules)
		}
		accept := func(fresh Facts) (Refresh, error) {
			previous := ""
			if rev, _, err := currentFacts().Revision(); err == nil {
				previous = rev
			}
			updateFacts(fresh)
			if err := sendInventory(fresh); err != nil {
				return Refresh{}, err
			}
			current, _, err := fresh.Revision()
			if err != nil {
				return Refresh{}, err
			}
			return Refresh{Revision: current, Changed: current != previous}, nil
		}
		if err := inventory.run(sessionCtx, collectScope, accept, opts.Log); err != nil {
			reportError(err)
		}
	}()

	// A refresh on request is a typed operation, so the executor has to be able
	// to ask for one - and to wait for the revision that came out of it.
	if opts.Executor != nil {
		opts.Executor.inventoryRefresh = func(ctx context.Context, modules []string) Refresh {
			return inventory.refresh(ctx, modules)
		}
	}

	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				receiveErr <- err
				return
			}
			switch payload := msg.GetPayload().(type) {
			case *agentv1.ServerMessage_InventoryRequest:
				inventory.request()

			case *agentv1.ServerMessage_Task:
				// A task runs next to the receive loop: a unit restart takes time,
				// and the heartbeat and the next tasks must not wait for it.
				task := payload.Task
				go func() {
					// The resources first, the budget slot second: a task waiting
					// for a busy resource has no reason to hold a slot that would
					// be useful to an operation without a collision.
					claims := taskClaims(task)
					releaseResources, reason := acquireResources(sessionCtx, resources, task, claims)
					if reason != "" {
						// A refusal naming the blocking task is an answer; silence
						// until the end of the time limit of the operation is not.
						refusal := rejected(agentv1.TaskResult_STATUS_REJECTED,
							RejectResourceBusy, reason)
						refusal.TaskId = task.GetTaskId()
						opts.Log.Info("the task was refused by a resource lock",
							"task_id", task.GetTaskId(), "reason", reason)
						if err := send(&agentv1.AgentMessage{
							Payload: &agentv1.AgentMessage_TaskResult{TaskResult: refusal},
						}); err != nil {
							opts.Log.Error("the refusal of the task was not sent back",
								"task_id", task.GetTaskId(), "err", err)
						}
						return
					}
					if releaseResources == nil {
						return
					}
					defer releaseResources()

					releaseSlot := slots.acquire(sessionCtx, taskClass(task))
					if releaseSlot == nil {
						return
					}
					defer releaseSlot()
					if len(claims) > 0 {
						opts.Log.Info("the resources were taken", "task_id", task.GetTaskId(),
							"claims", strings.Join(claims, ","))
					}
					result := executeTask(sessionCtx, opts.Executor, task, opts.Log)
					// An agent replacement has no result to send back: the process
					// that performed it is being replaced right now, and whether it
					// worked is decided by the return of the host with the new
					// version. Any other answer would be a guess.
					if result.GetErrorCode() == StatusAfterReplacement {
						opts.Log.Info("the agent replacement is in flight",
							"task_id", task.GetTaskId(), "description", result.GetMessage())
						return
					}
					opts.Log.Info("the task finished",
						"task_id", task.GetTaskId(), "status", result.GetStatus(),
						"error_code", result.GetErrorCode(), "replayed", result.GetReplayed())
					if err := send(&agentv1.AgentMessage{
						Payload: &agentv1.AgentMessage_TaskResult{TaskResult: result},
					}); err != nil {
						opts.Log.Error("the result of the task was not sent back",
							"task_id", task.GetTaskId(), "err", err)
					}
				}()

			case *agentv1.ServerMessage_CancelTask:
				// Not every system operation can be interrupted safely - a package
				// transaction must not be cut in half - so the cancellation works
				// where it was declared safe, and beyond that it is recorded.
				interrupted := false
				if opts.Executor != nil && opts.Executor.cancels != nil {
					interrupted = opts.Executor.cancels.Cancel(payload.CancelTask.GetTaskId())
				}
				opts.Log.Info("a cancellation of the task was requested",
					"task_id", payload.CancelTask.GetTaskId(),
					"reason", payload.CancelTask.GetReason(),
					"interrupted", interrupted)
			}
		}
	}()

	// A stable per-host offset spreads the heartbeats of the whole fleet over
	// time.
	heartbeatTimer := time.NewTimer(stableOffset(facts.MachineID, heartbeatInterval))
	defer heartbeatTimer.Stop()
	inventoryTicker := time.NewTicker(opts.InventoryInterval)
	defer inventoryTicker.Stop()

	for {
		select {
		case <-sessionCtx.Done():
			return nil

		case err := <-receiveErr:
			return err

		case <-heartbeatTimer.C:
			health := ReadHealth(currentFacts())
			if err := send(&agentv1.AgentMessage{
				Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{
					SentAt: timestampNow(),
					Health: healthToProto(health),
				}},
			}); err != nil {
				return err
			}
			heartbeatTimer.Reset(nextHeartbeat(heartbeatInterval, jitterWindow))

		case <-inventoryTicker.C:
			inventory.request()
		}
	}
}

// panelAddress returns the local address the host reaches the control plane
// with. The UDP socket sends no packet - the address is chosen by the routing
// table at bind time. This is the answer to the question "which address does
// this host talk to the panel with", and not the first address from the list of
// interfaces, which means nothing.
//
// An address that was not determined stays empty. The panel prefers not to know
// the address over showing the operator an address the host is not at.
func panelAddress(gatewayURL string) string {
	parsed, err := url.Parse(gatewayURL)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	conn, err := net.Dial("udp", net.JoinHostPort(parsed.Hostname(), port))
	if err != nil {
		return ""
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func newHTTP2Client(identity *Identity) *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{identity.Certificate},
				RootCAs:      identity.CAPool,
				MinVersion:   tls.VersionTLS13,
			},
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		},
	}
}

// stableOffset spreads the first heartbeat deterministically by machine-id, so
// the same host always lands in the same place of the window.
func stableOffset(machineID string, window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(machineID))
	slot := binary.BigEndian.Uint64(sum[:8]) % uint64(window)
	return time.Duration(slot)
}

func nextHeartbeat(interval, jitterWindow time.Duration) time.Duration {
	if jitterWindow <= 0 {
		return interval
	}
	return interval + time.Duration(rand.Int64N(int64(jitterWindow)))
}

func withJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return minBackoff
	}
	return base/2 + time.Duration(rand.Int64N(int64(base)))
}

// executeTask runs a task behind a resilience barrier.
//
// A panic while handling one task must not kill the agent: the host would then
// lose its management because of an error in one operation, and the control
// plane would see a broken session instead of information about what went
// wrong. The task ends with a negative result and the agent keeps working.
func executeTask(ctx context.Context, executor *TaskExecutor, task *agentv1.TaskEnvelope,
	log *slog.Logger) (result *agentv1.TaskResult) {
	if executor == nil {
		// An agent without a task executor is not broken - that is, for example,
		// the role of the simulator. A refusal is an answer, not a failure.
		return &agentv1.TaskResult{
			TaskId:    task.GetTaskId(),
			Status:    agentv1.TaskResult_STATUS_REJECTED,
			ExitCode:  -1,
			ErrorCode: RejectUnsupported,
			Message:   "the agent performs no tasks",
		}
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			log.Error("a panic while performing the task",
				"task_id", task.GetTaskId(), "reason", fmt.Sprint(recovered),
				"stack", string(debug.Stack()))
			result = &agentv1.TaskResult{
				TaskId:    task.GetTaskId(),
				Status:    agentv1.TaskResult_STATUS_FAILED,
				ExitCode:  -1,
				ErrorCode: RejectInternalError,
				Message:   "an internal error of the agent while performing the task",
			}
		}
	}()

	result = executor.Execute(ctx, task)
	if result == nil {
		// Silence from the agent is indistinguishable for the control plane from a
		// broken connection, so a missing result is an error here and not a void.
		result = &agentv1.TaskResult{
			TaskId:    task.GetTaskId(),
			Status:    agentv1.TaskResult_STATUS_FAILED,
			ExitCode:  -1,
			ErrorCode: RejectInternalError,
			Message:   "the executor returned no result",
		}
	}
	return result
}

// valueDigest computes the checksum of a fetched secret value.
//
// It serves only to check that the host got what the panel issued. The digest
// is written nowhere: for a short value the digest alone can be a hint.
func valueDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
