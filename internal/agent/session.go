package agent

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	"github.com/google/uuid"
	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/agentconfig"
	"github.com/ultherego/flotestro/internal/buildinfo"
	"github.com/ultherego/flotestro/internal/endpoints"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relayproof"
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
	// StateDir is where the agent keeps what has to survive a restart. The
	// spool of the resource samples the panel has not acknowledged lives
	// under it; empty means the samples are not kept, and a broken session
	// loses them.
	StateDir string

	// gatewayURL is the gateway chosen for this one session. It does not come
	// from the configuration but from the gateway manager, so it is not a public
	// field.
	gatewayURL string
	// material is the certificate and key this one session connected with,
	// taken at the moment the client was built. The envelopes of the
	// session are signed with exactly that key: a renewal that lands during
	// the session replaces the shared identity, and the relay attested the
	// certificate of the handshake, not the new one.
	material tls.Certificate
	// peer records what the server proved itself to be in the handshake -
	// a relay, or the gateway itself - so the envelopes can name the relay
	// they go through.
	peer *peerIdentity
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
		// without restarting the agent. The material is read once here, so
		// the handshake and the envelopes of the session use the same key.
		material := opts.Identity.Certificate
		peer := newPeerIdentity()
		client := agentv1connect.NewAgentServiceClient(
			newObservedHTTP2Client(material, opts.Identity.CAPool, peer),
			gateway.URL,
			// The Connect protocol does not support full duplex, so the
			// bidirectional stream travels over gRPC on top of HTTP/2.
			connect.WithGRPC(),
		)
		start := time.Now()
		session := opts
		session.gatewayURL = gateway.URL
		session.material = material
		session.peer = peer
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
		case errors.Is(err, ErrDecommissioned):
			// The panel ended the host's membership and the identity is
			// gone: there is nothing to reconnect with, and knocking would
			// only fill the audit trail of the panel with refusals.
			return err
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

// hello introduces the agent to the panel: what it is running, what it can
// talk, and what it was configured with.
//
// The build commit says which sources the binary came from, which the
// version alone does not once a package was rebuilt. The protocol range
// lets the panel judge compatibility from what the agent says it speaks
// rather than from a table of releases it may not know yet. The
// configuration fingerprint and schema say what the host runs on: a host
// still on the environment file has no file to fingerprint and reports no
// schema, which is what the panel shows as a legacy configuration.
func hello(facts Facts, revision, localAddress string) *agentv1.Hello {
	message := &agentv1.Hello{
		AgentVersion:      Version,
		BuildCommit:       buildinfo.FullCommit(),
		ProtocolMin:       buildinfo.AgentProtocolMin,
		ProtocolMax:       buildinfo.AgentProtocol,
		BootId:            facts.BootID,
		Capabilities:      capabilitiesToProto(facts.Capabilities),
		InventoryRevision: revision,
		LocalAddress:      localAddress,
		// This agent forwards the panel's capability to the helper; what
		// the helper does with it is the helper's word, or unknown.
		HelperCapabilitySupported: true,
		HelperCapabilityMode:      helperCapabilityMode(context.Background()),
	}
	if loaded, ok := agentconfig.Current(); ok {
		message.ConfigFingerprint = loaded.Fingerprint
		message.ConfigSchemaVersion = uint32(loaded.SchemaVersion)
	}
	return message
}

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

	// The request goes out before Hello, headers alone, so that the
	// handshake happens now and the session learns whom it reached: a
	// relay names itself in its certificate, and the envelope of every
	// message names the relay it goes through. The signer is the session's
	// own; a session without a usable key sends unsigned, which a relayed
	// session pays for at the gateway with its strength, not here.
	if err := stream.Send(nil); err != nil {
		return err
	}
	relayID := ""
	if opts.peer != nil {
		relayID = opts.peer.relayID(sessionCtx, handshakeWait)
	}
	signer := newEnvelopeSigner(opts.material, opts.Identity.HostID, relayID, opts.Log)
	sign := func(msg *agentv1.AgentMessage) error {
		if signer == nil {
			return nil
		}
		return signer.SignMessage(msg)
	}

	greeting := &agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Hello{Hello: hello(facts, revision, localAddress)},
	}
	if err := sign(greeting); err != nil {
		return err
	}
	if err := stream.Send(greeting); err != nil {
		// A server that refused the stream before Hello answers the send
		// with EOF; the refusal itself waits in Receive, and it is the
		// refusal that Run classifies - a revoked identity must not read
		// as a broken link.
		if errors.Is(err, io.EOF) {
			if _, refusal := stream.Receive(); refusal != nil {
				return refusal
			}
		}
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
	// The panel's capability keys go to the helper before any task of this
	// session: a task under a key the helper does not know yet would be
	// refused, and a rotated key must reach the host without a separate
	// distribution.
	deliverHelperTrust(sessionCtx, sessionConfig.GetHelperTrust(), opts.Log)
	heartbeatInterval := time.Duration(sessionConfig.GetHeartbeatSeconds()) * time.Second
	if heartbeatInterval <= 0 {
		heartbeatInterval = 60 * time.Second
	}
	jitterWindow := time.Duration(sessionConfig.GetHeartbeatJitterSeconds()) * time.Second

	opts.Log.Info("the session was established",
		"host_id", opts.Identity.HostID, "heartbeat", heartbeatInterval.String())
	opts.State.Connected(opts.gatewayURL, time.Now())

	// Send is not safe for concurrent calls. The envelope is signed under
	// the same lock: the sequence has to be the order on the wire, and the
	// gateway refuses a number below the last one it accepted.
	var sendMu sync.Mutex
	send := func(msg *agentv1.AgentMessage) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		if err := sign(msg); err != nil {
			return err
		}
		return stream.Send(msg)
	}

	// A report names only the modules that were read in the cycle. The
	// revision is still that of the whole picture - the carried-over modules
	// are part of it - so the panel can tell an unchanged host from a changed
	// one, and does not get a fresh observation date on a module nobody
	// looked at.
	sendInventory := func(f Facts, modules []string) error {
		rev, raw, err := f.Revision()
		if err != nil {
			return err
		}
		report := inventoryToProto(f, rev, raw)
		if len(modules) > 0 {
			restrictReport(report, modules)
		}
		if err := send(&agentv1.AgentMessage{
			Payload: &agentv1.AgentMessage_Inventory{Inventory: report},
		}); err != nil {
			return err
		}
		opts.State.Inventory(rev, time.Now())
		return nil
	}

	if err := sendInventory(facts, nil); err != nil {
		return err
	}

	// The periodic cycle: the fast modules every interval, the normal ones
	// every fourth, the static ones with the full report once a day in the
	// hour derived from the host identifier. The panel may set the interval
	// and the ratio in the session configuration.
	cadence := newCadence(opts.InventoryInterval, opts.Identity.HostID)
	if remote := sessionConfig.GetInventoryCadence(); remote != nil {
		cadence.applyRemote(remote.GetIntervalSeconds(), remote.GetNormalEvery(), remote.FullReportHourUtc)
	}
	// The report that opened the session was a full one.
	cadence.started(time.Now())
	opts.Log.Info("the inventory cadence was set",
		"interval", cadence.Interval.String(), "normal_every", cadence.NormalEvery,
		"full_report_hour_utc", cadence.FullHourUTC)

	// The decommission handshake: which attempts run, and whether the host
	// is leaving. It exists per session, because the final task and the
	// commit travel in it.
	final := newFinalHandshake()
	var wipe finalWiper
	if opts.Executor != nil {
		wipe = helperWiper(opts.Executor.helper)
	}
	// Whichever error ends the stream after the commit - the agent's own or
	// the panel closing the session - the reason the session ended is the
	// decommission, and Run must not reconnect.
	defer func() {
		if final.done.Load() {
			result = ErrDecommissioned
		}
	}()

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
	// The slots are counted separately for every resource class: a long package
	// read must not take the whole pool and stop the operations that last
	// milliseconds.
	slots := newBudget(opts.MaxConcurrentTasks)
	// The resource locks are a second layer next to the budget: the budget says
	// how many tasks the host can carry, and the locks - which of them cannot
	// run side by side.
	resources := newLocks()

	if opts.Executor != nil {
		opts.Executor.facts = currentFacts
		// The executor asks for the resources of the host after the checks
		// that refuse a task without touching it and after telling the
		// panel the task is accepted. The resources first, the budget slot
		// second: a task waiting for a busy resource has no reason to hold
		// a slot that would be useful to an operation without a collision.
		opts.Executor.admit = func(ctx context.Context, task *agentv1.TaskEnvelope,
			claims []opspec.ResourceClaim, waiting func(blocker string)) (func(), string) {
			releaseResources, reason := acquireResources(ctx, resources, task, claims, waiting)
			if releaseResources == nil {
				return nil, reason
			}
			releaseSlot := slots.acquire(ctx, taskClass(task))
			if releaseSlot == nil {
				releaseResources()
				return nil, ""
			}
			if len(claims) > 0 {
				opts.Log.Info("the resources were taken", "task_id", task.GetTaskId(),
					"claims", strings.Join(claimNames(claims), ","))
			}
			return func() {
				releaseSlot()
				releaseResources()
			}, ""
		}
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
			// After the final task the leases are dropped: no secret is
			// fetched for a host that is leaving, whatever the task.
			if final.isLeaving() {
				return nil, errLeasesDropped
			}
			// Through a relay the value comes back sealed to a one-time key
			// of this fetch; directly it comes as it is. The same call
			// serves both: the proof and the key travel with the request,
			// and the panel answers sealed when the relay is in the path.
			return fetchSecret(ctx, client, signer, taskID, name, version)
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
		accept := func(fresh Facts, modules []string) (Refresh, error) {
			previous := ""
			if rev, _, err := currentFacts().Revision(); err == nil {
				previous = rev
			}
			updateFacts(fresh)
			if err := sendInventory(fresh, modules); err != nil {
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

	// The resource sampler is built before the receive loop rather than
	// next to the heartbeat: the panel's acknowledgement of a sample
	// arrives on that loop and frees the copy the sampler keeps on disk,
	// so the two need the same one. Synthetic facts mean a synthetic host,
	// and the counters of the machine running a thousand simulated agents
	// would say nothing about any of them - such a sampler keeps nothing.
	var sampler *Sampler
	if opts.CollectFacts == nil {
		sampler = NewSpooledSampler(opts.StateDir, facts.BootID, opts.Log)
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

			case *agentv1.ServerMessage_MetricsAck:
				// The panel says what became of one resource sample, after
				// the transaction that stored it committed. The copy the
				// agent kept for a resend may go - and it may go on a
				// refusal too: a reading the panel will never take must
				// not hold a place in a bounded spool.
				if sampler != nil {
					sampler.Acknowledge(payload.MetricsAck)
				}

			case *agentv1.ServerMessage_MessageAck:
				// The acknowledgement of a consumed message is between the
				// panel and the relay: it says a record may leave the
				// relay's spool. A relay strips it from the stream, so the
				// agent normally never sees one - and when it does, over a
				// path without a relay or through one from before the
				// spool, it is nothing for the agent to do. Named all the
				// same rather than left to the default: a message the
				// agent does not understand must not cost the host its
				// session.

			case *agentv1.ServerMessage_Task:
				// A task runs next to the receive loop: a unit restart takes time,
				// and the heartbeat and the next tasks must not wait for it.
				task := payload.Task
				go func() {
					// A host that is leaving starts nothing new. The refusal is an
					// answer; the panel cancelled the queue already, so this task
					// was in flight when the final task went out.
					if !final.start(task.GetTaskId()) {
						opts.Log.Info("the task was refused: the host is leaving the fleet",
							"task_id", task.GetTaskId())
						if err := send(&agentv1.AgentMessage{
							Payload: &agentv1.AgentMessage_TaskResult{TaskResult: refuseRetiring(task.GetTaskId())},
						}); err != nil {
							opts.Log.Error("the refusal of the task was not sent back",
								"task_id", task.GetTaskId(), "err", err)
						}
						return
					}
					defer final.finish(task.GetTaskId())

					// A redelivery of an operation this process is still carrying
					// out is answered before the locks: its own first delivery
					// holds them, and a wait would end in a refusal naming the
					// operation as its own blocker. The answer is a progress
					// report; the result follows when the operation ends.
					if opts.Executor != nil && opts.Executor.Redelivered(task) {
						return
					}

					// The locks and the budget slot are taken inside the
					// executor, behind the checks that refuse a task without
					// touching the host and behind the acknowledgement: the
					// panel is to hear "accepted" before the task queues for a
					// busy resource, and "started" once it holds it.
					result := executeTask(sessionCtx, opts.Executor, task, opts.Log)
					// A wait for the resources that ended with the session has
					// nobody left to answer to; the panel's lease runs out and
					// the task comes back to the next session.
					if result.GetErrorCode() == StatusAbandoned {
						return
					}
					// An agent replacement has no result to send back: the process
					// that performed it is being replaced right now, and whether it
					// worked is decided by the return of the host with the new
					// version. Any other answer would be a guess.
					if result.GetErrorCode() == StatusAfterReplacement {
						opts.Log.Info("the agent replacement is in flight",
							"task_id", task.GetTaskId(), "description", result.GetMessage())
						return
					}
					// An acknowledged redelivery has no result of its own: the
					// answer went out as progress, and the result belongs to the
					// execution it waits on.
					if result.GetErrorCode() == StatusInProgress {
						return
					}
					// A restart has no result to send back either: its
					// verifier is the host coming up on another boot, and
					// this process goes down before that can be observed.
					// The panel settles the job from the next Hello.
					if result.GetErrorCode() == StatusAwaitingReturn {
						opts.Log.Info("the restart is in flight",
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
					// The panel may have given up on this attempt while the
					// operation ran and delivered the key again; that attempt is
					// owed the same result, after the original, so that the job
					// is settled from the attempt that did the work.
					if copied := opts.Executor.RedeliveredCopy(result); copied != nil {
						opts.Log.Info("the result is delivered to the redelivered attempt as well",
							"task_id", copied.GetTaskId(), "previous_task_id", task.GetTaskId())
						if err := send(&agentv1.AgentMessage{
							Payload: &agentv1.AgentMessage_TaskResult{TaskResult: copied},
						}); err != nil {
							opts.Log.Error("the result of the task was not sent back",
								"task_id", copied.GetTaskId(), "err", err)
						}
					}
				}()

			case *agentv1.ServerMessage_FinalTask:
				// The first step of the decommission handshake runs next to the
				// receive loop: it waits for the running work, and the commit
				// has to be able to arrive meanwhile.
				go func() {
					if err := answerFinalTask(sessionCtx, payload.FinalTask, final, send, opts.Log); err != nil {
						opts.Log.Error("FinalReady was not sent back", "err", err)
					}
				}()

			case *agentv1.ServerMessage_FinalCommit:
				// The second step ends the session - and the process - when the
				// wipe went through. A refusal of the helper leaves everything as
				// it was, and the loop goes on.
				go func() {
					if err := applyFinalCommit(sessionCtx, payload.FinalCommit, final, wipe, opts.Log); err != nil {
						reportError(err)
					}
				}()

			case *agentv1.ServerMessage_CancelTask:
				// A cancel is answered by what it finds, not carried out
				// blindly: a task that has not started is refused and never
				// starts, a read under way is interrupted where its module
				// allows, a mutation under way runs to its end - a package
				// transaction must not be cut in half - and a task that ended
				// is answered with the digest of its result. The answer goes
				// out first and the interruption follows it, so that the
				// host's own account of the interrupted work reaches the panel
				// after the acknowledgement and never overtakes it.
				cancel := payload.CancelTask
				outcome, phase, resultHash, interrupt := opts.Executor.CancelTask(cancel.GetTaskId())
				if err := send(&agentv1.AgentMessage{
					Payload: &agentv1.AgentMessage_CancelAck{CancelAck: &agentv1.CancelAck{
						TaskId:             cancel.GetTaskId(),
						Outcome:            outcome,
						Phase:              phase,
						ObservedResultHash: resultHash,
					}},
				}); err != nil {
					opts.Log.Error("the cancel acknowledgement was not sent back",
						"task_id", cancel.GetTaskId(), "err", err)
				}
				if interrupt != nil {
					interrupt()
				}
				opts.Log.Info("a cancellation of the task was requested",
					"task_id", cancel.GetTaskId(),
					"reason", cancel.GetReason(),
					"request_revision", cancel.GetRequestRevision(),
					"outcome", outcome.String(), "phase", phase)
			}
		}
	}()

	// A stable per-host offset spreads the heartbeats of the whole fleet over
	// time.
	heartbeatTimer := time.NewTimer(stableOffset(facts.MachineID, heartbeatInterval))
	defer heartbeatTimer.Stop()
	inventoryTimer := time.NewTimer(cadence.next())
	defer inventoryTimer.Stop()

	// The resource sampler runs next to the heartbeat rather than inside it:
	// a sample is a measurement kept for charts and alert rules, the
	// heartbeat a decision signal. Synthetic facts mean a synthetic host,
	// and the counters of the machine running a thousand simulated agents
	// would say nothing about any of them.
	if sampler != nil {
		metricsInterval := time.Duration(sessionConfig.GetMetricsIntervalSeconds()) * time.Second
		go sampler.Run(sessionCtx, metricsInterval, func(sample *agentv1.MetricsSample) error {
			return send(&agentv1.AgentMessage{
				Payload: &agentv1.AgentMessage_MetricsSample{MetricsSample: sample},
			})
		}, opts.Log)
	}

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

		case <-inventoryTimer.C:
			modules, full := cadence.due(time.Now())
			if full {
				inventory.request()
			} else {
				inventory.requestModules(modules)
			}
			inventoryTimer.Reset(cadence.next())
		}
	}
}

// restrictReport narrows a report to the modules of a partial collection.
//
// The basic facts travel always: they were read with the cycle, and the panel
// follows the hostname through them. The accounts go only when their module
// was read - the panel takes an empty account list in a partial report for
// "nothing new", not for "no accounts".
func restrictReport(report *agentv1.InventoryReport, modules []string) {
	report.Full = false
	selected := moduleSet(modules)
	kept := report.Fragments[:0]
	for _, fragment := range report.Fragments {
		if fragment.GetModule() == ModuleSystem || selected[fragment.GetModule()] {
			kept = append(kept, fragment)
		}
	}
	report.Fragments = kept
	if !selected[ModuleAccounts] {
		report.LocalAccounts = nil
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
	return newObservedHTTP2Client(identity.Certificate, identity.CAPool, nil)
}

// newObservedHTTP2Client builds the client of a session and lets the
// observer read the server's identity from the handshake. A nil observer
// is a client that does not care whom it reached.
func newObservedHTTP2Client(material tls.Certificate, trust *x509.CertPool, peer *peerIdentity) *http.Client {
	config := &tls.Config{
		Certificates: []tls.Certificate{material},
		RootCAs:      trust,
		MinVersion:   tls.VersionTLS13,
	}
	if peer != nil {
		config.VerifyConnection = peer.observe
	}
	return &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: config,
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		},
	}
}

// handshakeWait bounds how long a session waits to learn whom it reached
// before it sends Hello. A handshake that takes longer has failed for the
// stream as well, and Hello will say so.
const handshakeWait = 15 * time.Second

// peerIdentity is what the server proved itself to be in the handshake:
// a relay, by the flotestro://relay/<id> identity in its certificate, or
// the gateway of the centre. The chain was verified by the standard path
// before the hook runs; the hook only reads the identity.
type peerIdentity struct {
	mu    sync.Mutex
	kind  string
	id    string
	ready chan struct{}
	once  sync.Once
}

func newPeerIdentity() *peerIdentity { return &peerIdentity{ready: make(chan struct{})} }

// observe is the tls.Config hook.
func (p *peerIdentity) observe(state tls.ConnectionState) error {
	kind, id := "", ""
	if len(state.PeerCertificates) > 0 {
		if k, i, err := pki.IdentityFromCert(state.PeerCertificates[0]); err == nil {
			kind, id = k, i
		}
	}
	p.mu.Lock()
	p.kind, p.id = kind, id
	p.mu.Unlock()
	p.once.Do(func() { close(p.ready) })
	return nil
}

// relayID waits for the handshake and returns the identifier of the relay
// the connection reached, or empty for a direct connection or a handshake
// that did not happen in time. An envelope signed for no relay on a
// relayed session is refused by the gateway, and the next attempt gets
// the identity: that beats guessing.
func (p *peerIdentity) relayID(ctx context.Context, wait time.Duration) string {
	select {
	case <-p.ready:
	case <-ctx.Done():
		return ""
	case <-time.After(wait):
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.kind != "relay" {
		return ""
	}
	return p.id
}

// newEnvelopeSigner prepares the signer of a session from the material it
// connected with. Nil when the material cannot sign - no certificate, a
// key that is not a signer - which the log names once: a relayed session
// then rests on the relay's attestation, and the gateway says so on the
// host. The session is signed on a direct connection as well: the gateway
// ignores the envelope there, and one code path is one code path.
func newEnvelopeSigner(material tls.Certificate, hostID, relayID string, log *slog.Logger) *relayproof.Signer {
	if log == nil {
		log = slog.Default()
	}
	key, ok := material.PrivateKey.(crypto.Signer)
	if !ok || len(material.Certificate) == 0 {
		log.Warn("the session cannot sign its envelopes: the identity carries no signing key")
		return nil
	}
	leaf, err := x509.ParseCertificate(material.Certificate[0])
	if err != nil || leaf.SerialNumber == nil {
		log.Warn("the session cannot sign its envelopes: the certificate does not parse", "err", err)
		return nil
	}
	return relayproof.NewSigner(key, hostID, leaf.SerialNumber.String(), relayID, uuid.NewString())
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
