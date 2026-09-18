package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/jobs"
)

// The timing of the handshake.
const (
	// FinalReadyTimeout is how long the panel waits for the agent to report
	// that it stopped working. After it the host is retired anyway, with the
	// cleanup marked as unconfirmed: a host that does not answer in two
	// minutes is a host the operator has to look at, not one to wait for.
	FinalReadyTimeout = 2 * time.Minute
	// finalGrace is what the agent is told it may spend on the tasks under
	// way. Shorter than the panel's wait, so an agent that honours it always
	// answers in time.
	finalGrace = 90 * time.Second
	// finalLeaveTimeout is how long the panel lets the agent leave on its
	// own after the commit before the session is cut from this side.
	finalLeaveTimeout = 15 * time.Second
	// finalSendTimeout bounds the wait for a slot in the outbound buffer.
	finalSendTimeout = 5 * time.Second
)

// Decommission is the order of the operator to end the trust in a host.
type Decommission struct {
	HostID string
	Reason string
	Actor  string
	// FromStates are the states the host may be in when the order arrives.
	// The handler decides them; the coordinator only carries them out.
	FromStates []string
	// LocalIdentityWipe asks the agent to remove its identity and journal
	// and to disable its service at the commit. Without it the agent only
	// stops.
	LocalIdentityWipe bool
	// RevokeImmediatelyIfOffline revokes the certificates of a host that
	// has no session. Without it the certificates stay valid until the host
	// makes contact, and the gateway revokes them then: the operator who
	// knows the host is on a shelf may prefer to see it knock once.
	RevokeImmediatelyIfOffline bool
	// StepUp is the proof of fresh authentication, kept in the audit detail
	// next to the decision.
	StepUp map[string]any
}

// DecommissionOutcome is what the order ended with.
type DecommissionOutcome struct {
	State string `json:"lifecycle_state"`
	// RemoteCleanupUnconfirmed says the host did not confirm it stopped: it
	// had no session here, or it did not answer the final task in time. The
	// host is retired all the same; what is on its disk is unknown.
	RemoteCleanupUnconfirmed bool `json:"remote_cleanup_unconfirmed"`
	// Phase names how the handshake ended: committed, no_session, timeout.
	Phase string `json:"phase"`
	// RunningTasks are the attempts the agent reported still running when
	// it answered. They were cut short by the commit.
	RunningTasks        []string `json:"running_tasks"`
	LeasesDropped       bool     `json:"leases_dropped"`
	JobsCanceled        int      `json:"jobs_canceled"`
	CertificatesRevoked int      `json:"certificates_revoked"`
	SessionClosed       bool     `json:"session_closed"`
	// HandedOver says the handshake was carried out by the instance that
	// holds the host's session rather than by the one that took the
	// request. CommandID names the order it travelled on and
	// OwnerInstanceID the instance it went to, so the operator reading two
	// panels can follow one decision across them.
	HandedOver      bool   `json:"handed_over"`
	CommandID       string `json:"command_id,omitempty"`
	OwnerInstanceID string `json:"owner_instance_id,omitempty"`
	// HandoverError is what the owner said when it took the order and
	// could not finish it.
	HandoverError string `json:"handover_error,omitempty"`
}

// The phases of the outcome.
const (
	PhaseCommitted = "committed"
	PhaseNoSession = "no_session"
	PhaseTimeout   = "timeout"
	// PhaseHandoverPending: the host is connected to another instance, the
	// order is with that instance, and it had not answered within the
	// wait. The host stands in retiring; the owner finishes the handshake,
	// and a repeated order picks the host up from there.
	PhaseHandoverPending = "handover_pending"
	// PhaseHandoverFailed: the owner took the order and could not finish
	// it. The host stands in retiring and nothing was decided about its
	// disk.
	PhaseHandoverFailed = "handover_failed"
)

// Decommissioner drives the handshake that ends a host's membership in the
// fleet.
//
// Online, the host is told to stop, waits for its running work, reports it
// is ready, has its certificates revoked and is told to wipe itself. Offline,
// or silent for too long, it is retired without the confirmation - and the
// audit says so. Either way the panel ends with the host retired: the loss of
// trust is the panel's decision, and the host's cooperation only settles what
// is left on its disk.
type Decommissioner struct {
	pool     *pgxpool.Pool
	hosts    *hosts.Store
	jobs     *jobs.Store
	audit    *audit.Recorder
	registry *Registry
	log      *slog.Logger
	// commands carries the handshake to the instance that holds the host's
	// session when this one does not. Writing an order and waiting for it
	// needs the database alone, so the queue is opened here rather than
	// wired in: the loop that carries the orders out lives on every
	// instance and is started with the rest of the background work.
	commands *Commands
	// readyTimeout and leaveTimeout are fields so a test does not wait two
	// minutes for an agent that never answers, and handoverWait so it does
	// not wait a minute for an owner that does not exist.
	readyTimeout time.Duration
	leaveTimeout time.Duration
	handoverWait time.Duration
}

func NewDecommissioner(pool *pgxpool.Pool, hostStore *hosts.Store, jobStore *jobs.Store,
	recorder *audit.Recorder, registry *Registry, log *slog.Logger) *Decommissioner {
	return &Decommissioner{
		pool: pool, hosts: hostStore, jobs: jobStore, audit: recorder, registry: registry, log: log,
		commands:     NewCommands(pool, log, CommandOptions{}),
		readyTimeout: FinalReadyTimeout, leaveTimeout: finalLeaveTimeout,
		handoverWait: CommandWaitTimeout,
	}
}

// Run carries the order out and returns how it ended.
//
// The host moves to retiring first, in a transaction with the cancellation
// of its queued jobs and the audit of the decision: from that moment nothing
// new is ordered for it whatever happens to the handshake. A failure after
// that leaves the host in retiring, and a repeated order picks it up from
// there.
//
// The handshake needs the host's session, and in an installation of
// several instances the session may be on another one. The same
// transaction that records the decision then leaves an order for the
// instance that holds it, and this one waits for the answer instead of
// taking a connected host for an offline one. A host with no live owner
// anywhere is retired without the confirmation, as before.
func (d *Decommissioner) Run(ctx context.Context, order Decommission) (DecommissionOutcome, error) {
	// The handshake outlives the request that ordered it: a browser that
	// gave up waiting must not leave the host half-way between retiring and
	// retired. Its own clock bounds it instead.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.readyTimeout+d.leaveTimeout+time.Minute)
	defer cancel()
	outcome := DecommissionOutcome{RunningTasks: []string{}}

	canceled, handed, err := d.beginRetiring(ctx, order)
	if err != nil {
		return outcome, err
	}
	outcome.JobsCanceled = canceled
	if handed.CommandID != "" {
		return d.awaitHandover(ctx, order, outcome, handed)
	}
	return d.carryOut(ctx, order, outcome)
}

// CarryOut runs the part of the order that needs the host's session and
// retires the host. The command loop calls it for an order it claimed: the
// decision is recorded already - the host stands in retiring - and this
// instance is the one holding the session. It never hands the order on,
// because it is where the order was handed to.
func (d *Decommissioner) CarryOut(ctx context.Context, order Decommission) (DecommissionOutcome, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.readyTimeout+d.leaveTimeout+time.Minute)
	defer cancel()
	return d.carryOut(ctx, order, DecommissionOutcome{RunningTasks: []string{}})
}

// carryOut is the handshake itself, on the instance that holds the host.
func (d *Decommissioner) carryOut(ctx context.Context, order Decommission,
	outcome DecommissionOutcome) (DecommissionOutcome, error) {
	session, connected := d.registry.Get(order.HostID)
	if !connected {
		return d.retireOffline(ctx, order, outcome)
	}

	// The final task goes out over the session. A session that does not
	// take the message is a session that is not listening; it is treated
	// as silence rather than as a reason to keep the host in retiring.
	err := session.Send(&agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_FinalTask{FinalTask: &agentv1.FinalTask{
			Reason:            order.Reason,
			LocalIdentityWipe: order.LocalIdentityWipe,
			GraceSeconds:      uint32(finalGrace.Seconds()),
		}},
	}, finalSendTimeout)
	if err != nil {
		d.log.Warn("the final task was not delivered", "host_id", order.HostID, "err", err)
		return d.retireSilent(ctx, order, outcome)
	}
	d.log.Info("the final task was sent", "host_id", order.HostID, "session_id", session.ID)

	timer := time.NewTimer(d.readyTimeout)
	defer timer.Stop()
	var ready *agentv1.FinalReady
	select {
	case ready = <-session.FinalReady():
	case <-session.Finished():
		d.log.Warn("the session ended before the host answered the final task", "host_id", order.HostID)
		return d.retireSilent(ctx, order, outcome)
	case <-timer.C:
		d.log.Warn("the host did not answer the final task in time",
			"host_id", order.HostID, "waited", d.readyTimeout.String())
		return d.retireSilent(ctx, order, outcome)
	case <-ctx.Done():
		return outcome, ctx.Err()
	}
	outcome.RunningTasks = append(outcome.RunningTasks, ready.GetRunningTasks()...)
	outcome.LeasesDropped = ready.GetLeasesDropped()

	// The certificates are revoked before the commit: the agent wipes its
	// identity on the strength of the commit, and a commit sent with a live
	// certificate would leave a moment in which the host could come back.
	revoked, err := d.revokeInOwnTx(ctx, order.HostID, order.Actor, order.Reason)
	if err != nil {
		return outcome, err
	}
	outcome.CertificatesRevoked = revoked

	if err := session.Send(&agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_FinalCommit{FinalCommit: &agentv1.FinalCommit{
			LocalIdentityWipe: order.LocalIdentityWipe, Reason: order.Reason,
		}},
	}, finalSendTimeout); err != nil {
		// The host is ready and revoked; the commit did not get through. It
		// is retired with the cleanup unconfirmed - the agent will find its
		// certificate refused at the next connection, but its disk is as it
		// was.
		d.log.Warn("the final commit was not delivered", "host_id", order.HostID, "err", err)
		outcome.RemoteCleanupUnconfirmed = true
		outcome.Phase = PhaseTimeout
		outcome.SessionClosed = d.registry.EndSession(order.HostID, "host.decommission")
		return d.retire(ctx, order, outcome)
	}

	// The agent leaves on its own after the commit. The session is cut from
	// this side only when it lingers: cutting it at once could take the
	// commit out of the buffer before it was sent.
	leave := time.NewTimer(d.leaveTimeout)
	defer leave.Stop()
	select {
	case <-session.Finished():
	case <-leave.C:
		outcome.SessionClosed = d.registry.EndSession(order.HostID, "host.decommission")
	case <-ctx.Done():
		return outcome, ctx.Err()
	}
	outcome.Phase = PhaseCommitted
	return d.retire(ctx, order, outcome)
}

// handover names the order left for the instance that holds the host's
// session, and that instance. Both are empty when the handshake is this
// instance's to run.
type handover struct {
	CommandID       string
	OwnerInstanceID string
}

// beginRetiring moves the host to retiring, cancels what was queued and -
// when the host's session is held elsewhere - leaves the order for the
// instance that holds it. All in one transaction: a decision that does not
// commit leaves no order behind, and an order that is written is written
// only for a host the panel really put into retiring.
func (d *Decommissioner) beginRetiring(ctx context.Context, order Decommission) (int, handover, error) {
	var handed handover
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return 0, handed, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := d.hosts.ChangeLifecycleState(ctx, tx, order.HostID, order.FromStates,
		hosts.StateRetiring, order.Reason, order.Actor); err != nil {
		return 0, handed, err
	}
	canceled, err := d.jobs.CancelUndelivered(ctx, tx, order.HostID, order.Actor, "host.decommission")
	if err != nil {
		return 0, handed, err
	}
	handed, err = d.planHandover(ctx, tx, order)
	if err != nil {
		return 0, handed, err
	}
	if err := d.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: order.Actor,
		Action: "host.retiring", TargetType: "host", TargetID: order.HostID,
		Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"reason": order.Reason, "state": hosts.StateRetiring, "jobs_canceled": canceled,
			"local_identity_wipe":           order.LocalIdentityWipe,
			"revoke_immediately_if_offline": order.RevokeImmediatelyIfOffline,
			"handed_over":                   handed.CommandID != "",
			"owner_instance_id":             handed.OwnerInstanceID,
		}, order.StepUp),
	}); err != nil {
		return 0, handed, err
	}
	return canceled, handed, tx.Commit(ctx)
}

// planHandover decides whether the handshake belongs to another instance
// and writes the order when it does.
//
// The question is not "is the host connected here" but "who owns its
// session": the registry of this process answers the first, and
// host_session_owners - the one place that sees every instance - answers
// the second. A host with no live owner is a host nobody can talk to, and
// the order is carried out here, offline, as it always was.
func (d *Decommissioner) planHandover(ctx context.Context, tx pgx.Tx,
	order Decommission) (handover, error) {
	var handed handover
	if _, held := d.registry.Get(order.HostID); held {
		return handed, nil
	}
	owner, err := d.jobs.OwnerOf(ctx, order.HostID)
	if err != nil {
		return handed, err
	}
	if !owner.Live(time.Now()) || owner.InstanceID == jobs.InstanceID() {
		return handed, nil
	}
	commandID, err := d.commands.Enqueue(ctx, tx, Command{
		HostID: order.HostID, SessionID: owner.SessionID, FencingToken: owner.Token,
		Kind: CommandDecommissionFinal, CreatedBy: order.Actor,
		Payload: mustPayload(map[string]any{
			"reason": order.Reason, "actor": order.Actor,
			"local_identity_wipe":           order.LocalIdentityWipe,
			"revoke_immediately_if_offline": order.RevokeImmediatelyIfOffline,
			"step_up":                       order.StepUp,
		}),
	})
	if err != nil {
		return handed, err
	}
	d.log.Info("the decommission handshake was handed to the instance holding the host",
		"host_id", order.HostID, "command_id", commandID,
		"owner_instance_id", owner.InstanceID, "session_id", owner.SessionID)
	return handover{CommandID: commandID, OwnerInstanceID: owner.InstanceID}, nil
}

// awaitHandover waits for the instance that holds the host to carry the
// handshake out, and answers with what it reported.
//
// An order nobody claimed - the owner died between the decision and the
// claim, the host left it - ends as the panel has always ended a
// decommission of a host it cannot reach: retired, with the cleanup
// unconfirmed. An order claimed and not yet answered is neither: the host
// stands in retiring, the owner is finishing it, and saying anything else
// would mean two instances deciding the same host's end at once.
func (d *Decommissioner) awaitHandover(ctx context.Context, order Decommission,
	outcome DecommissionOutcome, handed handover) (DecommissionOutcome, error) {
	outcome.HandedOver = true
	outcome.CommandID = handed.CommandID
	outcome.OwnerInstanceID = handed.OwnerInstanceID
	outcome.State = hosts.StateRetiring

	result, err := d.commands.Await(ctx, handed.CommandID, d.handoverWait)
	if err != nil {
		return outcome, err
	}
	switch result.Outcome {
	case CommandDone:
		remote := DecommissionOutcome{RunningTasks: []string{}}
		if err := json.Unmarshal(result.Detail, &remote); err != nil {
			outcome.Phase = PhaseHandoverFailed
			outcome.HandoverError = "the owner's answer does not read: " + err.Error()
			return outcome, nil
		}
		remote.HandedOver = true
		remote.CommandID, remote.OwnerInstanceID = handed.CommandID, handed.OwnerInstanceID
		// The jobs were cancelled here, in the transaction of the decision;
		// the owner only ran the handshake and counts none.
		remote.JobsCanceled = outcome.JobsCanceled
		if remote.RunningTasks == nil {
			remote.RunningTasks = []string{}
		}
		d.log.Info("the instance holding the host carried the decommission out",
			"host_id", order.HostID, "command_id", handed.CommandID,
			"phase", remote.Phase, "state", remote.State)
		return remote, nil
	case CommandNoSession, CommandExpired:
		// Nothing was done to the host: the session was gone before the
		// owner acted, or no owner ever claimed the order.
		d.log.Warn("the order of the decommission was not carried out by the owner of the session; retiring the host without the confirmation",
			"host_id", order.HostID, "command_id", handed.CommandID, "outcome", result.Outcome)
		return d.retireOffline(ctx, order, outcome)
	case CommandFailed:
		outcome.Phase = PhaseHandoverFailed
		outcome.HandoverError = handoverErrorOf(result.Detail)
		return outcome, nil
	default:
		outcome.Phase = PhaseHandoverPending
		d.log.Warn("the instance holding the host has not answered the decommission order within the wait",
			"host_id", order.HostID, "command_id", handed.CommandID,
			"owner_instance_id", handed.OwnerInstanceID, "waited", d.handoverWait.String())
		return outcome, nil
	}
}

// handoverErrorOf reads the owner's reason out of the outcome it wrote.
func handoverErrorOf(detail []byte) string {
	var answer struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(detail, &answer); err != nil || answer.Error == "" {
		return "the instance holding the host could not finish the handshake"
	}
	return answer.Error
}

// retireOffline ends the order for a host with no session on this gateway.
func (d *Decommissioner) retireOffline(ctx context.Context, order Decommission,
	outcome DecommissionOutcome) (DecommissionOutcome, error) {
	outcome.RemoteCleanupUnconfirmed = true
	outcome.Phase = PhaseNoSession
	if order.RevokeImmediatelyIfOffline {
		revoked, err := d.revokeInOwnTx(ctx, order.HostID, order.Actor, order.Reason)
		if err != nil {
			return outcome, err
		}
		outcome.CertificatesRevoked = revoked
	}
	return d.retire(ctx, order, outcome)
}

// retireSilent ends the order for a host that had a session but did not
// answer. The certificates are always revoked here: the host is alive and
// did not cooperate, and that is the case the revocation exists for.
func (d *Decommissioner) retireSilent(ctx context.Context, order Decommission,
	outcome DecommissionOutcome) (DecommissionOutcome, error) {
	outcome.RemoteCleanupUnconfirmed = true
	outcome.Phase = PhaseTimeout
	revoked, err := d.revokeInOwnTx(ctx, order.HostID, order.Actor, order.Reason)
	if err != nil {
		return outcome, err
	}
	outcome.CertificatesRevoked = revoked
	// A session that ended by itself meanwhile is not closed twice; the
	// answer says whether the panel cut one.
	outcome.SessionClosed = d.registry.EndSession(order.HostID, "host.decommission")
	return d.retire(ctx, order, outcome)
}

// retire writes the final state and the audit of the whole order.
func (d *Decommissioner) retire(ctx context.Context, order Decommission,
	outcome DecommissionOutcome) (DecommissionOutcome, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return outcome, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := d.hosts.ChangeLifecycleState(ctx, tx, order.HostID, []string{hosts.StateRetiring},
		hosts.StateRetired, order.Reason, order.Actor); err != nil {
		return outcome, fmt.Errorf("retiring the host: %w", err)
	}
	outcome.State = hosts.StateRetired
	if err := d.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: order.Actor,
		Action: "host.decommission", TargetType: "host", TargetID: order.HostID,
		Outcome: audit.OutcomeSuccess,
		Detail: withStepUp(map[string]any{
			"reason": order.Reason, "state": hosts.StateRetired,
			"phase":                      outcome.Phase,
			"remote_cleanup_unconfirmed": outcome.RemoteCleanupUnconfirmed,
			"running_tasks":              outcome.RunningTasks,
			"leases_dropped":             outcome.LeasesDropped,
			"certificates_revoked":       outcome.CertificatesRevoked,
			"jobs_canceled":              outcome.JobsCanceled,
			"session_closed":             outcome.SessionClosed,
			"local_identity_wipe":        order.LocalIdentityWipe,
		}, order.StepUp),
	}); err != nil {
		return outcome, err
	}
	if err := tx.Commit(ctx); err != nil {
		return outcome, err
	}
	d.log.Info("the host was retired", "host_id", order.HostID, "phase", outcome.Phase,
		"remote_cleanup_unconfirmed", outcome.RemoteCleanupUnconfirmed,
		"certificates_revoked", outcome.CertificatesRevoked)
	return outcome, nil
}

// revokeInOwnTx revokes the live certificates of the host in a transaction
// of its own, with its audit entry.
func (d *Decommissioner) revokeInOwnTx(ctx context.Context, hostID, actor, reason string) (int, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	revoked, err := d.hosts.RevokeCertificates(ctx, tx, hostID, reason)
	if err != nil {
		return 0, err
	}
	if revoked > 0 {
		if err := d.audit.RecordTx(ctx, tx, audit.Event{
			ActorType: audit.ActorUser, ActorID: actor,
			Action: "host.certificate.revoke", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeSuccess,
			Detail:  map[string]any{"reason": reason, "certificates_revoked": revoked},
		}); err != nil {
			return 0, err
		}
	}
	return revoked, tx.Commit(ctx)
}

// withStepUp merges the proof of fresh authentication into the audit detail,
// the same way the panel does for every other decision of this weight.
func withStepUp(detail, evidence map[string]any) map[string]any {
	for key, value := range evidence {
		detail[key] = value
	}
	return detail
}

// IsForbiddenTransition says whether the order failed because the host was
// not in a state it could be carried out from.
func IsForbiddenTransition(err error) bool {
	return errors.Is(err, hosts.ErrForbiddenTransition)
}
