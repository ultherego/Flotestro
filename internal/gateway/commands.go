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
	"github.com/ultherego/flotestro/internal/events"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/outbox"
)

// The orders that travel between the instances of the control plane.

// The kinds of command an instance may be asked to carry out.
const (
	// CommandDecommissionFinal asks for the final task, the wait for the host's
	// readiness, the revocation and the commit - the part of the decommission
	// that needs the session.
	CommandDecommissionFinal = "decommission_final"
	// CommandSessionClose asks for the host's session to be ended.
	CommandSessionClose = "session_close"
)

// KnownCommandKind says whether the word is a kind this release carries out.
func KnownCommandKind(kind string) bool {
	switch kind {
	case CommandDecommissionFinal, CommandSessionClose:
		return true
	default:
		return false
	}
}

// The outcomes a command ends with.
const (
	// CommandDone: the instance holding the session carried the order out.
	// What it did is in the detail.
	CommandDone = "done"
	// CommandFailed: the owner took the order and could not finish it. The
	// decision stands recorded and the operator repeats the order.
	CommandFailed = "failed"
	// CommandNoSession: the owner claimed the order and found the session
	// gone before it acted. Nothing was done to the host.
	CommandNoSession = "no_session"
	// CommandExpired: nobody claimed the order in time - the instance that
	// held the host died, or the host left it. Nothing was done to the host.
	CommandExpired = "expired"
)

// EventCommandEnqueued is the type of the trail event a written command
// leaves.
const EventCommandEnqueued = "gateway.command_enqueued"

// The timing of the queue.
const (
	// DefaultCommandPoll is the tick of the loop: how long an order waits
	// at most when the trail's notification did not reach its owner.
	DefaultCommandPoll = 5 * time.Second
	// DefaultCommandExpiry is how long an unclaimed order stands.
	DefaultCommandExpiry = 5 * time.Minute
	// CommandWaitTimeout bounds the wait of the request that gave the order.
	CommandWaitTimeout = 10 * time.Second
	// sessionCloseWait is the shorter wait of a session close: ending a session
	// is one call on the owner, with nothing to wait for on the host.
	sessionCloseWait = 20 * time.Second
	// awaitPoll is how often the waiting request reads the row.
	awaitPoll = 250 * time.Millisecond
	// commandBatch bounds one round of the loop.
	commandBatch = 16
)

// ErrUnknownCommandKind refuses an order this release would not carry out.
var ErrUnknownCommandKind = errors.New("the command names a kind this panel does not carry out")

// Command is one order for the instance that holds a host's session.
type Command struct {
	ID     string
	HostID string
	// SessionID and FencingToken are the address: the session the order is
	// for and the token of the claim that session holds on the host.
	SessionID    string
	FencingToken uint64
	Kind         string
	// Payload is what the kind needs: the reason and the decisions of a
	// decommission, the reason of a session close.
	Payload   json.RawMessage
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CommandResult is what became of a command.
type CommandResult struct {
	Outcome string
	Detail  json.RawMessage
	DoneAt  time.Time
}

// Settled says whether the command has ended, whichever way.
func (r CommandResult) Settled() bool { return r.Outcome != "" }

// CommandOptions are what an instance needs to carry commands out.
type CommandOptions struct {
	// Registry is the sessions this instance holds. Without it the loop
	// carries nothing out.
	Registry *Registry
	// Decommissioner drives the handshake of a decommission_final.
	Decommissioner *Decommissioner
	Audit          *audit.Recorder
	Events         *events.Bus
	Poll           time.Duration
	Expiry         time.Duration
}

// Commands is the queue of the orders between instances: the writing of a
// command, the wait for its outcome, and the loop that carries out the
// commands addressed to the sessions of this instance.
type Commands struct {
	pool    *pgxpool.Pool
	log     *slog.Logger
	options CommandOptions
}

// NewCommands opens the queue on the given database.
func NewCommands(pool *pgxpool.Pool, log *slog.Logger, options CommandOptions) *Commands {
	if log == nil {
		log = slog.Default()
	}
	if options.Poll <= 0 {
		options.Poll = DefaultCommandPoll
	}
	if options.Expiry <= 0 {
		options.Expiry = DefaultCommandExpiry
	}
	return &Commands{pool: pool, log: log, options: options}
}

// Enqueue writes a command in the caller's transaction and returns its
// identifier.
func (c *Commands) Enqueue(ctx context.Context, tx pgx.Tx, command Command) (string, error) {
	if command.ExpiresAt.IsZero() {
		command.ExpiresAt = time.Now().Add(c.options.Expiry)
	}
	return enqueueCommand(ctx, tx, command)
}

// enqueueCommand writes the row and the trail event.
func enqueueCommand(ctx context.Context, tx pgx.Tx, command Command) (string, error) {
	if command.HostID == "" || command.SessionID == "" || command.FencingToken == 0 {
		return "", errors.New("a command names the host, the session it is for and that session's token")
	}
	if !KnownCommandKind(command.Kind) {
		return "", fmt.Errorf("%w: %s", ErrUnknownCommandKind, command.Kind)
	}
	if command.ExpiresAt.IsZero() {
		command.ExpiresAt = time.Now().Add(DefaultCommandExpiry)
	}
	payload := command.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	var id string
	if err := tx.QueryRow(ctx, `
		insert into gateway_commands
			(host_id, session_id, fencing_token, kind, payload, created_by, expires_at)
		values ($1::uuid, $2::uuid, $3, $4, $5::jsonb, $6, $7)
		returning id::text`,
		command.HostID, command.SessionID, int64(command.FencingToken), command.Kind,
		string(payload), command.CreatedBy, command.ExpiresAt).Scan(&id); err != nil {
		return "", fmt.Errorf("writing the %s command: %w", command.Kind, err)
	}
	if err := outbox.Record(ctx, tx, "host", command.HostID, EventCommandEnqueued, map[string]any{
		"command_id": id, "kind": command.Kind, "session_id": command.SessionID,
		"fencing_token": command.FencingToken, "created_by": command.CreatedBy,
		"expires_at_unix": command.ExpiresAt.Unix(),
	}); err != nil {
		return "", err
	}
	return id, nil
}

// Await waits for the outcome of a command, or for the wait to run out.
func (c *Commands) Await(ctx context.Context, id string, wait time.Duration) (CommandResult, error) {
	deadline := time.Now().Add(wait)
	ticker := time.NewTicker(awaitPoll)
	defer ticker.Stop()
	for {
		result, err := c.Result(ctx, id)
		if err != nil || result.Settled() {
			return result, err
		}
		if !time.Now().Before(deadline) {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-ticker.C:
		}
	}
}

// Result reads what became of a command.
func (c *Commands) Result(ctx context.Context, id string) (CommandResult, error) {
	var result CommandResult
	var outcome *string
	var detail []byte
	var doneAt *time.Time
	err := c.pool.QueryRow(ctx, `
		select outcome, outcome_detail, done_at from gateway_commands where id = $1::uuid`,
		id).Scan(&outcome, &detail, &doneAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, fmt.Errorf("the command %s is not on record", id)
	}
	if err != nil {
		return result, err
	}
	if outcome != nil {
		result.Outcome = *outcome
	}
	result.Detail = detail
	if doneAt != nil {
		result.DoneAt = *doneAt
	}
	return result, nil
}

// RunCommandLoop carries out the commands addressed to the sessions this
// instance holds, until the context ends. One goroutine per instance.
func (c *Commands) RunCommandLoop(ctx context.Context) {
	ticker := time.NewTicker(c.options.Poll)
	defer ticker.Stop()

	// The trail's notification wakes the loop the moment an order is
	// written; without the bus the tick alone carries the orders.
	var wakes <-chan events.Event
	if c.options.Events != nil {
		var unsubscribe func()
		wakes, unsubscribe = c.options.Events.Subscribe(func(event events.Event) bool {
			return event.Outbox != nil && event.Outbox.Type == EventCommandEnqueued
		})
		defer unsubscribe()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.expire(ctx)
			c.round(ctx)
		case <-wakes:
			c.round(ctx)
		}
	}
}

// round claims the orders of this instance's hosts and carries them out.
func (c *Commands) round(ctx context.Context) {
	if c.options.Registry == nil {
		return
	}
	claimed, err := c.claim(ctx, jobs.InstanceID(), commandBatch)
	if err != nil {
		c.log.Error("the commands of this instance were not read", "err", err)
		return
	}
	for _, command := range claimed {
		// Each order on its own goroutine: a decommission handshake waits up to two
		// minutes for the host, and the session close of a quarantine behind it in
		// the queue must not wait for that.
		go c.carry(ctx, command)
	}
}

// claim takes the open commands whose host this instance owns under the very
// session and token the command names.
func (c *Commands) claim(ctx context.Context, instanceID string, limit int) ([]Command, error) {
	rows, err := c.pool.Query(ctx, `
		with claimable as (
			select k.id
			  from gateway_commands k
			  join host_session_owners o on o.host_id = k.host_id
			 where k.claimed_at is null and k.done_at is null
			   and k.expires_at > now()
			   and o.owner_instance_id = $1::uuid
			   and o.session_id = k.session_id
			   and o.fencing_token = k.fencing_token
			   and o.lease_until > now()
			 order by k.created_at
			 limit $2
			 for update of k skip locked)
		update gateway_commands k
		   set claimed_at = now(), claimed_by = $1::uuid
		  from claimable c
		 where k.id = c.id
		returning k.id::text, k.host_id::text, k.session_id::text, k.fencing_token,
		          k.kind, k.payload, k.created_by, k.created_at, k.expires_at`,
		instanceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var claimed []Command
	for rows.Next() {
		var command Command
		var token int64
		var payload []byte
		if err := rows.Scan(&command.ID, &command.HostID, &command.SessionID, &token,
			&command.Kind, &payload, &command.CreatedBy,
			&command.CreatedAt, &command.ExpiresAt); err != nil {
			return nil, err
		}
		command.FencingToken = uint64(token)
		command.Payload = payload
		claimed = append(claimed, command)
	}
	return claimed, rows.Err()
}

// carry runs one claimed command and writes back what it ended with.
func (c *Commands) carry(ctx context.Context, command Command) {
	session, held := c.options.Registry.Get(command.HostID)
	if ok, reason := command.carriedBy(session, held, time.Now()); !ok {
		// The claim matched the ownership row and the registry does not: the session
		// ended between the two reads.
		c.settle(ctx, command, CommandNoSession, map[string]any{"reason": reason})
		return
	}
	outcome, detail := c.run(ctx, command, session)
	c.settle(ctx, command, outcome, detail)
}

// run carries one command out through the same local path the instance
// would take had the request landed on it.
func (c *Commands) run(ctx context.Context, command Command, session *Session) (string, map[string]any) {
	switch command.Kind {
	case CommandSessionClose:
		var payload struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(command.Payload, &payload)
		if payload.Reason == "" {
			payload.Reason = "lifecycle"
		}
		// The session named by the order, not whatever the registry holds now: the
		// two were compared a moment ago, and ending the one in hand cannot end a
		// session that replaced it meanwhile.
		session.End(payload.Reason)
		return CommandDone, map[string]any{"session_closed": true, "reason": payload.Reason}
	case CommandDecommissionFinal:
		if c.options.Decommissioner == nil {
			return CommandFailed, map[string]any{
				"error": "this instance does not drive the decommission handshake",
			}
		}
		var payload decommissionCommand
		if err := json.Unmarshal(command.Payload, &payload); err != nil {
			return CommandFailed, map[string]any{"error": "the order does not read: " + err.Error()}
		}
		outcome, err := c.options.Decommissioner.CarryOut(ctx, Decommission{
			HostID: command.HostID, Reason: payload.Reason, Actor: payload.Actor,
			LocalIdentityWipe:          payload.LocalIdentityWipe,
			RevokeImmediatelyIfOffline: payload.RevokeImmediatelyIfOffline,
			StepUp:                     payload.StepUp,
		})
		if err != nil {
			return CommandFailed, map[string]any{"error": err.Error(), "phase": outcome.Phase}
		}
		return CommandDone, map[string]any{
			"lifecycle_state":            outcome.State,
			"phase":                      outcome.Phase,
			"remote_cleanup_unconfirmed": outcome.RemoteCleanupUnconfirmed,
			"running_tasks":              outcome.RunningTasks,
			"leases_dropped":             outcome.LeasesDropped,
			"certificates_revoked":       outcome.CertificatesRevoked,
			"session_closed":             outcome.SessionClosed,
		}
	default:
		// Unreachable through Enqueue, which refuses an unknown kind; a row
		// written by hand ends here rather than in a guess.
		return CommandFailed, map[string]any{"error": "unknown command kind: " + command.Kind}
	}
}

// decommissionCommand is what a decommission_final carries.
type decommissionCommand struct {
	Reason                     string         `json:"reason"`
	Actor                      string         `json:"actor"`
	LocalIdentityWipe          bool           `json:"local_identity_wipe"`
	RevokeImmediatelyIfOffline bool           `json:"revoke_immediately_if_offline"`
	StepUp                     map[string]any `json:"step_up,omitempty"`
}

// carriedBy says whether a claimed command may be carried out on the session
// this instance holds for its host, and names the reason when it may not.
func (c Command) carriedBy(session *Session, held bool, now time.Time) (bool, string) {
	switch {
	case !now.Before(c.ExpiresAt):
		return false, "the order expired before it was carried out"
	case !held || session == nil:
		return false, "the host has no session on this instance"
	case session.ID != c.SessionID:
		return false, "this instance holds another session of the host"
	case session.FenceToken != c.FencingToken:
		return false, "the session of the host holds a newer fencing token"
	default:
		return true, ""
	}
}

// settle writes the outcome of a command and puts it on the trail.
func (c *Commands) settle(ctx context.Context, command Command, outcome string, detail map[string]any) {
	body, err := json.Marshal(detail)
	if err != nil {
		body = []byte(`{}`)
	}
	if _, err := c.pool.Exec(ctx, `
		update gateway_commands
		   set done_at = now(), outcome = $2, outcome_detail = $3::jsonb
		 where id = $1::uuid and done_at is null`,
		command.ID, outcome, string(body)); err != nil {
		c.log.Error("the outcome of a command was not written",
			"command_id", command.ID, "kind", command.Kind, "err", err)
		return
	}
	if c.options.Audit != nil {
		result := audit.OutcomeSuccess
		if outcome != CommandDone {
			result = audit.OutcomeFailure
		}
		c.options.Audit.Record(ctx, audit.Event{
			ActorType: audit.ActorSystem, ActorID: "instance:" + jobs.InstanceID(),
			Action: "host.command", TargetType: "host", TargetID: command.HostID,
			Outcome: result,
			Detail: map[string]any{
				"command_id": command.ID, "kind": command.Kind, "outcome": outcome,
				"requested_by": command.CreatedBy, "session_id": command.SessionID,
				"detail": detail,
			},
		})
	}
	c.log.Info("a lifecycle order from another instance was settled",
		"command_id", command.ID, "kind", command.Kind, "host_id", command.HostID,
		"outcome", outcome)
}

// expire ends the orders that ran out of time.
func (c *Commands) expire(ctx context.Context) {
	unclaimed, err := c.pool.Exec(ctx, `
		update gateway_commands
		   set done_at = now(), outcome = $1,
		       outcome_detail = jsonb_build_object('reason',
		           'no live owner of the host claimed the order before it expired')
		 where done_at is null and claimed_at is null and expires_at <= now()`, CommandExpired)
	if err != nil {
		c.log.Error("the expired commands were not settled", "err", err)
		return
	}
	if unclaimed.RowsAffected() > 0 {
		c.log.Warn("lifecycle orders expired without an owner to carry them out",
			"commands", unclaimed.RowsAffected())
	}
	abandoned, err := c.pool.Exec(ctx, `
		update gateway_commands
		   set done_at = now(), outcome = $1,
		       outcome_detail = jsonb_build_object('error',
		           'the instance that took the order did not finish it')
		 where done_at is null and claimed_at is not null and expires_at <= now()`, CommandFailed)
	if err != nil {
		c.log.Error("the abandoned commands were not settled", "err", err)
		return
	}
	if abandoned.RowsAffected() > 0 {
		c.log.Warn("lifecycle orders were taken up and never finished",
			"commands", abandoned.RowsAffected())
	}
}

// SessionClose says where a host's session was ended.
type SessionClose struct {
	// Where is local for a session this instance held, remote for one ended by
	// the instance that held it, none for a host with no live session anywhere,
	// and unconfirmed when the owner was asked and has not answered within the
	Where string `json:"session_close"`
	// Closed says whether a session was really ended. False under none, and false
	// under unconfirmed: the panel does not claim what it has not been told.
	Closed          bool   `json:"session_closed"`
	CommandID       string `json:"command_id,omitempty"`
	OwnerInstanceID string `json:"owner_instance_id,omitempty"`
}

// The values of SessionClose.Where.
const (
	SessionCloseLocal       = "local"
	SessionCloseRemote      = "remote"
	SessionCloseNone        = "none"
	SessionCloseUnconfirmed = "unconfirmed"
)

// PlanSessionClose decides, inside the caller's transaction, how a host's
// session is to be ended, and writes the order when it belongs to another
// instance.
func PlanSessionClose(ctx context.Context, tx pgx.Tx, registry *Registry, owners *jobs.Store,
	hostID, reason, actor string) (SessionClose, error) {
	if registry == nil {
		return SessionClose{Where: SessionCloseNone}, nil
	}
	if _, held := registry.Get(hostID); held {
		return SessionClose{Where: SessionCloseLocal}, nil
	}
	if owners == nil {
		return SessionClose{Where: SessionCloseNone}, nil
	}
	owner, err := owners.OwnerOf(ctx, hostID)
	if err != nil {
		return SessionClose{}, err
	}
	if !owner.Live(time.Now()) || owner.InstanceID == jobs.InstanceID() {
		// Nobody holds the host: an unheld host is refused at its next connection by
		// the state the decision wrote, which is what the panel has always relied on
		// here.
		return SessionClose{Where: SessionCloseNone}, nil
	}
	commandID, err := enqueueCommand(ctx, tx, Command{
		HostID: hostID, SessionID: owner.SessionID, FencingToken: owner.Token,
		Kind: CommandSessionClose, CreatedBy: actor,
		Payload: mustPayload(map[string]any{"reason": reason, "actor": actor}),
	})
	if err != nil {
		return SessionClose{}, err
	}
	return SessionClose{Where: SessionCloseRemote, CommandID: commandID,
		OwnerInstanceID: owner.InstanceID}, nil
}

// FinishSessionClose carries the plan out once the decision has committed.
func FinishSessionClose(ctx context.Context, pool *pgxpool.Pool, registry *Registry,
	log *slog.Logger, plan SessionClose, hostID, reason string) SessionClose {
	switch plan.Where {
	case SessionCloseLocal:
		plan.Closed = registry.EndSession(hostID, reason)
		if !plan.Closed {
			// The session ended by itself between the plan and here.
			plan.Where = SessionCloseNone
		}
		return plan
	case SessionCloseRemote:
		commands := NewCommands(pool, log, CommandOptions{})
		result, err := commands.Await(ctx, plan.CommandID, sessionCloseWait)
		if err != nil {
			plan.Where = SessionCloseUnconfirmed
			return plan
		}
		switch result.Outcome {
		case CommandDone:
			var detail struct {
				SessionClosed bool `json:"session_closed"`
			}
			_ = json.Unmarshal(result.Detail, &detail)
			plan.Closed = detail.SessionClosed
			if !plan.Closed {
				plan.Where = SessionCloseNone
			}
		case CommandNoSession, CommandExpired:
			plan.Where = SessionCloseNone
		case "":
			plan.Where = SessionCloseUnconfirmed
		default:
			plan.Where = SessionCloseUnconfirmed
		}
		return plan
	default:
		return plan
	}
}

// CloseHostSession ends the session of a host wherever the installation holds
// it, in a transaction of its own.
func CloseHostSession(ctx context.Context, pool *pgxpool.Pool, registry *Registry,
	owners *jobs.Store, log *slog.Logger, hostID, reason, actor string) (SessionClose, error) {
	if registry == nil {
		return SessionClose{Where: SessionCloseNone}, nil
	}
	if _, held := registry.Get(hostID); held {
		return FinishSessionClose(ctx, pool, registry, log,
			SessionClose{Where: SessionCloseLocal}, hostID, reason), nil
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return SessionClose{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	plan, err := PlanSessionClose(ctx, tx, registry, owners, hostID, reason, actor)
	if err != nil {
		return SessionClose{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SessionClose{}, err
	}
	return FinishSessionClose(ctx, pool, registry, log, plan, hostID, reason), nil
}

// mustPayload encodes what a command carries.
func mustPayload(value map[string]any) json.RawMessage {
	body, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage("{}")
	}
	return body
}
