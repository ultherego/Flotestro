// Package scheduler takes approved tasks from the queue and delivers them to
// the agents. It takes no business decisions beyond the execution limits.
package scheduler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/buildinfo"
	"github.com/ultherego/flotestro/internal/gateway"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/secrets"
)

// EnrollmentCredentials issues the single-use credential for joining a host
// to a domain. The credential comes into being at send time and is not stored
// in the database together with the task.
type EnrollmentCredentials interface {
	EnsureHostWithOTP(ctx context.Context, fqdn string) (string, error)
}

// Options configures the scheduler's loop.
type Options struct {
	GatewayID string
	// Interval is the basic gap between passes. A periodic scan guarantees
	// progress even when a notification is lost.
	Interval time.Duration
	// LeaseDuration has to be longer than the longest operation, otherwise
	// the lease expires during a correct execution.
	LeaseDuration time.Duration
	// BatchSize bounds the number of tasks taken in one pass.
	BatchSize int
	// SendTimeout bounds the wait for a session to accept a task.
	SendTimeout time.Duration
	// DispatchRate paces the envelopes leaving this gateway, in envelopes
	// per second, with a burst of one second's worth. Zero is no pacing:
	// every leased job goes out at once, which is what a test fleet wants
	// and a fleet of thousands coming back after an outage does not.
	DispatchRate float64
}

// SecretLeases issues short leases for the secrets named in a task.
//
// An interface instead of a concrete store: the scheduler is to issue the
// right to fetch rather than know how the secrets are kept.
type SecretLeases interface {
	Issue(ctx context.Context, name string, version int,
		jobID, hostID string, window time.Duration) (*secrets.Lease, error)
}

// Scheduler joins the task queue with the active agent sessions.
type Scheduler struct {
	store       *jobs.Store
	registry    *gateway.Registry
	audit       *audit.Recorder
	credentials EnrollmentCredentials
	secrets     SecretLeases
	admission   admission
	// bucket paces the dispatch; nil is no pacing.
	bucket  *Bucket
	log     *slog.Logger
	options Options
}

// SetSecrets attaches the secret store. Without it a task naming a secret
// will not be delivered: the host would get a reference it has no way of
// following, and the operation would fail only on the host.
func (s *Scheduler) SetSecrets(leases SecretLeases) { s.secrets = leases }

// SetBudgets replaces the capacity budgets the scheduler asks before it
// takes a task. The scheduler builds its own over the task store's
// database, so this is for an installation that keeps them elsewhere and
// for checking the decision without a database. A store that also knows
// the topology of the hosts places them in their failure domains.
func (s *Scheduler) SetBudgets(store Budgets) {
	s.admission.budgets = store
	s.admission.topology, _ = store.(Topology)
}

func New(store *jobs.Store, registry *gateway.Registry, recorder *audit.Recorder,
	credentials EnrollmentCredentials, log *slog.Logger, options Options) *Scheduler {
	if options.Interval <= 0 {
		options.Interval = 2 * time.Second
	}
	if options.LeaseDuration <= 0 {
		options.LeaseDuration = 5 * time.Minute
	}
	if options.BatchSize <= 0 {
		options.BatchSize = 32
	}
	if options.SendTimeout <= 0 {
		options.SendTimeout = 5 * time.Second
	}
	scheduler := &Scheduler{store: store, registry: registry, audit: recorder,
		credentials: credentials, log: log, options: options}
	scheduler.admission = admission{waits: store, log: log, gateway: options.GatewayID}
	// The budgets live in the database, not in the process: a second store
	// over the same tables sees the same grants as the orchestrator's, so
	// a task and a campaign target compete for the same tokens.
	if store != nil && store.Pool() != nil {
		scheduler.SetBudgets(budgets.NewStore(store.Pool(), log))
	}
	// The burst is one second of the rate: a pass after a quiet moment
	// sends what a second would have, no more, whatever the batch size.
	scheduler.bucket = NewBucket(options.DispatchRate, int(math.Ceil(options.DispatchRate)), nil)
	return scheduler
}

// Run keeps the delivery loop going until the context is closed.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.options.Interval)
	defer ticker.Stop()

	housekeeping := time.NewTicker(30 * time.Second)
	defer housekeeping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-housekeeping.C:
			s.housekeep(ctx)
		case <-ticker.C:
			s.dispatchOnce(ctx)
		}
	}
}

// housekeep returns tasks with an expired lease to the queue and ends tasks
// that passed their TTL. Without it a task lost together with a gateway would
// stay forever.
func (s *Scheduler) housekeep(ctx context.Context) {
	if count, err := s.store.ReclaimExpiredLeases(ctx); err != nil {
		s.log.Error("the expired leases were not reclaimed", "err", err)
	} else if count > 0 {
		s.log.Warn("tasks went back to the queue after their lease expired", "count", count)
	}
	if count, err := s.store.ExpireOverdue(ctx); err != nil {
		s.log.Error("the tasks past their TTL were not marked", "err", err)
	} else if count > 0 {
		s.log.Info("tasks expired before they started", "count", count)
	}
	s.renewBudgets(ctx)
}

// renewBudgets keeps the tokens of the running tasks alive.
//
// A budget lease is shorter than a package transaction on purpose - a
// gateway that vanished has to free its capacity after a moment - so the
// tasks that are still working have to say so, the way a campaign's hosts
// do every pass of the orchestrator.
func (s *Scheduler) renewBudgets(ctx context.Context) {
	if s.admission.budgets == nil {
		return
	}
	running, err := s.store.InFlight(ctx)
	if err != nil {
		s.log.Error("the running tasks were not listed for the budgets", "err", err)
		return
	}
	if len(running) == 0 {
		return
	}
	owners := make([]string, 0, len(running))
	for _, jobID := range running {
		owners = append(owners, budgets.JobOwner(jobID))
	}
	if err := s.admission.budgets.Renew(ctx, owners); err != nil {
		s.log.Error("the capacity of the running tasks was not renewed", "err", err)
	}
}

func (s *Scheduler) dispatchOnce(ctx context.Context) {
	hosts := s.registry.ConnectedHosts()
	if len(hosts) == 0 {
		return
	}

	candidates, err := s.store.Queued(ctx, hosts, s.options.BatchSize)
	if err != nil {
		s.log.Error("the queue was not read", "err", err)
		return
	}
	if len(candidates) == 0 {
		return
	}
	domains, err := s.admission.failureDomains(ctx, candidates)
	if err != nil {
		s.log.Error("the failure domains of the queued tasks were not read", "err", err)
		return
	}
	// The dispatch rate is looked at before any task is taken: a task the
	// rate has no token for stays queued, not leased, so its lease does
	// not tick while it waits for a pass that has room. The tokens are
	// spent only on the tasks actually admitted - a task the budgets
	// refuse costs no token, and the tasks behind it still get their turn.
	room := len(candidates)
	if s.bucket != nil {
		room = s.bucket.Available()
	}
	// Every task is admitted on its own, oldest first, before any is taken:
	// a task the budgets refuse stays queued as it was, with no attempt
	// opened, and the tasks behind it in the queue still get their turn - a
	// restart in one site does not wait behind a reboot refused in another.
	admitted := make([]string, 0, len(candidates))
	for i, candidate := range candidates {
		if len(admitted) >= room {
			throttled := len(candidates) - i
			metrics.DispatchThrottled.Add(float64(throttled), s.options.GatewayID)
			s.log.Info("the dispatch rate held tasks in the queue for the next pass",
				"held", throttled, "sent", len(admitted))
			break
		}
		ok, err := s.admission.admit(ctx, candidate, domains[candidate.Job.HostID])
		if err != nil {
			s.log.Error("the budgets did not answer for the task",
				"job_id", candidate.Job.ID, "err", err)
			continue
		}
		if ok {
			admitted = append(admitted, candidate.Job.ID)
		}
	}
	if len(admitted) == 0 {
		return
	}
	if s.bucket != nil {
		s.bucket.Take(len(admitted))
	}

	leased, err := s.store.LeaseJobs(ctx, s.options.GatewayID, admitted, s.options.LeaseDuration)
	if err != nil {
		s.log.Error("the tasks were not taken from the queue", "err", err)
		for _, jobID := range admitted {
			s.admission.release(ctx, jobID)
		}
		return
	}
	for _, jobID := range untaken(admitted, leased) {
		s.admission.release(ctx, jobID)
	}
	// A host with a session open on more than one gateway is not served
	// this pass: the registry of this gateway sees only its own session
	// and cannot tell whether it is the one the agent is still on. The
	// database can, and the check is one query for the whole batch.
	ambiguous, err := s.ambiguousHosts(ctx, hostsOf(leased))
	if err != nil {
		// A failed check holds nobody: the tasks go out as before the
		// check existed, and a stale session is caught by its lease.
		s.log.Error("the open sessions of the hosts were not read", "err", err)
		ambiguous = nil
	}
	for _, item := range leased {
		if ambiguous[item.Job.HostID] {
			s.holdAmbiguous(ctx, item)
			continue
		}
		s.deliver(ctx, item)
	}
}

// hostsOf lists the hosts of the leased tasks, each once.
func hostsOf(leased []jobs.LeasedJob) []string {
	seen := map[string]bool{}
	hosts := make([]string, 0, len(leased))
	for _, item := range leased {
		if !seen[item.Job.HostID] {
			seen[item.Job.HostID] = true
			hosts = append(hosts, item.Job.HostID)
		}
	}
	return hosts
}

// ambiguousHosts names the hosts among the given ones that have an open
// session on more than one gateway right now. The gateway that took the
// agent over closes the older rows a moment after opening its own, so the
// answer is normally empty; a host that stays on the list is reconnecting
// in a loop, or the gateways disagree about who serves it.
func (s *Scheduler) ambiguousHosts(ctx context.Context, hostIDs []string) (map[string]bool, error) {
	if len(hostIDs) == 0 || s.store == nil || s.store.Pool() == nil {
		return nil, nil
	}
	rows, err := s.store.Pool().Query(ctx, `
		select host_id::text from agent_sessions
		where host_id = any($1::uuid[]) and ended_at is null
		group by host_id
		having count(distinct gateway_id) > 1`, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ambiguous := map[string]bool{}
	for rows.Next() {
		var hostID string
		if err := rows.Scan(&hostID); err != nil {
			return nil, err
		}
		ambiguous[hostID] = true
	}
	return ambiguous, rows.Err()
}

// holdAmbiguous puts a task back in the queue because its host cannot be
// told apart between gateways. The attempt says why, under the code of the
// campaigns document, and the next pass tries again: by then one session
// has usually won.
func (s *Scheduler) holdAmbiguous(ctx context.Context, item jobs.LeasedJob) {
	s.log.Info("the task was held: the host has sessions on more than one gateway",
		"job_id", item.Job.ID, "host_id", item.Job.HostID)
	if err := s.store.ReleaseLease(ctx, item.Job.ID, item.AttemptID, "dispatch_ambiguous"); err != nil {
		s.log.Error("the held task was not returned to the queue", "job_id", item.Job.ID, "err", err)
	}
	metrics.JobDispatch.Inc("ambiguous", s.options.GatewayID)
}

func (s *Scheduler) deliver(ctx context.Context, item jobs.LeasedJob) {
	envelope, err := s.buildEnvelopeFor(ctx, item)
	if err != nil {
		s.log.Error("the task envelope was not built", "job_id", item.Job.ID, "err", err)
		metrics.JobDispatch.Inc("invalid_envelope", s.options.GatewayID)
		if permanentFailure(err) {
			// The same answer would come on every pass until the deadline;
			// a task that cannot be assembled is settled now, with the
			// reason, instead of waiting in the queue and saying nothing.
			if err := s.store.FailUndelivered(ctx, item.Job.ID, item.AttemptID,
				"envelope_rejected", err.Error()); err != nil {
				s.log.Error("the rejected task was not settled", "job_id", item.Job.ID, "err", err)
			}
			return
		}
		_ = s.store.ReleaseLease(ctx, item.Job.ID, item.AttemptID, "invalid_envelope")
		return
	}

	sessionID, err := s.registry.Dispatch(item.Job.HostID,
		&agentv1.ServerMessage{Payload: &agentv1.ServerMessage_Task{Task: envelope}},
		s.options.SendTimeout)
	if err != nil {
		// The host disconnected between the fetch and the send. The task goes
		// back to the queue and will be delivered on the next connection.
		s.log.Info("the task was not delivered, going back to the queue",
			"job_id", item.Job.ID, "host_id", item.Job.HostID, "reason", err)
		if releaseErr := s.store.ReleaseLease(ctx, item.Job.ID, item.AttemptID, err.Error()); releaseErr != nil {
			s.log.Error("the task was not returned to the queue", "job_id", item.Job.ID, "err", releaseErr)
		}
		metrics.JobDispatch.Inc("undelivered", s.options.GatewayID)
		return
	}

	// The dispatch lease is short only for an agent that will acknowledge
	// the task; an older one keeps the execution lease from the start.
	lease := s.options.LeaseDuration
	if session, ok := s.registry.Get(item.Job.HostID); ok && buildinfo.AcknowledgesTasks(session.AgentVersion) {
		lease = jobs.DispatchLease
	}
	if err := s.store.MarkDispatchedWithLease(ctx, item.Job.ID, item.AttemptID, sessionID, lease); err != nil {
		s.log.Error("the delivery was not recorded", "job_id", item.Job.ID, "err", err)
		metrics.JobDispatch.Inc("unrecorded", s.options.GatewayID)
		return
	}
	metrics.JobDispatch.Inc("dispatched", s.options.GatewayID)

	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: s.options.GatewayID,
		Action: "job.dispatch", TargetType: "job", TargetID: item.Job.ID,
		RequestID: item.Job.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": item.Job.HostID, "attempt": item.Attempt,
			"action_type": item.Job.ActionType, "session_id": sessionID,
		},
	})
	s.log.Info("the task was delivered",
		"job_id", item.Job.ID, "host_id", item.Job.HostID,
		"action", item.Job.ActionType, "attempt", item.Attempt)
}

// buildEnvelopeFor builds the envelope and fills in the credentials that are
// deliberately not stored in the database.
func (s *Scheduler) buildEnvelopeFor(ctx context.Context, item jobs.LeasedJob) (*agentv1.TaskEnvelope, error) {
	envelope, err := buildEnvelope(item)
	if err != nil {
		return nil, err
	}

	// The hash is spelled in the newest scheme the agent at the other end
	// verifies. An agent from before a scheme change refuses a hash it
	// cannot recompute - and it would refuse every task, with the host
	// managed by nobody until somebody upgraded it by hand.
	if session, ok := s.registry.Get(item.Job.HostID); ok {
		scheme := min(buildinfo.PayloadHashSchemeFor(session.AgentVersion), opspec.PayloadHashVersion)
		if scheme != opspec.PayloadHashVersion {
			var payload opspec.Payload
			if err := json.Unmarshal(item.Job.Payload, &payload); err != nil {
				return nil, err
			}
			hash, err := opspec.PayloadHashOfScheme(scheme, opspec.ActionType(item.Job.ActionType),
				item.Job.ActionVersion, payload)
			if err != nil {
				return nil, err
			}
			envelope.PayloadHash = hash
		}
	}

	// The secrets named in the task get their leases exactly at delivery
	// time: the short window starts when the host starts working rather than
	// when the operator clicked.
	if err := s.issueLeases(ctx, item); err != nil {
		return nil, err
	}

	enroll, ok := envelope.GetAction().(*agentv1.TaskEnvelope_DomainEnroll)
	if !ok || enroll.DomainEnroll.GetPreflightOnly() {
		return envelope, nil
	}
	if s.credentials == nil {
		return nil, errUnknownAction("there is no source of domain join credentials")
	}

	hostname := enroll.DomainEnroll.GetHostname()
	if hostname == "" {
		return nil, errUnknownAction("joining requires the host's FQDN")
	}
	// The password comes into being now and is valid until its first use; it
	// reaches neither the database nor the audit trail.
	password, err := s.credentials.EnsureHostWithOTP(ctx, hostname)
	if err != nil {
		return nil, err
	}
	enroll.DomainEnroll.OneTimePassword = password
	return envelope, nil
}

// issueLeases creates the right to fetch this task's secrets.
//
// The store fixes the version at this moment: a task ordered against the
// current version gets the one that is current at delivery - and only that
// one will be issued, even if another comes into being in the meantime.
func (s *Scheduler) issueLeases(ctx context.Context, item jobs.LeasedJob) error {
	var payload opspec.Payload
	if err := json.Unmarshal(item.Job.Payload, &payload); err != nil {
		return err
	}
	references := payload.Secrets()
	if len(references) == 0 {
		return nil
	}
	if s.secrets == nil {
		return errUnknownAction("this panel has no secret store")
	}
	for _, reference := range references {
		lease, err := s.secrets.Issue(ctx, reference.Name, reference.Version,
			item.Job.ID, item.Job.HostID, 0)
		if err != nil {
			return err
		}
		// The audit trail records the fact that the right was issued, the
		// name and the version - never the value.
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorSystem, ActorID: s.options.GatewayID,
			Action: "secret.lease", TargetType: "secret", TargetID: reference.Name,
			RequestID: item.Job.RequestID, Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"job_id": item.Job.ID, "host_id": item.Job.HostID,
				"version": lease.Version, "expires_at": lease.ExpiresAt,
			},
		})
	}
	return nil
}

// buildEnvelope turns a task from the database into an envelope of the agent
// protocol. task_id names one specific attempt and idempotency_key the whole
// operation - thanks to that delivering the same operation again returns the
// previous result.
func buildEnvelope(item jobs.LeasedJob) (*agentv1.TaskEnvelope, error) {
	var payload opspec.Payload
	if err := json.Unmarshal(item.Job.Payload, &payload); err != nil {
		return nil, err
	}
	var preconditions jobs.Preconditions
	if len(item.Job.Preconditions) > 0 {
		if err := json.Unmarshal(item.Job.Preconditions, &preconditions); err != nil {
			return nil, err
		}
	}
	hash, err := opspec.PayloadHash(opspec.ActionType(item.Job.ActionType),
		item.Job.ActionVersion, payload)
	if err != nil {
		return nil, err
	}

	// The resource scope comes from the registry by family: the host wraps
	// the tools of a package transaction or a backup in a transient scope
	// with these controls, so a heavy operation slows itself down on a busy
	// host rather than the host.
	scope := opspec.ActionType(item.Job.ActionType).ResourceLimits()
	envelope := &agentv1.TaskEnvelope{
		TaskId:         item.AttemptID,
		IdempotencyKey: item.Job.IdempotencyKey,
		CreatedAt:      timestamppb.New(item.Job.CreatedAt),
		ExpiresAt:      timestamppb.New(item.Job.ExpiresAt),
		PayloadHash:    hash,
		Preconditions: &agentv1.Preconditions{
			OsFamily:             preconditions.OSFamily,
			RequiredCapabilities: preconditions.RequiredCapabilities,
			ExpectedBootId:       preconditions.ExpectedBootID,
		},
		Limits: &agentv1.Limits{
			TimeoutSeconds:  uint32(item.Job.TimeoutSeconds),
			MaxOutputBytes:  uint32(item.Job.MaxOutputBytes),
			CpuWeight:       scope.CPUWeight,
			IoWeight:        scope.IOWeight,
			MemoryHighBytes: scope.MemoryHighBytes,
		},
		ActorContext: &agentv1.ActorContext{
			ActorId:   item.Job.CreatedBy,
			RequestId: item.Job.RequestID,
			Approvals: approvalsOf(item.Job),
		},
	}
	if item.Job.CampaignID != nil {
		envelope.CampaignId = *item.Job.CampaignID
	}

	action := opspec.ActionType(item.Job.ActionType)
	switch action {
	case opspec.ActionPackagePlan:
		envelope.Action = &agentv1.TaskEnvelope_PackagePlan{
			PackagePlan: &agentv1.PackagePlan{
				Mode:            payload.PackagePlan.Mode,
				RefreshMetadata: payload.PackagePlan.RefreshMetadata,
				OnlyPackages:    payload.PackagePlan.OnlyPackages,
				SecurityOnly:    payload.PackagePlan.SecurityOnly,
			},
		}

	case opspec.ActionPackageUpgrade:
		request := &agentv1.PackageUpgrade{
			Packages:     payload.PackageUpgrade.Packages,
			SecurityOnly: payload.PackageUpgrade.SecurityOnly,
		}
		if payload.PackageUpgrade.PlanHash != "" {
			hash, err := hex.DecodeString(payload.PackageUpgrade.PlanHash)
			if err != nil {
				return nil, fmt.Errorf("invalid plan hash: %w", err)
			}
			request.PlanHash = hash
		}
		envelope.Action = &agentv1.TaskEnvelope_PackageUpgrade{PackageUpgrade: request}

	case opspec.ActionAgentUpgrade:
		envelope.Action = &agentv1.TaskEnvelope_AgentUpgrade{
			AgentUpgrade: &agentv1.AgentUpgrade{
				TargetVersion:   payload.AgentUpgrade.TargetVersion,
				PackageSha256:   payload.AgentUpgrade.PackageSHA256,
				RollbackVersion: payload.AgentUpgrade.RollbackVersion,
			},
		}

	case opspec.ActionDomainEnroll, opspec.ActionDomainPreflight:
		envelope.Action = &agentv1.TaskEnvelope_DomainEnroll{
			DomainEnroll: &agentv1.DomainEnroll{
				Domain:        payload.DomainEnroll.Domain,
				Realm:         payload.DomainEnroll.Realm,
				Server:        payload.DomainEnroll.Server,
				Hostname:      payload.DomainEnroll.Hostname,
				PreflightOnly: action == opspec.ActionDomainPreflight,
			},
		}

	case opspec.ActionDomainLeave:
		// No credential is fetched for a leave: the host unenrolls itself
		// with its own keytab, so the envelope carries only the names.
		envelope.Action = &agentv1.TaskEnvelope_DomainLeave{
			DomainLeave: &agentv1.DomainLeave{
				Domain: payload.DomainLeave.Domain,
				Realm:  payload.DomainLeave.Realm,
			},
		}

	case opspec.ActionIdentityKeytabRenew:
		// The envelope carries the principal alone: the host fetches the
		// new key itself with the credentials it holds, and no key material
		// passes through the panel in either direction.
		envelope.Action = &agentv1.TaskEnvelope_KeytabRenew{
			KeytabRenew: &agentv1.KeytabRenew{Principal: payload.Keytab.Principal},
		}

	case opspec.ActionLocalUserCreate, opspec.ActionLocalUserLock,
		opspec.ActionLocalUserUnlock, opspec.ActionLocalSSHKeysSet,
		opspec.ActionLocalUserGroupsSet, opspec.ActionLocalUserExpirySet,
		opspec.ActionLocalUserDelete:
		envelope.Action = &agentv1.TaskEnvelope_LocalUserAction{
			LocalUserAction: &agentv1.LocalUserAction{
				Operation:  localUserOperations[action],
				Name:       payload.LocalUser.Name,
				Gecos:      payload.LocalUser.Gecos,
				Shell:      payload.LocalUser.Shell,
				Groups:     payload.LocalUser.Groups,
				SshKeys:    payload.LocalUser.SSHKeys,
				CreateHome: payload.LocalUser.CreateHome,
				ExpiresAt:  payload.LocalUser.ExpiresAt,
				RemoveHome: payload.LocalUser.RemoveHome,
			},
		}

	case opspec.ActionPackageRepair:
		answers := make([]*agentv1.DebconfAnswer, 0, len(payload.PackageRepair.Answers))
		for _, answer := range payload.PackageRepair.Answers {
			answers = append(answers, &agentv1.DebconfAnswer{
				Package:  answer.Package,
				Question: answer.Question,
				Type:     answer.Type,
				Value:    answer.Value,
			})
		}
		envelope.Action = &agentv1.TaskEnvelope_PackagesRepair{
			PackagesRepair: &agentv1.PackagesRepair{Answers: answers},
		}

	case opspec.ActionDockerRead:
		envelope.Action = &agentv1.TaskEnvelope_DockerRead{DockerRead: &agentv1.DockerRead{}}

	case opspec.ActionDockerEvents:
		// The window is optional: no payload means the module's default
		// window. The values go into the envelope in full, because the plan
		// hash is computed from them - an omitted field would give a
		// different plan on the host than in the panel.
		events := &agentv1.ReadDockerEvents{}
		if payload.DockerEvents != nil {
			events.SinceSeconds = uint32(payload.DockerEvents.SinceSeconds)
			events.FollowSeconds = uint32(payload.DockerEvents.FollowSeconds)
			events.Types = payload.DockerEvents.Types
			events.MaxEvents = uint32(payload.DockerEvents.MaxEvents)
		}
		envelope.Action = &agentv1.TaskEnvelope_ReadDockerEvents{ReadDockerEvents: events}

	case opspec.ActionDockerLogs:
		// Every field travels, the zero ones too: the plan hash is computed
		// from the whole payload on both sides.
		envelope.Action = &agentv1.TaskEnvelope_DockerLogs{
			DockerLogs: &agentv1.DockerLogs{
				ContainerId: payload.DockerLogs.ContainerID,
				Lines:       payload.DockerLogs.Lines,
				Since:       payload.DockerLogs.Since,
				Timestamps:  payload.DockerLogs.Timestamps,
			},
		}

	case opspec.ActionSystemHostnameSet:
		envelope.Action = &agentv1.TaskEnvelope_HostnameSet{
			HostnameSet: &agentv1.HostnameSet{
				Hostname: payload.Hostname.Hostname,
				Pretty:   payload.Hostname.Pretty,
			},
		}

	case opspec.ActionInventoryRefresh:
		// The scope is optional: no payload means the whole inventory.
		var modules []string
		if payload.Inventory != nil {
			modules = payload.Inventory.Modules
		}
		envelope.Action = &agentv1.TaskEnvelope_RefreshInventory{
			RefreshInventory: &agentv1.RefreshInventory{Modules: modules},
		}

	case opspec.ActionPackageInstall, opspec.ActionPackageRemove, opspec.ActionPackageHoldSet:
		operation := agentv1.PackageLifecycle_OPERATION_INSTALL
		switch action {
		case opspec.ActionPackageRemove:
			operation = agentv1.PackageLifecycle_OPERATION_REMOVE
		case opspec.ActionPackageHoldSet:
			operation = agentv1.PackageLifecycle_OPERATION_HOLD
		}
		envelope.Action = &agentv1.TaskEnvelope_PackageLifecycle{
			PackageLifecycle: &agentv1.PackageLifecycle{
				Operation:        operation,
				Packages:         payload.PackageChange.Packages,
				ExpectedRemovals: payload.PackageChange.ExpectedRemovals,
				Hold:             payload.PackageChange.Hold,
				PlanHash:         payload.PackageChange.PlanHash,
			},
		}

	case opspec.ActionFilePlan, opspec.ActionFileRead, opspec.ActionFileEnsure,
		opspec.ActionFileRemove, opspec.ActionFileRollback:
		operation := agentv1.FileAction_OPERATION_LIST
		switch action {
		case opspec.ActionFileRead:
			operation = agentv1.FileAction_OPERATION_READ
		case opspec.ActionFileEnsure:
			operation = agentv1.FileAction_OPERATION_ENSURE
		case opspec.ActionFileRollback:
			operation = agentv1.FileAction_OPERATION_ROLLBACK
		case opspec.ActionFileRemove:
			operation = agentv1.FileAction_OPERATION_REMOVE
		case opspec.ActionFilePlan:
			// A plan without a path is a read of the state of every file the
			// panel manages - that is how the host tab works. A plan with a
			// path computes the difference for that one file, and that is the
			// planning phase of a campaign.
			if payload.File != nil && strings.TrimSpace(payload.File.Path) != "" {
				operation = agentv1.FileAction_OPERATION_PLAN
			}
		}
		file := &agentv1.FileAction{Operation: operation}
		if payload.File != nil {
			file.Path = payload.File.Path
			file.Content = []byte(payload.File.Content)
			// The envelope carries a reference rather than a value: the host
			// fetches the content with a separate call when it starts the
			// operation.
			if !payload.File.ContentSecret.Empty() {
				file.ContentSecret = &agentv1.SecretRef{
					Name:    payload.File.ContentSecret.Name,
					Version: uint32(payload.File.ContentSecret.Version),
				}
			}
			file.Mode = payload.File.Mode
			file.Owner = payload.File.Owner
			file.Group = payload.File.Group
			file.ExpectedSha256 = payload.File.ExpectedSHA256
			file.Validator = payload.File.Validator
		}
		envelope.Action = &agentv1.TaskEnvelope_File{File: file}

	case opspec.ActionSecurityScan, opspec.ActionSELinuxModeSet, opspec.ActionAuditRulesReload:
		operation := agentv1.SecurityAction_OPERATION_SCAN
		switch action {
		case opspec.ActionSELinuxModeSet:
			operation = agentv1.SecurityAction_OPERATION_SELINUX_MODE
		case opspec.ActionAuditRulesReload:
			operation = agentv1.SecurityAction_OPERATION_AUDIT_RELOAD
		}
		ochrona := &agentv1.SecurityAction{Operation: operation}
		if payload.Security != nil {
			ochrona.Mode = payload.Security.Mode
		}
		envelope.Action = &agentv1.TaskEnvelope_Security{Security: ochrona}

	case opspec.ActionCertificateScan, opspec.ActionCertificatePlan,
		opspec.ActionCertificateDeploy, opspec.ActionCertificateRenew,
		opspec.ActionCertificateTrustPlan, opspec.ActionCertificateTrustEnsure,
		opspec.ActionCertificateTrustRemove:
		operation := agentv1.CertificateAction_OPERATION_SCAN
		switch action {
		case opspec.ActionCertificatePlan:
			operation = agentv1.CertificateAction_OPERATION_PLAN
		case opspec.ActionCertificateTrustPlan:
			operation = agentv1.CertificateAction_OPERATION_TRUST_PLAN
		case opspec.ActionCertificateTrustEnsure:
			operation = agentv1.CertificateAction_OPERATION_TRUST_ENSURE
		case opspec.ActionCertificateTrustRemove:
			operation = agentv1.CertificateAction_OPERATION_TRUST_REMOVE
		case opspec.ActionCertificateDeploy:
			operation = agentv1.CertificateAction_OPERATION_DEPLOY
		case opspec.ActionCertificateRenew:
			operation = agentv1.CertificateAction_OPERATION_RENEW
		}
		certificate := &agentv1.CertificateAction{Operation: operation}
		if payload.Certificate != nil {
			for _, target := range payload.Certificate.Targets {
				certificate.Targets = append(certificate.Targets, &agentv1.CertificateTarget{
					Path: target.Path, KeyPath: target.KeyPath, Service: target.Service,
				})
			}
			certificate.Path = payload.Certificate.Path
			certificate.KeyPath = payload.Certificate.KeyPath
			certificate.Certificate = payload.Certificate.Certificate
			// The envelope carries a reference to the key rather than the key
			// itself: the host fetches the value in a separate call once it
			// starts the operation.
			if !payload.Certificate.KeySecret.Empty() {
				certificate.KeySecret = &agentv1.SecretRef{
					Name:    payload.Certificate.KeySecret.Name,
					Version: uint32(payload.Certificate.KeySecret.Version),
				}
			}
			certificate.Owner = payload.Certificate.Owner
			certificate.Group = payload.Certificate.Group
			certificate.Mode = payload.Certificate.Mode
			certificate.KeyMode = payload.Certificate.KeyMode
			certificate.ReloadUnit = payload.Certificate.ReloadUnit
			certificate.ProbeTarget = payload.Certificate.ProbeTarget
			certificate.Request = payload.Certificate.Request
			certificate.PlanHash = payload.Certificate.PlanHash
			certificate.AnchorId = payload.Certificate.AnchorID
		}
		envelope.Action = &agentv1.TaskEnvelope_Certificate{Certificate: certificate}

	case opspec.ActionPackageList:
		envelope.Action = &agentv1.TaskEnvelope_ListPackages{ListPackages: &agentv1.ListPackages{}}

	case opspec.ActionMonitoringProbe:
		probe := &agentv1.MonitoringProbe{}
		if payload.Monitoring != nil {
			probe.Kind = payload.Monitoring.Kind
			probe.Target = payload.Monitoring.Target
			probe.ExpectStatus = int32(payload.Monitoring.ExpectStatus)
			probe.ExpectBody = payload.Monitoring.ExpectBody
			probe.TimeoutSeconds = int32(payload.Monitoring.TimeoutSeconds)
		}
		envelope.Action = &agentv1.TaskEnvelope_MonitoringProbe{MonitoringProbe: probe}

	case opspec.ActionBackupPlan, opspec.ActionBackupRun,
		opspec.ActionBackupVerify, opspec.ActionBackupRestore:
		operation := agentv1.BackupAction_OPERATION_PLAN
		switch action {
		case opspec.ActionBackupRun:
			operation = agentv1.BackupAction_OPERATION_RUN
		case opspec.ActionBackupVerify:
			operation = agentv1.BackupAction_OPERATION_VERIFY
		case opspec.ActionBackupRestore:
			operation = agentv1.BackupAction_OPERATION_RESTORE
		}
		backup := &agentv1.BackupAction{Operation: operation}
		if payload.Backup != nil {
			backup.Id = payload.Backup.ID
			backup.Tool = payload.Backup.Tool
			backup.Repository = payload.Backup.Repository
			backup.Paths = payload.Backup.Paths
			backup.Excludes = payload.Backup.Excludes
			backup.Tags = payload.Backup.Tags
			backup.KeepLast = int32(payload.Backup.KeepLast)
			backup.KeepDaily = int32(payload.Backup.KeepDaily)
			backup.KeepWeekly = int32(payload.Backup.KeepWeekly)
			backup.KeepMonthly = int32(payload.Backup.KeepMonthly)
			backup.Prune = payload.Backup.Prune
			backup.Runbook = payload.Backup.Runbook
			backup.Initialize = payload.Backup.Initialize
			backup.ReadData = payload.Backup.ReadData
			backup.SnapshotId = payload.Backup.SnapshotID
			backup.Target = payload.Backup.Target
			backup.Include = payload.Backup.Include
			backup.Overwrite = payload.Backup.Overwrite
			backup.Plan = payload.Backup.Plan
			backup.PlanHash = payload.Backup.PlanHash
			// The envelope carries references to the credentials, never
			// their values.
			if !payload.Backup.PasswordSecret.Empty() {
				backup.PasswordSecret = &agentv1.SecretRef{
					Name:    payload.Backup.PasswordSecret.Name,
					Version: uint32(payload.Backup.PasswordSecret.Version),
				}
			}
			if len(payload.Backup.EnvSecrets) > 0 {
				backup.EnvSecrets = map[string]*agentv1.SecretRef{}
				for name, reference := range payload.Backup.EnvSecrets {
					backup.EnvSecrets[name] = &agentv1.SecretRef{
						Name: reference.Name, Version: uint32(reference.Version),
					}
				}
			}
		}
		envelope.Action = &agentv1.TaskEnvelope_Backup{Backup: backup}

	case opspec.ActionRepositorySet:
		source := &agentv1.RepositoryAction{}
		if payload.Repository != nil {
			source.Id = payload.Repository.ID
			source.Name = payload.Repository.Name
			source.Url = payload.Repository.URL
			source.Suites = payload.Repository.Suites
			source.Components = payload.Repository.Components
			source.Architectures = payload.Repository.Architectures
			source.Enabled = payload.Repository.Enabled
			source.Priority = int32(payload.Repository.Priority)
			source.GpgKey = payload.Repository.GPGKey
			source.AllowUnsigned = payload.Repository.AllowUnsigned
			source.Username = payload.Repository.Username
			source.Remove = payload.Repository.Remove
			// The envelope carries a reference to the password rather than the
			// password.
			if !payload.Repository.PasswordSecret.Empty() {
				source.PasswordSecret = &agentv1.SecretRef{
					Name:    payload.Repository.PasswordSecret.Name,
					Version: uint32(payload.Repository.PasswordSecret.Version),
				}
			}
		}
		envelope.Action = &agentv1.TaskEnvelope_Repository{Repository: source}

	case opspec.ActionSystemShutdown:
		shutdown := &agentv1.SystemShutdown{}
		if payload.Power != nil {
			shutdown.DelaySeconds = payload.Power.DelaySeconds
			shutdown.Reason = payload.Power.Reason
			shutdown.Mode = payload.Power.Mode
			shutdown.IgnoreInhibitors = payload.Power.IgnoreInhibitors
		}
		envelope.Action = &agentv1.TaskEnvelope_SystemShutdown{SystemShutdown: shutdown}

	case opspec.ActionTimeSyncTest, opspec.ActionTimePlan, opspec.ActionTimeConfigApply,
		opspec.ActionTimezoneSet:
		operation := agentv1.TimeAction_OPERATION_SYNC_TEST
		switch action {
		case opspec.ActionTimePlan:
			operation = agentv1.TimeAction_OPERATION_PLAN
		case opspec.ActionTimeConfigApply:
			operation = agentv1.TimeAction_OPERATION_CONFIG_APPLY
		case opspec.ActionTimezoneSet:
			operation = agentv1.TimeAction_OPERATION_TIMEZONE_SET
		}
		clock := &agentv1.TimeAction{Operation: operation}
		if payload.Time != nil {
			clock.Servers = payload.Time.Servers
			clock.Probe = payload.Time.Probe
			clock.Timezone = payload.Time.Timezone
			clock.AllowStep = payload.Time.AllowStep
			clock.EnableDropin = payload.Time.EnableDropIn
			clock.PlanHash = payload.Time.PlanHash
		}
		envelope.Action = &agentv1.TaskEnvelope_Time{Time: clock}

	case opspec.ActionSysctlPlan, opspec.ActionSysctlEnsure, opspec.ActionKernelModulePlan,
		opspec.ActionKernelModuleLoad, opspec.ActionKernelModuleBlacklist:
		operation := agentv1.KernelAction_OPERATION_READ
		switch action {
		case opspec.ActionKernelModulePlan:
			operation = agentv1.KernelAction_OPERATION_MODULE_PLAN
		case opspec.ActionSysctlEnsure:
			operation = agentv1.KernelAction_OPERATION_SYSCTL_ENSURE
		case opspec.ActionKernelModuleLoad:
			operation = agentv1.KernelAction_OPERATION_MODULE_LOAD
		case opspec.ActionKernelModuleBlacklist:
			operation = agentv1.KernelAction_OPERATION_MODULE_BLACKLIST
		}
		kernel := &agentv1.KernelAction{Operation: operation}
		if payload.Kernel != nil {
			kernel.Settings = payload.Kernel.Settings
			kernel.Keys = payload.Kernel.Keys
			kernel.Module = payload.Kernel.Module
			kernel.Blacklist = payload.Kernel.Blacklist
			kernel.PlanHash = payload.Kernel.PlanHash
		}
		envelope.Action = &agentv1.TaskEnvelope_Kernel{Kernel: kernel}

	case opspec.ActionSSHConfigPlan, opspec.ActionSSHConfigApply,
		opspec.ActionSSHHostKeyRotate:
		operation := agentv1.SshAction_OPERATION_READ
		switch action {
		case opspec.ActionSSHConfigPlan:
			// A plan without settings is a read of state (the host tab); a
			// plan with settings computes the difference against them - the
			// planning phase.
			if payload.SSH != nil && payload.SSH.DescribesChange() {
				operation = agentv1.SshAction_OPERATION_PLAN
			}
		case opspec.ActionSSHConfigApply:
			operation = agentv1.SshAction_OPERATION_APPLY
		case opspec.ActionSSHHostKeyRotate:
			operation = agentv1.SshAction_OPERATION_ROTATE_HOSTKEY
		}
		server := &agentv1.SshAction{Operation: operation}
		if payload.SSH != nil {
			server.Port = payload.SSH.Port
			server.PermitRootLogin = payload.SSH.PermitRootLogin
			server.PasswordAuthentication = payload.SSH.PasswordAuthentication
			server.PubkeyAuthentication = payload.SSH.PubkeyAuthentication
			server.KbdInteractiveAuthentication = payload.SSH.KbdInteractive
			server.MaxAuthTries = payload.SSH.MaxAuthTries
			server.AllowUsers = payload.SSH.AllowUsers
			server.AllowGroups = payload.SSH.AllowGroups
			server.DenyUsers = payload.SSH.DenyUsers
			server.AllowLockout = payload.SSH.AllowLockout
			server.KeyType = payload.SSH.KeyType
			server.PlanHash = payload.SSH.PlanHash
		}
		envelope.Action = &agentv1.TaskEnvelope_Ssh{Ssh: server}

	case opspec.ActionStoragePlan, opspec.ActionMountEnsure,
		opspec.ActionMountRemove, opspec.ActionFilesystemCheck,
		opspec.ActionLVMExtend, opspec.ActionFilesystemResize,
		opspec.ActionFilesystemCreate, opspec.ActionDiskWipe,
		opspec.ActionStorageSmartRead:
		operation := agentv1.StorageAction_OPERATION_MOUNT_ENSURE
		switch action {
		case opspec.ActionStorageSmartRead:
			operation = agentv1.StorageAction_OPERATION_SMART_READ
		case opspec.ActionStoragePlan:
			// A plan without a target is a read of the topology (the host
			// tab); a plan with a target computes the difference for one
			// mount - the planning phase of a campaign.
			operation = agentv1.StorageAction_OPERATION_READ
			if payload.Storage != nil && strings.TrimSpace(payload.Storage.Target) != "" {
				operation = agentv1.StorageAction_OPERATION_MOUNT_PLAN
			}
			// A plan named by kind concerns a device: a check or a growth of
			// the filesystem or the volume.
			if payload.Storage != nil && payload.Storage.Plan != "" {
				operation = agentv1.StorageAction_OPERATION_DEVICE_PLAN
			}
		case opspec.ActionMountRemove:
			operation = agentv1.StorageAction_OPERATION_MOUNT_REMOVE
		case opspec.ActionFilesystemCheck:
			operation = agentv1.StorageAction_OPERATION_FS_CHECK
		case opspec.ActionLVMExtend:
			operation = agentv1.StorageAction_OPERATION_LVM_EXTEND
		case opspec.ActionFilesystemResize:
			operation = agentv1.StorageAction_OPERATION_FS_RESIZE
		case opspec.ActionFilesystemCreate:
			operation = agentv1.StorageAction_OPERATION_FS_CREATE
		case opspec.ActionDiskWipe:
			operation = agentv1.StorageAction_OPERATION_DISK_WIPE
		}
		storage := &agentv1.StorageAction{Operation: operation}
		if payload.Storage != nil {
			storage.Source = payload.Storage.Source
			storage.Target = payload.Storage.Target
			storage.FsType = payload.Storage.FSType
			storage.Options = payload.Storage.Options
			storage.Persist = payload.Storage.Persist
			storage.Device = payload.Storage.Device
			storage.ExpectedUuid = payload.Storage.ExpectedUUID
			storage.Repair = payload.Storage.Repair
			storage.ExpectedSerial = payload.Storage.ExpectedSerial
			storage.ExpectedSizeBytes = payload.Storage.ExpectedSizeBytes
			storage.Size = payload.Storage.Size
			storage.Label = payload.Storage.Label
			storage.Plan = payload.Storage.Plan
			storage.PlanHash = payload.Storage.PlanHash
		}
		envelope.Action = &agentv1.TaskEnvelope_Storage{Storage: storage}

	case opspec.ActionFirewallPlan, opspec.ActionFirewallRuleEnsure,
		opspec.ActionFirewallRuleRemove, opspec.ActionFirewallZonePort,
		opspec.ActionFirewallZoneService, opspec.ActionFirewallRulesetRestore:
		operation := agentv1.FirewallAction_OPERATION_RULE_ENSURE
		switch action {
		case opspec.ActionFirewallPlan:
			// A plan without a rule is a read of the ruleset (the host tab); a
			// plan with a rule computes the difference for it - the planning
			// phase of a campaign.
			operation = agentv1.FirewallAction_OPERATION_READ
			if payload.Firewall != nil && (strings.TrimSpace(payload.Firewall.RuleID) != "" ||
				strings.TrimSpace(payload.Firewall.Zone) != "") {
				operation = agentv1.FirewallAction_OPERATION_PLAN
			}
		case opspec.ActionFirewallRuleRemove:
			operation = agentv1.FirewallAction_OPERATION_RULE_REMOVE
		case opspec.ActionFirewallZonePort:
			operation = agentv1.FirewallAction_OPERATION_ZONE_PORT
		case opspec.ActionFirewallZoneService:
			operation = agentv1.FirewallAction_OPERATION_ZONE_SERVICE
		case opspec.ActionFirewallRulesetRestore:
			operation = agentv1.FirewallAction_OPERATION_RESTORE
		}
		firewall := &agentv1.FirewallAction{Operation: operation}
		if payload.Firewall != nil {
			firewall.RuleId = payload.Firewall.RuleID
			firewall.Chain = payload.Firewall.Chain
			firewall.Action = payload.Firewall.Action
			firewall.Protocol = payload.Firewall.Protocol
			firewall.Ports = payload.Firewall.Ports
			firewall.Sources = payload.Firewall.Sources
			firewall.Interface = payload.Firewall.Interface
			firewall.Comment = payload.Firewall.Comment
			firewall.Zone = payload.Firewall.Zone
			firewall.Service = payload.Firewall.Service
			firewall.Enable = payload.Firewall.Enable
			firewall.BreakGlass = payload.Firewall.BreakGlass
			firewall.RollbackSeconds = payload.Firewall.RollbackSeconds
			firewall.RollbackId = payload.Firewall.RollbackID
			firewall.ExpectedHash = payload.Firewall.ExpectedHash
		}
		envelope.Action = &agentv1.TaskEnvelope_Firewall{Firewall: firewall}

	case opspec.ActionDNSResolveTest, opspec.ActionDNSPlan, opspec.ActionDNSHostApply:
		operation := agentv1.DnsAction_OPERATION_APPLY
		switch action {
		case opspec.ActionDNSResolveTest:
			operation = agentv1.DnsAction_OPERATION_RESOLVE_TEST
		case opspec.ActionDNSPlan:
			operation = agentv1.DnsAction_OPERATION_PLAN
		}
		resolver := &agentv1.DnsAction{Operation: operation}
		if payload.DNS != nil {
			resolver.Interface = payload.DNS.Interface
			resolver.Servers = payload.DNS.Servers
			resolver.SearchDomains = payload.DNS.SearchDomains
			resolver.IgnoreAutoDns = payload.DNS.IgnoreAutoDNS
			resolver.RollbackSeconds = payload.DNS.RollbackSeconds
			resolver.Names = payload.DNS.Names
			resolver.PlanHash = payload.DNS.PlanHash
		}
		envelope.Action = &agentv1.TaskEnvelope_Dns{Dns: resolver}

	case opspec.ActionNetworkPlan, opspec.ActionNetworkMTUSet,
		opspec.ActionNetworkRouteEnsure, opspec.ActionNetworkProfileApply,
		opspec.ActionNetworkRollback:
		operation := agentv1.NetworkAction_OPERATION_APPLY_PROFILE
		switch action {
		case opspec.ActionNetworkPlan:
			// A plan without a description of the change is a read of the
			// profiles; with one it computes the difference against it on the
			// host.
			operation = agentv1.NetworkAction_OPERATION_READ
			if payload.Network != nil && payload.Network.DescribesChange() {
				operation = agentv1.NetworkAction_OPERATION_PLAN
			}
		case opspec.ActionNetworkMTUSet:
			operation = agentv1.NetworkAction_OPERATION_SET_MTU
		case opspec.ActionNetworkRouteEnsure:
			operation = agentv1.NetworkAction_OPERATION_ENSURE_ROUTES
		case opspec.ActionNetworkRollback:
			operation = agentv1.NetworkAction_OPERATION_ROLLBACK
		}
		network := &agentv1.NetworkAction{Operation: operation}
		if payload.Network != nil {
			network.Interface = payload.Network.Interface
			network.Mtu = payload.Network.MTU
			network.Routes = payload.Network.Routes
			network.Method = payload.Network.Method
			network.Addresses = payload.Network.Addresses
			network.Gateway = payload.Network.Gateway
			network.Dns = payload.Network.DNS
			network.RollbackSeconds = payload.Network.RollbackSeconds
			network.RollbackId = payload.Network.RollbackID
			network.PlanHash = payload.Network.PlanHash
		}
		envelope.Action = &agentv1.TaskEnvelope_Network{Network: network}

	case opspec.ActionScheduleEnsure, opspec.ActionScheduleDisable,
		opspec.ActionScheduleRemove, opspec.ActionScheduleRunNow,
		opspec.ActionSchedulePreview:
		operation := agentv1.ScheduleAction_OPERATION_ENSURE
		switch action {
		case opspec.ActionScheduleDisable:
			operation = agentv1.ScheduleAction_OPERATION_DISABLE
		case opspec.ActionScheduleRemove:
			operation = agentv1.ScheduleAction_OPERATION_REMOVE
		case opspec.ActionScheduleRunNow:
			operation = agentv1.ScheduleAction_OPERATION_RUN_NOW
		case opspec.ActionSchedulePreview:
			operation = agentv1.ScheduleAction_OPERATION_PREVIEW
		}
		envelope.Action = &agentv1.TaskEnvelope_Schedule{
			Schedule: &agentv1.ScheduleAction{
				Operation:  operation,
				Id:         payload.Schedule.ID,
				Expression: payload.Schedule.Expression,
				Command:    payload.Schedule.Command,
				User:       payload.Schedule.User,
				Comment:    payload.Schedule.Comment,
				Enabled:    payload.Schedule.Enabled,
				Adopt:      payload.Schedule.Adopt,
			},
		}

	case opspec.ActionProcessList:
		envelope.Action = &agentv1.TaskEnvelope_ListProcesses{
			ListProcesses: &agentv1.ListProcesses{
				SortBy: payload.ProcessList.SortBy,
				Limit:  payload.ProcessList.Limit,
			},
		}

	case opspec.ActionProcessSignal:
		envelope.Action = &agentv1.TaskEnvelope_SignalProcess{
			SignalProcess: &agentv1.SignalProcess{
				Pid:                payload.ProcessSignal.PID,
				ExpectedStartTicks: payload.ProcessSignal.ExpectedStart,
				Signal:             payload.ProcessSignal.Signal,
				Command:            payload.ProcessSignal.Command,
			},
		}

	case opspec.ActionFollowJournal:
		envelope.Action = &agentv1.TaskEnvelope_FollowJournal{
			FollowJournal: &agentv1.FollowJournal{
				Unit:          payload.Journal.Unit,
				MaxPriority:   payload.Journal.MaxPriority,
				BacklogLines:  payload.Journal.Lines,
				FollowSeconds: payload.Journal.FollowSeconds,
			},
		}

	case opspec.ActionReadLogFile:
		envelope.Action = &agentv1.TaskEnvelope_ReadLogFile{
			ReadLogFile: &agentv1.ReadLogFile{
				Path:  payload.LogFile.Path,
				Lines: payload.LogFile.Lines,
			},
		}

	case opspec.ActionUnitEnableSet, opspec.ActionUnitMaskSet:
		wlasciwosc := agentv1.UnitToggle_PROPERTY_ENABLED
		if action == opspec.ActionUnitMaskSet {
			wlasciwosc = agentv1.UnitToggle_PROPERTY_MASKED
		}
		envelope.Action = &agentv1.TaskEnvelope_UnitToggle{
			UnitToggle: &agentv1.UnitToggle{
				Unit:     payload.UnitToggle.Unit,
				Property: wlasciwosc,
				Value:    payload.UnitToggle.Enabled,
			},
		}

	case opspec.ActionComposePlan, opspec.ActionComposeDeploy:
		operation := agentv1.ComposeAction_OPERATION_PLAN
		if action == opspec.ActionComposeDeploy {
			operation = agentv1.ComposeAction_OPERATION_DEPLOY
		}
		envelope.Action = &agentv1.TaskEnvelope_Compose{
			Compose: &agentv1.ComposeAction{
				Operation:  operation,
				Project:    payload.Compose.Project,
				Manifest:   payload.Compose.Manifest,
				PlanDigest: payload.Compose.PlanDigest,
			},
		}

	case opspec.ActionDockerStart, opspec.ActionDockerStop, opspec.ActionDockerRestart,
		opspec.ActionDockerRemove, opspec.ActionDockerPull, opspec.ActionDockerPrune:
		envelope.Action = &agentv1.TaskEnvelope_DockerAction{
			DockerAction: dockerEnvelope(action, payload),
		}

	case opspec.ActionUnitStatus:
		envelope.Action = &agentv1.TaskEnvelope_ReadUnitStatus{
			ReadUnitStatus: &agentv1.ReadUnitStatus{
				Units:  payload.UnitStatus.Units,
				All:    payload.UnitStatus.All,
				Detail: payload.UnitStatus.Detail,
			},
		}

	case opspec.ActionSystemReboot:
		envelope.Action = &agentv1.TaskEnvelope_SystemReboot{
			SystemReboot: &agentv1.SystemReboot{
				DelaySeconds: payload.Reboot.DelaySeconds,
				Reason:       payload.Reboot.Reason,
			},
		}

	case opspec.ActionReadJournal:
		request := &agentv1.ReadJournal{
			Unit:        payload.Journal.Unit,
			Lines:       payload.Journal.Lines,
			Since:       payload.Journal.Since,
			Until:       payload.Journal.Until,
			AfterCursor: payload.Journal.AfterCursor,
		}
		if payload.Journal.MaxPriority != nil {
			request.MaxPriority = payload.Journal.MaxPriority
		}
		envelope.Action = &agentv1.TaskEnvelope_ReadJournal{ReadJournal: request}
	default:
		operation, ok := unitOperations[action]
		if !ok {
			return nil, errUnknownAction(item.Job.ActionType)
		}
		envelope.Action = &agentv1.TaskEnvelope_UnitAction{
			UnitAction: &agentv1.UnitAction{Unit: payload.Unit.Unit, Operation: operation},
		}
	}
	return envelope, nil
}

var unitOperations = map[opspec.ActionType]agentv1.UnitAction_Operation{
	opspec.ActionUnitStart:   agentv1.UnitAction_OPERATION_START,
	opspec.ActionUnitStop:    agentv1.UnitAction_OPERATION_STOP,
	opspec.ActionUnitRestart: agentv1.UnitAction_OPERATION_RESTART,
	opspec.ActionUnitReload:  agentv1.UnitAction_OPERATION_RELOAD,
	// Clearing the failed state travels like the other unit operations: one
	// unit, one verb.
	opspec.ActionUnitResetFailed: agentv1.UnitAction_OPERATION_RESET_FAILED,
}

// localUserOperations translates an operation type into the contract's
// value. The map is explicit, so adding an action without a mapping does not
// pass the tests.
var localUserOperations = map[opspec.ActionType]agentv1.LocalUserAction_Operation{
	opspec.ActionLocalUserCreate: agentv1.LocalUserAction_OPERATION_CREATE,
	opspec.ActionLocalUserLock:   agentv1.LocalUserAction_OPERATION_LOCK,
	opspec.ActionLocalUserUnlock: agentv1.LocalUserAction_OPERATION_UNLOCK,
	opspec.ActionLocalSSHKeysSet: agentv1.LocalUserAction_OPERATION_SET_SSH_KEYS,
	// The groups, the expiry date and the deletion of an account.
	opspec.ActionLocalUserGroupsSet: agentv1.LocalUserAction_OPERATION_SET_GROUPS,
	opspec.ActionLocalUserExpirySet: agentv1.LocalUserAction_OPERATION_SET_EXPIRY,
	opspec.ActionLocalUserDelete:    agentv1.LocalUserAction_OPERATION_DELETE,
}

func approvalsOf(job jobs.Job) []string {
	if job.ApprovedBy == "" {
		return nil
	}
	return []string{job.ApprovedBy}
}

type unknownActionError string

func (e unknownActionError) Error() string { return "unknown operation type: " + string(e) }

// Permanent: a payload that cannot be turned into an envelope does not
// become one by waiting.
func (e unknownActionError) Permanent() bool { return true }

// permanentFailure says whether an envelope error is one that a retry
// cannot mend: an error that says so itself, or a payload that does not
// decode. A directory or a secret store that is merely unreachable is not
// one - the next pass may find it back.
func permanentFailure(err error) bool {
	var permanent interface{ Permanent() bool }
	if errors.As(err, &permanent) && permanent.Permanent() {
		return true
	}
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	return errors.As(err, &syntax) || errors.As(err, &typeErr)
}

func errUnknownAction(action string) error { return unknownActionError(action) }

// Jitter spreads the start of the first loop, so that restarting many
// replicas does not hit the database all at once.
func Jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(base)))
}

// dockerEnvelope builds the envelope of a container operation. Every
// operation type has its own payload, so the translation is explicit rather
// than by field name.
func dockerEnvelope(action opspec.ActionType, payload opspec.Payload) *agentv1.DockerAction {
	envelope := &agentv1.DockerAction{}
	if container := payload.DockerContainer; container != nil {
		envelope.ContainerId = container.ContainerID
		envelope.ContainerName = container.Name
		envelope.TimeoutSeconds = container.TimeoutSeconds
		envelope.RemoveVolumes = container.RemoveVolumes
	}
	if image := payload.DockerImage; image != nil {
		envelope.ImageReference = image.Reference
	}
	if prune := payload.DockerPrune; prune != nil {
		envelope.ImageIds = prune.ImageIDs
		envelope.VolumeNames = prune.VolumeName
		envelope.NetworkIds = prune.NetworkIDs
	}
	switch action {
	case opspec.ActionDockerStart:
		envelope.Operation = agentv1.DockerAction_OPERATION_START
	case opspec.ActionDockerStop:
		envelope.Operation = agentv1.DockerAction_OPERATION_STOP
	case opspec.ActionDockerRestart:
		envelope.Operation = agentv1.DockerAction_OPERATION_RESTART
	case opspec.ActionDockerRemove:
		envelope.Operation = agentv1.DockerAction_OPERATION_REMOVE
	case opspec.ActionDockerPull:
		envelope.Operation = agentv1.DockerAction_OPERATION_PULL_IMAGE
	case opspec.ActionDockerPrune:
		envelope.Operation = agentv1.DockerAction_OPERATION_PRUNE
	}
	return envelope
}
