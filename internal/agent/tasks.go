package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/systemd"
)

// StatusAfterReplacement marks a result there is no point in sending back: the
// agent has just been replaced and its return is what decides on the success.
const StatusAfterReplacement = "agent_upgrade_in_flight"

// StatusAwaitingReturn marks a result there is no point in sending back
// because the operation's verifier is the host coming up again: a restart.
const StatusAwaitingReturn = "reboot_in_flight"

// StatusInProgress marks the answer to a redelivery of an operation this
// process is still carrying out.
const StatusInProgress = "operation_in_progress"

// StageInProgress is the stage of the progress report that answers such a
// redelivery.
const StageInProgress = "in_progress"

// The stages of the acknowledgement of a task (TaskProgress. stage in agent.
// proto).
const (
	// StageAccepted says the agent holds the task and will carry it out: the
	// checks that refuse it without touching the host are behind, the wait ahead.
	StageAccepted = "accepted"
	// StageAwaitingLock says the task waits for a resource another task of
	// this host holds; the message names the blocker.
	StageAwaitingLock = "awaiting_lock"
	// StageStarted says the claims are taken and the operation is starting
	// this instant. The panel moves the job to running on it.
	StageStarted = "started"
)

// StatusAbandoned marks a task whose wait for the resources of the host ended
// with the session.
const StatusAbandoned = "session_ended"

// Stable refusal codes. They are part of the contract and do not depend on the
// language.
const (
	RejectExpired        = "expired"
	RejectPrecondition   = "precondition_failed"
	RejectPayloadHash    = "payload_hash_mismatch"
	RejectUnknownAction  = "unknown_action"
	RejectHelperFailed   = "helper_unavailable"
	RejectCapability     = "capability_missing"
	RejectInvalidRequest = "invalid_request"
	// RejectPreconditionChanged marks a task whose preconditions held when it
	// was accepted and no longer hold after its wait for a resource of the host.
	RejectPreconditionChanged = "precondition_changed"
	// RejectUnsupported marks an agent that by design performs no tasks.
	RejectUnsupported = "unsupported"
	// RejectInternalError marks an error on the side of the agent. The task ends
	// with a negative result instead of taking the whole process with it.
	RejectInternalError = "agent_internal_error"
	// RejectJournalUnavailable marks a mutation the agent did not start because
	// its journal could not take the in-flight marker.
	RejectJournalUnavailable = "journal_unavailable"
	// RejectNetworkUnreachable marks a network change after which the host lost
	// its route to the panel.
	RejectNetworkUnreachable = "network_unreachable"
	// RejectReadOnly marks a host running in observation mode.
	RejectReadOnly = "agent_read_only"
	// RejectResourceBusy marks a task that waited for a resource of the host and
	// did not get it.
	RejectResourceBusy = "resource_busy"
	// RejectOutcomeUnknown marks an operation the previous process of the agent
	// started and did not live to see the end of.
	RejectOutcomeUnknown = "outcome_unknown"
	// RejectHelperRejected marks a request the root helper refused at its own
	// check of the contract, before running anything.
	RejectHelperRejected = "helper_rejected"
	// RejectCanceledBeforeStart marks a task a cancel reached before the host
	// touched anything: during its checks or its wait for a resource.
	RejectCanceledBeforeStart = "canceled_before_start"
)

// TaskExecutor performs the tasks delivered by the control plane.
type TaskExecutor struct {
	helper  *HelperClient
	journal *IdempotencyJournal
	facts   func() Facts
	log     *slog.Logger
	// progress reports the progress of a long operation to the control plane. Nil
	// means there is no session - progress without a receiver is not collected.
	progress func(*agentv1.TaskProgress)
	// admit waits for the resources of the host a task needs - the locks of its
	// claims first, a budget slot second - and returns the release.
	admit func(ctx context.Context, task *agentv1.TaskEnvelope, claims []opspec.ResourceClaim,
		waiting func(blocker string)) (release func(), reason string)
	// logLines passes on the journal preview. Nil means there is no session, and
	// then the preview is not started at all: the host is not to work for nobody.
	logLines func(*agentv1.TaskLogLines)
	// cancels allows interrupting the tasks that can be interrupted safely.
	cancels *cancellations
	// phases records where every attempt handed to this process stands, so that
	// a cancel is answered by what it finds rather than by a guess.
	phases *taskPhases
	// secrets fetches the value of a secret for the duration of one operation.
	secrets SecretFetch
	// readOnly marks a host in observation mode: the agent reports facts and
	// performs reads, but changes nothing on the host.
	readOnly bool
	// inventoryRefresh orders an inventory collection and waits for the revision
	// that came out of it.
	inventoryRefresh func(ctx context.Context, modules []string) Refresh
	// hostID is what the agent's certificate names. Empty means the executor
	// was not told, and the rename preflight says so rather than guessing.
	hostID string
	// running holds the keys of the tasks inside Execute right now, so that a
	// redelivery still in progress is acknowledged as alive, not replayed.
	running *runningKeys
	// packageState reads what the package adapter can say cheaply about the host.
	packageState PackageStateProbe
	// verifyReaders are the reads the verifiers observe the host through after a
	// change.
	verifyReaders *hostReaders
	// taskSecrets holds what a running task has fetched, so the read, the change
	// and the verification after it share one lease of the secret.
	secretsMu   sync.Mutex
	taskSecrets map[string][]byte
}

// SecretFetch reaches for the value of the secret named in the task.
type SecretFetch func(ctx context.Context, taskID, name string, version int) ([]byte, error)

func NewTaskExecutor(helperClient *HelperClient, journal *IdempotencyJournal,
	facts func() Facts, log *slog.Logger) *TaskExecutor {
	executor := &TaskExecutor{
		helper: helperClient, journal: journal, facts: facts, log: log,
		cancels:      newCancellationTable(),
		phases:       newTaskPhases(),
		running:      newRunningKeys(),
		packageState: packageStateNow,
	}
	// A marker without a result is an operation the previous process did not
	// finish reporting on.
	executor.reportInFlight()
	// The session reports the helper's capability mode and hands it the
	// panel's keys through this client.
	registerSessionHelper(helperClient)
	return executor
}

// SetReadOnlyMode turns on observation mode: the agent performs no mutation.
func (e *TaskExecutor) SetReadOnlyMode(readOnly bool) {
	e.readOnly = readOnly
	helperProbeDisabled.Store(readOnly)
}

// Execute carries out a task and always returns a result - also when the task
// was refused.
func (e *TaskExecutor) Execute(ctx context.Context, task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	taskID := task.GetTaskId()
	idempotencyKey := task.GetIdempotencyKey()
	started := time.Now().UTC()

	// A delivery of a task this process is still working on is neither a replay
	// nor a failure: the work is under way, and the panel is told so.
	if current, claimed := e.running.claim(idempotencyKey, taskID, started); !claimed {
		e.acknowledgeRunning(task, current)
		return inProgress(task)
	}
	defer e.running.release(idempotencyKey)
	// Whatever this task fetched from the secret store is forgotten with it,
	// whichever way it ends, and the pages it needed go back to the host.
	defer e.forgetTaskSecrets(taskID)
	defer releaseAfterTask()

	// The task runs under a context of its own, which a cancel arriving before the
	// start closes, ending the checks and the wait for the host's resources.
	taskCtx, stop := context.WithCancel(ctx)
	defer stop()
	if e.phases.enter(taskID, idempotencyKey, stop) {
		e.log.Info("the task was refused: a cancel reached it before its delivery", "task_id", taskID)
		result := canceledBeforeStart(task, "a cancel reached the task before it was delivered")
		e.phases.finish(taskID, result)
		return result
	}
	ctx = taskCtx

	// A repeated delivery returns the previous result instead of performing the
	// mutation a second time. That is the whole point of at-least-once.
	if previous := e.journal.Lookup(idempotencyKey); previous != nil {
		e.log.Info("a repeated delivery of the operation, returning the stored result",
			"task_id", taskID, "idempotency_key", idempotencyKey, "status", previous.GetStatus())
		replayed := cloneResult(previous)
		// task_id points at the current attempt so that the server can correlate
		// the result.
		replayed.TaskId = taskID
		replayed.Replayed = true
		e.phases.finish(taskID, replayed)
		return replayed
	}

	// A marker without a result: the previous process of the agent started the
	// operation and stopped before writing down how it ended.
	if marker, found := e.journal.InFlight(idempotencyKey); found {
		e.log.Warn("the task was in flight when the previous process of the agent stopped; answering with an unknown outcome",
			"task_id", taskID, "previous_task_id", marker.TaskID, "action", marker.Action,
			"started_at", marker.StartedAt.Format(time.RFC3339))
		result := e.outcomeUnknown(ctx, marker)
		e.settle(task, result, marker.StartedAt)
		e.phases.finish(taskID, result)
		return result
	}

	settled := false
	defer func() {
		if settled {
			return
		}
		// Whatever the exit, the attempt is over for the cancel protocol:
		// a cancel of it from here on finds a task that ended.
		e.phases.finish(taskID, nil)
		// Leaving without a result - a panic on the way - must not leave the marker
		// for a later delivery to judge as a restart.
		if marker, found := e.journal.InFlight(idempotencyKey); found {
			e.settle(task, e.outcomeUnknown(ctx, marker), marker.StartedAt)
		}
	}()
	// The panel's authorization of the task rides on every helper request made
	// for it, attached by the client in one place.
	if capability := task.GetHelperCapability(); capability != nil {
		if !bytes.Equal(helpercap.PayloadDigest(task.GetCanonicalPayload()), capability.GetPayloadSha256()) {
			result := rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
				"the helper capability does not bind the payload of the task")
			e.settle(task, result, started)
			settled = true
			e.phases.finish(taskID, result)
			return result
		}
		e.helper.Attach(taskID, capability, task.GetHelperCapabilitySignature(), task.GetCanonicalPayload())
		defer e.helper.Detach(taskID)
	}
	result := e.run(ctx, task, started)
	switch result.GetErrorCode() {
	case RejectResourceBusy, StatusAbandoned, RejectCanceledBeforeStart:
		// The task never reached the host: it waited for a resource and the wait
		// ended, with a refusal, with the session or with a cancel.
		result.TaskId = task.GetTaskId()
		result.IdempotencyKey = idempotencyKey
	default:
		e.settle(task, result, started)
	}
	settled = true
	e.phases.finish(taskID, result)
	return result
}

// canceledBeforeStart is the result of a task a cancel reached before it
// started: nothing ran on the host.
func canceledBeforeStart(task *agentv1.TaskEnvelope, why string) *agentv1.TaskResult {
	result := rejected(agentv1.TaskResult_STATUS_CANCELED, RejectCanceledBeforeStart, why)
	result.TaskId = task.GetTaskId()
	result.IdempotencyKey = task.GetIdempotencyKey()
	return result
}

// lookup returns the interruption registered for a task without calling it.
func (c *cancellations) lookup(taskID string) (context.CancelFunc, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cancel, known := c.actions[taskID]
	return cancel, known
}

// CancelTask answers a cancel for an attempt: the outcome and the phase for
// the acknowledgement, the hash of a finished result, and the interruption.
func (e *TaskExecutor) CancelTask(taskID string) (outcome agentv1.CancelAck_Outcome,
	phase string, resultHash []byte, interrupt func()) {
	if e == nil {
		return agentv1.CancelAck_NOT_STARTED, PhaseNotDelivered, nil, nil
	}
	if origin := e.running.origin(taskID); origin != "" {
		taskID = origin
	}
	var interruptible func(string) (context.CancelFunc, bool)
	if e.cancels != nil {
		interruptible = e.cancels.lookup
	}
	outcome, phase, resultHash, stop := e.phases.answer(taskID, interruptible)
	if stop != nil {
		interrupt = func() { stop() }
	}
	return outcome, phase, resultHash, interrupt
}

// reportStage sends one stage of the acknowledgement of a task.
func (e *TaskExecutor) reportStage(task *agentv1.TaskEnvelope, stage, message string, claims []string) {
	if e.progress == nil {
		return
	}
	e.progress(&agentv1.TaskProgress{
		TaskId:  task.GetTaskId(),
		Stage:   stage,
		Message: message,
		Claims:  claims,
	})
}

// Redelivered answers a delivery of a key this process is still executing,
// before the session queues the task behind the locks of the host.
func (e *TaskExecutor) Redelivered(task *agentv1.TaskEnvelope) bool {
	current, running := e.running.redeliver(task.GetIdempotencyKey(), task.GetTaskId())
	if !running {
		return false
	}
	e.acknowledgeRunning(task, current)
	return true
}

// acknowledgeRunning reports a redelivered attempt as alive.
func (e *TaskExecutor) acknowledgeRunning(task *agentv1.TaskEnvelope, current execution) {
	e.log.Info("a redelivery of an operation still under way; the attempt is answered as in progress",
		"task_id", task.GetTaskId(), "previous_task_id", current.taskID,
		"idempotency_key", task.GetIdempotencyKey(),
		"started_at", current.startedAt.Format(time.RFC3339))
	if e.progress == nil {
		return
	}
	e.progress(&agentv1.TaskProgress{
		TaskId:         task.GetTaskId(),
		Stage:          StageInProgress,
		Message:        fmt.Sprintf("the operation is still under way on this host; started %s", current.startedAt.Format(time.RFC3339)),
		PreviousTaskId: current.taskID,
	})
}

// inProgress is the placeholder Execute returns for an acknowledged
// redelivery.
func inProgress(task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	return &agentv1.TaskResult{
		TaskId:         task.GetTaskId(),
		IdempotencyKey: task.GetIdempotencyKey(),
		Status:         agentv1.TaskResult_STATUS_UNSPECIFIED,
		ErrorCode:      StatusInProgress,
		Message:        "the operation is still under way; the attempt was acknowledged as in progress",
	}
}

// RedeliveredCopy returns the copy of a final result owed to the attempt the
// panel redelivered while the result was computed, addressed to that attempt.
func (e *TaskExecutor) RedeliveredCopy(result *agentv1.TaskResult) *agentv1.TaskResult {
	// An agent without an executor - the simulator - runs nothing, so it
	// owes nothing.
	if e == nil {
		return nil
	}
	latest := e.running.followUp(result.GetTaskId())
	if latest == "" {
		return nil
	}
	copied := cloneResult(result)
	copied.TaskId = latest
	copied.Replayed = true
	return copied
}

// settle stamps the result with the attempt and the times and stores it in
// the journal, where it replaces the in-flight marker of the same key.
func (e *TaskExecutor) settle(task *agentv1.TaskEnvelope, result *agentv1.TaskResult, started time.Time) {
	taskID := task.GetTaskId()
	idempotencyKey := task.GetIdempotencyKey()
	result.TaskId = taskID
	result.IdempotencyKey = idempotencyKey
	result.StartedAt = timestamppb.New(started)
	result.FinishedAt = timestamppb.New(time.Now().UTC())

	if err := e.journal.Store(idempotencyKey, result); err != nil {
		e.log.Error("the result was not stored in the idempotency journal",
			"task_id", taskID, "idempotency_key", idempotencyKey, "err", err)
	}
}

func (e *TaskExecutor) run(ctx context.Context, task *agentv1.TaskEnvelope, now time.Time) *agentv1.TaskResult {
	// The TTL is checked before anything else: a task that arrived after the
	// network came back must not be performed.
	if expires := task.GetExpiresAt(); expires != nil && now.After(expires.AsTime()) {
		return rejected(agentv1.TaskResult_STATUS_EXPIRED, RejectExpired,
			fmt.Sprintf("the task expired at %s", expires.AsTime().Format(time.RFC3339)))
	}

	facts := e.facts()
	if err := checkPreconditions(task.GetPreconditions(), facts); err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition, err.Error())
	}

	action, payload, err := decodeAction(task)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectUnknownAction, err.Error())
	}
	// Observation mode refuses a mutation before anything else is checked: a
	// host that is only to watch has no right even to try.
	if e.readOnly && action.Mutating() {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectReadOnly,
			"the agent works in read_only mode and performs no changes")
	}
	if capability := action.RequiredCapability(); !facts.Capabilities.Satisfies(capability) {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectCapability,
			fmt.Sprintf("the host does not have the capability %s", capability))
	}

	// The hash of the plan is computed locally and compared with the envelope.
	if expected := task.GetPayloadHash(); len(expected) > 0 {
		if err := verifyPayloadHash(action, payload); err != nil {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, err.Error())
		}
		if !payloadHashMatches(action, payload, expected) {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPayloadHash,
				"the content of the task does not match the approved plan")
		}
	}

	// Every check that can refuse the task without touching the host is behind
	// us: the task is accepted.
	claims := taskClaims(task)
	e.reportStage(task, StageAccepted, "", nil)
	// A cancel that arrived during the checks refuses the task here:
	// nothing has touched the host, and nothing will.
	if e.phases.canceledBeforeStart(task.GetTaskId()) {
		return canceledBeforeStart(task, "a cancel reached the task before it started")
	}
	if e.admit != nil {
		release, reason := e.admit(ctx, task, claims, func(blocker string) {
			e.log.Info("the task waits for a resource of the host",
				"task_id", task.GetTaskId(), "blocker", blocker)
			e.phases.move(task.GetTaskId(), PhaseAwaitingLock)
			e.reportStage(task, StageAwaitingLock, blocker, nil)
		})
		if reason != "" {
			// A refusal naming the blocking task is an answer; silence
			// until the end of the time limit of the operation is not.
			e.log.Info("the task was refused by a resource lock",
				"task_id", task.GetTaskId(), "reason", reason)
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectResourceBusy, reason)
		}
		if release == nil {
			// The wait ended without the resources: with the session, or with a cancel
			// that closed the task's context.
			if e.phases.canceledBeforeStart(task.GetTaskId()) {
				return canceledBeforeStart(task, "a cancel reached the task while it waited for the resources of the host")
			}
			return rejected(agentv1.TaskResult_STATUS_UNSPECIFIED, StatusAbandoned,
				"the session ended while the task waited for the resources of the host")
		}
		defer release()
		// The resources are held; a cancel that arrived meanwhile still
		// finds nothing started, and the task gives them back unused.
		if e.phases.canceledBeforeStart(task.GetTaskId()) {
			return canceledBeforeStart(task, "a cancel reached the task before it started")
		}

		// The preconditions were checked before the wait, against the host as it was
		// then.
		if err := checkPreconditions(task.GetPreconditions(), e.facts()); err != nil {
			e.log.Info("the preconditions changed while the task waited for the resources of the host",
				"task_id", task.GetTaskId(), "reason", err.Error())
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPreconditionChanged,
				"the preconditions changed while the task waited for the resources of the host: "+err.Error())
		}
	}

	// From here on the host may change, so the journal says so before the helper
	// is asked: without the marker a restart could not tell that it ran.
	if err := e.markInFlight(task, action, payload, now); err != nil {
		// Not knowing is allowed; a silent second execution is not. A host
		// whose journal cannot take the marker performs no mutation.
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectJournalUnavailable,
			"the in-flight marker was not written to the journal: "+err.Error())
	}
	// The marker is down and the claims are held: the operation starts this
	// instant, and the panel counts the host as running from here.
	if action.Mutating() {
		e.phases.move(task.GetTaskId(), PhaseMutating)
	} else {
		e.phases.move(task.GetTaskId(), PhaseStarted)
	}
	e.reportStage(task, StageStarted, "", claimNames(claims))

	// The state the host is in before the change: the verifier compares against
	// it where the promise is relative, such as a key that must differ.
	before := e.observeBaseline(ctx, task, action, payload)
	result := e.perform(ctx, task, action, payload)
	// The change is done; now the host is read again and the result says
	// what was seen. A change nobody could observe is not a success.
	return e.verifyOutcome(ctx, task, action, payload, before, result)
}

// perform hands the task to the module of its operation.
func (e *TaskExecutor) perform(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload opspec.Payload) *agentv1.TaskResult {
	switch action {
	case opspec.ActionReadJournal:
		return e.readJournal(ctx, task, payload.Journal)
	case opspec.ActionPackagePlan:
		return e.planPackages(ctx, task, payload.PackagePlan)
	case opspec.ActionPackageUpgrade:
		return e.upgradePackages(ctx, task, payload.PackageUpgrade)
	case opspec.ActionAgentUpgrade:
		return e.upgradeAgent(ctx, task, payload.AgentUpgrade)
	case opspec.ActionPackageRepair:
		return e.repairPackages(ctx, task, payload.PackageRepair)
	case opspec.ActionSystemReboot:
		return e.rebootHost(ctx, task, payload.Reboot)
	case opspec.ActionUnitStatus:
		return e.readUnitStatus(ctx, task, payload.UnitStatus)
	case opspec.ActionDockerRead:
		return e.readDocker(ctx, task)
	case opspec.ActionDockerEvents:
		return e.readDockerEvents(ctx, task)
	case opspec.ActionDockerLogs:
		return e.readDockerLogs(ctx, task, payload.DockerLogs)
	case opspec.ActionSystemHostnameSet:
		return e.setHostname(ctx, task, payload.Hostname)
	case opspec.ActionStorageSmartRead:
		return e.readSmart(ctx, task, payload.Storage)
	case opspec.ActionInventoryRefresh:
		return e.refreshInventory(ctx, task)
	case opspec.ActionDockerStart, opspec.ActionDockerStop, opspec.ActionDockerRestart,
		opspec.ActionDockerRemove, opspec.ActionDockerPull, opspec.ActionDockerPrune:
		return e.applyDocker(ctx, task, task.GetDockerAction())
	case opspec.ActionComposePlan, opspec.ActionComposeDeploy:
		return e.applyCompose(ctx, task, task.GetCompose())
	case opspec.ActionDockerPlan, opspec.ActionDockerContainerEnsure,
		opspec.ActionDockerNetworkEnsure, opspec.ActionDockerNetworkRemove,
		opspec.ActionDockerVolumeEnsure, opspec.ActionDockerVolumeRemove:
		return e.applyDockerEnsure(ctx, task, action, payload.DockerEnsure)
	case opspec.ActionUnitEnableSet, opspec.ActionUnitMaskSet:
		return e.applyUnitToggle(ctx, task, action, task.GetUnitToggle())
	case opspec.ActionReadLogFile:
		return e.readLogFile(ctx, task, payload.LogFile)
	case opspec.ActionFollowJournal:
		return e.followJournal(ctx, task, payload.Journal)
	case opspec.ActionPackageInstall, opspec.ActionPackageRemove, opspec.ActionPackageHoldSet:
		return e.applyPackageLifecycle(ctx, task, action, payload.PackageChange)
	case opspec.ActionFilePlan, opspec.ActionFileRead, opspec.ActionFileEnsure,
		opspec.ActionFileRemove, opspec.ActionFileRollback:
		return e.applyFile(ctx, task, action, payload.File)
	case opspec.ActionSysctlPlan, opspec.ActionSysctlEnsure, opspec.ActionKernelModulePlan,
		opspec.ActionKernelModuleLoad, opspec.ActionKernelModuleBlacklist:
		return e.applyKernel(ctx, task, action, payload.Kernel)
	case opspec.ActionTimeSyncTest, opspec.ActionTimePlan, opspec.ActionTimeConfigApply,
		opspec.ActionTimezoneSet:
		return e.applyTime(ctx, task, action, payload.Time)
	case opspec.ActionSystemShutdown:
		return e.shutdownHost(ctx, task, payload.Power)
	case opspec.ActionSecurityScan, opspec.ActionSELinuxModeSet, opspec.ActionAuditRulesReload:
		return e.applySecurity(ctx, task, action, payload.Security)
	case opspec.ActionCertificateScan, opspec.ActionCertificatePlan, opspec.ActionCertificateDeploy,
		opspec.ActionCertificateTrustPlan, opspec.ActionCertificateTrustEnsure,
		opspec.ActionCertificateTrustRemove,
		opspec.ActionCertificateRenew:
		return e.applyCertificate(ctx, task, action, payload.Certificate)
	case opspec.ActionRepositorySet:
		return e.applyRepository(ctx, task, action, payload.Repository)
	case opspec.ActionBackupPlan, opspec.ActionBackupRun,
		opspec.ActionBackupVerify, opspec.ActionBackupRestore:
		return e.applyBackup(ctx, task, action, payload.Backup)
	case opspec.ActionMonitoringProbe:
		return e.applyProbe(ctx, task, action, payload.Monitoring)
	case opspec.ActionPackageList:
		return e.listPackages(ctx, task, action)
	case opspec.ActionSSHConfigPlan, opspec.ActionSSHConfigApply,
		opspec.ActionSSHHostKeyRotate:
		return e.applySSH(ctx, task, action, payload.SSH)
	case opspec.ActionStoragePlan, opspec.ActionMountEnsure,
		opspec.ActionMountRemove, opspec.ActionFilesystemCheck,
		opspec.ActionLVMExtend, opspec.ActionFilesystemResize,
		opspec.ActionFilesystemCreate, opspec.ActionDiskWipe,
		opspec.ActionRAIDMemberFail, opspec.ActionRAIDMemberRemove,
		opspec.ActionRAIDMemberAdd, opspec.ActionLVMVolumeCreate,
		opspec.ActionLVMVolumeRemove, opspec.ActionLVMGroupExtend,
		opspec.ActionLVMSnapshotCreate, opspec.ActionLVMSnapshotRemove:
		return e.applyStorage(ctx, task, action, payload.Storage)
	case opspec.ActionFirewallPlan, opspec.ActionFirewallRuleEnsure,
		opspec.ActionFirewallRuleRemove, opspec.ActionFirewallZonePort,
		opspec.ActionFirewallZoneService, opspec.ActionFirewallRulesetRestore:
		return e.applyFirewall(ctx, task, action, payload.Firewall)
	case opspec.ActionDNSResolveTest, opspec.ActionDNSPlan, opspec.ActionDNSHostApply:
		return e.applyDNS(ctx, task, action, payload.DNS)
	case opspec.ActionNetworkPlan, opspec.ActionNetworkMTUSet,
		opspec.ActionNetworkRouteEnsure, opspec.ActionNetworkProfileApply,
		opspec.ActionNetworkRollback,
		opspec.ActionNetworkLinkApply, opspec.ActionNetworkLinkRemove:
		return e.applyNetwork(ctx, task, action, payload.Network)
	case opspec.ActionScheduleEnsure, opspec.ActionScheduleDisable,
		opspec.ActionScheduleRemove, opspec.ActionScheduleRunNow:
		return e.applySchedule(ctx, task, action, payload.Schedule)
	case opspec.ActionSchedulePreview:
		return e.previewSchedule(task, payload.Schedule)
	case opspec.ActionProcessList:
		return e.listProcesses(ctx, task, payload.ProcessList)
	case opspec.ActionProcessSignal:
		return e.signalProcess(ctx, task, payload.ProcessSignal)
	case opspec.ActionLocalUserCreate, opspec.ActionLocalUserLock,
		opspec.ActionLocalUserUnlock, opspec.ActionLocalSSHKeysSet,
		opspec.ActionLocalSSHKeysAdd, opspec.ActionLocalSSHKeysRemove,
		opspec.ActionLocalSSHKeysReplaceAll,
		opspec.ActionLocalUserGroupsSet, opspec.ActionLocalUserExpirySet,
		opspec.ActionLocalUserDelete:
		return e.applyLocalUser(ctx, task, action, payload.LocalUser)
	case opspec.ActionDomainPreflight:
		return e.enrollDomain(ctx, task, payload.DomainEnroll, true)
	case opspec.ActionDomainEnroll:
		return e.enrollDomain(ctx, task, payload.DomainEnroll, false)
	case opspec.ActionDomainLeave:
		return e.leaveDomain(ctx, task, payload.DomainLeave)
	case opspec.ActionIdentityKeytabRenew:
		return e.renewKeytab(ctx, task, payload.Keytab)
	default:
		return e.applyUnitAction(ctx, task, action, payload.Unit)
	}
}

// readUnitStatus reads the state of the units. The operation is non-mutating
// and works without root, so it does not go through the helper.
func (e *TaskExecutor) readUnitStatus(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.UnitStatusPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, opspec.ActionUnitStatus)
	statusCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The full list of units is a separate path: systemd is not asked about each
	// of them separately, because a host sometimes has hundreds of them.
	if payload.All {
		return e.listUnits(statusCtx, task)
	}
	// The full picture of a few units is a separate path as well: it starts
	// several processes per unit and reads files.
	if payload.Detail {
		return e.detailUnits(statusCtx, task, payload.Units)
	}

	states := make([]*agentv1.UnitState, 0, len(payload.Units))
	unhealthy := make([]string, 0)
	for _, unit := range payload.Units {
		state, err := systemd.Show(statusCtx, unit)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, err.Error())
		}
		states = append(states, &agentv1.UnitState{
			Name:          state.Name,
			LoadState:     state.LoadState,
			ActiveState:   state.ActiveState,
			SubState:      state.SubState,
			UnitFileState: state.UnitFileState,
			Result:        state.Result,
			MainPid:       state.MainPID,
			NRestarts:     state.NRestarts,
		})
		if !state.Healthy() {
			unhealthy = append(unhealthy, unit)
		}
	}

	result := &agentv1.TaskResult{
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Detail:   &agentv1.TaskResult_UnitStatus{UnitStatus: &agentv1.UnitStatusResult{Units: states}},
	}
	// An unhealthy unit is a negative result and not an execution error: the
	// read succeeded, only the state of the host does not meet expectations.
	if len(unhealthy) > 0 {
		result.Status = agentv1.TaskResult_STATUS_FAILED
		result.ExitCode = 1
		result.ErrorCode = "unit_unhealthy"
		result.Message = "units in a bad state: " + strings.Join(unhealthy, ", ")
	}
	return result
}

// detailUnits reads the full picture of a few units: the dependencies, the
// drop-ins with their content, and the last journal lines with their cursor.
func (e *TaskExecutor) detailUnits(ctx context.Context, task *agentv1.TaskEnvelope,
	units []string) *agentv1.TaskResult {
	details := make([]systemd.UnitDetail, 0, len(units))
	typed := make([]*agentv1.UnitDetail, 0, len(units))
	for _, unit := range units {
		detail, err := systemd.ShowDetail(ctx, unit)
		if err != nil {
			status := agentv1.TaskResult_STATUS_REJECTED
			if ctx.Err() != nil {
				status = agentv1.TaskResult_STATUS_TIMED_OUT
			}
			return rejected(status, RejectInvalidRequest, err.Error())
		}
		details = append(details, detail)
		typed = append(typed, unitDetailToAgent(detail))
	}

	encoded, err := json.Marshal(map[string]any{"kind": "unit_detail", "units": details})
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	// A cut JSON document is no document at all, so the limit refuses the
	// result instead of trimming it.
	limit := int(task.GetLimits().GetMaxOutputBytes())
	if limit > 0 && len(encoded) > limit {
		return rejected(agentv1.TaskResult_STATUS_FAILED, "output_too_large",
			fmt.Sprintf("the unit detail takes %d bytes, the task allows %d", len(encoded), limit))
	}
	return &agentv1.TaskResult{
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Stdout:   encoded,
		Detail: &agentv1.TaskResult_UnitStatus{
			UnitStatus: &agentv1.UnitStatusResult{Details: typed},
		},
	}
}

// unitDetailToAgent translates the detail into the contract message.
func unitDetailToAgent(detail systemd.UnitDetail) *agentv1.UnitDetail {
	dropIns := make([]*agentv1.UnitDropIn, 0, len(detail.DropIns))
	for _, dropIn := range detail.DropIns {
		dropIns = append(dropIns, &agentv1.UnitDropIn{
			Path:      dropIn.Path,
			Content:   dropIn.Content,
			Truncated: dropIn.Truncated,
			Error:     dropIn.Error,
		})
	}
	return &agentv1.UnitDetail{
		State: &agentv1.UnitState{
			Name:          detail.State.Name,
			LoadState:     detail.State.LoadState,
			ActiveState:   detail.State.ActiveState,
			SubState:      detail.State.SubState,
			UnitFileState: detail.State.UnitFileState,
			Result:        detail.State.Result,
			MainPid:       detail.State.MainPID,
			NRestarts:     detail.State.NRestarts,
		},
		Description:      detail.Description,
		FragmentPath:     detail.FragmentPath,
		Requires:         detail.Requires,
		Wants:            detail.Wants,
		After:            detail.After,
		Before:           detail.Before,
		BindsTo:          detail.BindsTo,
		PartOf:           detail.PartOf,
		TriggeredBy:      detail.TriggeredBy,
		Triggers:         detail.Triggers,
		DropIns:          dropIns,
		ExecMainStart:    detail.ExecMainStart,
		JournalLines:     detail.JournalLines,
		JournalCursor:    detail.JournalCursor,
		JournalTruncated: detail.JournalTruncated,
		JournalError:     detail.JournalError,
	}
}

// rebootHost orders a restart through the helper.
func (e *TaskExecutor) rebootHost(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.RebootPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, opspec.ActionSystemReboot)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	delay := payload.DelaySeconds
	if delay == 0 {
		delay = 15
	}

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_Reboot{
			Reboot: &helperv1.RebootRequest{DelaySeconds: delay, Reason: payload.Reason},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	if !response.GetAccepted() {
		return rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
	}
	return &agentv1.TaskResult{
		TaskId:    task.GetTaskId(),
		Status:    agentv1.TaskResult_STATUS_UNSPECIFIED,
		ErrorCode: StatusAwaitingReturn,
		Stdout:    response.GetStdout(),
		Message:   "the restart was scheduled; the return of the host decides the result",
	}
}

func (e *TaskExecutor) applyUnitAction(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.UnitPayload) *agentv1.TaskResult {
	// The unit handler is the last branch of the dispatch, so an operation the
	// switch forgot lands here with a payload of another shape.
	if payload == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectUnknownAction,
			"this agent does not know how to perform "+string(action))
	}
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout+15*time.Second)
	defer cancel()

	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_UnitAction{
			UnitAction: &helperv1.UnitActionRequest{
				Unit:      payload.Unit,
				Operation: helperOperation(action, task),
			},
		},
	}, timeout)
	if err != nil {
		// An unavailable helper is a failure of the agent, not a result of the
		// operation.
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}

	if !response.GetAccepted() {
		status := agentv1.TaskResult_STATUS_REJECTED
		if response.GetErrorCode() == "timeout" {
			status = agentv1.TaskResult_STATUS_TIMED_OUT
		}
		result := rejected(status, response.GetErrorCode(), response.GetMessage())
		result.UnitStateBefore = unitStateToAgent(response.GetStateBefore())
		return result
	}

	result := &agentv1.TaskResult{
		Status:          agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode:        response.GetExitCode(),
		Stdout:          response.GetStdout(),
		Stderr:          response.GetStderr(),
		OutputTruncated: response.GetOutputTruncated(),
		UnitStateBefore: unitStateToAgent(response.GetStateBefore()),
		UnitStateAfter:  unitStateToAgent(response.GetStateAfter()),
	}
	// A non-zero exit code is a failure of the operation and not of the agent.
	if response.GetExitCode() != 0 {
		result.Status = agentv1.TaskResult_STATUS_FAILED
		result.ErrorCode = systemd.ErrorCodeForExit(int(response.GetExitCode()))
		result.Message = firstLine(string(response.GetStderr()))
	}
	return result
}

// helperOperation translates the type of an operation into a helper command.
func helperOperation(action opspec.ActionType, task *agentv1.TaskEnvelope) helperv1.UnitActionRequest_Operation {
	toggle := task.GetUnitToggle()
	switch action {
	case opspec.ActionUnitEnableSet:
		if toggle.GetValue() {
			return helperv1.UnitActionRequest_OPERATION_ENABLE
		}
		return helperv1.UnitActionRequest_OPERATION_DISABLE
	case opspec.ActionUnitMaskSet:
		if toggle.GetValue() {
			return helperv1.UnitActionRequest_OPERATION_MASK
		}
		return helperv1.UnitActionRequest_OPERATION_UNMASK
	}
	return helperOperations[action]
}

var helperOperations = map[opspec.ActionType]helperv1.UnitActionRequest_Operation{
	opspec.ActionUnitStart:   helperv1.UnitActionRequest_OPERATION_START,
	opspec.ActionUnitStop:    helperv1.UnitActionRequest_OPERATION_STOP,
	opspec.ActionUnitRestart: helperv1.UnitActionRequest_OPERATION_RESTART,
	opspec.ActionUnitReload:  helperv1.UnitActionRequest_OPERATION_RELOAD,
	// Clearing the failed state goes through the helper like every other
	// unit verb: systemctl reset-failed needs the manager's consent.
	opspec.ActionUnitResetFailed: helperv1.UnitActionRequest_OPERATION_RESET_FAILED,
}

// checkPreconditions checks whether the base state has changed since the
// planning.
func checkPreconditions(preconditions *agentv1.Preconditions, facts Facts) error {
	if preconditions == nil {
		return nil
	}
	if want := preconditions.GetOsFamily(); want != "" && want != facts.OS.Family {
		return fmt.Errorf("the system %s was expected, the host has %s", want, facts.OS.Family)
	}
	for _, capability := range preconditions.GetRequiredCapabilities() {
		if !facts.Capabilities.Satisfies(capability) {
			return fmt.Errorf("the host does not have the capability %s", capability)
		}
	}
	// A changed boot_id means the host managed to restart since the planning.
	if want := preconditions.GetExpectedBootId(); want != "" && want != facts.BootID {
		return fmt.Errorf("the host has been restarted since the planning")
	}
	return nil
}

// verifyPayloadHash says whether the payload can be hashed at all.
func verifyPayloadHash(action opspec.ActionType, payload opspec.Payload) error {
	_, err := opspec.PayloadHash(action, opspec.ActionVersion, payload)
	return err
}

// payloadHashMatches compares the envelope's hash with the one computed here
// over the payload as received.
func payloadHashMatches(action opspec.ActionType, payload opspec.Payload, expected []byte) bool {
	for _, scheme := range opspec.PayloadHashSchemes {
		computed, err := opspec.PayloadHashOfScheme(scheme, action, opspec.ActionVersion, payload)
		if err == nil && bytes.Equal(expected, computed) {
			return true
		}
	}
	return false
}

// decodeAction translates an envelope into the type of the operation and the
// payload in its canonical form.
func decodeAction(task *agentv1.TaskEnvelope) (opspec.ActionType, opspec.Payload, error) {
	switch action := task.GetAction().(type) {
	case *agentv1.TaskEnvelope_UnitAction:
		actionType, ok := unitActionTypes[action.UnitAction.GetOperation()]
		if !ok {
			return "", opspec.Payload{}, fmt.Errorf("unknown unit operation")
		}
		return actionType, opspec.Payload{
			Unit: &opspec.UnitPayload{Unit: action.UnitAction.GetUnit()},
		}, nil

	case *agentv1.TaskEnvelope_PackagePlan:
		request := action.PackagePlan
		return opspec.ActionPackagePlan, opspec.Payload{
			PackagePlan: &opspec.PackagePlanPayload{
				Mode:            request.GetMode(),
				RefreshMetadata: request.GetRefreshMetadata(),
				OnlyPackages:    request.GetOnlyPackages(),
				SecurityOnly:    request.GetSecurityOnly(),
			},
		}, nil

	case *agentv1.TaskEnvelope_PackageUpgrade:
		request := action.PackageUpgrade
		payload := opspec.PackageUpgradePayload{
			Packages:     request.GetPackages(),
			SecurityOnly: request.GetSecurityOnly(),
		}
		if len(request.GetPlanHash()) > 0 {
			payload.PlanHash = hex.EncodeToString(request.GetPlanHash())
		}
		payload.Plan = planReferenceFromProto(request.GetPlanReference())
		return opspec.ActionPackageUpgrade, opspec.Payload{PackageUpgrade: &payload}, nil

	case *agentv1.TaskEnvelope_AgentUpgrade:
		request := action.AgentUpgrade
		return opspec.ActionAgentUpgrade, opspec.Payload{
			AgentUpgrade: &opspec.AgentUpgradePayload{
				TargetVersion:   request.GetTargetVersion(),
				PackageSHA256:   request.GetPackageSha256(),
				PackageSigner:   request.GetPackageSigner(),
				RollbackVersion: request.GetRollbackVersion(),
				ReleaseRollback: request.GetReleaseRollback(),
			},
		}, nil

	case *agentv1.TaskEnvelope_SystemReboot:
		request := action.SystemReboot
		return opspec.ActionSystemReboot, opspec.Payload{
			Reboot: &opspec.RebootPayload{
				DelaySeconds: request.GetDelaySeconds(),
				Reason:       request.GetReason(),
			},
		}, nil

	case *agentv1.TaskEnvelope_DomainEnroll:
		request := action.DomainEnroll
		actionType := opspec.ActionDomainEnroll
		if request.GetPreflightOnly() {
			actionType = opspec.ActionDomainPreflight
		}
		// The one-time password does not enter the canonical payload, so it does
		// not affect the hash of the plan and cannot be recovered from it.
		return actionType, opspec.Payload{
			DomainEnroll: &opspec.DomainEnrollPayload{
				Domain:   request.GetDomain(),
				Realm:    request.GetRealm(),
				Server:   request.GetServer(),
				Hostname: request.GetHostname(),
			},
		}, nil

	case *agentv1.TaskEnvelope_DomainLeave:
		request := action.DomainLeave
		return opspec.ActionDomainLeave, opspec.Payload{
			DomainLeave: &opspec.DomainLeavePayload{
				Domain: request.GetDomain(),
				Realm:  request.GetRealm(),
			},
		}, nil

	case *agentv1.TaskEnvelope_KeytabRenew:
		return opspec.ActionIdentityKeytabRenew, opspec.Payload{
			Keytab: &opspec.KeytabPayload{Principal: action.KeytabRenew.GetPrincipal()},
		}, nil

	case *agentv1.TaskEnvelope_PackagesRepair:
		// An empty list and a missing list have to give the same payload: the plan's
		// hash comes from the JSON, where nil and an empty array differ.
		var answers []opspec.DebconfAnswer
		for _, answer := range action.PackagesRepair.GetAnswers() {
			answers = append(answers, opspec.DebconfAnswer{
				Package:  answer.GetPackage(),
				Question: answer.GetQuestion(),
				Type:     answer.GetType(),
				Value:    answer.GetValue(),
			})
		}
		return opspec.ActionPackageRepair, opspec.Payload{
			PackageRepair: &opspec.PackageRepairPayload{Answers: answers},
		}, nil

	case *agentv1.TaskEnvelope_LocalUserAction:
		request := action.LocalUserAction
		actionType, known := localUserActions[request.GetOperation()]
		if !known {
			return "", opspec.Payload{}, fmt.Errorf("unknown account operation: %v", request.GetOperation())
		}
		keys := make([]opspec.SSHKeyInput, 0, len(request.GetKeys()))
		for _, key := range request.GetKeys() {
			keys = append(keys, opspec.SSHKeyInput{PublicKey: key.GetPublicKey(), Comment: key.GetComment()})
		}
		return actionType, opspec.Payload{
			LocalUser: &opspec.LocalUserPayload{
				Name:                 request.GetName(),
				Gecos:                request.GetGecos(),
				Shell:                request.GetShell(),
				Groups:               request.GetGroups(),
				SSHKeys:              request.GetSshKeys(),
				CreateHome:           request.GetCreateHome(),
				ExpiresAt:            request.GetExpiresAt(),
				RemoveHome:           request.GetRemoveHome(),
				Keys:                 keys,
				Fingerprints:         request.GetFingerprints(),
				IgnoreMissing:        request.GetIgnoreMissing(),
				ExpectedFingerprints: request.GetExpectedFingerprints(),
				AllowLockout:         request.GetAllowLockout(),
				ManagedFile:          request.GetManagedFile(),
				System:               request.GetSystem(),
				Inactive:             request.GetInactive(),
			},
		}, nil

	case *agentv1.TaskEnvelope_DockerRead:
		return opspec.ActionDockerRead, opspec.Payload{DockerRead: &opspec.DockerReadPayload{}}, nil

	case *agentv1.TaskEnvelope_ReadDockerEvents:
		events := action.ReadDockerEvents
		return opspec.ActionDockerEvents, opspec.Payload{
			DockerEvents: &opspec.DockerEventsPayload{
				SinceSeconds:  int(events.GetSinceSeconds()),
				FollowSeconds: int(events.GetFollowSeconds()),
				Types:         events.GetTypes(),
				MaxEvents:     int(events.GetMaxEvents()),
			},
		}, nil

	case *agentv1.TaskEnvelope_DockerLogs:
		logs := action.DockerLogs
		return opspec.ActionDockerLogs, opspec.Payload{
			DockerLogs: &opspec.DockerLogsPayload{
				ContainerID: logs.GetContainerId(),
				Lines:       logs.GetLines(),
				Since:       logs.GetSince(),
				Timestamps:  logs.GetTimestamps(),
			},
		}, nil

	case *agentv1.TaskEnvelope_HostnameSet:
		rename := action.HostnameSet
		return opspec.ActionSystemHostnameSet, opspec.Payload{
			Hostname: &opspec.HostnamePayload{
				Hostname: rename.GetHostname(),
				Pretty:   rename.GetPretty(),
			},
		}, nil

	case *agentv1.TaskEnvelope_RefreshInventory:
		return opspec.ActionInventoryRefresh, opspec.Payload{
			Inventory: &opspec.InventoryPayload{Modules: action.RefreshInventory.GetModules()},
		}, nil

	case *agentv1.TaskEnvelope_DockerAction:
		return dockerAction(action.DockerAction)

	case *agentv1.TaskEnvelope_DockerEnsure:
		return dockerDeclaration(action.DockerEnsure)

	case *agentv1.TaskEnvelope_Compose:
		kind := opspec.ActionComposePlan
		if action.Compose.GetOperation() == agentv1.ComposeAction_OPERATION_DEPLOY {
			kind = opspec.ActionComposeDeploy
		}
		return kind, opspec.Payload{Compose: &opspec.ComposePayload{
			Project:      action.Compose.GetProject(),
			Manifest:     action.Compose.GetManifest(),
			PlanDigest:   action.Compose.GetPlanDigest(),
			ImageDigests: action.Compose.GetImageDigests(),
		}}, nil

	case *agentv1.TaskEnvelope_UnitToggle:
		kind := opspec.ActionUnitEnableSet
		if action.UnitToggle.GetProperty() == agentv1.UnitToggle_PROPERTY_MASKED {
			kind = opspec.ActionUnitMaskSet
		}
		return kind, opspec.Payload{UnitToggle: &opspec.UnitToggle{
			Unit:    action.UnitToggle.GetUnit(),
			Enabled: action.UnitToggle.GetValue(),
		}}, nil

	case *agentv1.TaskEnvelope_PackageLifecycle:
		change := action.PackageLifecycle
		kind := opspec.ActionPackageInstall
		switch change.GetOperation() {
		case agentv1.PackageLifecycle_OPERATION_REMOVE:
			kind = opspec.ActionPackageRemove
		case agentv1.PackageLifecycle_OPERATION_HOLD:
			kind = opspec.ActionPackageHoldSet
		}
		return kind, opspec.Payload{PackageChange: &opspec.PackageChangePayload{
			Packages:         change.GetPackages(),
			ExpectedRemovals: change.GetExpectedRemovals(),
			Hold:             change.GetHold(),
			PlanHash:         change.GetPlanHash(),
			Plan:             planReferenceFromProto(change.GetPlanReference()),
		}}, nil

	case *agentv1.TaskEnvelope_File:
		file := action.File
		kind := opspec.ActionFilePlan
		switch file.GetOperation() {
		case agentv1.FileAction_OPERATION_READ:
			kind = opspec.ActionFileRead
		case agentv1.FileAction_OPERATION_ENSURE:
			kind = opspec.ActionFileEnsure
		case agentv1.FileAction_OPERATION_ROLLBACK:
			kind = opspec.ActionFileRollback
		case agentv1.FileAction_OPERATION_REMOVE:
			kind = opspec.ActionFileRemove
		case agentv1.FileAction_OPERATION_PLAN:
			// The plan and the read of the list are the same operation of the panel:
			// they are told apart by the presence of a path, not by a name.
			kind = opspec.ActionFilePlan
		}
		reference := (*opspec.SecretRef)(nil)
		if ref := file.GetContentSecret(); ref != nil && ref.GetName() != "" {
			reference = &opspec.SecretRef{Name: ref.GetName(), Version: int(ref.GetVersion())}
		}
		return kind, opspec.Payload{File: &opspec.FilePayload{
			ContentSecret:  reference,
			Path:           file.GetPath(),
			Content:        string(file.GetContent()),
			Mode:           file.GetMode(),
			Owner:          file.GetOwner(),
			Group:          file.GetGroup(),
			ExpectedSHA256: file.GetExpectedSha256(),
			Validator:      file.GetValidator(),
			// Part of the payload hash: a flag the agent added on its own
			// would not match the approved plan.
			AllowMissingValidator: file.GetAllowMissingValidator(),
			// Part of the payload hash: the digest names which content the
			// host is to put back.
			VersionSHA256: file.GetVersionSha256(),
		}}, nil

	case *agentv1.TaskEnvelope_Security:
		ochrona := action.Security
		kind := opspec.ActionSecurityScan
		switch ochrona.GetOperation() {
		case agentv1.SecurityAction_OPERATION_SELINUX_MODE:
			kind = opspec.ActionSELinuxModeSet
		case agentv1.SecurityAction_OPERATION_AUDIT_RELOAD:
			kind = opspec.ActionAuditRulesReload
		}
		return kind, opspec.Payload{Security: &opspec.SecurityPayload{Mode: ochrona.GetMode()}}, nil

	case *agentv1.TaskEnvelope_ListPackages:
		return opspec.ActionPackageList, opspec.Payload{}, nil

	case *agentv1.TaskEnvelope_MonitoringProbe:
		sonda := action.MonitoringProbe
		return opspec.ActionMonitoringProbe, opspec.Payload{
			Monitoring: &opspec.MonitoringPayload{
				Kind: sonda.GetKind(), Target: sonda.GetTarget(),
				ExpectStatus:   int(sonda.GetExpectStatus()),
				ExpectBody:     sonda.GetExpectBody(),
				TimeoutSeconds: int(sonda.GetTimeoutSeconds()),
			},
		}, nil

	case *agentv1.TaskEnvelope_Backup:
		backup := action.Backup
		kind := opspec.ActionBackupPlan
		switch backup.GetOperation() {
		case agentv1.BackupAction_OPERATION_RUN:
			kind = opspec.ActionBackupRun
		case agentv1.BackupAction_OPERATION_VERIFY:
			kind = opspec.ActionBackupVerify
		case agentv1.BackupAction_OPERATION_RESTORE:
			kind = opspec.ActionBackupRestore
		}
		payload := &opspec.BackupPayload{
			ID: backup.GetId(), Tool: backup.GetTool(), Repository: backup.GetRepository(),
			Paths: backup.GetPaths(), Excludes: backup.GetExcludes(), Tags: backup.GetTags(),
			KeepLast: int(backup.GetKeepLast()), KeepDaily: int(backup.GetKeepDaily()),
			KeepWeekly: int(backup.GetKeepWeekly()), KeepMonthly: int(backup.GetKeepMonthly()),
			Prune: backup.GetPrune(), Runbook: backup.GetRunbook(),
			Initialize: backup.GetInitialize(), ReadData: backup.GetReadData(), SnapshotID: backup.GetSnapshotId(),
			Target: backup.GetTarget(), Include: backup.GetInclude(),
			Overwrite: backup.GetOverwrite(), Plan: backup.GetPlan(), PlanHash: backup.GetPlanHash(),
		}
		if ref := backup.GetPasswordSecret(); ref != nil && ref.GetName() != "" {
			payload.PasswordSecret = &opspec.SecretRef{
				Name: ref.GetName(), Version: int(ref.GetVersion()),
			}
		}
		if len(backup.GetEnvSecrets()) > 0 {
			payload.EnvSecrets = map[string]opspec.SecretRef{}
			for name, ref := range backup.GetEnvSecrets() {
				payload.EnvSecrets[name] = opspec.SecretRef{
					Name: ref.GetName(), Version: int(ref.GetVersion()),
				}
			}
		}
		return kind, opspec.Payload{Backup: payload}, nil

	case *agentv1.TaskEnvelope_Repository:
		repository := action.Repository
		reference := (*opspec.SecretRef)(nil)
		if ref := repository.GetPasswordSecret(); ref != nil && ref.GetName() != "" {
			reference = &opspec.SecretRef{Name: ref.GetName(), Version: int(ref.GetVersion())}
		}
		return opspec.ActionRepositorySet, opspec.Payload{Repository: &opspec.RepositoryPayload{
			ID:             repository.GetId(),
			Name:           repository.GetName(),
			URL:            repository.GetUrl(),
			Suites:         repository.GetSuites(),
			Components:     repository.GetComponents(),
			Architectures:  repository.GetArchitectures(),
			Enabled:        repository.GetEnabled(),
			Priority:       int(repository.GetPriority()),
			GPGKey:         repository.GetGpgKey(),
			AllowUnsigned:  repository.GetAllowUnsigned(),
			Username:       repository.GetUsername(),
			PasswordSecret: reference,
			Remove:         repository.GetRemove(),
		}}, nil

	case *agentv1.TaskEnvelope_Certificate:
		certificate := action.Certificate
		kind := opspec.ActionCertificateScan
		switch certificate.GetOperation() {
		case agentv1.CertificateAction_OPERATION_DEPLOY:
			kind = opspec.ActionCertificateDeploy
		case agentv1.CertificateAction_OPERATION_RENEW:
			kind = opspec.ActionCertificateRenew
		case agentv1.CertificateAction_OPERATION_PLAN:
			kind = opspec.ActionCertificatePlan
		case agentv1.CertificateAction_OPERATION_TRUST_PLAN:
			kind = opspec.ActionCertificateTrustPlan
		case agentv1.CertificateAction_OPERATION_TRUST_ENSURE:
			kind = opspec.ActionCertificateTrustEnsure
		case agentv1.CertificateAction_OPERATION_TRUST_REMOVE:
			kind = opspec.ActionCertificateTrustRemove
		}
		reference := (*opspec.SecretRef)(nil)
		if ref := certificate.GetKeySecret(); ref != nil && ref.GetName() != "" {
			reference = &opspec.SecretRef{Name: ref.GetName(), Version: int(ref.GetVersion())}
		}
		payload := &opspec.CertificatePayload{
			Path:        certificate.GetPath(),
			KeyPath:     certificate.GetKeyPath(),
			Certificate: certificate.GetCertificate(),
			KeySecret:   reference,
			Owner:       certificate.GetOwner(),
			Group:       certificate.GetGroup(),
			Mode:        certificate.GetMode(),
			KeyMode:     certificate.GetKeyMode(),
			ReloadUnit:  certificate.GetReloadUnit(),
			ProbeTarget: certificate.GetProbeTarget(),
			Request:     certificate.GetRequest(),
			PlanHash:    certificate.GetPlanHash(),
			AnchorID:    certificate.GetAnchorId(),
		}
		for _, target := range certificate.GetTargets() {
			payload.Targets = append(payload.Targets, opspec.CertificateTarget{
				Path: target.GetPath(), KeyPath: target.GetKeyPath(), Service: target.GetService(),
			})
		}
		return kind, opspec.Payload{Certificate: payload}, nil

	case *agentv1.TaskEnvelope_SystemShutdown:
		shutdown := action.SystemShutdown
		return opspec.ActionSystemShutdown, opspec.Payload{Power: &opspec.PowerPayload{
			Mode:             shutdown.GetMode(),
			DelaySeconds:     shutdown.GetDelaySeconds(),
			Reason:           shutdown.GetReason(),
			IgnoreInhibitors: shutdown.GetIgnoreInhibitors(),
		}}, nil

	case *agentv1.TaskEnvelope_Time:
		clock := action.Time
		kind := opspec.ActionTimeSyncTest
		switch clock.GetOperation() {
		case agentv1.TimeAction_OPERATION_CONFIG_APPLY:
			kind = opspec.ActionTimeConfigApply
		case agentv1.TimeAction_OPERATION_TIMEZONE_SET:
			kind = opspec.ActionTimezoneSet
		case agentv1.TimeAction_OPERATION_PLAN:
			kind = opspec.ActionTimePlan
		}
		return kind, opspec.Payload{Time: &opspec.TimePayload{
			Servers:      clock.GetServers(),
			Probe:        clock.GetProbe(),
			Timezone:     clock.GetTimezone(),
			AllowStep:    clock.GetAllowStep(),
			EnableDropIn: clock.GetEnableDropin(),
			PlanHash:     clock.GetPlanHash(),
		}}, nil

	case *agentv1.TaskEnvelope_Kernel:
		kernel := action.Kernel
		kind := opspec.ActionSysctlPlan
		switch kernel.GetOperation() {
		case agentv1.KernelAction_OPERATION_SYSCTL_ENSURE:
			kind = opspec.ActionSysctlEnsure
		case agentv1.KernelAction_OPERATION_MODULE_LOAD:
			kind = opspec.ActionKernelModuleLoad
		case agentv1.KernelAction_OPERATION_MODULE_BLACKLIST:
			kind = opspec.ActionKernelModuleBlacklist
		case agentv1.KernelAction_OPERATION_MODULE_PLAN:
			kind = opspec.ActionKernelModulePlan
		}
		return kind, opspec.Payload{Kernel: &opspec.KernelPayload{
			Settings:  kernel.GetSettings(),
			Keys:      kernel.GetKeys(),
			Module:    kernel.GetModule(),
			Blacklist: kernel.GetBlacklist(),
			PlanHash:  kernel.GetPlanHash(),
		}}, nil

	case *agentv1.TaskEnvelope_Ssh:
		sshd := action.Ssh
		kind := opspec.ActionSSHConfigPlan
		switch sshd.GetOperation() {
		case agentv1.SshAction_OPERATION_APPLY:
			kind = opspec.ActionSSHConfigApply
		case agentv1.SshAction_OPERATION_ROTATE_HOSTKEY:
			kind = opspec.ActionSSHHostKeyRotate
		}
		return kind, opspec.Payload{SSH: &opspec.SSHPayload{
			Port:                   sshd.GetPort(),
			PermitRootLogin:        sshd.GetPermitRootLogin(),
			PasswordAuthentication: sshd.GetPasswordAuthentication(),
			PubkeyAuthentication:   sshd.GetPubkeyAuthentication(),
			KbdInteractive:         sshd.GetKbdInteractiveAuthentication(),
			MaxAuthTries:           sshd.GetMaxAuthTries(),
			AllowUsers:             sshd.GetAllowUsers(),
			AllowGroups:            sshd.GetAllowGroups(),
			DenyUsers:              sshd.GetDenyUsers(),
			AllowLockout:           sshd.GetAllowLockout(),
			KeyType:                sshd.GetKeyType(),
			PlanHash:               sshd.GetPlanHash(),
		}}, nil

	case *agentv1.TaskEnvelope_Storage:
		disks := action.Storage
		kind := opspec.ActionMountEnsure
		switch disks.GetOperation() {
		case agentv1.StorageAction_OPERATION_READ, agentv1.StorageAction_OPERATION_MOUNT_PLAN,
			agentv1.StorageAction_OPERATION_DEVICE_PLAN:
			// The read and the plan are the same operation of the panel; they are told
			// apart by the presence of a target.
			kind = opspec.ActionStoragePlan
		case agentv1.StorageAction_OPERATION_MOUNT_REMOVE:
			kind = opspec.ActionMountRemove
		case agentv1.StorageAction_OPERATION_FS_CHECK:
			kind = opspec.ActionFilesystemCheck
		case agentv1.StorageAction_OPERATION_LVM_EXTEND:
			kind = opspec.ActionLVMExtend
		case agentv1.StorageAction_OPERATION_FS_RESIZE:
			kind = opspec.ActionFilesystemResize
		case agentv1.StorageAction_OPERATION_FS_CREATE:
			kind = opspec.ActionFilesystemCreate
		case agentv1.StorageAction_OPERATION_DISK_WIPE:
			kind = opspec.ActionDiskWipe
		case agentv1.StorageAction_OPERATION_SMART_READ:
			kind = opspec.ActionStorageSmartRead
		case agentv1.StorageAction_OPERATION_RAID_MEMBER_FAIL:
			kind = opspec.ActionRAIDMemberFail
		case agentv1.StorageAction_OPERATION_RAID_MEMBER_REMOVE:
			kind = opspec.ActionRAIDMemberRemove
		case agentv1.StorageAction_OPERATION_RAID_MEMBER_ADD:
			kind = opspec.ActionRAIDMemberAdd
		case agentv1.StorageAction_OPERATION_LVM_LV_CREATE:
			kind = opspec.ActionLVMVolumeCreate
		case agentv1.StorageAction_OPERATION_LVM_LV_REMOVE:
			kind = opspec.ActionLVMVolumeRemove
		case agentv1.StorageAction_OPERATION_LVM_VG_EXTEND:
			kind = opspec.ActionLVMGroupExtend
		case agentv1.StorageAction_OPERATION_LVM_SNAPSHOT_CREATE:
			kind = opspec.ActionLVMSnapshotCreate
		case agentv1.StorageAction_OPERATION_LVM_SNAPSHOT_REMOVE:
			kind = opspec.ActionLVMSnapshotRemove
		}
		return kind, opspec.Payload{Storage: &opspec.StoragePayload{
			Source:            disks.GetSource(),
			Target:            disks.GetTarget(),
			FSType:            disks.GetFsType(),
			Options:           disks.GetOptions(),
			Persist:           disks.GetPersist(),
			Device:            disks.GetDevice(),
			ExpectedUUID:      disks.GetExpectedUuid(),
			Repair:            disks.GetRepair(),
			ExpectedSerial:    disks.GetExpectedSerial(),
			ExpectedSizeBytes: disks.GetExpectedSizeBytes(),
			ExpectedByID:      disks.GetExpectedById(),
			ExpectedWWN:       disks.GetExpectedWwn(),
			Size:              disks.GetSize(),
			Label:             disks.GetLabel(),
			Plan:              disks.GetPlan(),
			PlanHash:          disks.GetPlanHash(),
			// The identities of the layers above a bare disk.
			Array:              disks.GetArray(),
			ExpectedArrayUUID:  disks.GetExpectedArrayUuid(),
			Group:              disks.GetGroup(),
			ExpectedGroupUUID:  disks.GetExpectedGroupUuid(),
			Volume:             disks.GetVolume(),
			ExpectedVolumeUUID: disks.GetExpectedVolumeUuid(),
		}}, nil

	case *agentv1.TaskEnvelope_Firewall:
		firewall := action.Firewall
		kind := opspec.ActionFirewallRuleEnsure
		switch firewall.GetOperation() {
		case agentv1.FirewallAction_OPERATION_READ, agentv1.FirewallAction_OPERATION_PLAN:
			// The read and the plan are the same operation of the panel; they are told
			// apart by the presence of a rule.
			kind = opspec.ActionFirewallPlan
		case agentv1.FirewallAction_OPERATION_RULE_REMOVE:
			kind = opspec.ActionFirewallRuleRemove
		case agentv1.FirewallAction_OPERATION_ZONE_PORT:
			kind = opspec.ActionFirewallZonePort
		case agentv1.FirewallAction_OPERATION_ZONE_SERVICE:
			kind = opspec.ActionFirewallZoneService
		case agentv1.FirewallAction_OPERATION_RESTORE:
			kind = opspec.ActionFirewallRulesetRestore
		}
		return kind, opspec.Payload{Firewall: &opspec.FirewallPayload{
			RuleID:          firewall.GetRuleId(),
			Chain:           firewall.GetChain(),
			Action:          firewall.GetAction(),
			Protocol:        firewall.GetProtocol(),
			Ports:           firewall.GetPorts(),
			Sources:         firewall.GetSources(),
			Interface:       firewall.GetInterface(),
			Comment:         firewall.GetComment(),
			Zone:            firewall.GetZone(),
			Service:         firewall.GetService(),
			Enable:          firewall.GetEnable(),
			BreakGlass:      firewall.GetBreakGlass(),
			RollbackSeconds: firewall.GetRollbackSeconds(),
			RollbackID:      firewall.GetRollbackId(),
			ExpectedHash:    firewall.GetExpectedHash(),
		}}, nil

	case *agentv1.TaskEnvelope_Dns:
		resolver := action.Dns
		kind := opspec.ActionDNSHostApply
		switch resolver.GetOperation() {
		case agentv1.DnsAction_OPERATION_RESOLVE_TEST:
			kind = opspec.ActionDNSResolveTest
		case agentv1.DnsAction_OPERATION_PLAN:
			kind = opspec.ActionDNSPlan
		}
		return kind, opspec.Payload{DNS: &opspec.DNSPayload{
			Interface:       resolver.GetInterface(),
			Servers:         resolver.GetServers(),
			SearchDomains:   resolver.GetSearchDomains(),
			IgnoreAutoDNS:   resolver.GetIgnoreAutoDns(),
			RollbackSeconds: resolver.GetRollbackSeconds(),
			Names:           resolver.GetNames(),
			PlanHash:        resolver.GetPlanHash(),
		}}, nil

	case *agentv1.TaskEnvelope_Network:
		network := action.Network
		kind := opspec.ActionNetworkProfileApply
		switch network.GetOperation() {
		case agentv1.NetworkAction_OPERATION_READ, agentv1.NetworkAction_OPERATION_PLAN:
			kind = opspec.ActionNetworkPlan
		case agentv1.NetworkAction_OPERATION_SET_MTU:
			kind = opspec.ActionNetworkMTUSet
		case agentv1.NetworkAction_OPERATION_ENSURE_ROUTES:
			kind = opspec.ActionNetworkRouteEnsure
		case agentv1.NetworkAction_OPERATION_ROLLBACK:
			kind = opspec.ActionNetworkRollback
		case agentv1.NetworkAction_OPERATION_APPLY_LINK:
			kind = opspec.ActionNetworkLinkApply
		case agentv1.NetworkAction_OPERATION_REMOVE_LINK:
			kind = opspec.ActionNetworkLinkRemove
		}
		return kind, opspec.Payload{Network: &opspec.NetworkPayload{
			Interface:       network.GetInterface(),
			MTU:             network.GetMtu(),
			Routes:          network.GetRoutes(),
			Method:          network.GetMethod(),
			Addresses:       network.GetAddresses(),
			Gateway:         network.GetGateway(),
			DNS:             network.GetDns(),
			PlanHash:        network.GetPlanHash(),
			RollbackSeconds: network.GetRollbackSeconds(),
			RollbackID:      network.GetRollbackId(),
			// The second family and the layering are read back exactly as they were
			// built, so the digest over the payload is the one the panel computed.
			Method6:    network.GetMethod6(),
			Addresses6: network.GetAddresses6(),
			Gateway6:   network.GetGateway6(),
			AcceptRA:   network.GetAcceptRa(),
			Privacy:    network.GetPrivacy(),
			Link:       networkLinkPayload(network.GetLink()),
			LinkRemove: network.GetLinkRemove(),
		}}, nil

	case *agentv1.TaskEnvelope_Schedule:
		schedule := action.Schedule
		kind := opspec.ActionScheduleEnsure
		switch schedule.GetOperation() {
		case agentv1.ScheduleAction_OPERATION_DISABLE:
			kind = opspec.ActionScheduleDisable
		case agentv1.ScheduleAction_OPERATION_REMOVE:
			kind = opspec.ActionScheduleRemove
		case agentv1.ScheduleAction_OPERATION_RUN_NOW:
			kind = opspec.ActionScheduleRunNow
		case agentv1.ScheduleAction_OPERATION_PREVIEW:
			kind = opspec.ActionSchedulePreview
		}
		return kind, opspec.Payload{Schedule: &opspec.SchedulePayload{
			ID:         schedule.GetId(),
			Expression: schedule.GetExpression(),
			Command:    schedule.GetCommand(),
			User:       schedule.GetUser(),
			Comment:    schedule.GetComment(),
			Enabled:    schedule.GetEnabled(),
			Adopt:      schedule.GetAdopt(),
			Kind:       schedule.GetKind(),
		}}, nil

	case *agentv1.TaskEnvelope_ListProcesses:
		return opspec.ActionProcessList, opspec.Payload{ProcessList: &opspec.ProcessListPayload{
			SortBy: action.ListProcesses.GetSortBy(),
			Limit:  action.ListProcesses.GetLimit(),
		}}, nil

	case *agentv1.TaskEnvelope_SignalProcess:
		return opspec.ActionProcessSignal, opspec.Payload{ProcessSignal: &opspec.ProcessSignalPayload{
			PID:           action.SignalProcess.GetPid(),
			ExpectedStart: action.SignalProcess.GetExpectedStartTicks(),
			Signal:        action.SignalProcess.GetSignal(),
			Command:       action.SignalProcess.GetCommand(),
		}}, nil

	case *agentv1.TaskEnvelope_FollowJournal:
		follow := action.FollowJournal
		return opspec.ActionFollowJournal, opspec.Payload{Journal: &opspec.JournalPayload{
			Unit:          follow.GetUnit(),
			Lines:         follow.GetBacklogLines(),
			MaxPriority:   follow.MaxPriority,
			FollowSeconds: follow.GetFollowSeconds(),
			Since:         follow.GetSince(),
			AfterCursor:   follow.GetAfterCursor(),
			BootID:        follow.GetBootId(),
		}}, nil

	case *agentv1.TaskEnvelope_ReadLogFile:
		return opspec.ActionReadLogFile, opspec.Payload{LogFile: &opspec.LogFilePayload{
			Path:  action.ReadLogFile.GetPath(),
			Lines: action.ReadLogFile.GetLines(),
		}}, nil

	case *agentv1.TaskEnvelope_ReadUnitStatus:
		return opspec.ActionUnitStatus, opspec.Payload{
			UnitStatus: &opspec.UnitStatusPayload{
				Units:  action.ReadUnitStatus.GetUnits(),
				All:    action.ReadUnitStatus.GetAll(),
				Detail: action.ReadUnitStatus.GetDetail(),
			},
		}, nil

	case *agentv1.TaskEnvelope_ReadJournal:
		request := action.ReadJournal
		payload := opspec.JournalPayload{
			Unit:        request.GetUnit(),
			Lines:       request.GetLines(),
			Since:       request.GetSince(),
			Until:       request.GetUntil(),
			AfterCursor: request.GetAfterCursor(),
			BootID:      request.GetBootId(),
		}
		if request.MaxPriority != nil {
			priority := request.GetMaxPriority()
			payload.MaxPriority = &priority
		}
		return opspec.ActionReadJournal, opspec.Payload{Journal: &payload}, nil

	default:
		return "", opspec.Payload{}, fmt.Errorf("the envelope contains no supported action")
	}
}

var unitActionTypes = map[agentv1.UnitAction_Operation]opspec.ActionType{
	agentv1.UnitAction_OPERATION_START:   opspec.ActionUnitStart,
	agentv1.UnitAction_OPERATION_STOP:    opspec.ActionUnitStop,
	agentv1.UnitAction_OPERATION_RESTART: opspec.ActionUnitRestart,
	agentv1.UnitAction_OPERATION_RELOAD:  opspec.ActionUnitReload,
	// The map is the whole set of verbs the agent accepts: a verb outside it
	// is refused, not guessed.
	agentv1.UnitAction_OPERATION_RESET_FAILED: opspec.ActionUnitResetFailed,
}

func timeoutOf(task *agentv1.TaskEnvelope, action opspec.ActionType) time.Duration {
	seconds := int(task.GetLimits().GetTimeoutSeconds())
	if seconds <= 0 {
		seconds = action.DefaultTimeout()
	}
	if seconds <= 0 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}

func rejected(status agentv1.TaskResult_Status, code, message string) *agentv1.TaskResult {
	return &agentv1.TaskResult{
		Status:    status,
		ExitCode:  -1,
		ErrorCode: code,
		Message:   strings.TrimSpace(message),
	}
}

// cloneResult copies the result through proto. Clone.
func cloneResult(result *agentv1.TaskResult) *agentv1.TaskResult {
	return proto.Clone(result).(*agentv1.TaskResult)
}

func unitStateToAgent(state *helperv1.UnitState) *agentv1.UnitState {
	if state == nil {
		return nil
	}
	return &agentv1.UnitState{
		Name:          state.GetName(),
		LoadState:     state.GetLoadState(),
		ActiveState:   state.GetActiveState(),
		SubState:      state.GetSubState(),
		UnitFileState: state.GetUnitFileState(),
		Result:        state.GetResult(),
		MainPid:       state.GetMainPid(),
		NRestarts:     state.GetNRestarts(),
	}
}

// localUserActions translates the operations of the contract into operation
// types.
var localUserActions = map[agentv1.LocalUserAction_Operation]opspec.ActionType{
	agentv1.LocalUserAction_OPERATION_CREATE:           opspec.ActionLocalUserCreate,
	agentv1.LocalUserAction_OPERATION_LOCK:             opspec.ActionLocalUserLock,
	agentv1.LocalUserAction_OPERATION_UNLOCK:           opspec.ActionLocalUserUnlock,
	agentv1.LocalUserAction_OPERATION_SET_SSH_KEYS:     opspec.ActionLocalSSHKeysSet,
	agentv1.LocalUserAction_OPERATION_ADD_SSH_KEYS:     opspec.ActionLocalSSHKeysAdd,
	agentv1.LocalUserAction_OPERATION_REMOVE_SSH_KEYS:  opspec.ActionLocalSSHKeysRemove,
	agentv1.LocalUserAction_OPERATION_REPLACE_SSH_KEYS: opspec.ActionLocalSSHKeysReplaceAll,
	agentv1.LocalUserAction_OPERATION_SET_GROUPS:       opspec.ActionLocalUserGroupsSet,
	agentv1.LocalUserAction_OPERATION_SET_EXPIRY:       opspec.ActionLocalUserExpirySet,
	agentv1.LocalUserAction_OPERATION_DELETE:           opspec.ActionLocalUserDelete,
}

// joinNames assembles the names into a readable list for the message shown to
// the operator.
func joinNames(names []string) string {
	return strings.Join(names, ", ")
}

// dockerAction translates the envelope of a container operation into a type
// and a payload.
func dockerAction(action *agentv1.DockerAction) (opspec.ActionType, opspec.Payload, error) {
	container := &opspec.DockerContainerPayload{
		ContainerID:    action.GetContainerId(),
		Name:           action.GetContainerName(),
		TimeoutSeconds: action.GetTimeoutSeconds(),
		RemoveVolumes:  action.GetRemoveVolumes(),
	}
	switch action.GetOperation() {
	case agentv1.DockerAction_OPERATION_START:
		return opspec.ActionDockerStart, opspec.Payload{DockerContainer: container}, nil
	case agentv1.DockerAction_OPERATION_STOP:
		return opspec.ActionDockerStop, opspec.Payload{DockerContainer: container}, nil
	case agentv1.DockerAction_OPERATION_RESTART:
		return opspec.ActionDockerRestart, opspec.Payload{DockerContainer: container}, nil
	case agentv1.DockerAction_OPERATION_REMOVE:
		return opspec.ActionDockerRemove, opspec.Payload{DockerContainer: container}, nil
	case agentv1.DockerAction_OPERATION_PULL_IMAGE:
		return opspec.ActionDockerPull, opspec.Payload{
			DockerImage: &opspec.DockerImagePayload{Reference: action.GetImageReference()},
		}, nil
	case agentv1.DockerAction_OPERATION_PRUNE:
		return opspec.ActionDockerPrune, opspec.Payload{
			DockerPrune: &opspec.DockerPrunePayload{
				ImageIDs:   action.GetImageIds(),
				VolumeName: action.GetVolumeNames(),
				NetworkIDs: action.GetNetworkIds(),
			},
		}, nil
	}
	return "", opspec.Payload{}, fmt.Errorf("unknown container operation")
}

// dockerDeclaration reads a declared object back out of the envelope.
func dockerDeclaration(action *agentv1.DockerEnsureAction) (opspec.ActionType, opspec.Payload, error) {
	declaration := &opspec.DockerEnsurePayload{
		PlanDigest: action.GetPlanDigest(),
		Force:      action.GetForce(),
	}
	// The kind and the name are derived from the description where there is one,
	// and only an order without a description carries them itself.
	if len(action.GetSpec()) == 0 {
		declaration.Kind = action.GetKind()
		declaration.Name = action.GetName()
	}
	if references := action.GetEnvSecrets(); len(references) > 0 {
		declaration.EnvSecrets = make(map[string]opspec.SecretRef, len(references))
		for name, reference := range references {
			declaration.EnvSecrets[name] = opspec.SecretRef{
				Name: reference.GetName(), Version: int(reference.GetVersion()),
			}
		}
	}

	if spec := action.GetSpec(); len(spec) > 0 {
		switch action.GetKind() {
		case opspec.DockerKindContainer:
			declaration.Container = &docker.ContainerRequest{}
			if err := json.Unmarshal(spec, declaration.Container); err != nil {
				return "", opspec.Payload{}, fmt.Errorf("the container description: %w", err)
			}
		case opspec.DockerKindNetwork:
			declaration.Network = &docker.NetworkSpec{}
			if err := json.Unmarshal(spec, declaration.Network); err != nil {
				return "", opspec.Payload{}, fmt.Errorf("the network description: %w", err)
			}
		case opspec.DockerKindVolume:
			declaration.Volume = &docker.VolumeSpec{}
			if err := json.Unmarshal(spec, declaration.Volume); err != nil {
				return "", opspec.Payload{}, fmt.Errorf("the volume description: %w", err)
			}
		default:
			return "", opspec.Payload{}, fmt.Errorf("a description of an object of unknown kind %q",
				action.GetKind())
		}
	}

	payload := opspec.Payload{DockerEnsure: declaration}
	switch action.GetOperation() {
	case agentv1.DockerEnsureAction_OPERATION_PLAN:
		return opspec.ActionDockerPlan, payload, nil
	case agentv1.DockerEnsureAction_OPERATION_CONTAINER_ENSURE:
		return opspec.ActionDockerContainerEnsure, payload, nil
	case agentv1.DockerEnsureAction_OPERATION_NETWORK_ENSURE:
		return opspec.ActionDockerNetworkEnsure, payload, nil
	case agentv1.DockerEnsureAction_OPERATION_NETWORK_REMOVE:
		return opspec.ActionDockerNetworkRemove, payload, nil
	case agentv1.DockerEnsureAction_OPERATION_VOLUME_ENSURE:
		return opspec.ActionDockerVolumeEnsure, payload, nil
	case agentv1.DockerEnsureAction_OPERATION_VOLUME_REMOVE:
		return opspec.ActionDockerVolumeRemove, payload, nil
	}
	return "", opspec.Payload{}, fmt.Errorf("unknown declared object operation")
}

// listUnits returns the full list of the units of the host.
func (e *TaskExecutor) listUnits(ctx context.Context, task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	units, truncated, err := systemd.List(ctx)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	states := make([]*agentv1.UnitState, 0, len(units))
	for _, unit := range units {
		states = append(states, &agentv1.UnitState{
			Name:          unit.Name,
			LoadState:     unit.LoadState,
			ActiveState:   unit.ActiveState,
			SubState:      unit.SubState,
			UnitFileState: unit.UnitFileState,
		})
	}
	return &agentv1.TaskResult{
		TaskId:   task.GetTaskId(),
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Detail: &agentv1.TaskResult_UnitStatus{
			UnitStatus: &agentv1.UnitStatusResult{Units: states, Truncated: truncated},
		},
	}
}

// applyUnitToggle enables or masks a unit. The operation describes the desired
// state and not a switch: repeating it does not reverse the change.
func (e *TaskExecutor) applyUnitToggle(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, toggle *agentv1.UnitToggle) *agentv1.TaskResult {
	if toggle == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the description of the unit change is missing")
	}
	return e.applyUnitAction(ctx, task, action, &opspec.UnitPayload{Unit: toggle.GetUnit()})
}

// planReferenceFromProto reads the approved plan reference back into the
// payload shape the panel hashed; nil for an order without one.
func planReferenceFromProto(reference *agentv1.PackagePlanReference) *opspec.PlanReference {
	if reference == nil {
		return nil
	}
	out := &opspec.PlanReference{
		SchemaVersion:     reference.GetSchemaVersion(),
		PlannerVersion:    reference.GetPlannerVersion(),
		InventoryRevision: reference.GetInventoryRevision(),
		ResourceRevision:  reference.GetResourceRevision(),
		ExpiresAt:         reference.GetExpiresAt(),
	}
	for _, change := range reference.GetChanges() {
		out.Changes = append(out.Changes, opspec.PlanChangeEntry{
			Name: change.GetName(), CurrentVersion: change.GetCurrentVersion(), CandidateVersion: change.GetCandidateVersion(),
			Architecture: change.GetArchitecture(), Origin: change.GetOrigin(), Action: change.GetAction(),
		})
	}
	return out
}
