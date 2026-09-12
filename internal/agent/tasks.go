package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/systemd"
)

// StatusAfterReplacement marks a result there is no point in sending back: the
// agent has just been replaced and its return is what decides on the success.
//
// Normally silence from the agent is an error - the control plane cannot tell
// it from a broken connection. Here it is the other way round: any result sent
// at this moment would be untrue, because the process computing it stops
// existing a second later, and whether the replacement worked shows only after
// a new Hello.
const StatusAfterReplacement = "agent_upgrade_in_flight"

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
	// RejectUnsupported marks an agent that by design performs no tasks.
	RejectUnsupported = "unsupported"
	// RejectInternalError marks an error on the side of the agent. The task ends
	// with a negative result instead of taking the whole process with it.
	RejectInternalError = "agent_internal_error"
	// RejectNetworkUnreachable marks a network change after which the host lost
	// its route to the panel. The change is not confirmed, so the host goes back
	// on its own to the configuration from before it.
	RejectNetworkUnreachable = "network_unreachable"
	// RejectReadOnly marks a host running in observation mode. This is neither a
	// failure nor a missing capability: the owner of the host configured it that
	// way and the panel is to see it as a decision, not as a fault.
	RejectReadOnly = "agent_read_only"
	// RejectResourceBusy marks a task that waited for a resource of the host and
	// did not get it. This is not a failure: the host is working, only on
	// something else this operation cannot run in parallel with.
	RejectResourceBusy = "resource_busy"
)

// TaskExecutor performs the tasks delivered by the control plane.
type TaskExecutor struct {
	helper  *HelperClient
	journal *IdempotencyJournal
	facts   func() Facts
	log     *slog.Logger
	// progress reports the progress of a long operation to the control plane.
	// Nil means there is no session - progress without a receiver is not
	// collected.
	progress func(*agentv1.TaskProgress)
	// logLines passes on the journal preview. Nil means there is no session, and
	// then the preview is not started at all: the host is not to work for
	// nobody.
	logLines func(*agentv1.TaskLogLines)
	// cancels allows interrupting the tasks that can be interrupted safely.
	cancels *cancellations
	// secrets fetches the value of a secret for the duration of one operation.
	// Nil means there is no session with the panel - and without one there is no
	// point in asking for a secret.
	secrets SecretFetch
	// readOnly marks a host in observation mode: the agent reports facts and
	// performs reads, but changes nothing on the host.
	readOnly bool
	// inventoryRefresh orders an inventory collection and waits for the revision
	// that came out of it. Nil means there is no session - and without one there
	// is nowhere to send a new picture, so there is nothing to refresh either.
	inventoryRefresh func(ctx context.Context, modules []string) Refresh
}

// SecretFetch reaches for the value of the secret named in the task.
//
// The value does not come in the envelope: the envelope carries a reference,
// and the host fetches the content only when it starts the operation. The
// function is injected by the session, because the session is what has the
// connection to the panel.
type SecretFetch func(ctx context.Context, taskID, name string, version int) ([]byte, error)

func NewTaskExecutor(helperClient *HelperClient, journal *IdempotencyJournal,
	facts func() Facts, log *slog.Logger) *TaskExecutor {
	return &TaskExecutor{
		helper: helperClient, journal: journal, facts: facts, log: log,
		cancels: newCancellationTable(),
	}
}

// SetReadOnlyMode turns on observation mode: the agent performs no mutation.
func (e *TaskExecutor) SetReadOnlyMode(readOnly bool) {
	e.readOnly = readOnly
}

// Execute carries out a task and always returns a result - also when the task
// was refused. Silence from the agent would be indistinguishable for the
// control plane from a broken connection.
func (e *TaskExecutor) Execute(ctx context.Context, task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	taskID := task.GetTaskId()
	idempotencyKey := task.GetIdempotencyKey()

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
		return replayed
	}

	started := time.Now().UTC()
	result := e.run(ctx, task, started)
	result.TaskId = taskID
	result.IdempotencyKey = idempotencyKey
	result.StartedAt = timestamppb.New(started)
	result.FinishedAt = timestamppb.New(time.Now().UTC())

	if err := e.journal.Store(idempotencyKey, result); err != nil {
		e.log.Error("the result was not stored in the idempotency journal",
			"task_id", taskID, "idempotency_key", idempotencyKey, "err", err)
	}
	return result
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

	// The hash of the plan is computed locally and compared with the envelope. A
	// swap of the payload between the approval and the delivery is detectable
	// this way.
	if expected := task.GetPayloadHash(); len(expected) > 0 {
		computed, err := opspec.PayloadHash(action, opspec.ActionVersion, payload)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, err.Error())
		}
		if !bytes.Equal(expected, computed) {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPayloadHash,
				"the content of the task does not match the approved plan")
		}
	}

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
	case opspec.ActionInventoryRefresh:
		return e.refreshInventory(ctx, task)
	case opspec.ActionDockerStart, opspec.ActionDockerStop, opspec.ActionDockerRestart,
		opspec.ActionDockerRemove, opspec.ActionDockerPull, opspec.ActionDockerPrune:
		return e.applyDocker(ctx, task, task.GetDockerAction())
	case opspec.ActionComposePlan, opspec.ActionComposeDeploy:
		return e.applyCompose(ctx, task, task.GetCompose())
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
		opspec.ActionFilesystemCreate, opspec.ActionDiskWipe:
		return e.applyStorage(ctx, task, action, payload.Storage)
	case opspec.ActionFirewallPlan, opspec.ActionFirewallRuleEnsure,
		opspec.ActionFirewallRuleRemove, opspec.ActionFirewallZonePort,
		opspec.ActionFirewallZoneService, opspec.ActionFirewallRulesetRestore:
		return e.applyFirewall(ctx, task, action, payload.Firewall)
	case opspec.ActionDNSResolveTest, opspec.ActionDNSPlan, opspec.ActionDNSHostApply:
		return e.applyDNS(ctx, task, action, payload.DNS)
	case opspec.ActionNetworkPlan, opspec.ActionNetworkMTUSet,
		opspec.ActionNetworkRouteEnsure, opspec.ActionNetworkProfileApply,
		opspec.ActionNetworkRollback:
		return e.applyNetwork(ctx, task, action, payload.Network)
	case opspec.ActionScheduleEnsure, opspec.ActionScheduleDisable,
		opspec.ActionScheduleRemove, opspec.ActionScheduleRunNow:
		return e.applySchedule(ctx, task, action, payload.Schedule)
	case opspec.ActionProcessList:
		return e.listProcesses(ctx, task, payload.ProcessList)
	case opspec.ActionProcessSignal:
		return e.signalProcess(ctx, task, payload.ProcessSignal)
	case opspec.ActionLocalUserCreate, opspec.ActionLocalUserLock,
		opspec.ActionLocalUserUnlock, opspec.ActionLocalSSHKeysSet:
		return e.applyLocalUser(ctx, task, action, payload.LocalUser)
	case opspec.ActionDomainPreflight:
		return e.enrollDomain(ctx, task, payload.DomainEnroll, true)
	case opspec.ActionDomainEnroll:
		return e.enrollDomain(ctx, task, payload.DomainEnroll, false)
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
	// of them separately, because a host sometimes has hundreds of them and
	// every query is a separate process.
	if payload.All {
		return e.listUnits(statusCtx, task)
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

// rebootHost orders a restart through the helper. The result is sent back
// before the host disappears: the delay on the helper side leaves time for
// that.
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
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Stdout:   response.GetStdout(),
		Message:  "restart zaplanowany",
	}
}

func (e *TaskExecutor) applyUnitAction(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.UnitPayload) *agentv1.TaskResult {
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
	// The error code and the message have to reach the campaign report, otherwise
	// the operator sees the bare word "failed" and has to look for the cause in
	// the output of the task.
	if response.GetExitCode() != 0 {
		result.Status = agentv1.TaskResult_STATUS_FAILED
		result.ErrorCode = systemd.ErrorCodeForExit(int(response.GetExitCode()))
		result.Message = firstLine(string(response.GetStderr()))
	}
	return result
}

// helperOperation translates the type of an operation into a helper command.
// Enabling and masking additionally depend on the desired value: one operation
// describes both sides of the toggle, because both are the same decision about
// the same property.
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
		return opspec.ActionPackageUpgrade, opspec.Payload{PackageUpgrade: &payload}, nil

	case *agentv1.TaskEnvelope_AgentUpgrade:
		request := action.AgentUpgrade
		return opspec.ActionAgentUpgrade, opspec.Payload{
			AgentUpgrade: &opspec.AgentUpgradePayload{
				TargetVersion:   request.GetTargetVersion(),
				PackageSHA256:   request.GetPackageSha256(),
				RollbackVersion: request.GetRollbackVersion(),
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

	case *agentv1.TaskEnvelope_PackagesRepair:
		// An empty list and a missing list have to give the same payload: the hash
		// of the plan is computed from the JSON, and an empty array is written
		// differently than a missing one. A repair without answers used to end in
		// payload_hash_mismatch because of that.
		var odpowiedzi []opspec.DebconfAnswer
		for _, answer := range action.PackagesRepair.GetAnswers() {
			odpowiedzi = append(odpowiedzi, opspec.DebconfAnswer{
				Package:  answer.GetPackage(),
				Question: answer.GetQuestion(),
				Type:     answer.GetType(),
				Value:    answer.GetValue(),
			})
		}
		return opspec.ActionPackageRepair, opspec.Payload{
			PackageRepair: &opspec.PackageRepairPayload{Answers: odpowiedzi},
		}, nil

	case *agentv1.TaskEnvelope_LocalUserAction:
		request := action.LocalUserAction
		actionType, known := localUserActions[request.GetOperation()]
		if !known {
			return "", opspec.Payload{}, fmt.Errorf("unknown account operation: %v", request.GetOperation())
		}
		return actionType, opspec.Payload{
			LocalUser: &opspec.LocalUserPayload{
				Name:       request.GetName(),
				Gecos:      request.GetGecos(),
				Shell:      request.GetShell(),
				Groups:     request.GetGroups(),
				SSHKeys:    request.GetSshKeys(),
				CreateHome: request.GetCreateHome(),
			},
		}, nil

	case *agentv1.TaskEnvelope_DockerRead:
		return opspec.ActionDockerRead, opspec.Payload{DockerRead: &opspec.DockerReadPayload{}}, nil

	case *agentv1.TaskEnvelope_ReadDockerEvents:
		zdarzenia := action.ReadDockerEvents
		return opspec.ActionDockerEvents, opspec.Payload{
			DockerEvents: &opspec.DockerEventsPayload{
				SinceSeconds:  int(zdarzenia.GetSinceSeconds()),
				FollowSeconds: int(zdarzenia.GetFollowSeconds()),
				Types:         zdarzenia.GetTypes(),
				MaxEvents:     int(zdarzenia.GetMaxEvents()),
			},
		}, nil

	case *agentv1.TaskEnvelope_RefreshInventory:
		return opspec.ActionInventoryRefresh, opspec.Payload{
			Inventory: &opspec.InventoryPayload{Modules: action.RefreshInventory.GetModules()},
		}, nil

	case *agentv1.TaskEnvelope_DockerAction:
		return dockerAction(action.DockerAction)

	case *agentv1.TaskEnvelope_Compose:
		kind := opspec.ActionComposePlan
		if action.Compose.GetOperation() == agentv1.ComposeAction_OPERATION_DEPLOY {
			kind = opspec.ActionComposeDeploy
		}
		return kind, opspec.Payload{Compose: &opspec.ComposePayload{
			Project:    action.Compose.GetProject(),
			Manifest:   action.Compose.GetManifest(),
			PlanDigest: action.Compose.GetPlanDigest(),
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
			// The plan and the read of the list are the same operation of the
			// panel: they are told apart by the presence of a path, not by a
			// name. The hash of the payload has to come out the same on both
			// sides, so the type here is one.
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
		kopia := action.Backup
		kind := opspec.ActionBackupPlan
		switch kopia.GetOperation() {
		case agentv1.BackupAction_OPERATION_RUN:
			kind = opspec.ActionBackupRun
		case agentv1.BackupAction_OPERATION_VERIFY:
			kind = opspec.ActionBackupVerify
		case agentv1.BackupAction_OPERATION_RESTORE:
			kind = opspec.ActionBackupRestore
		}
		zawartosc := &opspec.BackupPayload{
			ID: kopia.GetId(), Tool: kopia.GetTool(), Repository: kopia.GetRepository(),
			Paths: kopia.GetPaths(), Excludes: kopia.GetExcludes(), Tags: kopia.GetTags(),
			KeepLast: int(kopia.GetKeepLast()), KeepDaily: int(kopia.GetKeepDaily()),
			KeepWeekly: int(kopia.GetKeepWeekly()), KeepMonthly: int(kopia.GetKeepMonthly()),
			Prune: kopia.GetPrune(), Runbook: kopia.GetRunbook(),
			Initialize: kopia.GetInitialize(), ReadData: kopia.GetReadData(), SnapshotID: kopia.GetSnapshotId(),
			Target: kopia.GetTarget(), Include: kopia.GetInclude(),
			Overwrite: kopia.GetOverwrite(), Plan: kopia.GetPlan(), PlanHash: kopia.GetPlanHash(),
		}
		if ref := kopia.GetPasswordSecret(); ref != nil && ref.GetName() != "" {
			zawartosc.PasswordSecret = &opspec.SecretRef{
				Name: ref.GetName(), Version: int(ref.GetVersion()),
			}
		}
		if len(kopia.GetEnvSecrets()) > 0 {
			zawartosc.EnvSecrets = map[string]opspec.SecretRef{}
			for name, ref := range kopia.GetEnvSecrets() {
				zawartosc.EnvSecrets[name] = opspec.SecretRef{
					Name: ref.GetName(), Version: int(ref.GetVersion()),
				}
			}
		}
		return kind, opspec.Payload{Backup: zawartosc}, nil

	case *agentv1.TaskEnvelope_Repository:
		zrodlo := action.Repository
		reference := (*opspec.SecretRef)(nil)
		if ref := zrodlo.GetPasswordSecret(); ref != nil && ref.GetName() != "" {
			reference = &opspec.SecretRef{Name: ref.GetName(), Version: int(ref.GetVersion())}
		}
		return opspec.ActionRepositorySet, opspec.Payload{Repository: &opspec.RepositoryPayload{
			ID:             zrodlo.GetId(),
			Name:           zrodlo.GetName(),
			URL:            zrodlo.GetUrl(),
			Suites:         zrodlo.GetSuites(),
			Components:     zrodlo.GetComponents(),
			Architectures:  zrodlo.GetArchitectures(),
			Enabled:        zrodlo.GetEnabled(),
			Priority:       int(zrodlo.GetPriority()),
			GPGKey:         zrodlo.GetGpgKey(),
			AllowUnsigned:  zrodlo.GetAllowUnsigned(),
			Username:       zrodlo.GetUsername(),
			PasswordSecret: reference,
			Remove:         zrodlo.GetRemove(),
		}}, nil

	case *agentv1.TaskEnvelope_Certificate:
		certyfikat := action.Certificate
		kind := opspec.ActionCertificateScan
		switch certyfikat.GetOperation() {
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
		if ref := certyfikat.GetKeySecret(); ref != nil && ref.GetName() != "" {
			reference = &opspec.SecretRef{Name: ref.GetName(), Version: int(ref.GetVersion())}
		}
		zawartosc := &opspec.CertificatePayload{
			Path:        certyfikat.GetPath(),
			KeyPath:     certyfikat.GetKeyPath(),
			Certificate: certyfikat.GetCertificate(),
			KeySecret:   reference,
			Owner:       certyfikat.GetOwner(),
			Group:       certyfikat.GetGroup(),
			Mode:        certyfikat.GetMode(),
			KeyMode:     certyfikat.GetKeyMode(),
			ReloadUnit:  certyfikat.GetReloadUnit(),
			ProbeTarget: certyfikat.GetProbeTarget(),
			Request:     certyfikat.GetRequest(),
			PlanHash:    certyfikat.GetPlanHash(),
			AnchorID:    certyfikat.GetAnchorId(),
		}
		for _, cel := range certyfikat.GetTargets() {
			zawartosc.Targets = append(zawartosc.Targets, opspec.CertificateTarget{
				Path: cel.GetPath(), KeyPath: cel.GetKeyPath(), Service: cel.GetService(),
			})
		}
		return kind, opspec.Payload{Certificate: zawartosc}, nil

	case *agentv1.TaskEnvelope_SystemShutdown:
		wylaczenie := action.SystemShutdown
		return opspec.ActionSystemShutdown, opspec.Payload{Power: &opspec.PowerPayload{
			Mode:             wylaczenie.GetMode(),
			DelaySeconds:     wylaczenie.GetDelaySeconds(),
			Reason:           wylaczenie.GetReason(),
			IgnoreInhibitors: wylaczenie.GetIgnoreInhibitors(),
		}}, nil

	case *agentv1.TaskEnvelope_Time:
		zegar := action.Time
		kind := opspec.ActionTimeSyncTest
		switch zegar.GetOperation() {
		case agentv1.TimeAction_OPERATION_CONFIG_APPLY:
			kind = opspec.ActionTimeConfigApply
		case agentv1.TimeAction_OPERATION_TIMEZONE_SET:
			kind = opspec.ActionTimezoneSet
		case agentv1.TimeAction_OPERATION_PLAN:
			kind = opspec.ActionTimePlan
		}
		return kind, opspec.Payload{Time: &opspec.TimePayload{
			Servers:      zegar.GetServers(),
			Probe:        zegar.GetProbe(),
			Timezone:     zegar.GetTimezone(),
			AllowStep:    zegar.GetAllowStep(),
			EnableDropIn: zegar.GetEnableDropin(),
			PlanHash:     zegar.GetPlanHash(),
		}}, nil

	case *agentv1.TaskEnvelope_Kernel:
		jadro := action.Kernel
		kind := opspec.ActionSysctlPlan
		switch jadro.GetOperation() {
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
			Settings:  jadro.GetSettings(),
			Keys:      jadro.GetKeys(),
			Module:    jadro.GetModule(),
			Blacklist: jadro.GetBlacklist(),
			PlanHash:  jadro.GetPlanHash(),
		}}, nil

	case *agentv1.TaskEnvelope_Ssh:
		serwer := action.Ssh
		kind := opspec.ActionSSHConfigPlan
		switch serwer.GetOperation() {
		case agentv1.SshAction_OPERATION_APPLY:
			kind = opspec.ActionSSHConfigApply
		case agentv1.SshAction_OPERATION_ROTATE_HOSTKEY:
			kind = opspec.ActionSSHHostKeyRotate
		}
		return kind, opspec.Payload{SSH: &opspec.SSHPayload{
			Port:                   serwer.GetPort(),
			PermitRootLogin:        serwer.GetPermitRootLogin(),
			PasswordAuthentication: serwer.GetPasswordAuthentication(),
			PubkeyAuthentication:   serwer.GetPubkeyAuthentication(),
			KbdInteractive:         serwer.GetKbdInteractiveAuthentication(),
			MaxAuthTries:           serwer.GetMaxAuthTries(),
			AllowUsers:             serwer.GetAllowUsers(),
			AllowGroups:            serwer.GetAllowGroups(),
			DenyUsers:              serwer.GetDenyUsers(),
			AllowLockout:           serwer.GetAllowLockout(),
			KeyType:                serwer.GetKeyType(),
			PlanHash:               serwer.GetPlanHash(),
		}}, nil

	case *agentv1.TaskEnvelope_Storage:
		przestrzen := action.Storage
		kind := opspec.ActionMountEnsure
		switch przestrzen.GetOperation() {
		case agentv1.StorageAction_OPERATION_READ, agentv1.StorageAction_OPERATION_MOUNT_PLAN,
			agentv1.StorageAction_OPERATION_DEVICE_PLAN:
			// The read and the plan are the same operation of the panel; they are
			// told apart by the presence of a target. The type is one, because the
			// hash of the payload is computed from the type on both
			// stronach.
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
		}
		return kind, opspec.Payload{Storage: &opspec.StoragePayload{
			Source:            przestrzen.GetSource(),
			Target:            przestrzen.GetTarget(),
			FSType:            przestrzen.GetFsType(),
			Options:           przestrzen.GetOptions(),
			Persist:           przestrzen.GetPersist(),
			Device:            przestrzen.GetDevice(),
			ExpectedUUID:      przestrzen.GetExpectedUuid(),
			Repair:            przestrzen.GetRepair(),
			ExpectedSerial:    przestrzen.GetExpectedSerial(),
			ExpectedSizeBytes: przestrzen.GetExpectedSizeBytes(),
			Size:              przestrzen.GetSize(),
			Label:             przestrzen.GetLabel(),
			Plan:              przestrzen.GetPlan(),
			PlanHash:          przestrzen.GetPlanHash(),
		}}, nil

	case *agentv1.TaskEnvelope_Firewall:
		zapora := action.Firewall
		kind := opspec.ActionFirewallRuleEnsure
		switch zapora.GetOperation() {
		case agentv1.FirewallAction_OPERATION_READ, agentv1.FirewallAction_OPERATION_PLAN:
			// The read and the plan are the same operation of the panel; they are
			// told apart by the presence of a rule. The type has to be one, because
			// the hash of the payload is computed on both
			// stronach z tego samego typu.
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
			RuleID:          zapora.GetRuleId(),
			Chain:           zapora.GetChain(),
			Action:          zapora.GetAction(),
			Protocol:        zapora.GetProtocol(),
			Ports:           zapora.GetPorts(),
			Sources:         zapora.GetSources(),
			Interface:       zapora.GetInterface(),
			Comment:         zapora.GetComment(),
			Zone:            zapora.GetZone(),
			Service:         zapora.GetService(),
			Enable:          zapora.GetEnable(),
			BreakGlass:      zapora.GetBreakGlass(),
			RollbackSeconds: zapora.GetRollbackSeconds(),
			RollbackID:      zapora.GetRollbackId(),
			ExpectedHash:    zapora.GetExpectedHash(),
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
		siec := action.Network
		kind := opspec.ActionNetworkProfileApply
		switch siec.GetOperation() {
		case agentv1.NetworkAction_OPERATION_READ, agentv1.NetworkAction_OPERATION_PLAN:
			kind = opspec.ActionNetworkPlan
		case agentv1.NetworkAction_OPERATION_SET_MTU:
			kind = opspec.ActionNetworkMTUSet
		case agentv1.NetworkAction_OPERATION_ENSURE_ROUTES:
			kind = opspec.ActionNetworkRouteEnsure
		case agentv1.NetworkAction_OPERATION_ROLLBACK:
			kind = opspec.ActionNetworkRollback
		}
		return kind, opspec.Payload{Network: &opspec.NetworkPayload{
			Interface:       siec.GetInterface(),
			MTU:             siec.GetMtu(),
			Routes:          siec.GetRoutes(),
			Method:          siec.GetMethod(),
			Addresses:       siec.GetAddresses(),
			Gateway:         siec.GetGateway(),
			DNS:             siec.GetDns(),
			PlanHash:        siec.GetPlanHash(),
			RollbackSeconds: siec.GetRollbackSeconds(),
			RollbackID:      siec.GetRollbackId(),
		}}, nil

	case *agentv1.TaskEnvelope_Schedule:
		harmonogram := action.Schedule
		kind := opspec.ActionScheduleEnsure
		switch harmonogram.GetOperation() {
		case agentv1.ScheduleAction_OPERATION_DISABLE:
			kind = opspec.ActionScheduleDisable
		case agentv1.ScheduleAction_OPERATION_REMOVE:
			kind = opspec.ActionScheduleRemove
		case agentv1.ScheduleAction_OPERATION_RUN_NOW:
			kind = opspec.ActionScheduleRunNow
		}
		return kind, opspec.Payload{Schedule: &opspec.SchedulePayload{
			ID:         harmonogram.GetId(),
			Expression: harmonogram.GetExpression(),
			Command:    harmonogram.GetCommand(),
			User:       harmonogram.GetUser(),
			Comment:    harmonogram.GetComment(),
			Enabled:    harmonogram.GetEnabled(),
			Adopt:      harmonogram.GetAdopt(),
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
		}}, nil

	case *agentv1.TaskEnvelope_ReadLogFile:
		return opspec.ActionReadLogFile, opspec.Payload{LogFile: &opspec.LogFilePayload{
			Path:  action.ReadLogFile.GetPath(),
			Lines: action.ReadLogFile.GetLines(),
		}}, nil

	case *agentv1.TaskEnvelope_ReadUnitStatus:
		return opspec.ActionUnitStatus, opspec.Payload{
			UnitStatus: &opspec.UnitStatusPayload{
				Units: action.ReadUnitStatus.GetUnits(),
				All:   action.ReadUnitStatus.GetAll(),
			},
		}, nil

	case *agentv1.TaskEnvelope_ReadJournal:
		request := action.ReadJournal
		payload := opspec.JournalPayload{
			Unit:  request.GetUnit(),
			Lines: request.GetLines(),
			Since: request.GetSince(),
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

// cloneResult copies the result through proto.Clone. Copying the struct by
// assignment would copy the internal state of the message together with its
// mutex.
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
// types. The agent accepts no operation from outside the map, so an extension
// of the contract by a third party gives it no new abilities.
var localUserActions = map[agentv1.LocalUserAction_Operation]opspec.ActionType{
	agentv1.LocalUserAction_OPERATION_CREATE:       opspec.ActionLocalUserCreate,
	agentv1.LocalUserAction_OPERATION_LOCK:         opspec.ActionLocalUserLock,
	agentv1.LocalUserAction_OPERATION_UNLOCK:       opspec.ActionLocalUserUnlock,
	agentv1.LocalUserAction_OPERATION_SET_SSH_KEYS: opspec.ActionLocalSSHKeysSet,
}

// joinNames assembles the names into a readable list for the message shown to
// the operator.
func joinNames(names []string) string {
	return strings.Join(names, ", ")
}

// dockerAction translates the envelope of a container operation into a type and
// a payload. Every operation has its own type, because every one carries a
// different risk and a different permission.
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

// applyUnitToggle enables or masks a unit.
//
// The operation describes the desired state and not a switch: repeating it does
// not reverse the change. The path is the same as with start and stop, so the
// state before and after and the error codes stay the same for the whole
// module.
func (e *TaskExecutor) applyUnitToggle(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, toggle *agentv1.UnitToggle) *agentv1.TaskResult {
	if toggle == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"the description of the unit change is missing")
	}
	return e.applyUnitAction(ctx, task, action, &opspec.UnitPayload{Unit: toggle.GetUnit()})
}
