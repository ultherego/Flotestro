package helper

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/backup"
)

// applyBackup drives the backup tool.
//
// The helper does not make the backup itself: it is made by the tool the host
// already has and the administrator already trusts. Here there is only what the
// tool will not do on its own - checking the restore target, passing the
// credentials through the environment and turning the result into something the
// panel can show.
func (s *Server) applyBackup(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.BackupRequest, progress func(*helperv1.TaskProgress)) *helperv1.HelperResponse {
	// A backup takes a long time and that is normal. The limit comes from the
	// order, because it is the panel that knows how much time the operator gave
	// this operation.
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 12*time.Hour {
		timeout = 2 * time.Hour
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	definition := backup.Definition{
		ID: action.GetId(), Tool: action.GetTool(), Repository: action.GetRepository(),
		Paths: action.GetPaths(), Excludes: action.GetExcludes(), Tags: action.GetTags(),
		KeepLast: int(action.GetKeepLast()), KeepDaily: int(action.GetKeepDaily()),
		KeepWeekly: int(action.GetKeepWeekly()), KeepMonthly: int(action.GetKeepMonthly()),
		Prune: action.GetPrune(), Runbook: action.GetRunbook(),
		Initialize: action.GetInitialize(),
	}
	if err := definition.Validate(); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	adapter, err := backup.Select(definition.Tool)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if !adapter.Available() {
		return reject(ErrorUnsupported, "this host has no "+definition.Tool+" tool")
	}

	order := backup.Order{
		Definition: definition,
		Password:   action.GetPassword(),
		ReadData:   action.GetReadData(),
		Restore: backup.Restore{
			SnapshotID: action.GetSnapshotId(), Target: action.GetTarget(),
			Include: action.GetInclude(), Overwrite: action.GetOverwrite(),
		},
	}
	if len(action.GetEnv()) > 0 {
		order.Environment = map[string][]byte{}
		for name, value := range action.GetEnv() {
			order.Environment[name] = value
		}
	}

	receiver := backup.ProgressFunc(nil)
	if progress != nil {
		receiver = func(p backup.Progress) {
			progress(&helperv1.TaskProgress{Percent: p.Percent, Message: p.Message})
		}
	}

	switch action.GetOperation() {
	case helperv1.BackupRequest_OPERATION_PLAN:
		state, err := adapter.Plan(actionCtx, order)
		// A plan named by its kind is a plan of the copy and not a read of the
		// repository: it computes what will really travel from this host and
		// what it costs. The order itself looks the same in both cases.
		if kind := action.GetPlan(); kind != "" {
			if err != nil {
				state.UnavailableReason = err.Error()
			}
			return backupPlanResponse(state, order.Definition,
				kind == backup.PlanVerify, action.GetReadData())
		}
		encoded, marshalErr := json.Marshal(state)
		if marshalErr != nil {
			return reject(ErrorExecFailed, marshalErr.Error())
		}
		if err != nil {
			// A repository that was not read is not an empty repository, so the
			// state goes to the panel together with the reason - and the
			// operation is a refusal.
			return &helperv1.HelperResponse{
				Accepted:  false,
				ErrorCode: backupErrorCode(err),
				Message:   err.Error(),
				BackupResult: &helperv1.BackupResult{
					State: encoded, Message: err.Error(),
				},
			}
		}
		return &helperv1.HelperResponse{
			Accepted:     true,
			BackupResult: &helperv1.BackupResult{State: encoded, Message: "the repository state was read"},
		}

	case helperv1.BackupRequest_OPERATION_RUN:
		if refusal := checkBackupPlanDigest(actionCtx, adapter, order, action, false); refusal != nil {
			return refusal
		}
		result, err := adapter.Run(actionCtx, order, receiver)
		if err != nil {
			return backupResponse(result, err)
		}
		// A copy nobody checked is not a success: a repository is sometimes
		// damaged in exactly the way it looks like a working one. The host
		// checks it right away and only then reports the copy.
		if _, err := adapter.Verify(actionCtx, order); err != nil {
			response := backupResponse(result, nil)
			response.Accepted = false
			response.ErrorCode = ErrorPreconditionFailed
			response.Message = "the copy was created, but the repository did not pass the check: " + err.Error()
			response.BackupResult.Message = response.Message
			return response
		}
		response := backupResponse(result, nil)
		response.BackupResult.Verified = true
		response.BackupResult.Message = result.Message + "; the repository was checked"
		return response

	case helperv1.BackupRequest_OPERATION_VERIFY:
		if refusal := checkBackupPlanDigest(actionCtx, adapter, order, action, true); refusal != nil {
			return refusal
		}
		result, err := adapter.Verify(actionCtx, order)
		response := backupResponse(result, err)
		if err == nil {
			response.BackupResult.Verified = true
		}
		return response

	case helperv1.BackupRequest_OPERATION_RESTORE:
		if err := backup.ValidateRestore(order.Restore); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		// The target is checked right before unpacking: only the host knows what
		// really lies in that directory, and it knows it only now.
		if err := backup.CheckTarget(order.Restore); err != nil {
			return reject(ErrorPreconditionFailed, err.Error())
		}
		result, err := adapter.RestoreData(actionCtx, order)
		return backupResponse(result, err)
	}
	return reject(ErrorUnknownAction, "unknown backup operation")
}

// backupResponse assembles the answer from the result of the operation.
//
// The result goes to the panel on failure as well: an interrupted copy leaves a
// state that has to be named, not the bare words "it failed".
func backupResponse(result backup.Result, err error) *helperv1.HelperResponse {
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return reject(ErrorExecFailed, marshalErr.Error())
	}
	if err != nil {
		return &helperv1.HelperResponse{
			Accepted:  false,
			ErrorCode: backupErrorCode(err),
			Message:   err.Error(),
			BackupResult: &helperv1.BackupResult{
				Outcome: encoded, Message: err.Error(),
			},
		}
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		BackupResult: &helperv1.BackupResult{
			Outcome: encoded, Message: result.Message,
		},
	}
}

// backupErrorCode tells an interruption from an ordinary failure of the tool.
func backupErrorCode(err error) string {
	if errors.Is(err, backup.ErrInterrupted) {
		return ErrorTimeout
	}
	return ErrorExecFailed
}

// backupPlanResponse assembles the plan of the copy against the state of the
// repository.
//
// The size of the scope is computed by the host: the panel does not know how
// much data really lies there, and the operator is to see it before consenting.
func backupPlanResponse(state backup.State, definition backup.Definition,
	verification, readData bool) *helperv1.HelperResponse {
	plan := backup.Compute(state, definition, verification, readData, backup.PathSize)
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the copy will not be created on this host: " + plan.Refusal
	if plan.Refusal == "" {
		message = strings.Join(plan.Changes, "; ")
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		BackupResult: &helperv1.BackupResult{
			State: stateJSON, Plan: encoded, Message: message,
		},
	}
}

// checkBackupPlanDigest compares the plan computed now with the one the
// operator consented to. A different digest means the scope or the repository
// changed since the planning - and that is a refusal, not a warning.
func checkBackupPlanDigest(ctx context.Context, adapter backup.Adapter,
	order backup.Order, action *helperv1.BackupRequest, verification bool) *helperv1.HelperResponse {
	expected := action.GetPlanHash()
	if expected == "" {
		return nil
	}
	state, err := adapter.Plan(ctx, order)
	if err != nil {
		state.UnavailableReason = err.Error()
	}
	now := backup.Compute(state, order.Definition, verification,
		order.ReadData, backup.PathSize)
	if now.PlanHash != expected {
		return reject(ErrorPreconditionFailed,
			"the scope of the copy or the repository changed since the planning; the operation needs a new plan")
	}
	return nil
}
