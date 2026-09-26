package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/opspec"
)

// backupGuard names the guard of a backup operation.
func backupGuard(operation helperv1.BackupRequest_Operation) string {
	switch operation {
	case helperv1.BackupRequest_OPERATION_RUN,
		helperv1.BackupRequest_OPERATION_VERIFY,
		helperv1.BackupRequest_OPERATION_RESTORE:
		return GuardBackup
	}
	return ""
}

// applyBackup drives the backup tool.
func (s *Server) applyBackup(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.BackupRequest, progress func(*helperv1.TaskProgress)) *helperv1.HelperResponse {
	release, busy := s.hold(backupGuard(action.GetOperation()), request)
	if busy != nil {
		return busy
	}
	defer release()

	// A backup takes a long time and that is normal.
	actionCtx, cancel := deadline(ctx, request, 2*time.Hour, longestOperation)
	defer cancel()
	// The operations that hold the guard are the ones that walk the file system
	// and hash it, so they run in the scope of the backup family; the tool reads
	// the scope out of the context.
	if backupGuard(action.GetOperation()) != "" {
		actionCtx = s.scopeContext(actionCtx, request.GetTaskId(), opspec.FamilyBackups)
	}

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
		// repository: it computes what will really travel from this host and what it
		// costs.
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
			// A repository that was not read is not an empty repository, so the state
			// goes to the panel together with the reason - and the operation is a
			// refusal.
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
		// A copy binds to the plan when the order carries one. It is not required:
		// the first copy of a repository creates it, and a repository that is not
		// there yet cannot be planned against.
		if refusal := checkBackupPlanDigest(actionCtx, adapter, order, action, false, false); refusal != nil {
			return refusal
		}
		result, err := adapter.Run(actionCtx, order, receiver)
		if err != nil {
			return backupResponse(result, err)
		}
		// A copy nobody checked is not a success: a repository is sometimes damaged
		// in exactly the way it looks like a working one.
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
		// A check is not a change and is not held to a plan: it reads what is
		// there, which is the whole of what it is for.
		if refusal := checkBackupPlanDigest(actionCtx, adapter, order, action, true, false); refusal != nil {
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
		// A restore is bound to its plan like a copy and a check: the operator
		// approved unpacking out of the repository as the plan described it, and a
		// repository that has taken another copy or lost one since is not that.
		if refusal := checkBackupPlanDigest(actionCtx, adapter, order, action, false, true); refusal != nil {
			return refusal
		}
		// The target is checked right before unpacking: only the host knows what
		// really lies in that directory, and it knows it only now.
		if err := backup.CheckTarget(order.Restore); err != nil {
			code := ErrorPreconditionFailed
			if errors.Is(err, backup.ErrUnsafeTarget) {
				code = ErrorUnsafeRestoreTarget
			}
			return reject(code, err.Error())
		}
		result, err := adapter.RestoreData(actionCtx, order)
		response := backupResponse(result, err)
		// The helper counts what now lies under the target, because it is the part
		// of the host that may look: a restore writes as root into a directory the
		// agent often cannot open, and a verifier reading "permission denied" would.
		if response.GetBackupResult() != nil {
			if entries, counted := countEntries(order.Restore.Target); counted {
				response.BackupResult.TargetEntries = entries
				response.BackupResult.TargetRead = true
			}
		}
		return response
	}
	return reject(ErrorUnknownAction, "unknown backup operation")
}

// backupResponse assembles the answer from the result of the operation.
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
	// A repository that does not exist yet is named as such, so the caller
	// can tell "no copies here" from "the copies could not be listed".
	if errors.Is(err, backup.ErrRepositoryAbsent) {
		return ErrorRepositoryAbsent
	}
	return ErrorExecFailed
}

// backupPlanResponse assembles the plan of the copy against the state of the
// repository.
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
// operator consented to.
func checkBackupPlanDigest(ctx context.Context, adapter backup.Adapter,
	order backup.Order, action *helperv1.BackupRequest, verification, required bool) *helperv1.HelperResponse {
	expected := action.GetPlanHash()
	if expected == "" {
		if required {
			// The panel sent no plan for an operation that is bound to one. The
			// check used to pass on an empty hash, which made the binding a thing
			// that happened when somebody remembered it.
			return reject(errorStalePlan,
				"this operation is bound to a plan of the repository and the order carries none; read the repository and order again")
		}
		return nil
	}
	state, err := adapter.Plan(ctx, order)
	if err != nil {
		state.UnavailableReason = err.Error()
	}
	now := backup.Compute(state, order.Definition, verification,
		order.ReadData, backup.PathSize)
	if now.PlanHash != expected {
		// The shared code of every planned family: the fingerprint computed again
		// under the lock is not the one that was approved.
		return reject(errorStalePlan,
			"the scope of the copy or the repository changed since the planning; the operation needs a new plan")
	}
	return nil
}

// countEntries counts what lies directly under a directory.
func countEntries(path string) (int64, bool) {
	if path == "" {
		return 0, false
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, false
	}
	return int64(len(entries)), true
}
