package agent

import (
	"context"
	"sort"
	"strings"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// applyLocalUser performs an operation on a local account through the root
// helper.
//
// The state of the account is read before the change and after it. That lets
// the result tell a real change from an agreement with the requested state, and
// the panel gets the actual state of the host instead of a repetition of the
// content of the task.
func (e *TaskExecutor) applyLocalUser(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.LocalUserPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	before := e.readSingleAccount(callCtx, payload.Name)

	// The refusal concerning a system account belongs to the helper, which sees
	// /etc/passwd and NSS. The agent does not repeat that decision so that there
	// are not two different security boundaries for the same operation.
	keys := make([]*helperv1.LocalSSHKeyInput, 0, len(payload.Keys))
	for _, key := range payload.Keys {
		keys = append(keys, &helperv1.LocalSSHKeyInput{PublicKey: key.PublicKey, Comment: key.Comment})
	}
	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_LocalUserAction{
			LocalUserAction: &helperv1.LocalUserActionRequest{
				Operation:            helperUserOperations[action],
				Name:                 payload.Name,
				Gecos:                payload.Gecos,
				Shell:                payload.Shell,
				Groups:               payload.Groups,
				SshKeys:              payload.SSHKeys,
				CreateHome:           payload.CreateHome,
				ExpiresAt:            payload.ExpiresAt,
				RemoveHome:           payload.RemoveHome,
				Keys:                 keys,
				Fingerprints:         payload.Fingerprints,
				IgnoreMissing:        payload.IgnoreMissing,
				ExpectedFingerprints: payload.ExpectedFingerprints,
				AllowLockout:         payload.AllowLockout,
				ManagedFile:          payload.ManagedFile,
				System:               payload.System,
				Inactive:             payload.Inactive,
			},
		},
	}, timeout)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectHelperFailed, err.Error())
	}
	if !response.GetAccepted() {
		result := rejected(agentv1.TaskResult_STATUS_REJECTED,
			response.GetErrorCode(), response.GetMessage())
		result.Stderr = response.GetStderr()
		return result
	}

	after := e.readSingleAccount(callCtx, payload.Name)
	detail := &agentv1.LocalUserResult{
		Name:    payload.Name,
		Changed: !sameAccountState(before, after),
	}
	if after != nil {
		detail.Account = localAccountsToProto([]LocalAccount{*after})[0]
	}
	// The result of a key operation names the keys on both sides of the
	// change and the difference, as the host reads them back - not as the
	// order described them. An idempotent repeat shows an empty difference.
	if keyOperation(action) {
		detail.FingerprintsBefore = fingerprintsOrEmpty(before)
		detail.FingerprintsAfter = fingerprintsOrEmpty(after)
		detail.KeysAdded = difference(detail.FingerprintsAfter, detail.FingerprintsBefore)
		detail.KeysRemoved = difference(detail.FingerprintsBefore, detail.FingerprintsAfter)
	}

	// An account created with no way in is confirmed as such: the plan
	// and the panel name the outcome "no login" rather than "created",
	// because an account nobody can enter is the point of such an order.
	message := localUserMessages[action]
	if action == opspec.ActionLocalUserCreate && payload.Inactive {
		message = "the local account was created locked, with no way to log in"
	}
	return &agentv1.TaskResult{
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Message:  message,
		Detail:   &agentv1.TaskResult_LocalUser{LocalUser: detail},
	}
}

// keyOperation says whether the operation edits the keys of an account.
func keyOperation(action opspec.ActionType) bool {
	switch action {
	case opspec.ActionLocalSSHKeysAdd, opspec.ActionLocalSSHKeysRemove,
		opspec.ActionLocalSSHKeysReplaceAll, opspec.ActionLocalSSHKeysSet:
		return true
	}
	return false
}

// fingerprintsOrEmpty lists the keys of an account; a missing account
// has none. The list is never nil so the result says "no keys" in so
// many words rather than leaving the field out.
func fingerprintsOrEmpty(account *LocalAccount) []string {
	if account == nil {
		return []string{}
	}
	return append([]string{}, fingerprintsOf(account)...)
}

// difference returns the entries of left that right does not have, in
// the order of left.
func difference(left, right []string) []string {
	present := map[string]bool{}
	for _, item := range right {
		present[item] = true
	}
	result := []string{}
	for _, item := range left {
		if !present[item] {
			result = append(result, item)
		}
	}
	return result
}

// readSingleAccount returns the state of one account together with the
// privileged part. A missing account gives nil: non-existence is information
// here and not an error.
func (e *TaskExecutor) readSingleAccount(ctx context.Context, name string) *LocalAccount {
	accounts := ReadLocalAccounts()
	index := -1
	for i := range accounts {
		if accounts[i].Name == name {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	found := accounts[index : index+1]
	if result, err := e.ProbeLocalAccounts(ctx, []string{name}); err == nil {
		found = mergePrivilegedAccounts(found, result)
	} else {
		// A failed privileged read leaves the lock state unknown. Writing
		// "unlocked" here would be an invented fact.
		found[0].UnavailableReason = "helper_unavailable"
	}
	return &found[0]
}

// sameAccountState compares the properties of an account the panel manages.
// Differences in fields outside that scope are not a change made by the task.
func sameAccountState(before, after *LocalAccount) bool {
	if before == nil || after == nil {
		return before == after
	}
	if before.Shell != after.Shell || before.Gecos != after.Gecos || before.ExpiresAt != after.ExpiresAt {
		return false
	}
	if !sameStrings(before.Groups, after.Groups) {
		return false
	}
	if !sameOptionalBool(before.Locked, after.Locked) {
		return false
	}
	if !sameOptionalBool(before.PasswordSet, after.PasswordSet) {
		return false
	}
	return sameStrings(fingerprintsOf(before), fingerprintsOf(after))
}

// sameOptionalBool treats an unknown state as different from every known one: a
// move from "not known" to "locked" is a change in the knowledge of the panel.
func sameOptionalBool(before, after *bool) bool {
	if before == nil || after == nil {
		return before == nil && after == nil
	}
	return *before == *after
}

func fingerprintsOf(account *LocalAccount) []string {
	values := make([]string, 0, len(account.SSHKeys))
	for _, key := range account.SSHKeys {
		values = append(values, key.Fingerprint)
	}
	return values
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

var helperUserOperations = map[opspec.ActionType]helperv1.LocalUserActionRequest_Operation{
	opspec.ActionLocalUserCreate: helperv1.LocalUserActionRequest_OPERATION_CREATE,
	opspec.ActionLocalUserLock:   helperv1.LocalUserActionRequest_OPERATION_LOCK,
	opspec.ActionLocalUserUnlock: helperv1.LocalUserActionRequest_OPERATION_UNLOCK,
	opspec.ActionLocalSSHKeysSet: helperv1.LocalUserActionRequest_OPERATION_SET_SSH_KEYS,
	// The keys one at a time: an add, a remove by fingerprint, a replace
	// bound to the list the operator saw.
	opspec.ActionLocalSSHKeysAdd:        helperv1.LocalUserActionRequest_OPERATION_ADD_SSH_KEYS,
	opspec.ActionLocalSSHKeysRemove:     helperv1.LocalUserActionRequest_OPERATION_REMOVE_SSH_KEYS,
	opspec.ActionLocalSSHKeysReplaceAll: helperv1.LocalUserActionRequest_OPERATION_REPLACE_SSH_KEYS,
	// The groups, the expiry date and the deletion of an account.
	opspec.ActionLocalUserGroupsSet: helperv1.LocalUserActionRequest_OPERATION_SET_GROUPS,
	opspec.ActionLocalUserExpirySet: helperv1.LocalUserActionRequest_OPERATION_SET_EXPIRY,
	opspec.ActionLocalUserDelete:    helperv1.LocalUserActionRequest_OPERATION_DELETE,
}

var localUserMessages = map[opspec.ActionType]string{
	opspec.ActionLocalUserCreate:        "the local account was created",
	opspec.ActionLocalUserLock:          "the local account was locked",
	opspec.ActionLocalUserUnlock:        "the local account was unlocked",
	opspec.ActionLocalSSHKeysSet:        "the SSH keys were replaced",
	opspec.ActionLocalSSHKeysAdd:        "the SSH keys were added",
	opspec.ActionLocalSSHKeysRemove:     "the SSH keys were removed",
	opspec.ActionLocalSSHKeysReplaceAll: "the SSH keys were replaced",
	// The groups, the expiry date and the deletion of an account.
	opspec.ActionLocalUserGroupsSet: "the groups of the local account were set",
	opspec.ActionLocalUserExpirySet: "the expiry of the local account was set",
	opspec.ActionLocalUserDelete:    "the local account was deleted",
}
