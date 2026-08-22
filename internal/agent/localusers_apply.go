package agent

import (
	"context"
	"sort"
	"strings"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// applyLocalUser wykonuje operacje na koncie lokalnym przez helpera roota.
//
// Stan konta jest odczytywany przed zmiana i po niej. Dzieki temu wynik
// odroznia realna zmiane od zgodnosci ze stanem zadanym, a panel dostaje
// stan faktyczny hosta zamiast powtorzenia tresci zadania.
func (e *TaskExecutor) applyLocalUser(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload *opspec.LocalUserPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, action)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	before := e.readSingleAccount(callCtx, payload.Name)

	// Odmowa dotyczaca konta systemowego nalezy do helpera, ktory widzi
	// /etc/passwd i NSS. Agent nie powtarza tej decyzji, zeby nie istnialy
	// dwie rozne granice bezpieczenstwa dla tej samej operacji.
	response, err := e.helper.Call(callCtx, &helperv1.HelperRequest{
		TaskId:         task.GetTaskId(),
		ExpiresAt:      task.GetExpiresAt(),
		TimeoutSeconds: uint32(timeout.Seconds()),
		MaxOutputBytes: task.GetLimits().GetMaxOutputBytes(),
		Action: &helperv1.HelperRequest_LocalUserAction{
			LocalUserAction: &helperv1.LocalUserActionRequest{
				Operation:  helperUserOperations[action],
				Name:       payload.Name,
				Gecos:      payload.Gecos,
				Shell:      payload.Shell,
				Groups:     payload.Groups,
				SshKeys:    payload.SSHKeys,
				CreateHome: payload.CreateHome,
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

	return &agentv1.TaskResult{
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Message:  localUserMessages[action],
		Detail:   &agentv1.TaskResult_LocalUser{LocalUser: detail},
	}
}

// readSingleAccount zwraca stan jednego konta wraz z czescia uprzywilejowana.
// Brak konta daje nil: nieistnienie jest tu informacja, a nie bledem.
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
		// Nieudany odczyt uprzywilejowany zostawia stan blokady nieznanym.
		// Wpisanie tu "odblokowane" bylo by zmyslonym faktem.
		found[0].UnavailableReason = "helper_unavailable"
	}
	return &found[0]
}

// sameAccountState porownuje te cechy konta, ktorymi zarzadza panel. Roznice
// w polach spoza tego zakresu nie sa zmiana wykonana przez zadanie.
func sameAccountState(before, after *LocalAccount) bool {
	if before == nil || after == nil {
		return before == after
	}
	if before.Shell != after.Shell || before.Gecos != after.Gecos {
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

// sameOptionalBool traktuje stan nieznany jako rozny od kazdego znanego:
// przejscie z "nie wiadomo" na "zablokowane" jest zmiana wiedzy panelu.
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
}

var localUserMessages = map[opspec.ActionType]string{
	opspec.ActionLocalUserCreate: "konto lokalne utworzone",
	opspec.ActionLocalUserLock:   "konto lokalne zablokowane",
	opspec.ActionLocalUserUnlock: "konto lokalne odblokowane",
	opspec.ActionLocalSSHKeysSet: "klucze SSH ustawione",
}
