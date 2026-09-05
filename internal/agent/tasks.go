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

// Stabilne kody odrzucenia. Sa czescia kontraktu i nie zaleza od jezyka.
const (
	RejectExpired        = "expired"
	RejectPrecondition   = "precondition_failed"
	RejectPayloadHash    = "payload_hash_mismatch"
	RejectUnknownAction  = "unknown_action"
	RejectHelperFailed   = "helper_unavailable"
	RejectCapability     = "capability_missing"
	RejectInvalidRequest = "invalid_request"
	// RejectUnsupported oznacza agenta, ktory z zalozenia nie wykonuje zadan.
	RejectUnsupported = "unsupported"
	// RejectInternalError oznacza blad po stronie agenta. Zadanie konczy sie
	// wynikiem negatywnym zamiast zabierac ze soba caly proces.
	RejectInternalError = "agent_internal_error"
	// RejectNetworkUnreachable oznacza zmiane sieci, po ktorej host stracil
	// droge do panelu. Zmiana nie zostaje potwierdzona, wiec host wroci sam
	// do konfiguracji sprzed niej.
	RejectNetworkUnreachable = "network_unreachable"
)

// TaskExecutor wykonuje zadania dostarczone przez control plane.
type TaskExecutor struct {
	helper  *HelperClient
	journal *IdempotencyJournal
	facts   func() Facts
	log     *slog.Logger
	// progress melduje postep dlugiej operacji do control plane. Nil oznacza
	// brak sesji - postep bez odbiorcy nie jest zbierany.
	progress func(*agentv1.TaskProgress)
	// logLines przekazuje podglad dziennika. Nil oznacza brak sesji, a wtedy
	// podglad nie jest w ogole uruchamiany: host nie ma pracowac dla nikogo.
	logLines func(*agentv1.TaskLogLines)
	// cancels pozwala przerwac zadania, ktore da sie bezpiecznie przerwac.
	cancels *anulowania
	// sekrety pobiera wartosc sekretu na czas jednej operacji. Nil oznacza
	// brak sesji z panelem - a bez niej nie ma po co pytac o sekret.
	sekrety PobranieSekretu
}

// PobranieSekretu siega po wartosc sekretu wskazanego w zadaniu.
//
// Wartosc nie przychodzi w kopercie: koperta niesie odnosnik, a host pobiera
// tresc dopiero wtedy, gdy zaczyna operacje. Funkcja jest wstrzykiwana przez
// sesje, bo to ona ma polaczenie z panelem.
type PobranieSekretu func(ctx context.Context, taskID, nazwa string, wersja int) ([]byte, error)

func NewTaskExecutor(helperClient *HelperClient, journal *IdempotencyJournal,
	facts func() Facts, log *slog.Logger) *TaskExecutor {
	return &TaskExecutor{
		helper: helperClient, journal: journal, facts: facts, log: log,
		cancels: nowaTablicaAnulowan(),
	}
}

// Execute realizuje zadanie i zawsze zwraca wynik - takze wtedy, gdy zadanie
// zostalo odrzucone. Milczenie agenta byloby dla control plane nieodrozninalne
// od zerwanego polaczenia.
func (e *TaskExecutor) Execute(ctx context.Context, task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	taskID := task.GetTaskId()
	idempotencyKey := task.GetIdempotencyKey()

	// Ponowne dostarczenie zwraca poprzedni wynik zamiast wykonywac mutacje
	// drugi raz. To jest cala istota at-least-once.
	if previous := e.journal.Lookup(idempotencyKey); previous != nil {
		e.log.Info("ponowne dostarczenie operacji, zwracam zapisany wynik",
			"task_id", taskID, "idempotency_key", idempotencyKey, "status", previous.GetStatus())
		replayed := cloneResult(previous)
		// task_id wskazuje biezaca probe, zeby serwer mogl skorelowac wynik.
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
		e.log.Error("nie zapisano wyniku w dzienniku idempotencji",
			"task_id", taskID, "idempotency_key", idempotencyKey, "err", err)
	}
	return result
}

func (e *TaskExecutor) run(ctx context.Context, task *agentv1.TaskEnvelope, now time.Time) *agentv1.TaskResult {
	// TTL sprawdzamy przed czymkolwiek innym: zadanie, ktore dotarlo po
	// powrocie sieci, nie moze zostac wykonane.
	if expires := task.GetExpiresAt(); expires != nil && now.After(expires.AsTime()) {
		return rejected(agentv1.TaskResult_STATUS_EXPIRED, RejectExpired,
			fmt.Sprintf("zadanie wygaslo %s", expires.AsTime().Format(time.RFC3339)))
	}

	facts := e.facts()
	if err := checkPreconditions(task.GetPreconditions(), facts); err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPrecondition, err.Error())
	}

	action, payload, err := decodeAction(task)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectUnknownAction, err.Error())
	}
	if capability := action.RequiredCapability(); !facts.Capabilities.Spelnia(capability) {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectCapability,
			fmt.Sprintf("host nie ma zdolnosci %s", capability))
	}

	// Hash planu liczymy lokalnie i porownujemy z koperta. Podmiana payloadu
	// miedzy zatwierdzeniem a dostarczeniem jest w ten sposob wykrywalna.
	if expected := task.GetPayloadHash(); len(expected) > 0 {
		computed, err := opspec.PayloadHash(action, opspec.ActionVersion, payload)
		if err != nil {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest, err.Error())
		}
		if !bytes.Equal(expected, computed) {
			return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectPayloadHash,
				"tresc zadania nie odpowiada zatwierdzonemu planowi")
		}
	}

	switch action {
	case opspec.ActionReadJournal:
		return e.readJournal(ctx, task, payload.Journal)
	case opspec.ActionPackagePlan:
		return e.planPackages(ctx, task, payload.PackagePlan)
	case opspec.ActionPackageUpgrade:
		return e.upgradePackages(ctx, task, payload.PackageUpgrade)
	case opspec.ActionPackageRepair:
		return e.repairPackages(ctx, task, payload.PackageRepair)
	case opspec.ActionSystemReboot:
		return e.rebootHost(ctx, task, payload.Reboot)
	case opspec.ActionUnitStatus:
		return e.readUnitStatus(ctx, task, payload.UnitStatus)
	case opspec.ActionDockerRead:
		return e.readDocker(ctx, task)
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
	case opspec.ActionSysctlPlan, opspec.ActionSysctlEnsure,
		opspec.ActionKernelModuleLoad, opspec.ActionKernelModuleBlacklist:
		return e.applyKernel(ctx, task, action, payload.Kernel)
	case opspec.ActionTimeSyncTest, opspec.ActionTimeConfigApply, opspec.ActionTimezoneSet:
		return e.applyTime(ctx, task, action, payload.Time)
	case opspec.ActionSystemShutdown:
		return e.shutdownHost(ctx, task, payload.Power)
	case opspec.ActionSecurityScan, opspec.ActionSELinuxModeSet, opspec.ActionAuditRulesReload:
		return e.applySecurity(ctx, task, action, payload.Security)
	case opspec.ActionCertificateScan, opspec.ActionCertificateDeploy,
		opspec.ActionCertificateRenew:
		return e.applyCertificate(ctx, task, action, payload.Certificate)
	case opspec.ActionRepositorySet:
		return e.applyRepository(ctx, task, action, payload.Repository)
	case opspec.ActionBackupPlan, opspec.ActionBackupRun,
		opspec.ActionBackupVerify, opspec.ActionBackupRestore:
		return e.applyBackup(ctx, task, action, payload.Backup)
	case opspec.ActionMonitoringProbe:
		return e.applyProbe(ctx, task, action, payload.Monitoring)
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
	case opspec.ActionDNSResolveTest, opspec.ActionDNSHostApply:
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

// readUnitStatus odczytuje stan jednostek. Operacja jest niemutujaca i dziala
// bez roota, wiec nie idzie przez helpera.
func (e *TaskExecutor) readUnitStatus(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.UnitStatusPayload) *agentv1.TaskResult {
	timeout := timeoutOf(task, opspec.ActionUnitStatus)
	statusCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Pelny wykaz jednostek jest osobna sciezka: nie pytamy systemd o kazda
	// z nich z osobna, bo host miewa ich kilkaset i kazde zapytanie to
	// osobny proces.
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
	// Niezdrowa jednostka jest wynikiem negatywnym, a nie bledem wykonania:
	// odczyt sie udal, tylko stan hosta nie spelnia oczekiwan.
	if len(unhealthy) > 0 {
		result.Status = agentv1.TaskResult_STATUS_FAILED
		result.ExitCode = 1
		result.ErrorCode = "unit_unhealthy"
		result.Message = "jednostki w zlym stanie: " + strings.Join(unhealthy, ", ")
	}
	return result
}

// rebootHost zleca restart przez helpera. Wynik jest odsylany, zanim host
// zniknie: opoznienie po stronie helpera daje na to czas.
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
				Operation: operacjaHelpera(action, task),
			},
		},
	}, timeout)
	if err != nil {
		// Niedostepny helper jest awaria agenta, nie wynikiem operacji.
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
	// Niezerowy kod wyjscia jest niepowodzeniem operacji, a nie awaria agenta.
	// Kod bledu i komunikat musza dotrzec do raportu kampanii, inaczej operator
	// widzi samo slowo "failed" i musi szukac przyczyny w wyjsciu zadania.
	if response.GetExitCode() != 0 {
		result.Status = agentv1.TaskResult_STATUS_FAILED
		result.ErrorCode = systemd.ErrorCodeForExit(int(response.GetExitCode()))
		result.Message = firstLine(string(response.GetStderr()))
	}
	return result
}

// operacjaHelpera tlumaczy typ operacji na polecenie helpera. Wlaczenie
// i maskowanie zaleza dodatkowo od wartosci docelowej: jedna operacja opisuje
// obie strony przelacznika, bo obie sa ta sama decyzja o tej samej wlasciwosci.
func operacjaHelpera(action opspec.ActionType, task *agentv1.TaskEnvelope) helperv1.UnitActionRequest_Operation {
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

// checkPreconditions sprawdza, czy stan bazowy nie zmienil sie od planowania.
func checkPreconditions(preconditions *agentv1.Preconditions, facts Facts) error {
	if preconditions == nil {
		return nil
	}
	if want := preconditions.GetOsFamily(); want != "" && want != facts.OS.Family {
		return fmt.Errorf("oczekiwano systemu %s, host ma %s", want, facts.OS.Family)
	}
	for _, capability := range preconditions.GetRequiredCapabilities() {
		if !facts.Capabilities.Spelnia(capability) {
			return fmt.Errorf("host nie ma zdolnosci %s", capability)
		}
	}
	// Zmiana boot_id oznacza, ze host zdazyl sie zrestartowac od planowania.
	if want := preconditions.GetExpectedBootId(); want != "" && want != facts.BootID {
		return fmt.Errorf("host zostal zrestartowany od czasu planowania")
	}
	return nil
}

// decodeAction tlumaczy koperte na typ operacji i payload w postaci kanonicznej.
func decodeAction(task *agentv1.TaskEnvelope) (opspec.ActionType, opspec.Payload, error) {
	switch action := task.GetAction().(type) {
	case *agentv1.TaskEnvelope_UnitAction:
		actionType, ok := unitActionTypes[action.UnitAction.GetOperation()]
		if !ok {
			return "", opspec.Payload{}, fmt.Errorf("nieznana operacja na jednostce")
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
		// Haslo jednorazowe nie wchodzi do payloadu kanonicznego, wiec nie
		// wplywa na hash planu i nie jest z niego odtwarzalne.
		return actionType, opspec.Payload{
			DomainEnroll: &opspec.DomainEnrollPayload{
				Domain:   request.GetDomain(),
				Realm:    request.GetRealm(),
				Server:   request.GetServer(),
				Hostname: request.GetHostname(),
			},
		}, nil

	case *agentv1.TaskEnvelope_PackagesRepair:
		odpowiedzi := make([]opspec.DebconfAnswer, 0, len(action.PackagesRepair.GetAnswers()))
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
			return "", opspec.Payload{}, fmt.Errorf("nieznana operacja na koncie: %v", request.GetOperation())
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

	case *agentv1.TaskEnvelope_DockerAction:
		return akcjaDockera(action.DockerAction)

	case *agentv1.TaskEnvelope_Compose:
		typ := opspec.ActionComposePlan
		if action.Compose.GetOperation() == agentv1.ComposeAction_OPERATION_DEPLOY {
			typ = opspec.ActionComposeDeploy
		}
		return typ, opspec.Payload{Compose: &opspec.ComposePayload{
			Project:    action.Compose.GetProject(),
			Manifest:   action.Compose.GetManifest(),
			PlanDigest: action.Compose.GetPlanDigest(),
		}}, nil

	case *agentv1.TaskEnvelope_UnitToggle:
		typ := opspec.ActionUnitEnableSet
		if action.UnitToggle.GetProperty() == agentv1.UnitToggle_PROPERTY_MASKED {
			typ = opspec.ActionUnitMaskSet
		}
		return typ, opspec.Payload{UnitToggle: &opspec.UnitToggle{
			Unit:    action.UnitToggle.GetUnit(),
			Enabled: action.UnitToggle.GetValue(),
		}}, nil

	case *agentv1.TaskEnvelope_PackageLifecycle:
		zmiana := action.PackageLifecycle
		typ := opspec.ActionPackageInstall
		switch zmiana.GetOperation() {
		case agentv1.PackageLifecycle_OPERATION_REMOVE:
			typ = opspec.ActionPackageRemove
		case agentv1.PackageLifecycle_OPERATION_HOLD:
			typ = opspec.ActionPackageHoldSet
		}
		return typ, opspec.Payload{PackageChange: &opspec.PackageChangePayload{
			Packages:         zmiana.GetPackages(),
			ExpectedRemovals: zmiana.GetExpectedRemovals(),
			Hold:             zmiana.GetHold(),
		}}, nil

	case *agentv1.TaskEnvelope_File:
		plik := action.File
		typ := opspec.ActionFilePlan
		switch plik.GetOperation() {
		case agentv1.FileAction_OPERATION_READ:
			typ = opspec.ActionFileRead
		case agentv1.FileAction_OPERATION_ENSURE:
			typ = opspec.ActionFileEnsure
		case agentv1.FileAction_OPERATION_ROLLBACK:
			typ = opspec.ActionFileRollback
		case agentv1.FileAction_OPERATION_REMOVE:
			typ = opspec.ActionFileRemove
		}
		odnosnik := (*opspec.SecretRef)(nil)
		if ref := plik.GetContentSecret(); ref != nil && ref.GetName() != "" {
			odnosnik = &opspec.SecretRef{Name: ref.GetName(), Version: int(ref.GetVersion())}
		}
		return typ, opspec.Payload{File: &opspec.FilePayload{
			ContentSecret:  odnosnik,
			Path:           plik.GetPath(),
			Content:        string(plik.GetContent()),
			Mode:           plik.GetMode(),
			Owner:          plik.GetOwner(),
			Group:          plik.GetGroup(),
			ExpectedSHA256: plik.GetExpectedSha256(),
			Validator:      plik.GetValidator(),
		}}, nil

	case *agentv1.TaskEnvelope_Security:
		ochrona := action.Security
		typ := opspec.ActionSecurityScan
		switch ochrona.GetOperation() {
		case agentv1.SecurityAction_OPERATION_SELINUX_MODE:
			typ = opspec.ActionSELinuxModeSet
		case agentv1.SecurityAction_OPERATION_AUDIT_RELOAD:
			typ = opspec.ActionAuditRulesReload
		}
		return typ, opspec.Payload{Security: &opspec.SecurityPayload{Mode: ochrona.GetMode()}}, nil

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
		typ := opspec.ActionBackupPlan
		switch kopia.GetOperation() {
		case agentv1.BackupAction_OPERATION_RUN:
			typ = opspec.ActionBackupRun
		case agentv1.BackupAction_OPERATION_VERIFY:
			typ = opspec.ActionBackupVerify
		case agentv1.BackupAction_OPERATION_RESTORE:
			typ = opspec.ActionBackupRestore
		}
		zawartosc := &opspec.BackupPayload{
			ID: kopia.GetId(), Tool: kopia.GetTool(), Repository: kopia.GetRepository(),
			Paths: kopia.GetPaths(), Excludes: kopia.GetExcludes(), Tags: kopia.GetTags(),
			KeepLast: int(kopia.GetKeepLast()), KeepDaily: int(kopia.GetKeepDaily()),
			KeepWeekly: int(kopia.GetKeepWeekly()), KeepMonthly: int(kopia.GetKeepMonthly()),
			Prune: kopia.GetPrune(), Runbook: kopia.GetRunbook(),
			Initialize: kopia.GetInitialize(), ReadData: kopia.GetReadData(), SnapshotID: kopia.GetSnapshotId(),
			Target: kopia.GetTarget(), Include: kopia.GetInclude(),
			Overwrite: kopia.GetOverwrite(),
		}
		if ref := kopia.GetPasswordSecret(); ref != nil && ref.GetName() != "" {
			zawartosc.PasswordSecret = &opspec.SecretRef{
				Name: ref.GetName(), Version: int(ref.GetVersion()),
			}
		}
		if len(kopia.GetEnvSecrets()) > 0 {
			zawartosc.EnvSecrets = map[string]opspec.SecretRef{}
			for nazwa, ref := range kopia.GetEnvSecrets() {
				zawartosc.EnvSecrets[nazwa] = opspec.SecretRef{
					Name: ref.GetName(), Version: int(ref.GetVersion()),
				}
			}
		}
		return typ, opspec.Payload{Backup: zawartosc}, nil

	case *agentv1.TaskEnvelope_Repository:
		zrodlo := action.Repository
		odnosnik := (*opspec.SecretRef)(nil)
		if ref := zrodlo.GetPasswordSecret(); ref != nil && ref.GetName() != "" {
			odnosnik = &opspec.SecretRef{Name: ref.GetName(), Version: int(ref.GetVersion())}
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
			PasswordSecret: odnosnik,
			Remove:         zrodlo.GetRemove(),
		}}, nil

	case *agentv1.TaskEnvelope_Certificate:
		certyfikat := action.Certificate
		typ := opspec.ActionCertificateScan
		switch certyfikat.GetOperation() {
		case agentv1.CertificateAction_OPERATION_DEPLOY:
			typ = opspec.ActionCertificateDeploy
		case agentv1.CertificateAction_OPERATION_RENEW:
			typ = opspec.ActionCertificateRenew
		}
		odnosnik := (*opspec.SecretRef)(nil)
		if ref := certyfikat.GetKeySecret(); ref != nil && ref.GetName() != "" {
			odnosnik = &opspec.SecretRef{Name: ref.GetName(), Version: int(ref.GetVersion())}
		}
		zawartosc := &opspec.CertificatePayload{
			Path:        certyfikat.GetPath(),
			KeyPath:     certyfikat.GetKeyPath(),
			Certificate: certyfikat.GetCertificate(),
			KeySecret:   odnosnik,
			Owner:       certyfikat.GetOwner(),
			Group:       certyfikat.GetGroup(),
			Mode:        certyfikat.GetMode(),
			KeyMode:     certyfikat.GetKeyMode(),
			ReloadUnit:  certyfikat.GetReloadUnit(),
			ProbeTarget: certyfikat.GetProbeTarget(),
			Request:     certyfikat.GetRequest(),
		}
		for _, cel := range certyfikat.GetTargets() {
			zawartosc.Targets = append(zawartosc.Targets, opspec.CertificateTarget{
				Path: cel.GetPath(), KeyPath: cel.GetKeyPath(), Service: cel.GetService(),
			})
		}
		return typ, opspec.Payload{Certificate: zawartosc}, nil

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
		typ := opspec.ActionTimeSyncTest
		switch zegar.GetOperation() {
		case agentv1.TimeAction_OPERATION_CONFIG_APPLY:
			typ = opspec.ActionTimeConfigApply
		case agentv1.TimeAction_OPERATION_TIMEZONE_SET:
			typ = opspec.ActionTimezoneSet
		}
		return typ, opspec.Payload{Time: &opspec.TimePayload{
			Servers:      zegar.GetServers(),
			Probe:        zegar.GetProbe(),
			Timezone:     zegar.GetTimezone(),
			AllowStep:    zegar.GetAllowStep(),
			EnableDropIn: zegar.GetEnableDropin(),
		}}, nil

	case *agentv1.TaskEnvelope_Kernel:
		jadro := action.Kernel
		typ := opspec.ActionSysctlPlan
		switch jadro.GetOperation() {
		case agentv1.KernelAction_OPERATION_SYSCTL_ENSURE:
			typ = opspec.ActionSysctlEnsure
		case agentv1.KernelAction_OPERATION_MODULE_LOAD:
			typ = opspec.ActionKernelModuleLoad
		case agentv1.KernelAction_OPERATION_MODULE_BLACKLIST:
			typ = opspec.ActionKernelModuleBlacklist
		}
		return typ, opspec.Payload{Kernel: &opspec.KernelPayload{
			Settings:  jadro.GetSettings(),
			Keys:      jadro.GetKeys(),
			Module:    jadro.GetModule(),
			Blacklist: jadro.GetBlacklist(),
		}}, nil

	case *agentv1.TaskEnvelope_Ssh:
		serwer := action.Ssh
		typ := opspec.ActionSSHConfigPlan
		switch serwer.GetOperation() {
		case agentv1.SshAction_OPERATION_APPLY:
			typ = opspec.ActionSSHConfigApply
		case agentv1.SshAction_OPERATION_ROTATE_HOSTKEY:
			typ = opspec.ActionSSHHostKeyRotate
		}
		return typ, opspec.Payload{SSH: &opspec.SSHPayload{
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
		}}, nil

	case *agentv1.TaskEnvelope_Storage:
		przestrzen := action.Storage
		typ := opspec.ActionMountEnsure
		switch przestrzen.GetOperation() {
		case agentv1.StorageAction_OPERATION_READ:
			typ = opspec.ActionStoragePlan
		case agentv1.StorageAction_OPERATION_MOUNT_REMOVE:
			typ = opspec.ActionMountRemove
		case agentv1.StorageAction_OPERATION_FS_CHECK:
			typ = opspec.ActionFilesystemCheck
		case agentv1.StorageAction_OPERATION_LVM_EXTEND:
			typ = opspec.ActionLVMExtend
		case agentv1.StorageAction_OPERATION_FS_RESIZE:
			typ = opspec.ActionFilesystemResize
		case agentv1.StorageAction_OPERATION_FS_CREATE:
			typ = opspec.ActionFilesystemCreate
		case agentv1.StorageAction_OPERATION_DISK_WIPE:
			typ = opspec.ActionDiskWipe
		}
		return typ, opspec.Payload{Storage: &opspec.StoragePayload{
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
		}}, nil

	case *agentv1.TaskEnvelope_Firewall:
		zapora := action.Firewall
		typ := opspec.ActionFirewallRuleEnsure
		switch zapora.GetOperation() {
		case agentv1.FirewallAction_OPERATION_READ:
			typ = opspec.ActionFirewallPlan
		case agentv1.FirewallAction_OPERATION_RULE_REMOVE:
			typ = opspec.ActionFirewallRuleRemove
		case agentv1.FirewallAction_OPERATION_ZONE_PORT:
			typ = opspec.ActionFirewallZonePort
		case agentv1.FirewallAction_OPERATION_ZONE_SERVICE:
			typ = opspec.ActionFirewallZoneService
		case agentv1.FirewallAction_OPERATION_RESTORE:
			typ = opspec.ActionFirewallRulesetRestore
		}
		return typ, opspec.Payload{Firewall: &opspec.FirewallPayload{
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
		typ := opspec.ActionDNSHostApply
		if resolver.GetOperation() == agentv1.DnsAction_OPERATION_RESOLVE_TEST {
			typ = opspec.ActionDNSResolveTest
		}
		return typ, opspec.Payload{DNS: &opspec.DNSPayload{
			Interface:       resolver.GetInterface(),
			Servers:         resolver.GetServers(),
			SearchDomains:   resolver.GetSearchDomains(),
			IgnoreAutoDNS:   resolver.GetIgnoreAutoDns(),
			RollbackSeconds: resolver.GetRollbackSeconds(),
			Names:           resolver.GetNames(),
		}}, nil

	case *agentv1.TaskEnvelope_Network:
		siec := action.Network
		typ := opspec.ActionNetworkProfileApply
		switch siec.GetOperation() {
		case agentv1.NetworkAction_OPERATION_READ:
			typ = opspec.ActionNetworkPlan
		case agentv1.NetworkAction_OPERATION_SET_MTU:
			typ = opspec.ActionNetworkMTUSet
		case agentv1.NetworkAction_OPERATION_ENSURE_ROUTES:
			typ = opspec.ActionNetworkRouteEnsure
		case agentv1.NetworkAction_OPERATION_ROLLBACK:
			typ = opspec.ActionNetworkRollback
		}
		return typ, opspec.Payload{Network: &opspec.NetworkPayload{
			Interface:       siec.GetInterface(),
			MTU:             siec.GetMtu(),
			Routes:          siec.GetRoutes(),
			Method:          siec.GetMethod(),
			Addresses:       siec.GetAddresses(),
			Gateway:         siec.GetGateway(),
			DNS:             siec.GetDns(),
			RollbackSeconds: siec.GetRollbackSeconds(),
			RollbackID:      siec.GetRollbackId(),
		}}, nil

	case *agentv1.TaskEnvelope_Schedule:
		harmonogram := action.Schedule
		typ := opspec.ActionScheduleEnsure
		switch harmonogram.GetOperation() {
		case agentv1.ScheduleAction_OPERATION_DISABLE:
			typ = opspec.ActionScheduleDisable
		case agentv1.ScheduleAction_OPERATION_REMOVE:
			typ = opspec.ActionScheduleRemove
		case agentv1.ScheduleAction_OPERATION_RUN_NOW:
			typ = opspec.ActionScheduleRunNow
		}
		return typ, opspec.Payload{Schedule: &opspec.SchedulePayload{
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
		return "", opspec.Payload{}, fmt.Errorf("koperta nie zawiera obslugiwanej akcji")
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

// cloneResult kopiuje wynik przez proto.Clone. Kopiowanie struktury przez
// przypisanie skopiowaloby wewnetrzny stan wiadomosci wraz z mutexem.
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

// localUserActions tlumaczy operacje kontraktu na typ operacji. Agent nie
// przyjmuje operacji spoza mapy, wiec rozszerzenie kontraktu przez strone
// trzecia nie da mu nowych mozliwosci.
var localUserActions = map[agentv1.LocalUserAction_Operation]opspec.ActionType{
	agentv1.LocalUserAction_OPERATION_CREATE:       opspec.ActionLocalUserCreate,
	agentv1.LocalUserAction_OPERATION_LOCK:         opspec.ActionLocalUserLock,
	agentv1.LocalUserAction_OPERATION_UNLOCK:       opspec.ActionLocalUserUnlock,
	agentv1.LocalUserAction_OPERATION_SET_SSH_KEYS: opspec.ActionLocalSSHKeysSet,
}

// joinNames sklada nazwy w czytelna liste dla komunikatu operatora.
func joinNames(nazwy []string) string {
	return strings.Join(nazwy, ", ")
}

// akcjaDockera tlumaczy koperte operacji kontenerowej na typ i payload.
// Kazda operacja ma wlasny typ, bo kazda ma inne ryzyko i inne uprawnienie.
func akcjaDockera(action *agentv1.DockerAction) (opspec.ActionType, opspec.Payload, error) {
	kontener := &opspec.DockerContainerPayload{
		ContainerID:    action.GetContainerId(),
		Name:           action.GetContainerName(),
		TimeoutSeconds: action.GetTimeoutSeconds(),
		RemoveVolumes:  action.GetRemoveVolumes(),
	}
	switch action.GetOperation() {
	case agentv1.DockerAction_OPERATION_START:
		return opspec.ActionDockerStart, opspec.Payload{DockerContainer: kontener}, nil
	case agentv1.DockerAction_OPERATION_STOP:
		return opspec.ActionDockerStop, opspec.Payload{DockerContainer: kontener}, nil
	case agentv1.DockerAction_OPERATION_RESTART:
		return opspec.ActionDockerRestart, opspec.Payload{DockerContainer: kontener}, nil
	case agentv1.DockerAction_OPERATION_REMOVE:
		return opspec.ActionDockerRemove, opspec.Payload{DockerContainer: kontener}, nil
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
	return "", opspec.Payload{}, fmt.Errorf("nieznana operacja na kontenerach")
}

// listUnits zwraca pelny wykaz jednostek hosta.
func (e *TaskExecutor) listUnits(ctx context.Context, task *agentv1.TaskEnvelope) *agentv1.TaskResult {
	jednostki, urwane, err := systemd.List(ctx)
	if err != nil {
		return rejected(agentv1.TaskResult_STATUS_FAILED, RejectInternalError, err.Error())
	}
	stany := make([]*agentv1.UnitState, 0, len(jednostki))
	for _, jednostka := range jednostki {
		stany = append(stany, &agentv1.UnitState{
			Name:          jednostka.Name,
			LoadState:     jednostka.LoadState,
			ActiveState:   jednostka.ActiveState,
			SubState:      jednostka.SubState,
			UnitFileState: jednostka.UnitFileState,
		})
	}
	return &agentv1.TaskResult{
		TaskId:   task.GetTaskId(),
		Status:   agentv1.TaskResult_STATUS_SUCCEEDED,
		ExitCode: 0,
		Detail: &agentv1.TaskResult_UnitStatus{
			UnitStatus: &agentv1.UnitStatusResult{Units: stany, Truncated: urwane},
		},
	}
}

// applyUnitToggle wlacza albo maskuje jednostke.
//
// Operacja opisuje stan docelowy, a nie przelacznik: powtorzenie jej nie
// odwraca zmiany. Sciezka jest ta sama co przy start i stop, wiec stan przed
// i po oraz kody bledow pozostaja jednakowe dla calego modulu.
func (e *TaskExecutor) applyUnitToggle(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, toggle *agentv1.UnitToggle) *agentv1.TaskResult {
	if toggle == nil {
		return rejected(agentv1.TaskResult_STATUS_REJECTED, RejectInvalidRequest,
			"brak opisu zmiany jednostki")
	}
	return e.applyUnitAction(ctx, task, action, &opspec.UnitPayload{Unit: toggle.GetUnit()})
}
