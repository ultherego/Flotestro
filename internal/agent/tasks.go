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
}

func NewTaskExecutor(helperClient *HelperClient, journal *IdempotencyJournal,
	facts func() Facts, log *slog.Logger) *TaskExecutor {
	return &TaskExecutor{helper: helperClient, journal: journal, facts: facts, log: log}
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
