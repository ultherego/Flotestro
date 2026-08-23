package helper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/systemd"
)

// Server obsluguje zadania mutujace w imieniu agenta.
type Server struct {
	// allowedUID jest jedynym identyfikatorem, ktory moze wydawac polecenia.
	// Weryfikacja idzie przez SO_PEERCRED jadra, nie przez tresc wiadomosci.
	allowedUID uint32
	log        *slog.Logger

	// Jednoczesnie wykonuje sie najwyzej jedna mutacja jednostek. Rownolegle
	// start i stop tej samej jednostki daja nieprzewidywalny wynik.
	unitMutex sync.Mutex
	// Osobna blokada dla operacji pakietowych: transakcja moze trwac minuty,
	// a operacje na jednostkach nie musza na nia czekac.
	packageMutex sync.Mutex
	// Dolaczenie do domeny zmienia SSSD, Kerberosa i PAM naraz.
	enrollMutex sync.Mutex
	// Zmiany kont lokalnych sa serializowane: useradd i usermod pisza do
	// tych samych plikow.
	accountMutex sync.Mutex
	// Rownolegly restart i usuniecie tego samego kontenera daja
	// nieprzewidywalny wynik.
	containerMutex sync.Mutex
}

func NewServer(allowedUID uint32, log *slog.Logger) *Server {
	return &Server{allowedUID: allowedUID, log: log}
}

// Serve przyjmuje polaczenia do zamkniecia kontekstu.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		s.log.Warn("odrzucono polaczenie spoza gniazda unixowego")
		return
	}
	uid, pid, err := peerCredentials(unixConn)
	if err != nil {
		s.log.Error("nie odczytano tozsamosci rozmowcy", "err", err)
		return
	}
	// Tozsamosc rozmowcy pochodzi z jadra. Wiadomosc nie moze jej podmienic.
	if uid != s.allowedUID {
		s.log.Warn("odrzucono polaczenie od obcego uzytkownika", "uid", uid, "pid", pid)
		return
	}

	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))

	var request helperv1.HelperRequest
	if err := ReadMessage(conn, &request); err != nil {
		s.log.Error("nieczytelne zadanie", "err", err)
		_ = WriteMessage(conn, reject(ErrorMalformed, err.Error()))
		return
	}

	// Postep dlugiej operacji leci osobnymi wiadomosciami, zanim przyjdzie
	// odpowiedz koncowa. Klient, ktory o niego nie prosil, dostaje jedna
	// wiadomosc jak dotad - starszy agent nie moze wziac postepu za wynik.
	var wysylkaMu sync.Mutex
	var postep func(*helperv1.TaskProgress)
	if request.GetWantProgress() {
		postep = func(p *helperv1.TaskProgress) {
			wysylkaMu.Lock()
			defer wysylkaMu.Unlock()
			if err := WriteMessage(conn, &helperv1.HelperResponse{Progress: p}); err != nil {
				// Zerwana wysylka postepu nie moze przerwac operacji: sama
				// transakcja jest wazniejsza od jej podgladu.
				s.log.Debug("nie wyslano postepu", "task_id", request.GetTaskId(), "err", err)
			}
		}
	}

	response := s.handle(ctx, &request, postep)
	response.Final = true
	wysylkaMu.Lock()
	defer wysylkaMu.Unlock()
	if err := WriteMessage(conn, response); err != nil {
		s.log.Error("nie odeslano odpowiedzi", "task_id", request.GetTaskId(), "err", err)
	}
}

// handle waliduje zadanie i wykonuje operacje. Kazde odrzucenie ma stabilny
// kod maszynowy, zeby agent mogl je zaraportowac bez parsowania tekstu.
// handle obsluguje zadanie. Odbiorca postepu jest przekazywany wglab wywolan,
// a nie trzymany w serwerze: polaczenia sa obslugiwane rownolegle i pole
// wspoldzielone laczyloby postep jednej operacji z inna.
func (s *Server) handle(ctx context.Context, request *helperv1.HelperRequest,
	postep func(*helperv1.TaskProgress)) *helperv1.HelperResponse {
	if request.GetProtocolVersion() != ProtocolVersion {
		return reject(ErrorUnsupportedVersion,
			fmt.Sprintf("wersja %d, obslugiwana %d", request.GetProtocolVersion(), ProtocolVersion))
	}
	// Helper sprawdza TTL samodzielnie. Agent moze byc opozniony albo bledny,
	// a zadanie po terminie nie moze zostac wykonane.
	if expires := request.GetExpiresAt(); expires != nil && time.Now().After(expires.AsTime()) {
		return reject(ErrorExpired,
			fmt.Sprintf("zadanie wygaslo %s", expires.AsTime().Format(time.RFC3339)))
	}

	switch action := request.GetAction().(type) {
	case *helperv1.HelperRequest_UnitAction:
		return s.applyUnitAction(ctx, request, action.UnitAction)
	case *helperv1.HelperRequest_PackageAction:
		return s.applyPackageAction(ctx, request, action.PackageAction, postep)
	case *helperv1.HelperRequest_Kernel:
		return s.applyKernel(ctx, request, action.Kernel)

	case *helperv1.HelperRequest_Ssh:
		return s.applySSH(ctx, request, action.Ssh)

	case *helperv1.HelperRequest_Storage:
		return s.applyStorage(ctx, request, action.Storage)

	case *helperv1.HelperRequest_Firewall:
		return s.applyFirewall(ctx, request, action.Firewall)

	case *helperv1.HelperRequest_Dns:
		return s.applyDNS(ctx, request, action.Dns)

	case *helperv1.HelperRequest_Network:
		return s.applyNetwork(ctx, request, action.Network)

	case *helperv1.HelperRequest_Schedule:
		return s.applySchedule(ctx, request, action.Schedule)

	case *helperv1.HelperRequest_ProcessSignal:
		return s.signalProcess(ctx, request, action.ProcessSignal)

	case *helperv1.HelperRequest_LogFile:
		return s.readLogFile(ctx, request, action.LogFile)

	case *helperv1.HelperRequest_Compose:
		return s.applyCompose(ctx, request, action.Compose)

	case *helperv1.HelperRequest_DockerAction:
		return s.applyDocker(ctx, request, action.DockerAction)

	case *helperv1.HelperRequest_DockerRead:
		return s.readDocker(ctx, request, action.DockerRead)

	case *helperv1.HelperRequest_PackageRepair:
		return s.repairPackages(ctx, request, action.PackageRepair)
	case *helperv1.HelperRequest_Reboot:
		return s.applyReboot(ctx, request, action.Reboot)
	case *helperv1.HelperRequest_IdentityProbe:
		return s.probeIdentity(ctx, request, action.IdentityProbe)
	case *helperv1.HelperRequest_DomainEnroll:
		return s.enrollDomain(ctx, request, action.DomainEnroll)
	case *helperv1.HelperRequest_LocalAccounts:
		return s.readLocalAccounts(ctx, request, action.LocalAccounts)
	case *helperv1.HelperRequest_LocalUserAction:
		return s.applyLocalUserAction(ctx, request, action.LocalUserAction)
	default:
		return reject(ErrorUnknownAction, "brak obslugiwanej akcji")
	}
}

// applyPackageAction odswieza metadane albo wykonuje transakcje pakietowa.
// Jednoczesnie moze dzialac najwyzej jedna transakcja: rownolegle operacje na
// tej samej bazie pakietow moga ja uszkodzic.
func (s *Server) applyPackageAction(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.PackageActionRequest, postep func(*helperv1.TaskProgress)) *helperv1.HelperResponse {
	manager, err := packages.Detect()
	if err != nil {
		return reject(packages.ErrorUnsupported, err.Error())
	}

	if !s.packageMutex.TryLock() {
		return reject(ErrorLocked, "inna operacja pakietowa jest w toku")
	}
	defer s.packageMutex.Unlock()

	// Blokade menedzera sprawdzamy jawnie i jej nie obchodzimy. Reczna praca
	// administratora ma pierwszenstwo przed zadaniem z panelu.
	if held, path := manager.LockHeld(); held {
		return reject(packages.ErrorLocked,
			fmt.Sprintf("menedzer pakietow jest zajety (%s)", path))
	}

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 2*time.Hour {
		timeout = 30 * time.Minute
	}
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	options := packages.Options{
		Packages:     action.GetPackages(),
		SecurityOnly: action.GetSecurityOnly(),
	}
	if postep != nil {
		options.Progress = func(p packages.Progress) {
			postep(&helperv1.TaskProgress{
				Step: p.Step, Total: p.Total, Percent: p.Percent, Message: p.Message,
			})
		}
	}

	switch action.GetOperation() {
	case helperv1.PackageActionRequest_OPERATION_INSTALL,
		helperv1.PackageActionRequest_OPERATION_REMOVE,
		helperv1.PackageActionRequest_OPERATION_HOLD:
		return s.cyklZyciaPakietow(operationCtx, manager, action, options)

	case helperv1.PackageActionRequest_OPERATION_REFRESH:
		if err := manager.Refresh(operationCtx); err != nil {
			return packageFailure(manager.Name(), err)
		}
		s.log.Info("odswiezono metadane repozytorium",
			"task_id", request.GetTaskId(), "manager", manager.Name())
		return &helperv1.HelperResponse{
			Accepted:      true,
			PackageResult: &helperv1.PackageActionResult{Manager: manager.Name()},
		}

	case helperv1.PackageActionRequest_OPERATION_UPGRADE:
		apply, err := manager.Upgrade(operationCtx, options)
		response := &helperv1.HelperResponse{
			PackageResult: packageResultToProto(apply),
		}
		if err != nil {
			// Wynik czesciowy jest zwracany takze przy bledzie: administrator
			// musi wiedziec, co zdazylo sie zmienic przed awaria.
			response.Accepted = false
			response.ErrorCode = packageErrorCode(err)
			response.Message = err.Error()
			response.ExitCode = -1
			s.log.Error("transakcja pakietowa nie powiodla sie",
				"task_id", request.GetTaskId(), "manager", manager.Name(),
				"zmienionych", len(apply.Applied), "baza_uszkodzona", apply.DatabaseBroken,
				"err", err)
			return response
		}
		response.Accepted = true
		s.log.Info("transakcja pakietowa zakonczona",
			"task_id", request.GetTaskId(), "manager", manager.Name(),
			"zmienionych", len(apply.Applied), "reboot", apply.RebootRequired)
		return response

	default:
		return reject(ErrorUnknownAction, "nieznana operacja pakietowa")
	}
}

// applyReboot zleca restart z opoznieniem. Opoznienie jest konieczne: bez
// niego host znika, zanim agent zdazy odeslac wynik, i zadanie wygladaloby na
// zerwane zamiast wykonane.
func (s *Server) applyReboot(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.RebootRequest) *helperv1.HelperResponse {
	delay := action.GetDelaySeconds()
	if delay == 0 {
		delay = 10
	}
	if delay > 3600 {
		return reject(ErrorUnknownAction, "opoznienie restartu przekracza godzine")
	}

	reason := action.GetReason()
	if reason == "" {
		reason = "Flotestro: kontrolowany restart"
	}

	// shutdown -r przyjmuje czas w minutach albo slowo now, wiec krotkie
	// opoznienia realizujemy przez transient timer systemd.
	stdout, stderr, exitCode, err := systemd.ScheduleReboot(ctx, time.Duration(delay)*time.Second, reason)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	if exitCode != 0 {
		response := reject(ErrorExecFailed, strings.TrimSpace(stderr))
		response.ExitCode = int32(exitCode)
		return response
	}

	s.log.Warn("zaplanowano restart hosta",
		"task_id", request.GetTaskId(), "za_sekund", delay, "powod", reason)

	limit := int(request.GetMaxOutputBytes())
	out, truncated := clamp([]byte(stdout), limit)
	return &helperv1.HelperResponse{
		Accepted: true, ExitCode: 0, Stdout: out, OutputTruncated: truncated,
	}
}

func packageFailure(manager string, err error) *helperv1.HelperResponse {
	response := reject(packageErrorCode(err), err.Error())
	response.PackageResult = &helperv1.PackageActionResult{Manager: manager}
	return response
}

// packageErrorCode zamienia blad adaptera na stabilny kod maszynowy.
func packageErrorCode(err error) string {
	switch {
	case errors.Is(err, packages.ErrLocked):
		return packages.ErrorLocked
	case errors.Is(err, packages.ErrModulesHidden):
		return packages.ErrorModulesHidden
	case errors.Is(err, context.DeadlineExceeded):
		return ErrorTimeout
	default:
		return packages.ErrorTransaction
	}
}

func packageResultToProto(apply packages.Apply) *helperv1.PackageActionResult {
	changes := make([]*helperv1.PackageVersionChange, 0, len(apply.Applied))
	for _, change := range apply.Applied {
		changes = append(changes, &helperv1.PackageVersionChange{
			Name:          change.Name,
			VersionBefore: change.CurrentVersion,
			VersionAfter:  change.CandidateVersion,
		})
	}
	return &helperv1.PackageActionResult{
		Manager:                  apply.Manager,
		Applied:                  changes,
		RebootRequired:           apply.RebootRequired,
		ServicesNeedingRestart:   apply.ServicesNeedingRestart,
		PackageDatabaseBroken:    apply.DatabaseBroken,
		PackagesNeedingAttention: apply.PackagesNeedingAttention,
		SelfRepair:               apply.SelfRepair,
		Output:                   apply.Output,
	}
}

func (s *Server) applyUnitAction(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.UnitActionRequest) *helperv1.HelperResponse {
	operation, ok := unitOperations[action.GetOperation()]
	if !ok {
		return reject(ErrorUnknownAction, fmt.Sprintf("operacja %s", action.GetOperation()))
	}
	unit := action.GetUnit()

	// Walidacja powtorzona po stronie roota: helper nie ufa temu, ze agent
	// sprawdzil nazwe i polityke ochrony.
	if err := systemd.ValidateUnit(unit); err != nil {
		switch {
		case errors.Is(err, systemd.ErrProtectedUnit):
			return reject(ErrorProtectedUnit, err.Error())
		default:
			return reject(ErrorInvalidUnit, err.Error())
		}
	}

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 60 * time.Second
	}

	if !s.unitMutex.TryLock() {
		return reject(ErrorLocked, "inna mutacja jednostek jest w toku")
	}
	defer s.unitMutex.Unlock()

	before, _ := systemd.Show(ctx, unit)
	stdout, stderr, exitCode, err := systemd.Apply(ctx, unit, operation, timeout)
	if err != nil {
		code := ErrorExecFailed
		if errors.Is(err, context.DeadlineExceeded) {
			code = ErrorTimeout
		}
		response := reject(code, err.Error())
		response.StateBefore = toProtoState(before)
		return response
	}
	after, _ := systemd.Show(ctx, unit)

	limit := int(request.GetMaxOutputBytes())
	outBytes, outTruncated := clamp([]byte(stdout), limit)
	errBytes, errTruncated := clamp([]byte(stderr), limit)

	s.log.Info("wykonano operacje na jednostce",
		"task_id", request.GetTaskId(), "unit", unit, "operation", operation,
		"exit_code", exitCode, "active_before", before.ActiveState, "active_after", after.ActiveState)

	return &helperv1.HelperResponse{
		Accepted:        true,
		ExitCode:        int32(exitCode),
		Stdout:          outBytes,
		Stderr:          errBytes,
		OutputTruncated: outTruncated || errTruncated,
		StateBefore:     toProtoState(before),
		StateAfter:      toProtoState(after),
	}
}

var unitOperations = map[helperv1.UnitActionRequest_Operation]systemd.Operation{
	helperv1.UnitActionRequest_OPERATION_START:   systemd.OperationStart,
	helperv1.UnitActionRequest_OPERATION_STOP:    systemd.OperationStop,
	helperv1.UnitActionRequest_OPERATION_RESTART: systemd.OperationRestart,
	helperv1.UnitActionRequest_OPERATION_RELOAD:  systemd.OperationReload,
	// Wlaczenie i maskowanie zmieniaja to, co host zrobi po restarcie.
	helperv1.UnitActionRequest_OPERATION_ENABLE:  systemd.OperationEnable,
	helperv1.UnitActionRequest_OPERATION_DISABLE: systemd.OperationDisable,
	helperv1.UnitActionRequest_OPERATION_MASK:    systemd.OperationMask,
	helperv1.UnitActionRequest_OPERATION_UNMASK:  systemd.OperationUnmask,
}

func reject(code, message string) *helperv1.HelperResponse {
	return &helperv1.HelperResponse{Accepted: false, ErrorCode: code, Message: message, ExitCode: -1}
}

// clamp przycina output do limitu i sygnalizuje obciecie. Wynik zadania nie
// moze urosnac do dowolnego rozmiaru.
func clamp(data []byte, limit int) ([]byte, bool) {
	if limit <= 0 {
		limit = 64 << 10
	}
	if len(data) <= limit {
		return data, false
	}
	return data[:limit], true
}

func toProtoState(state systemd.UnitState) *helperv1.UnitState {
	return &helperv1.UnitState{
		Name:          state.Name,
		LoadState:     state.LoadState,
		ActiveState:   state.ActiveState,
		SubState:      state.SubState,
		UnitFileState: state.UnitFileState,
		Result:        state.Result,
		MainPid:       state.MainPID,
		NRestarts:     state.NRestarts,
	}
}

// peerCredentials odczytuje tozsamosc rozmowcy z jadra przez SO_PEERCRED.
func peerCredentials(conn *net.UnixConn) (uid uint32, pid int32, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var credentials *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return credentials.Uid, credentials.Pid, nil
}

// ListenerFromSystemd zwraca gniazdo przekazane przez socket activation.
// Helper nie tworzy gniazda sam, wiec nie musi decydowac o jego prawach.
func ListenerFromSystemd() (net.Listener, bool, error) {
	if os.Getenv("LISTEN_PID") != fmt.Sprint(os.Getpid()) {
		return nil, false, nil
	}
	if os.Getenv("LISTEN_FDS") != "1" {
		return nil, false, nil
	}
	const firstSocketFD = 3
	file := os.NewFile(firstSocketFD, "flotestro-helper.socket")
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, false, fmt.Errorf("gniazdo z systemd: %w", err)
	}
	return listener, true, nil
}

// repairPackages odblokowuje operacje pakietowe na hoscie.
//
// Odpowiedzi na pytania konfiguracyjne pochodza od operatora i dotycza
// wylacznie pakietow, ktore faktycznie blokuja transakcje. Helper nie
// wymysla odpowiedzi za nikogo: wybor urzadzenia rozruchowego czy sposobu
// obslugi plikow konfiguracyjnych jest decyzja czlowieka, a maszyna moze
// nia jedynie wykonac.
func (s *Server) repairPackages(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.PackageRepairRequest) *helperv1.HelperResponse {
	manager, err := packages.Detect()
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	apt, ok := manager.(*packages.APT)
	if !ok {
		// Na innych rodzinach systemow blokada wyglada inaczej i naprawa tez
		// wygladalaby inaczej; udawanie, ze operacja dziala, byloby gorsze
		// niz jasna odmowa.
		return reject(ErrorUnsupported,
			"naprawa pakietow jest obslugiwana wylacznie dla menedzera apt")
	}

	answers := make([]packages.Answer, 0, len(action.GetAnswers()))
	for _, answer := range action.GetAnswers() {
		answers = append(answers, packages.Answer{
			Package:  answer.GetPackage(),
			Question: answer.GetQuestion(),
			Type:     answer.GetType(),
			Value:    answer.GetValue(),
		})
	}

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	repairCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ustawione, pozostale, err := apt.Repair(repairCtx, answers)
	response := &helperv1.PackageRepairResponse{
		Manager:      apt.Name(),
		Answered:     ustawione,
		StillBlocked: blockedToProto(pozostale),
		Repaired:     len(pozostale) == 0,
	}
	if err != nil {
		s.log.Warn("naprawa pakietow nie powiodla sie",
			"task_id", request.GetTaskId(), "err", err, "pozostalo", len(pozostale))
		return &helperv1.HelperResponse{
			Accepted:     false,
			ErrorCode:    ErrorExecFailed,
			Message:      err.Error(),
			RepairResult: response,
		}
	}

	s.log.Info("pakiety odblokowane",
		"task_id", request.GetTaskId(), "odpowiedzi", len(ustawione))
	return &helperv1.HelperResponse{Accepted: true, RepairResult: response}
}

func blockedToProto(blocked []packages.Blocked) []*helperv1.BlockedPackageDetail {
	result := make([]*helperv1.BlockedPackageDetail, 0, len(blocked))
	for _, pakiet := range blocked {
		pytania := make([]*helperv1.DebconfQuestionDetail, 0, len(pakiet.Questions))
		for _, pytanie := range pakiet.Questions {
			pytania = append(pytania, &helperv1.DebconfQuestionDetail{
				Name: pytanie.Name, Value: pytanie.Value, Answered: pytanie.Answered,
			})
		}
		result = append(result, &helperv1.BlockedPackageDetail{
			Name: pakiet.Name, Status: pakiet.Status, Questions: pytania,
		})
	}
	return result
}

// cyklZyciaPakietow wykonuje instalacje, usuniecie albo wstrzymanie.
//
// Kazda z tych operacji istnieje tylko dla menedzerow, ktore ja obsluguja.
// Jasna odmowa jest lepsza niz udawanie, ze operacja sie wykonala - a udawac
// bylo by latwo, bo wynik "zero zmian" wyglada tak samo jak sukces.
func (s *Server) cyklZyciaPakietow(ctx context.Context, manager packages.Manager,
	action *helperv1.PackageActionRequest, options packages.Options) *helperv1.HelperResponse {
	apt, ok := manager.(*packages.APT)
	if !ok {
		return reject(ErrorUnsupported,
			"pelny cykl zycia pakietow jest obslugiwany wylacznie dla menedzera apt")
	}

	var apply packages.Apply
	var err error
	switch action.GetOperation() {
	case helperv1.PackageActionRequest_OPERATION_INSTALL:
		apply, err = apt.Install(ctx, options)
	case helperv1.PackageActionRequest_OPERATION_REMOVE:
		apply, err = apt.Remove(ctx, options, action.GetExpectedRemovals())
	case helperv1.PackageActionRequest_OPERATION_HOLD:
		apply, err = apt.SetHold(ctx, options.Packages, action.GetHold())
	}
	if err != nil {
		response := packageFailure(manager.Name(), err)
		response.PackageResult = packageResultToProto(apply)
		response.PackageResult.Manager = manager.Name()
		return response
	}
	return &helperv1.HelperResponse{
		Accepted:      true,
		PackageResult: packageResultToProto(apply),
	}
}
