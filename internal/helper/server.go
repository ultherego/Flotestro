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

	response := s.handle(ctx, &request)
	if err := WriteMessage(conn, response); err != nil {
		s.log.Error("nie odeslano odpowiedzi", "task_id", request.GetTaskId(), "err", err)
	}
}

// handle waliduje zadanie i wykonuje operacje. Kazde odrzucenie ma stabilny
// kod maszynowy, zeby agent mogl je zaraportowac bez parsowania tekstu.
func (s *Server) handle(ctx context.Context, request *helperv1.HelperRequest) *helperv1.HelperResponse {
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
		return s.applyPackageAction(ctx, request, action.PackageAction)
	case *helperv1.HelperRequest_Reboot:
		return s.applyReboot(ctx, request, action.Reboot)
	case *helperv1.HelperRequest_IdentityProbe:
		return s.probeIdentity(ctx, request, action.IdentityProbe)
	case *helperv1.HelperRequest_DomainEnroll:
		return s.enrollDomain(ctx, request, action.DomainEnroll)
	default:
		return reject(ErrorUnknownAction, "brak obslugiwanej akcji")
	}
}

// applyPackageAction odswieza metadane albo wykonuje transakcje pakietowa.
// Jednoczesnie moze dzialac najwyzej jedna transakcja: rownolegle operacje na
// tej samej bazie pakietow moga ja uszkodzic.
func (s *Server) applyPackageAction(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.PackageActionRequest) *helperv1.HelperResponse {
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

	switch action.GetOperation() {
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
		Manager:                apply.Manager,
		Applied:                changes,
		RebootRequired:         apply.RebootRequired,
		ServicesNeedingRestart: apply.ServicesNeedingRestart,
		PackageDatabaseBroken:  apply.DatabaseBroken,
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
