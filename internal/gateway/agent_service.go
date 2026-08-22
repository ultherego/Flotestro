package gateway

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/pki"
)

type contextKey string

const (
	clientCertKey contextKey = "flotestro.client-cert"
	remoteAddrKey contextKey = "flotestro.remote-addr"
)

// WithClientCertificate przenosi certyfikat klienta z warstwy TLS do kontekstu,
// dzieki czemu handler nie musi znac szczegolow serwera HTTP.
func WithClientCertificate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			ctx = context.WithValue(ctx, clientCertKey, r.TLS.PeerCertificates[0])
		}
		ctx = context.WithValue(ctx, remoteAddrKey, r.RemoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func clientCertificate(ctx context.Context) (*x509.Certificate, bool) {
	cert, ok := ctx.Value(clientCertKey).(*x509.Certificate)
	return cert, ok
}

func remoteAddr(ctx context.Context) string {
	addr, _ := ctx.Value(remoteAddrKey).(string)
	return addr
}

// AgentService obsluguje dlugotrwaly stream agenta. Stream jest jedynym
// kanalem polecen; helper root nigdy nie rozmawia z centrala.
type AgentService struct {
	pool      *pgxpool.Pool
	hosts     *hosts.Store
	inventory *inventory.Store
	jobs      *jobs.Store
	audit     *audit.Recorder
	registry  *Registry
	log       *slog.Logger
	gatewayID string

	heartbeatSeconds int
	heartbeatJitter  int
}

func NewAgentService(pool *pgxpool.Pool, hostStore *hosts.Store, inventoryStore *inventory.Store,
	jobStore *jobs.Store, recorder *audit.Recorder, registry *Registry, log *slog.Logger,
	gatewayID string, heartbeatSeconds, heartbeatJitter int) *AgentService {
	return &AgentService{
		pool: pool, hosts: hostStore, inventory: inventoryStore, jobs: jobStore,
		audit: recorder, registry: registry, log: log, gatewayID: gatewayID,
		heartbeatSeconds: heartbeatSeconds, heartbeatJitter: heartbeatJitter,
	}
}

// Connect obsluguje sesje agenta. Tozsamosc hosta pochodzi wylacznie z
// certyfikatu klienta; tresc wiadomosci nigdy nie moze jej nadpisac.
func (s *AgentService) Connect(ctx context.Context,
	stream *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("brak certyfikatu klienta"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return connect.NewError(connect.CodeUnauthenticated, err)
	}

	fingerprint := pki.Fingerprint(cert)
	status, err := s.hosts.LookupCertificate(ctx, fingerprint)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	switch {
	case !status.Known:
		s.denied(ctx, hostID, "unknown_certificate")
		return connect.NewError(connect.CodeUnauthenticated, errors.New("certyfikat nieznany"))
	case status.Revoked:
		s.denied(ctx, hostID, "revoked_certificate")
		return connect.NewError(connect.CodeUnauthenticated, errors.New("certyfikat odwolany"))
	case status.HostID != hostID:
		s.denied(ctx, hostID, "identity_mismatch")
		return connect.NewError(connect.CodeUnauthenticated, errors.New("tozsamosc nie zgadza sie z certyfikatem"))
	case status.LifecycleState == "quarantined":
		s.denied(ctx, hostID, "quarantined")
		return connect.NewError(connect.CodePermissionDenied, errors.New("host jest w kwarantannie"))
	}

	// Pierwsza wiadomosc musi byc Hello. Inny start konczy sesje.
	first, err := stream.Receive()
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("oczekiwano Hello: %w", err))
	}
	hello := first.GetHello()
	if hello == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("pierwsza wiadomosc musi byc Hello"))
	}

	caps := capabilitiesFromProto(hello.GetCapabilities())
	if err := s.hosts.ApplyHello(ctx, hostID, hello.GetAgentVersion(), hello.GetBootId(), caps); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	session := NewSession(uuid.NewString(), hostID, hello.GetAgentVersion(),
		hello.GetBootId(), remoteAddr(ctx), 32)
	if err := s.openSession(ctx, session, fingerprint); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	s.registry.Add(session)
	s.log.Info("sesja agenta otwarta",
		"host_id", hostID, "session_id", session.ID, "agent_version", session.AgentVersion,
		"boot_id", session.BootID, "sessions", s.registry.Count())

	defer func() {
		s.registry.Remove(hostID, session.ID)
		// Kontekst zadania jest juz anulowany, wiec sprzatanie ma wlasny.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		s.closeSession(cleanupCtx, session, hostID)
	}()

	// Jedna goroutine pisze do streamu, bo Send nie jest bezpieczny wspolbieznie.
	// Scheduler kolejkuje zadania przez kanal sesji, nie przez stream wprost.
	sendCtx, stopSender := context.WithCancel(ctx)
	defer stopSender()
	senderErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-sendCtx.Done():
				return
			case message := <-session.Outbound():
				if err := stream.Send(message); err != nil {
					senderErr <- err
					return
				}
			}
		}
	}()

	// Serwer natychmiast odsyla parametry sesji. Pelny inventory jest zamawiany
	// wtedy, gdy agent zglasza inna rewizje niz zapisana.
	if err := stream.Send(&agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_SessionConfig{
			SessionConfig: &agentv1.SessionConfig{
				HeartbeatSeconds:       int32(s.heartbeatSeconds),
				HeartbeatJitterSeconds: int32(s.heartbeatJitter),
				FullInventoryRequested: true,
			},
		},
	}); err != nil {
		return err
	}

	received := make(chan *agentv1.AgentMessage)
	receiveErr := make(chan error, 1)
	go func() {
		defer close(received)
		for {
			msg, err := stream.Receive()
			if err != nil {
				receiveErr <- err
				return
			}
			select {
			case received <- msg:
			case <-sendCtx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil

		case err := <-senderErr:
			s.log.Info("wysylka do agenta zakonczona", "host_id", hostID, "err", err)
			return nil

		case err := <-receiveErr:
			if errors.Is(err, io.EOF) || errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			s.log.Info("stream agenta zakonczony", "host_id", hostID, "err", err)
			return nil

		case msg, ok := <-received:
			if !ok {
				return nil
			}
			if err := s.handle(ctx, hostID, session, msg); err != nil {
				s.log.Error("blad obslugi wiadomosci agenta", "host_id", hostID, "err", err)
			}
		}
	}
}

func (s *AgentService) handle(ctx context.Context, hostID string, session *Session,
	msg *agentv1.AgentMessage) error {
	switch payload := msg.GetPayload().(type) {
	case *agentv1.AgentMessage_Heartbeat:
		health := payload.Heartbeat.GetHealth()
		// Pola nieobecne w wiadomosci oznaczaja stan nieustalony i przechodza
		// dalej jako brak wartosci, nie jako zero.
		if err := s.hosts.ApplyHeartbeat(ctx, hostID, hosts.Health{
			FailedUnits:            health.FailedUnits,
			RebootRequired:         health.RebootRequired,
			Load1Milli:             health.GetLoad1Milli(),
			RootFSUsedPercent:      health.GetRootFsUsedPercent(),
			UptimeSeconds:          health.GetUptimeSeconds(),
			PendingUpdates:         health.PendingUpdates,
			PendingSecurityUpdates: health.PendingSecurityUpdates,
		}); err != nil {
			return err
		}
		const query = `update agent_sessions set last_heartbeat_at = now() where id = $1`
		_, err := s.pool.Exec(ctx, query, session.ID)
		return err

	case *agentv1.AgentMessage_Inventory:
		report := payload.Inventory
		raw := report.GetRawJson()
		if len(raw) == 0 {
			raw = []byte("{}")
		}
		if !json.Valid(raw) {
			return fmt.Errorf("inventory nie jest poprawnym JSON")
		}
		os := report.GetOs()
		identity := report.GetIdentity()
		stored, err := s.inventory.Save(ctx, hostID, inventory.Report{
			Revision:       report.GetRevision(),
			Full:           report.GetFull(),
			SchemaVersion:  report.GetSchemaVersion(),
			OSFamily:       os.GetFamily(),
			OSDistribution: os.GetDistribution(),
			OSVersion:      os.GetVersion(),
			Architecture:   os.GetArchitecture(),
			RawJSON:        raw,

			IdentityEnrolled:   identity.GetEnrolled(),
			IdentityDomain:     identity.GetDomain(),
			IdentityRealm:      identity.GetRealm(),
			IdentitySSSDOnline: identity.SssdOnline,

			LocalAccounts: localAccountsFromReport(report),
		})
		if err != nil {
			return err
		}
		if stored {
			s.log.Info("nowa rewizja inventory",
				"host_id", hostID, "revision", report.GetRevision(), "full", report.GetFull())
		}
		return nil

	case *agentv1.AgentMessage_TaskResult:
		return s.recordTaskResult(ctx, hostID, payload.TaskResult)

	case *agentv1.AgentMessage_TaskProgress:
		// Czesciowy output jest na razie odnotowywany, a nie strumieniowany
		// dalej; strumien do UI nalezy do modulu logow.
		s.log.Debug("czesciowy wynik zadania",
			"host_id", hostID, "task_id", payload.TaskProgress.GetTaskId(),
			"bajtow", len(payload.TaskProgress.GetChunk()))
		return nil

	case *agentv1.AgentMessage_Hello:
		// Powtorzone Hello w trakcie sesji jest ignorowane, ale odnotowane.
		s.log.Warn("powtorzone Hello w aktywnej sesji", "host_id", hostID)
		return nil

	default:
		return fmt.Errorf("nieznany typ wiadomosci agenta")
	}
}

// recordTaskResult zapisuje wynik zgloszony przez agenta i przenosi zadanie
// do stanu koncowego. Wynik zawsze trafia do proby; o tym, czy zmienia stan
// zadania, decyduje maszyna stanow.
func (s *AgentService) recordTaskResult(ctx context.Context, hostID string,
	result *agentv1.TaskResult) error {
	attemptID := result.GetTaskId()
	jobID, err := s.jobs.AttemptOwner(ctx, attemptID)
	if err != nil {
		return fmt.Errorf("wynik dla nieznanej proby %s: %w", attemptID, err)
	}

	state, statusName := jobStateFor(result.GetStatus())
	accepted, err := s.jobs.RecordResult(ctx, jobID, attemptID, jobs.Result{
		Status:          statusName,
		ExitCode:        result.GetExitCode(),
		Stdout:          result.GetStdout(),
		Stderr:          result.GetStderr(),
		OutputTruncated: result.GetOutputTruncated(),
		ErrorCode:       result.GetErrorCode(),
		Message:         result.GetMessage(),
		Replayed:        result.GetReplayed(),
		UnitStateBefore: unitStateJSON(result.GetUnitStateBefore()),
		UnitStateAfter:  unitStateJSON(result.GetUnitStateAfter()),
		Detail:          resultDetailJSON(result),
	}, state)
	if err != nil {
		return err
	}

	// Operacja na koncie zmienia stan hosta natychmiast, a pelny raport
	// inventory przyjdzie dopiero za kilkanascie minut. Agent odczytuje konto
	// po zmianie, wiec zapisujemy stan faktyczny hosta zamiast czekac;
	// bez tego panel pokazywalby stan sprzed operacji.
	if user, ok := result.GetDetail().(*agentv1.TaskResult_LocalUser); ok &&
		state == jobs.StateSucceeded && user.LocalUser.GetAccount() != nil {
		accounts := localAccountsFromReport(&agentv1.InventoryReport{
			Full:          true,
			LocalAccounts: []*agentv1.LocalAccount{user.LocalUser.GetAccount()},
		})
		if err := s.inventory.UpsertLocalAccount(ctx, hostID, accounts[0]); err != nil {
			s.log.Error("nie zapisano stanu konta po operacji",
				"host_id", hostID, "konto", user.LocalUser.GetName(), "err", err)
		}
	}

	// Uszkodzona baza pakietow blokuje hosta przed kolejnymi kampaniami.
	if apply, ok := result.GetDetail().(*agentv1.TaskResult_PackageApply); ok {
		if err := s.hosts.SetPackageDatabaseBroken(ctx, hostID,
			apply.PackageApply.GetPackageDatabaseBroken()); err != nil {
			s.log.Error("nie zapisano stanu bazy pakietow", "host_id", hostID, "err", err)
		}
		if apply.PackageApply.GetPackageDatabaseBroken() {
			s.log.Error("baza pakietow hosta wymaga naprawy; kampanie wstrzymane",
				"host_id", hostID)
		}
	}

	outcome := audit.OutcomeSuccess
	if state != jobs.StateSucceeded {
		outcome = audit.OutcomeFailure
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "job.result", TargetType: "job", TargetID: jobID, Outcome: outcome,
		Detail: map[string]any{
			"attempt_id": attemptID, "status": statusName,
			"exit_code": result.GetExitCode(), "error_code": result.GetErrorCode(),
			"replayed": result.GetReplayed(), "applied": accepted,
		},
	})

	if !accepted {
		// Pozny wynik jest zachowany diagnostycznie w probie, ale nie cofa
		// decyzji podjetej w miedzyczasie.
		s.log.Warn("wynik nie zmienil stanu zadania",
			"job_id", jobID, "attempt_id", attemptID, "status", statusName)
		return nil
	}
	s.log.Info("wynik zadania zapisany",
		"job_id", jobID, "host_id", hostID, "status", statusName,
		"exit_code", result.GetExitCode(), "replayed", result.GetReplayed())
	return nil
}

// jobStateFor tlumaczy status zgloszony przez agenta na stan zadania.
func jobStateFor(status agentv1.TaskResult_Status) (jobs.State, string) {
	switch status {
	case agentv1.TaskResult_STATUS_SUCCEEDED:
		return jobs.StateSucceeded, "succeeded"
	case agentv1.TaskResult_STATUS_TIMED_OUT:
		return jobs.StateTimedOut, "timed_out"
	case agentv1.TaskResult_STATUS_EXPIRED:
		return jobs.StateExpired, "expired"
	case agentv1.TaskResult_STATUS_CANCELED:
		return jobs.StateCanceled, "canceled"
	case agentv1.TaskResult_STATUS_REJECTED:
		// Odrzucenie lokalne jest niepowodzeniem zadania, ale zachowuje wlasny
		// kod bledu, zeby operator widzial, ze nic nie zostalo zmienione.
		return jobs.StateFailed, "rejected"
	default:
		return jobs.StateFailed, "failed"
	}
}

// resultDetailJSON zapisuje wynik wlasciwy dla typu operacji. Plan aktualizacji
// i raport transakcji maja rozny ksztalt, wiec trafiaja do JSONB.
func resultDetailJSON(result *agentv1.TaskResult) json.RawMessage {
	switch detail := result.GetDetail().(type) {
	case *agentv1.TaskResult_PackagePlan:
		plan := detail.PackagePlan
		encoded, err := json.Marshal(map[string]any{
			"kind":                 "package_plan",
			"manager":              plan.GetManager(),
			"changes":              packageChangesJSON(plan.GetChanges()),
			"download_bytes":       plan.GetDownloadBytes(),
			"disk_available_bytes": plan.GetDiskAvailableBytes(),
			"plan_hash":            hex.EncodeToString(plan.GetPlanHash()),
			"reboot_predicted":     plan.GetRebootPredicted(),
			"metadata_refreshed":   plan.GetMetadataRefreshed(),
		})
		if err != nil {
			return nil
		}
		return encoded

	case *agentv1.TaskResult_LocalUser:
		user := detail.LocalUser
		encoded, err := json.Marshal(map[string]any{
			"kind":    "local_user",
			"name":    user.GetName(),
			"changed": user.GetChanged(),
			"account": localAccountResultJSON(user.GetAccount()),
		})
		if err != nil {
			return nil
		}
		return encoded

	case *agentv1.TaskResult_DomainEnroll:
		enroll := detail.DomainEnroll
		encoded, err := json.Marshal(map[string]any{
			"kind":           "domain_enroll",
			"enrolled":       enroll.GetEnrolled(),
			"host_principal": enroll.GetHostPrincipal(),
			"checks":         preflightChecksJSON(enroll.GetChecks()),
			"verifications":  preflightChecksJSON(enroll.GetVerifications()),
		})
		if err != nil {
			return nil
		}
		return encoded

	case *agentv1.TaskResult_UnitStatus:
		units := make([]map[string]any, 0)
		for _, unit := range detail.UnitStatus.GetUnits() {
			units = append(units, map[string]any{
				"name":            unit.GetName(),
				"load_state":      unit.GetLoadState(),
				"active_state":    unit.GetActiveState(),
				"sub_state":       unit.GetSubState(),
				"unit_file_state": unit.GetUnitFileState(),
				"result":          unit.GetResult(),
				"main_pid":        unit.GetMainPid(),
				"n_restarts":      unit.GetNRestarts(),
			})
		}
		encoded, err := json.Marshal(map[string]any{"kind": "unit_status", "units": units})
		if err != nil {
			return nil
		}
		return encoded

	case *agentv1.TaskResult_PackageApply:
		apply := detail.PackageApply
		encoded, err := json.Marshal(map[string]any{
			"kind":                     "package_apply",
			"manager":                  apply.GetManager(),
			"applied":                  packageChangesJSON(apply.GetApplied()),
			"reboot_required":          apply.GetRebootRequired(),
			"services_needing_restart": apply.GetServicesNeedingRestart(),
			"package_database_broken":  apply.GetPackageDatabaseBroken(),
		})
		if err != nil {
			return nil
		}
		return encoded

	default:
		return nil
	}
}

// preflightChecksJSON zachowuje trojstanowy wynik sprawdzenia: przeszlo,
// nie przeszlo albo nie udalo sie ustalic.
func preflightChecksJSON(checks []*agentv1.PreflightCheck) []map[string]any {
	items := make([]map[string]any, 0, len(checks))
	for _, check := range checks {
		item := map[string]any{
			"name":     check.GetName(),
			"detail":   check.GetDetail(),
			"blocking": check.GetBlocking(),
			"passed":   nil,
		}
		if check.Passed != nil {
			item["passed"] = check.GetPassed()
		}
		items = append(items, item)
	}
	return items
}

func packageChangesJSON(changes []*agentv1.PackageChange) []map[string]any {
	items := make([]map[string]any, 0, len(changes))
	for _, change := range changes {
		items = append(items, map[string]any{
			"name":              change.GetName(),
			"current_version":   change.GetCurrentVersion(),
			"candidate_version": change.GetCandidateVersion(),
			"origin":            change.GetOrigin(),
			"security":          change.GetSecurity(),
		})
	}
	return items
}

func unitStateJSON(state *agentv1.UnitState) json.RawMessage {
	if state == nil {
		return nil
	}
	encoded, err := json.Marshal(map[string]any{
		"name":            state.GetName(),
		"load_state":      state.GetLoadState(),
		"active_state":    state.GetActiveState(),
		"sub_state":       state.GetSubState(),
		"unit_file_state": state.GetUnitFileState(),
		"result":          state.GetResult(),
		"main_pid":        state.GetMainPid(),
		"n_restarts":      state.GetNRestarts(),
	})
	if err != nil {
		return nil
	}
	return encoded
}

func (s *AgentService) openSession(ctx context.Context, session *Session, fingerprint []byte) error {
	const query = `
		insert into agent_sessions
			(id, host_id, gateway_id, cert_fingerprint, remote_addr, agent_version, boot_id)
		values ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.pool.Exec(ctx, query, session.ID, session.HostID, s.gatewayID,
		fingerprint, session.RemoteAddr, session.AgentVersion, session.BootID)
	if err != nil {
		return err
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: session.HostID,
		Action: "agent.session.open", TargetType: "host", TargetID: session.HostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"session_id": session.ID, "gateway_id": s.gatewayID,
			"agent_version": session.AgentVersion, "boot_id": session.BootID,
		},
	})
	return nil
}

func (s *AgentService) closeSession(ctx context.Context, session *Session, hostID string) {
	const query = `update agent_sessions set ended_at = now(), end_reason = $2 where id = $1`
	if _, err := s.pool.Exec(ctx, query, session.ID, "stream_closed"); err != nil {
		s.log.Error("nie zamknieto sesji", "session_id", session.ID, "err", err)
	}
	// Host jest offline tylko wtedy, gdy nie zdazyl otworzyc nowszej sesji.
	if _, active := s.registry.Get(hostID); !active {
		if err := s.hosts.MarkDisconnected(ctx, hostID); err != nil {
			s.log.Error("nie oznaczono hosta jako offline", "host_id", hostID, "err", err)
		}
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "agent.session.close", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"session_id": session.ID,
			"duration_s": int(time.Since(session.StartedAt).Seconds()),
		},
	})
	s.log.Info("sesja agenta zamknieta",
		"host_id", hostID, "session_id", session.ID, "sessions", s.registry.Count())
}

func (s *AgentService) denied(ctx context.Context, hostID, reason string) {
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "agent.session.open", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": reason},
	})
	s.log.Warn("odrzucono sesje agenta", "host_id", hostID, "reason", reason)
}

func capabilitiesFromProto(caps *agentv1.Capabilities) hosts.Capabilities {
	return hosts.Capabilities{
		Systemd:  caps.GetSystemd(),
		APT:      caps.GetApt(),
		DNF:      caps.GetDnf(),
		Docker:   caps.GetDocker(),
		Journald: caps.GetJournald(),
	}
}

// localAccountsFromReport przenosi konta z raportu do modelu inventory.
//
// Raport przyrostowy bez sekcji kont zwraca nil, a nie pusta liste: brak
// danych nie moze skasowac ostatniej znanej listy kont hosta.
func localAccountsFromReport(report *agentv1.InventoryReport) []inventory.LocalAccount {
	if !report.GetFull() && len(report.GetLocalAccounts()) == 0 {
		return nil
	}
	accounts := make([]inventory.LocalAccount, 0, len(report.GetLocalAccounts()))
	for _, account := range report.GetLocalAccounts() {
		keys, err := json.Marshal(sshKeysJSON(account.GetSshKeys()))
		if err != nil {
			keys = json.RawMessage("[]")
		}
		accounts = append(accounts, inventory.LocalAccount{
			Name:              account.GetName(),
			UID:               int64(account.GetUid()),
			GID:               int64(account.GetGid()),
			Home:              account.GetHome(),
			Shell:             account.GetShell(),
			Gecos:             account.GetGecos(),
			Source:            accountSourceName(account.GetSource()),
			Groups:            account.GetGroups(),
			Locked:            account.Locked,
			PasswordSet:       account.PasswordSet,
			SSHKeys:           keys,
			UnavailableReason: account.GetUnavailableReason(),
		})
	}
	return accounts
}

// accountSourceName odwzorowuje zrodlo konta na nazwe uzywana w bazie i API.
// Wartosc nieokreslona zostaje nieokreslona: "local" byloby zgadywaniem.
func accountSourceName(source agentv1.LocalAccount_Source) string {
	switch source {
	case agentv1.LocalAccount_SOURCE_LOCAL:
		return "local"
	case agentv1.LocalAccount_SOURCE_DIRECTORY:
		return "directory"
	case agentv1.LocalAccount_SOURCE_SYSTEM:
		return "system"
	default:
		return "unknown"
	}
}

func sshKeysJSON(keys []*agentv1.SSHKey) []map[string]any {
	encoded := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		encoded = append(encoded, map[string]any{
			"fingerprint": key.GetFingerprint(),
			"type":        key.GetType(),
			"comment":     key.GetComment(),
			"source":      key.GetSource(),
		})
	}
	return encoded
}

// localAccountResultJSON opisuje stan konta po operacji. Brak konta daje nil,
// bo konto usuniete lub nieutworzone nie ma stanu do pokazania.
func localAccountResultJSON(account *agentv1.LocalAccount) map[string]any {
	if account == nil {
		return nil
	}
	return map[string]any{
		"name":         account.GetName(),
		"uid":          account.GetUid(),
		"gid":          account.GetGid(),
		"shell":        account.GetShell(),
		"gecos":        account.GetGecos(),
		"source":       accountSourceName(account.GetSource()),
		"groups":       account.GetGroups(),
		"locked":       account.Locked,
		"password_set": account.PasswordSet,
		"ssh_keys":     sshKeysJSON(account.GetSshKeys()),
	}
}
