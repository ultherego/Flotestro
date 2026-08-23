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
	"net"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/events"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relays"
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
	// trust podpisuje odnowienia i opisuje, komu panel ufa. Wymiana CA
	// zmienia ten zbior w trakcie pracy, wiec uslugi nie moga trzymac
	// pojedynczego CA skopiowanego przy starcie.
	trust *pki.Trust
	// relays rozpoznaje relaye lokalizacji. Puste wylacza posredniczenie.
	relays *relays.Store
	// events rozglasza postep operacji do otwartych ekranow panelu.
	events *events.Bus
	// proby tlumaczy identyfikator proby na identyfikator operacji. Agent
	// melduje postep dla proby, a operator patrzy na operacje.
	probyMu   sync.RWMutex
	proby     map[string]kontekstZadania
	log       *slog.Logger
	gatewayID string

	heartbeatSeconds int
	heartbeatJitter  int
}

func NewAgentService(pool *pgxpool.Pool, hostStore *hosts.Store, inventoryStore *inventory.Store,
	jobStore *jobs.Store, recorder *audit.Recorder, registry *Registry, trust *pki.Trust,
	relayStore *relays.Store, log *slog.Logger, gatewayID string,
	heartbeatSeconds, heartbeatJitter int) *AgentService {
	return &AgentService{
		pool: pool, hosts: hostStore, inventory: inventoryStore, jobs: jobStore,
		audit: recorder, registry: registry, trust: trust, relays: relayStore,
		log: log, gatewayID: gatewayID,
		heartbeatSeconds: heartbeatSeconds, heartbeatJitter: heartbeatJitter,
		proby: map[string]kontekstZadania{},
	}
}

// SetEvents podlacza magistrale zdarzen. Bez niej agent dziala tak samo,
// tylko postep dlugiej operacji nie dociera na ekran operatora.
func (s *AgentService) SetEvents(bus *events.Bus) { s.events = bus }

// Connect obsluguje sesje agenta. Tozsamosc hosta pochodzi wylacznie z
// certyfikatu klienta; tresc wiadomosci nigdy nie moze jej nadpisac.
func (s *AgentService) Connect(ctx context.Context,
	stream *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("brak certyfikatu klienta"))
	}

	// Sesja moze przyjsc bezposrednio od agenta albo przez relay lokalizacji.
	// W drugim przypadku tozsamosc hosta nie pochodzi z uscisku TLS, tylko
	// z poswiadczenia relaya, i wlasnie dlatego jest sprawdzana osobno.
	hostID, relayID, err := s.identifyPeer(ctx, cert, stream.RequestHeader().Get(relayHostHeader))
	if err != nil {
		return err
	}
	if relayID != "" {
		s.relays.MarkSeen(ctx, relayID)
	}

	// Certyfikat relaya nie opisuje hosta, wiec stan certyfikatu hosta
	// sprawdzamy wylacznie przy polaczeniu bezposrednim. Tozsamosc hosta
	// z poswiadczenia relaya zostala juz sprawdzona wyzej.
	if relayID == "" {
		status, err := s.hosts.LookupCertificate(ctx, pki.Fingerprint(cert))
		if err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
		if problem := s.rejectCertificate(ctx, status, hostID); problem != nil {
			return problem
		}
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
	if err := s.openSession(ctx, session, pki.Fingerprint(cert), relayID); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	// Adres zarzadzania jest odswiezany przy kazdym polaczeniu: host moze
	// zmienic adres, przeniesc sie za relay albo wrocic sprzed niego.
	if address, source := managementAddress(session.RemoteAddr, hello.GetLocalAddress(), relayID); address != "" {
		if err := s.hosts.SetManagementAddress(ctx, hostID, address, source); err != nil {
			s.log.Error("nie zapisano adresu zarzadzania", "host_id", hostID, "err", err)
		}
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
			Fragments:     fragmentsFromReport(report),
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
		// Postep idzie prosto na ekran operatora i nie jest zapisywany:
		// jest ulotny z zalozenia, a trwaly jest wynik. Blad rozgloszenia
		// nie moze zerwac sesji agenta - stracony podglad jest mniejsza
		// szkoda niz przerwana operacja.
		if s.events != nil {
			progress := payload.TaskProgress
			// Agent zna identyfikator proby, a operator patrzy na operacje.
			// Tlumaczenie jest zapamietywane, bo postep melduje sie kilka
			// razy na sekunde, a przypisanie proby do operacji sie nie zmienia.
			jobID, campaignID := s.kontekstProby(ctx, progress.GetTaskId())
			if jobID == "" {
				return nil
			}
			if err := s.events.PublishProgress(ctx, events.Event{
				JobID:      jobID,
				CampaignID: campaignID,
				Progress: &events.Progress{
					Step: progress.GetStep(), Total: progress.GetTotal(),
					Percent: progress.Percent, Message: progress.GetMessage(),
				},
			}); err != nil {
				s.log.Debug("nie rozgloszono postepu",
					"host_id", hostID, "task_id", progress.GetTaskId(), "err", err)
			}
		}
		return nil

	case *agentv1.AgentMessage_Hello:
		// Powtorzone Hello w trakcie sesji jest ignorowane, ale odnotowane.
		s.log.Warn("powtorzone Hello w aktywnej sesji", "host_id", hostID)
		return nil

	default:
		return fmt.Errorf("nieznany typ wiadomosci agenta")
	}
}

// kontekstProby tlumaczy identyfikator proby na operacje i jej kampanie.
// Nieznana proba zwraca pustke: postep bez operacji nie ma komu trafic.
func (s *AgentService) kontekstProby(ctx context.Context, attemptID string) (string, string) {
	if attemptID == "" {
		return "", ""
	}
	s.probyMu.RLock()
	kontekst, znane := s.proby[attemptID]
	s.probyMu.RUnlock()
	if znane {
		return kontekst.jobID, kontekst.campaignID
	}

	jobID, campaignID, err := s.jobs.AttemptContext(ctx, attemptID)
	if err != nil {
		return "", ""
	}
	s.probyMu.Lock()
	// Mapa jest czyszczona przy wyniku proby, ale operacja moze skonczyc sie
	// bez wyniku - zerwana sesja, wygasly lease. Twardy limit trzyma pamiec
	// w ryzach niezaleznie od tego, co poszlo nie tak.
	if len(s.proby) >= maksymalnieZapamietanychProb {
		s.proby = map[string]kontekstZadania{}
	}
	s.proby[attemptID] = kontekstZadania{jobID: jobID, campaignID: campaignID}
	s.probyMu.Unlock()
	return jobID, campaignID
}

// kontekstZadania wiaze probe z operacja i kampania, w ktorej powstala.
type kontekstZadania struct {
	jobID      string
	campaignID string
}

// maksymalnieZapamietanychProb ogranicza pamiec tlumaczen proba -> operacja.
const maksymalnieZapamietanychProb = 4096

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

	s.probyMu.Lock()
	delete(s.proby, attemptID)
	s.probyMu.Unlock()

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

	// Stan bazy pakietow aktualizuje kazdy wynik, ktory go zna: transakcja,
	// plan i naprawa.
	//
	// Wczesniej robila to wylacznie transakcja, a poniewaz uszkodzona baza
	// blokuje transakcje, host nie mial jak wrocic do stanu sprawnego z poziomu
	// panelu - nawet po udanej naprawie. Plan jest tu rownie wiarygodny:
	// czyta stan pakietow i niczego nie zmienia.
	if uszkodzona, znane := stanBazyPakietow(result); znane {
		if err := s.hosts.SetPackageDatabaseBroken(ctx, hostID, uszkodzona); err != nil {
			s.log.Error("nie zapisano stanu bazy pakietow", "host_id", hostID, "err", err)
		}
		if uszkodzona {
			s.log.Error("baza pakietow hosta wymaga naprawy; operacje pakietowe wstrzymane",
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
			"blocked":              blockedJSON(plan.GetBlocked()),
		})
		if err != nil {
			return nil
		}
		return encoded

	case *agentv1.TaskResult_PackageRepair:
		repair := detail.PackageRepair
		encoded, err := json.Marshal(map[string]any{
			"kind":          "package_repair",
			"manager":       repair.GetManager(),
			"repaired":      repair.GetRepaired(),
			"answered":      repair.GetAnswered(),
			"still_blocked": blockedJSON(repair.GetStillBlocked()),
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
			"kind":                       "package_apply",
			"manager":                    apply.GetManager(),
			"applied":                    packageChangesJSON(apply.GetApplied()),
			"reboot_required":            apply.GetRebootRequired(),
			"services_needing_restart":   apply.GetServicesNeedingRestart(),
			"package_database_broken":    apply.GetPackageDatabaseBroken(),
			"packages_needing_attention": apply.GetPackagesNeedingAttention(),
			"self_repair":                apply.GetSelfRepair(),
			"output":                     apply.GetOutput(),
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

// managementAddress wybiera adres zarzadzania hosta i mowi, skad pochodzi.
//
// Przy polaczeniu bezposrednim panel widzi adres hosta na wlasnym koncu
// polaczenia i to jest fakt najmocniejszy, jaki ma. Za relayem widzi adres
// relaya - podanie go jako adresu hosta byloby falszem, wiec jedynym zrodlem
// pozostaje to, co host deklaruje o sobie. Gdy nie ma ani jednego, adres
// zostaje nieustalony; poprzednio znanego nie kasujemy.
func managementAddress(remoteAddr, declared, relayID string) (address, source string) {
	if relayID == "" {
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil && host != "" {
			return host, hosts.AddressFromSession
		}
	}
	if declared != "" {
		return declared, hosts.AddressFromAgent
	}
	return "", ""
}

// openSession zapisuje sesje. relayID jest pusty przy polaczeniu bezposrednim;
// wypelniony mowi, ktory relay poswiadczyl tozsamosc hosta - bez tego slad
// audytowy nie odroznia dwoch roznych podstaw zaufania.
func (s *AgentService) openSession(ctx context.Context, session *Session,
	fingerprint []byte, relayID string) error {
	const query = `
		insert into agent_sessions
			(id, host_id, gateway_id, cert_fingerprint, remote_addr, agent_version, boot_id, relay_id)
		values ($1, $2, $3, $4, $5, $6, $7, nullif($8, '')::uuid)`
	_, err := s.pool.Exec(ctx, query, session.ID, session.HostID, s.gatewayID,
		fingerprint, session.RemoteAddr, session.AgentVersion, session.BootID, relayID)
	if err != nil {
		return err
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: session.HostID,
		Action: "agent.session.open", TargetType: "host", TargetID: session.HostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"relay_id":   nullableRelay(relayID),
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

// capabilitiesFromProto czyta rejestr adapterow. Agent w starszej wersji
// rejestru nie przysyla wcale, a flota aktualizuje sie stopniowo - rejestr
// jest wtedy odtwarzany z pol logicznych sprzed jego wprowadzenia. Uznanie
// takiego hosta za pozbawiony wszystkich adapterow odcieloby go od zarzadzania.
func capabilitiesFromProto(caps *agentv1.Capabilities) hosts.Capabilities {
	if zgloszone := caps.GetRegistry(); len(zgloszone) > 0 {
		registry := make(hosts.Capabilities, 0, len(zgloszone))
		for _, capability := range zgloszone {
			registry = append(registry, hosts.Capability{
				Name:      capability.GetName(),
				Version:   capability.GetVersion(),
				Available: capability.GetAvailable(),
				ReadOnly:  capability.GetReadOnly(),
				Reason:    capability.GetReason(),
				Features:  capability.GetFeatures(),
			})
		}
		return registry
	}

	// Pola logiczne nie niosly powodu ani cech, wiec odtworzony rejestr tez
	// ich nie ma. Zmyslony powod bylby gorszy niz jego brak.
	sprzedRejestru := []struct {
		nazwa    string
		dostepny bool
	}{
		{hosts.CapSystemd, caps.GetSystemd()},
		{hosts.CapAPT, caps.GetApt()},
		{hosts.CapDNF, caps.GetDnf()},
		{hosts.CapDocker, caps.GetDocker()},
		{hosts.CapJournald, caps.GetJournald()},
	}
	registry := make(hosts.Capabilities, 0, len(sprzedRejestru))
	for _, pozycja := range sprzedRejestru {
		registry = append(registry, hosts.Capability{
			Name: pozycja.nazwa, Version: 0, Available: pozycja.dostepny,
		})
	}
	return registry
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

// relayHostHeader niesie tozsamosc hosta poswiadczona przez relay.
const relayHostHeader = "Flotestro-Relay-Host"

// identifyPeer ustala, czyja jest sesja i kto za nia rreczy.
//
// Polaczenie bezposrednie: tozsamosc pochodzi z certyfikatu klienta i jest
// dowodem posiadania klucza prywatnego hosta.
//
// Polaczenie przez relay: certyfikat nalezy do relaya, a tozsamosc hosta jest
// poswiadczeniem relaya. Panel nie moze jej sprawdzic kryptograficznie, wiec
// sprawdza to, co moze: czy relay jest znany, nieodwolany i czy host nalezy
// do jego lokalizacji. To jest wlasnie ta granica zaufania, o ktorej mowi
// dokument - i dlatego jest zapisana w sesji.
func (s *AgentService) identifyPeer(ctx context.Context, cert *x509.Certificate,
	asserted string) (hostID string, relayID string, err error) {
	if hostID, hostErr := pki.HostIDFromCert(cert); hostErr == nil {
		if asserted != "" {
			// Agent nie moze udawac relaya: poswiadczanie cudzej tozsamosci
			// jest uprawnieniem relaya, a nie naglowkiem do dopisania.
			return "", "", connect.NewError(connect.CodePermissionDenied,
				errors.New("certyfikat hosta nie pozwala poswiadczac innych hostow"))
		}
		return hostID, "", nil
	}

	relayIdentity, relayErr := pki.RelayIDFromCert(cert)
	if relayErr != nil {
		return "", "", connect.NewError(connect.CodeUnauthenticated, relayErr)
	}
	if s.relays == nil {
		return "", "", connect.NewError(connect.CodePermissionDenied,
			errors.New("posredniczenie przez relay nie jest wlaczone"))
	}
	if asserted == "" {
		return "", "", connect.NewError(connect.CodeInvalidArgument,
			errors.New("relay musi wskazac host w naglowku "+relayHostHeader))
	}

	status, err := s.relays.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return "", "", connect.NewError(connect.CodeInternal, err)
	}
	switch {
	case !status.Known:
		s.denied(ctx, relayIdentity, "unknown_relay_certificate")
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("certyfikat relaya nieznany"))
	case status.Revoked:
		s.denied(ctx, relayIdentity, "revoked_relay")
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("relay odwolany"))
	case status.ID != relayIdentity:
		s.denied(ctx, relayIdentity, "relay_identity_mismatch")
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("tozsamosc relaya nie zgadza sie z certyfikatem"))
	}

	host, err := s.hosts.Get(ctx, asserted)
	if err != nil {
		s.denied(ctx, asserted, "relay_unknown_host")
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("host nieznany"))
	}
	// Relay posredniczy wylacznie za swoja lokalizacje. Bez tego jeden
	// przejety relay obslugiwalby cala flote.
	if host.Site != status.Site {
		s.denied(ctx, asserted, "relay_scope_mismatch")
		return "", "", connect.NewError(connect.CodePermissionDenied,
			errors.New("host nie nalezy do lokalizacji relaya"))
	}
	if host.LifecycleState == "quarantined" {
		s.denied(ctx, asserted, "quarantined")
		return "", "", connect.NewError(connect.CodePermissionDenied, errors.New("host jest w kwarantannie"))
	}
	return asserted, status.ID, nil
}

// rejectCertificate sprawdza stan certyfikatu hosta przy polaczeniu
// bezposrednim.
func (s *AgentService) rejectCertificate(ctx context.Context,
	status hosts.CertificateStatus, hostID string) error {
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
	return nil
}

// nullableRelay zwraca nil dla polaczenia bezposredniego. Pusty ciag w sladzie
// audytowym wygladalby jak relay bez nazwy, a nie jak jego brak.
func nullableRelay(relayID string) any {
	if relayID == "" {
		return nil
	}
	return relayID
}

// CloseOrphanSessions zamyka wpisy sesji, ktorych ta instancja juz nie
// utrzymuje.
//
// Sesja konczy sie zapisem przy rozlaczeniu, ale przy padzie procesu ten zapis
// nie ma jak powstac i wpis zostaje otwarty na zawsze. Kazdy pomiar liczacy
// aktywne sesje z bazy widzialby wtedy fikcyjna flote, a slad audytowy -
// polaczenia, ktorych nie ma.
//
// Wolno zamykac wylacznie sesje wlasnego gatewaya: sesje innej instancji sa
// zywe, a jej stan zna tylko ona.
func (s *AgentService) CloseOrphanSessions(ctx context.Context) (int64, error) {
	const query = `
		update agent_sessions set ended_at = now(), end_reason = 'orphaned'
		where gateway_id = $1 and ended_at is null and id <> all($2)`
	tag, err := s.pool.Exec(ctx, query, s.gatewayID, s.registry.SessionIDs())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ReapOrphanSessions zamyka osierocone wpisy przy starcie i okresowo w trakcie
// pracy. Pojedynczy strumien moze zginac bez zapisu konca takze wtedy, gdy
// proces zyje dalej.
func (s *AgentService) ReapOrphanSessions(ctx context.Context, interval time.Duration) {
	if zamkniete, err := s.CloseOrphanSessions(ctx); err != nil {
		s.log.Error("nie zamknieto osieroconych sesji", "err", err)
	} else if zamkniete > 0 {
		s.log.Info("zamknieto osierocone sesje po starcie", "wpisow", zamkniete)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if zamkniete, err := s.CloseOrphanSessions(ctx); err != nil {
				s.log.Error("nie zamknieto osieroconych sesji", "err", err)
			} else if zamkniete > 0 {
				s.log.Warn("zamknieto osierocone sesje", "wpisow", zamkniete)
			}
		}
	}
}

// blockedJSON opisuje pakiety blokujace operacje pakietowe wraz z pytaniami
// konfiguracyjnymi. Panel pokazuje je operatorowi, bo to on podejmuje decyzje.
func blockedJSON(blocked []*agentv1.BlockedPackage) []map[string]any {
	result := make([]map[string]any, 0, len(blocked))
	for _, pakiet := range blocked {
		pytania := make([]map[string]any, 0, len(pakiet.GetQuestions()))
		for _, pytanie := range pakiet.GetQuestions() {
			pytania = append(pytania, map[string]any{
				"name": pytanie.GetName(), "value": pytanie.GetValue(),
				"answered": pytanie.Answered,
			})
		}
		result = append(result, map[string]any{
			"name": pakiet.GetName(), "status": pakiet.GetStatus(), "questions": pytania,
		})
	}
	return result
}

// stanBazyPakietow odczytuje stan bazy pakietow z wyniku zadania.
//
// Drugi zwracany parametr mowi, czy wynik w ogole cokolwiek o tym stanie wie.
// Zadanie niepakietowe nie moze zdejmowac ani nakladac tej flagi: brak wiedzy
// to nie to samo co stwierdzenie, ze baza jest sprawna.
func stanBazyPakietow(result *agentv1.TaskResult) (uszkodzona bool, znane bool) {
	switch detail := result.GetDetail().(type) {
	case *agentv1.TaskResult_PackageApply:
		return detail.PackageApply.GetPackageDatabaseBroken(), true
	case *agentv1.TaskResult_PackagePlan:
		return len(detail.PackagePlan.GetBlocked()) > 0, true
	case *agentv1.TaskResult_PackageRepair:
		return len(detail.PackageRepair.GetStillBlocked()) > 0, true
	}
	return false, false
}

// fragmentsFromReport czyta moduly raportu. Agent sprzed podzialu ich nie
// przysyla; pusta lista nie kasuje tego, co juz wiadomo o modulach hosta.
func fragmentsFromReport(report *agentv1.InventoryReport) []inventory.Fragment {
	zgloszone := report.GetFragments()
	if len(zgloszone) == 0 {
		return nil
	}
	wynik := make([]inventory.Fragment, 0, len(zgloszone))
	for _, fragment := range zgloszone {
		wynik = append(wynik, inventory.Fragment{
			Module:            fragment.GetModule(),
			Revision:          fragment.GetRevision(),
			Source:            fragment.GetSource(),
			Payload:           fragment.GetPayload(),
			UnavailableReason: fragment.GetUnavailableReason(),
			ObservedAt:        fragment.GetObservedAt().AsTime(),
		})
	}
	return wynik
}
