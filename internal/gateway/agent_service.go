package gateway

import (
	"context"
	"crypto/sha256"
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
	backupstore "github.com/ultherego/flotestro/internal/backup"
	certyfikaty "github.com/ultherego/flotestro/internal/certificates"
	"github.com/ultherego/flotestro/internal/events"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/issuer"
	"github.com/ultherego/flotestro/internal/jobs"
	backupmodule "github.com/ultherego/flotestro/internal/modules/backup"
	certmodule "github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/opspec"
	modulpakiety "github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relays"
	"github.com/ultherego/flotestro/internal/vuln"
)

type contextKey string

const (
	clientCertKey contextKey = "flotestro.client-cert"
	remoteAddrKey contextKey = "flotestro.remote-addr"
)

// WithClientCertificate carries the client certificate from the TLS layer
// into the context, so that the handler does not have to know the details of
// the HTTP server.
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

// AgentService serves the long-lived stream of an agent. The stream is the
// only channel of commands; the root helper never speaks to the centre.
type AgentService struct {
	pool      *pgxpool.Pool
	hosts     *hosts.Store
	inventory *inventory.Store
	jobs      *jobs.Store
	audit     *audit.Recorder
	registry  *Registry
	// certIssuer signs the renewals and describes whom the panel trusts. An
	// interface rather than an authority: an exchange of the CA changes the
	// trust set while the panel works, and moving the key into an HSM is not
	// to touch this service.
	certIssuer issuer.Issuer
	// relays recognises the relays of the sites. Empty disables the
	// mediation.
	relays *relays.Store
	// events broadcasts the progress of the operations to the open screens of
	// the panel.
	events *events.Bus
	// refreshAssessment asks the correlator to recompute a host out of turn.
	// Empty when the correlator is disabled.
	refreshAssessment func(hostID string)
	// files keeps the desired state of the configuration files. We write it
	// only after a successful operation: the panel must not claim it manages
	// a file the host did not accept.
	files *managedfiles.Store
	// certificates keeps the history of the deployed certificates. We write it
	// only after a successful operation, and on the basis of the fingerprint
	// the host sent back - not the one the panel sent.
	certificates *certyfikaty.Store
	// backups keeps the history of the backup runs. The panel does not know
	// when a copy succeeded unless it records it: the host does not remember
	// that between operations, and the repository answers only once a
	// password is given.
	backups *backupstore.Store
	// packages keep the full package lists of the hosts. Without them nothing
	// can be said about vulnerabilities - and a missing list has to be visible
	// as missing knowledge rather than as a host without findings.
	pkgs *vuln.PackageStore
	// secrets releases the values of the secrets against a lease. Empty means
	// a panel without a store: the operations that name a secret are then not
	// delivered.
	secrets SecretIssuing
	// leases makes it possible to check which version of a secret the panel
	// really released.
	leases SecretLeases
	// attempts translates the identifier of an attempt into the identifier of
	// an operation. The agent reports progress for an attempt, and the
	// operator looks at an operation.
	attemptsMu sync.RWMutex
	attempts   map[string]attemptContextEntry
	log        *slog.Logger
	gatewayID  string

	heartbeatSeconds int
	heartbeatJitter  int
}

func NewAgentService(pool *pgxpool.Pool, hostStore *hosts.Store, inventoryStore *inventory.Store,
	jobStore *jobs.Store, recorder *audit.Recorder, registry *Registry, certIssuer issuer.Issuer,
	relayStore *relays.Store, log *slog.Logger, gatewayID string,
	heartbeatSeconds, heartbeatJitter int) *AgentService {
	return &AgentService{
		pool: pool, hosts: hostStore, inventory: inventoryStore, jobs: jobStore,
		files:        managedfiles.NewStore(pool),
		certificates: certyfikaty.NewStore(pool),
		backups:      backupstore.NewStore(pool),
		pkgs:         vuln.NewPackageStore(pool),
		audit:        recorder, registry: registry, certIssuer: certIssuer, relays: relayStore,
		log: log, gatewayID: gatewayID,
		heartbeatSeconds: heartbeatSeconds, heartbeatJitter: heartbeatJitter,
		attempts: map[string]attemptContextEntry{},
	}
}

// SetAssessmentRefresh connects the request to recompute the vulnerability
// assessment.
//
// Optional: without the correlator the gateway works the same, only nobody
// waits for these data.
func (s *AgentService) SetAssessmentRefresh(refresh func(hostID string)) {
	s.refreshAssessment = refresh
}

// SetEvents connects the event bus. Without it the agent works the same, only
// the progress of a long operation does not reach the screen of the
// operator.
func (s *AgentService) SetEvents(bus *events.Bus) { s.events = bus }

// Connect serves the session of an agent. The identity of the host comes from
// the client certificate alone; the content of a message must never overwrite
// it.
func (s *AgentService) Connect(ctx context.Context,
	stream *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("brak certyfikatu klienta"))
	}

	// A session can come straight from an agent or through the relay of a
	// site. In the second case the identity of the host does not come from the
	// TLS handshake but from the attestation of the relay, and that is exactly
	// why it is checked separately.
	hostID, relayID, err := s.identifyPeer(ctx, cert, stream.RequestHeader().Get(relayHostHeader))
	if err != nil {
		return err
	}
	if relayID != "" {
		s.relays.MarkSeen(ctx, relayID)
	}

	// The certificate of a relay does not describe a host, so the state of the
	// certificate of a host is checked only for a direct connection. The
	// identity of a host from the attestation of a relay has already been
	// checked above.
	if relayID == "" {
		status, err := s.hosts.LookupCertificate(ctx, pki.Fingerprint(cert))
		if err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
		if problem := s.rejectCertificate(ctx, status, hostID); problem != nil {
			return problem
		}
	}

	// The first message has to be Hello. Any other start ends the session.
	first, err := stream.Receive()
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("Hello was expected: %w", err))
	}
	hello := first.GetHello()
	if hello == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("the first message has to be Hello"))
	}

	caps := capabilitiesFromProto(hello.GetCapabilities())
	if err := s.hosts.ApplyHello(ctx, hostID, hello.GetAgentVersion(), hello.GetBootId(), caps); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	// The return of the agent settles its replacement rather than the exit code
	// of the package manager: the process that carried the job out was
	// replaced halfway.
	s.settleAgentUpgrade(ctx, hostID, hello.GetAgentVersion())

	session := NewSession(uuid.NewString(), hostID, hello.GetAgentVersion(),
		hello.GetBootId(), remoteAddr(ctx), 32)
	session.RelayID = relayID
	if err := s.openSession(ctx, session, pki.Fingerprint(cert), relayID); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	// The management address is refreshed at every connection: a host can
	// change its address, move behind a relay or come back from behind one.
	if address, source := managementAddress(session.RemoteAddr, hello.GetLocalAddress(), relayID); address != "" {
		if err := s.hosts.SetManagementAddress(ctx, hostID, address, source); err != nil {
			s.log.Error("the management address was not written", "host_id", hostID, "err", err)
		}
	}

	s.registry.Add(session)
	s.log.Info("the session of the agent was opened",
		"host_id", hostID, "session_id", session.ID, "agent_version", session.AgentVersion,
		"boot_id", session.BootID, "sessions", s.registry.Count())

	defer func() {
		s.registry.Remove(hostID, session.ID)
		// The context of the request is already cancelled, so the cleanup has
		// one of its own.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		s.closeSession(cleanupCtx, session, hostID)
	}()

	// One goroutine writes to the stream, because Send is not safe
	// concurrently. The scheduler queues the jobs over the channel of the
	// session rather than over the stream directly.
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

	// The server sends the parameters of the session back at once. A full
	// inventory is ordered when the agent reports a revision other than the
	// recorded one.
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

		case <-session.Closed():
			// The panel ended the session: a quarantine or a withdrawal of the
			// host. A check at the next connection would not cut off a machine
			// that is carrying out somebody's commands right now.
			s.log.Info("the session of the agent was closed by the panel",
				"host_id", hostID, "session_id", session.ID,
				"reason", session.CloseReason())
			return connect.NewError(connect.CodePermissionDenied,
				errors.New(session.CloseReason()))

		case err := <-senderErr:
			s.log.Info("the sending to the agent has ended", "host_id", hostID, "err", err)
			return nil

		case err := <-receiveErr:
			if errors.Is(err, io.EOF) || errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			s.log.Info("the stream of the agent has ended", "host_id", hostID, "err", err)
			return nil

		case msg, ok := <-received:
			if !ok {
				return nil
			}
			if err := s.handle(ctx, hostID, session, msg); err != nil {
				s.log.Error("an error while handling a message of the agent", "host_id", hostID, "err", err)
			}
		}
	}
}

func (s *AgentService) handle(ctx context.Context, hostID string, session *Session,
	msg *agentv1.AgentMessage) error {
	switch payload := msg.GetPayload().(type) {
	case *agentv1.AgentMessage_Heartbeat:
		health := payload.Heartbeat.GetHealth()
		// The fields absent from a message mean an undetermined state and go on
		// as a missing value rather than as zero.
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
			return fmt.Errorf("the inventory is not valid JSON")
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
			s.log.Info("a new inventory revision",
				"host_id", hostID, "revision", report.GetRevision(), "full", report.GetFull())
		}
		return nil

	case *agentv1.AgentMessage_TaskResult:
		return s.recordTaskResult(ctx, hostID, payload.TaskResult)

	case *agentv1.AgentMessage_TaskLogLines:
		// The live view of a log goes straight to the screen of the operator
		// and is not recorded. An error of the broadcast must not tear down the
		// session of the agent.
		if s.events != nil {
			lines := payload.TaskLogLines
			jobID, campaignID := s.attemptContext(ctx, lines.GetTaskId())
			if jobID == "" {
				return nil
			}
			if err := s.events.PublishLog(ctx, events.Event{
				JobID: jobID, CampaignID: campaignID,
				Log: &events.LogLines{
					Lines: lines.GetLines(), Dropped: lines.GetDropped(),
				},
			}); err != nil {
				s.log.Debug("the live view of the log was not broadcast",
					"host_id", hostID, "task_id", lines.GetTaskId(), "err", err)
			}
		}
		return nil

	case *agentv1.AgentMessage_TaskProgress:
		// The progress goes straight to the screen of the operator and is not
		// recorded: it is transient by design, and what lasts is the result. An
		// error of the broadcast must not tear down the session of the agent -
		// a lost view is a smaller harm than an interrupted operation.
		if s.events != nil {
			progress := payload.TaskProgress
			// The agent knows the identifier of the attempt, and the operator
			// looks at the operation. The translation is remembered, because
			// progress reports several times a second while the assignment of
			// an attempt to an operation does not change.
			jobID, campaignID := s.attemptContext(ctx, progress.GetTaskId())
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
				s.log.Debug("the progress was not broadcast",
					"host_id", hostID, "task_id", progress.GetTaskId(), "err", err)
			}
		}
		return nil

	case *agentv1.AgentMessage_Hello:
		// A repeated Hello during a session is ignored but noted.
		s.log.Warn("a repeated Hello in an active session", "host_id", hostID)
		return nil

	default:
		return fmt.Errorf("an unknown type of an agent message")
	}
}

// attemptContext translates the identifier of an attempt into the operation
// and its campaign. An unknown attempt returns nothing: progress without an
// operation has nobody to reach.
func (s *AgentService) attemptContext(ctx context.Context, attemptID string) (string, string) {
	if attemptID == "" {
		return "", ""
	}
	s.attemptsMu.RLock()
	entry, known := s.attempts[attemptID]
	s.attemptsMu.RUnlock()
	if known {
		return entry.jobID, entry.campaignID
	}

	jobID, campaignID, err := s.jobs.AttemptContext(ctx, attemptID)
	if err != nil {
		return "", ""
	}
	s.attemptsMu.Lock()
	// The map is cleared at the result of an attempt, but an operation can end
	// without a result - a broken session, an expired lease. A hard limit
	// keeps the memory in check regardless of what went wrong.
	if len(s.attempts) >= maxRememberedAttempts {
		s.attempts = map[string]attemptContextEntry{}
	}
	s.attempts[attemptID] = attemptContextEntry{jobID: jobID, campaignID: campaignID}
	s.attemptsMu.Unlock()
	return jobID, campaignID
}

// attemptContextEntry binds an attempt to the operation and the campaign it
// was created in.
type attemptContextEntry struct {
	jobID      string
	campaignID string
}

// maxRememberedAttempts limits the memory of the attempt -> operation
// translations.
const maxRememberedAttempts = 4096

// recordTaskResult writes the result reported by the agent and moves the job
// into a final state. The result always reaches the attempt; whether it
// changes the state of the job is decided by the state machine.
func (s *AgentService) recordTaskResult(ctx context.Context, hostID string,
	result *agentv1.TaskResult) error {
	attemptID := result.GetTaskId()
	jobID, action, err := s.jobs.AttemptOwner(ctx, attemptID)
	if err != nil {
		return fmt.Errorf("a result for the unknown attempt %s: %w", attemptID, err)
	}

	s.attemptsMu.Lock()
	delete(s.attempts, attemptID)
	s.attemptsMu.Unlock()

	// The desired state of a file is written after a successful operation
	// rather than at the ordering: the panel must not claim it manages a file
	// the host rejected.
	// A job that has finished has no reason to keep an open right to a secret.
	// The lease will expire on its own anyway, but the window is to be as
	// short as it can be - not as long as the clock allows.
	if s.leases != nil {
		if err := s.leases.Revoke(ctx, jobID); err != nil {
			s.log.Debug("the leases of the secrets were not closed", "job_id", jobID, "err", err)
		}
	}

	if result.GetStatus() == agentv1.TaskResult_STATUS_SUCCEEDED {
		s.saveFileState(ctx, hostID, jobID)
		s.saveCertificateDeployment(ctx, hostID, jobID, result.GetCertificateResult())
		// The content that was read goes into the store of versions: without
		// that there is no getting back to the state from before the first
		// change from the panel, because the panel never recorded that
		// content.
		if file := result.GetFileResult(); file != nil && len(file.GetContent()) > 0 &&
			!file.GetTruncated() {
			if _, err := s.files.SaveVersion(ctx, s.pool, file.GetContent()); err != nil {
				s.log.Error("the version of the file that was read was not written", "host_id", hostID, "err", err)
			}
		}
	}

	// The state of the managed files goes into the inventory: it is what shows
	// the drift, that is a file changed outside the panel.
	if file := result.GetFileResult(); file != nil && len(file.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "files",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(file.GetSnapshot())),
			Source:     "agent/managed-files",
			Payload:    file.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the state of the files was not written", "host_id", hostID, "err", err)
		}
	}

	// The full package list goes into a table of its own: the vulnerability
	// assessment is computed from it, so rows for joins are needed rather than
	// a blob in the inventory.
	if list := result.GetInstalledPackagesResult(); list != nil &&
		result.GetStatus() == agentv1.TaskResult_STATUS_SUCCEEDED {
		s.savePackageList(ctx, hostID, jobID, list)
	}

	// A backup run is recorded also when it failed: "the backup did not work"
	// is a more important message than "the backup worked", and without an
	// entry in the history there would be nowhere to see it.
	if backup := result.GetBackupResult(); backup != nil {
		s.saveBackupRun(ctx, hostID, jobID, backup,
			result.GetStatus() == agentv1.TaskResult_STATUS_SUCCEEDED)
	}

	// The package sources go into the inventory after every change. The
	// package fragment also carries the counters, so only the sources in it
	// are replaced - overwriting the whole thing would erase what this
	// operation did not concern.
	if sources := result.GetRepositoryResult(); sources != nil && len(sources.GetSnapshot()) > 0 {
		if err := s.mergeRepositories(ctx, hostID, sources.GetSnapshot()); err != nil {
			s.log.Error("the package sources were not written", "host_id", hostID, "err", err)
		}
	}

	// The image of the certificates goes into the inventory after a scan and
	// after a deployment: the tab is to show the file that really lies on the
	// host rather than the one the panel sent.
	if certificate := result.GetCertificateResult(); certificate != nil &&
		len(certificate.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "certificates",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(certificate.GetSnapshot())),
			Source:     "agent/certificates+certmonger",
			Payload:    certificate.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the image of the certificates was not written", "host_id", hostID, "err", err)
		}
	}

	// The settings of the kernel go into the inventory after every change.
	if kernel := result.GetKernelResult(); kernel != nil && len(kernel.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "kernel",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(kernel.GetSnapshot())),
			Source:     "agent/procfs+sysctl",
			Payload:    kernel.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the settings of the kernel were not written", "host_id", hostID, "err", err)
		}
	}

	// The protective state goes into the inventory after every operation: a
	// scan exists exactly to refresh it on demand, and a switch of MAC is to
	// be visible in the findings at once rather than after the next cycle.
	if protection := result.GetSecurityResult(); protection != nil && len(protection.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "security",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(protection.GetSnapshot())),
			Source:     "agent/selinux+audit+ss",
			Payload:    protection.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the protective state was not written", "host_id", hostID, "err", err)
		}
	}

	// The boot state goes into the inventory: it is the last image of the host
	// the panel gets before the machine goes down.
	if power := result.GetPowerResult(); power != nil && len(power.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "power",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(power.GetSnapshot())),
			Source:     "agent/procfs+logind",
			Payload:    power.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the power state was not written", "host_id", hostID, "err", err)
		}
	}

	// The state of time goes into the inventory after every operation. The
	// clock changes on its own between cycles, so a fresh read right after a
	// change is the only one that says anything about the effect of that
	// change.
	if clock := result.GetTimeResult(); clock != nil && len(clock.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "time",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(clock.GetSnapshot())),
			Source:     "agent/timedatectl+chronyc",
			Payload:    clock.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the state of time was not written", "host_id", hostID, "err", err)
		}
	}

	// The configuration of sshd goes into the inventory after every change: the
	// tab is to show the state after the operation rather than the one from
	// before the cycle.
	if server := result.GetSshResult(); server != nil && len(server.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "ssh",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(server.GetSnapshot())),
			Source:     "agent/sshd",
			Payload:    server.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the configuration of sshd was not written", "host_id", hostID, "err", err)
		}
	}

	// The image of the disk space goes into the inventory: every operation
	// sends the state back after itself, so the tab does not wait for the next
	// cycle.
	if storage := result.GetStorageResult(); storage != nil && len(storage.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "storage",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(storage.GetSnapshot())),
			Source:     "agent/lsblk+mountinfo",
			Payload:    storage.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the image of the storage was not written", "host_id", hostID, "err", err)
		}
	}

	// The state of the firewall goes into the inventory: the tab asks about the
	// set of rules, and every change sends the full image back after itself
	// anyway.
	if firewall := result.GetFirewallResult(); firewall != nil && len(firewall.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "firewall",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(firewall.GetSnapshot())),
			Source:     "agent/nftables",
			Payload:    firewall.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the state of the firewall was not written", "host_id", hostID, "err", err)
		}
	}

	// The schedules go into the inventory module: the tab asks about the state
	// of the host, and every operation sends the full image back after a change
	// anyway.
	if schedule := result.GetScheduleResult(); schedule != nil && len(schedule.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "schedules",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(schedule.GetSnapshot())),
			Source:     "agent/cron+systemd",
			Payload:    schedule.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the schedules were not written", "host_id", hostID, "err", err)
		}
	}

	// The snapshot of the processes goes into an inventory module, like the
	// state of the containers and the list of the units: the tab asks about the
	// state of the host rather than about the history of the jobs.
	if list := result.GetProcessListResult(); list != nil && len(list.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:     "processes",
			Revision:   fmt.Sprintf("%x", sha256.Sum256(list.GetSnapshot())),
			Source:     "agent/procfs",
			Payload:    list.GetSnapshot(),
			ObservedAt: time.Now().UTC(),
		}); err != nil {
			s.log.Error("the snapshot of the processes was not written", "host_id", hostID, "err", err)
		}
	}

	// The full list of the units goes into an inventory module for the same
	// reason as the state of the containers: the tab asks about the state of
	// the host rather than about the history of the jobs.
	if status := result.GetUnitStatus(); status != nil && len(status.GetUnits()) > 0 {
		if encoded, err := json.Marshal(map[string]any{
			"units":     unitStatesJSON(status.GetUnits()),
			"truncated": status.GetTruncated(),
		}); err == nil {
			if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
				Module:     "services.full",
				Revision:   fmt.Sprintf("%x", sha256.Sum256(encoded)),
				Source:     "agent/systemctl",
				Payload:    encoded,
				ObservedAt: time.Now().UTC(),
			}); err != nil {
				s.log.Error("the list of the units was not written", "host_id", hostID, "err", err)
			}
		}
	}

	// The full state of the containers is written as an inventory module rather
	// than only as the result of an operation. A result is a record of what
	// happened; the tab asks about the state of the host and is to get it
	// without browsing the history of the jobs.
	if docker := result.GetDockerResult(); docker != nil && len(docker.GetSnapshot()) > 0 {
		if err := s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
			Module:            "containers.full",
			Revision:          fmt.Sprintf("%x", sha256.Sum256(docker.GetSnapshot())),
			Source:            "agent/docker-engine",
			Payload:           docker.GetSnapshot(),
			UnavailableReason: docker.GetUnavailableReason(),
			ObservedAt:        time.Now().UTC(),
		}); err != nil {
			s.log.Error("the state of the containers was not written", "host_id", hostID, "err", err)
		}
	}

	state, statusName := jobStateFor(result.GetStatus())

	// A refresh of the inventory is settled by the appearance of a revision
	// rather than by the report of the agent. The agent sends the image over
	// the same stream right before the result, so by the time we get here the
	// revision is already recorded. When it is not there, the image did not
	// arrive - and a job that says "refreshed" over a state from a quarter of
	// an hour ago is worse than a failed job.
	errorCode, errorMessage := result.GetErrorCode(), result.GetMessage()
	if state == jobs.StateSucceeded && action == string(opspec.ActionInventoryRefresh) {
		if code, message := s.checkRefresh(ctx, hostID, result); code != "" {
			state, statusName = jobs.StateFailed, "failed"
			errorCode, errorMessage = code, message
		}
	}

	accepted, err := s.jobs.RecordResult(ctx, jobID, attemptID, jobs.Result{
		Status:          statusName,
		ExitCode:        result.GetExitCode(),
		Stdout:          result.GetStdout(),
		Stderr:          result.GetStderr(),
		OutputTruncated: result.GetOutputTruncated(),
		ErrorCode:       errorCode,
		Message:         errorMessage,
		Replayed:        result.GetReplayed(),
		UnitStateBefore: unitStateJSON(result.GetUnitStateBefore()),
		UnitStateAfter:  unitStateJSON(result.GetUnitStateAfter()),
		Detail:          resultDetailJSON(result),
	}, state)
	if err != nil {
		return err
	}

	// An operation on an account changes the state of the host at once, while
	// the full inventory report comes only in a dozen or so minutes. The agent
	// reads the account after the change, so we record the actual state of the
	// host instead of waiting; without that the panel would show the state from
	// before the operation.
	if user, ok := result.GetDetail().(*agentv1.TaskResult_LocalUser); ok &&
		state == jobs.StateSucceeded && user.LocalUser.GetAccount() != nil {
		accounts := localAccountsFromReport(&agentv1.InventoryReport{
			Full:          true,
			LocalAccounts: []*agentv1.LocalAccount{user.LocalUser.GetAccount()},
		})
		if err := s.inventory.UpsertLocalAccount(ctx, hostID, accounts[0]); err != nil {
			s.log.Error("the state of the account was not written after the operation",
				"host_id", hostID, "account", user.LocalUser.GetName(), "err", err)
		}
	}

	// The state of the package database is updated by every result that knows
	// it: a transaction, a plan and a repair.
	//
	// Earlier only a transaction did it, and because a damaged database blocks
	// transactions, the host had no way back to a working state from the panel
	// - not even after a successful repair. A plan is just as credible here: it
	// reads the state of the packages and changes nothing.
	if broken, known := packageDatabaseState(result); known {
		if err := s.hosts.SetPackageDatabaseBroken(ctx, hostID, broken); err != nil {
			s.log.Error("the state of the package database was not written", "host_id", hostID, "err", err)
		}
		if broken {
			s.log.Error("the package database of the host needs repairing; the package operations are held back",
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
		// A late result is kept in the attempt for diagnostics but does not take
		// back a decision made in the meantime.
		s.log.Warn("the result did not change the state of the job",
			"job_id", jobID, "attempt_id", attemptID, "status", statusName)
		return nil
	}
	s.log.Info("the result of the job was written",
		"job_id", jobID, "host_id", hostID, "status", statusName,
		"exit_code", result.GetExitCode(), "replayed", result.GetReplayed())
	return nil
}

// jobStateFor translates the status reported by the agent into the state of a
// job.
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
		// A local rejection is a failure of the job but keeps an error code of
		// its own, so that the operator sees that nothing was changed.
		return jobs.StateFailed, "rejected"
	default:
		return jobs.StateFailed, "failed"
	}
}

// resultDetailJSON writes the result proper for the type of the operation. An
// upgrade plan and a transaction report have different shapes, so they go into
// JSONB.
func resultDetailJSON(result *agentv1.TaskResult) json.RawMessage {
	// The event log is the answer to a question from one moment rather than the
	// state of the host: it stays in the result of the job and does not reach
	// the inventory.
	if zdarzenia := result.GetDockerEventsResult(); zdarzenia != nil &&
		(len(zdarzenia.GetEvents()) > 0 || zdarzenia.GetUnavailableReason() != "") {
		// An unavailable engine carries no log at all, and the result is to
		// come into being anyway: it is what tells the operator why they see
		// nothing.
		odczyt := json.RawMessage(zdarzenia.GetEvents())
		if len(odczyt) == 0 {
			odczyt = json.RawMessage("{}")
		}
		encoded, err := json.Marshal(map[string]any{
			"kind":               "docker_events",
			"events":             odczyt,
			"truncated":          zdarzenia.GetTruncated(),
			"truncated_reason":   zdarzenia.GetTruncatedReason(),
			"unavailable_reason": zdarzenia.GetUnavailableReason(),
		})
		if err == nil {
			return encoded
		}
	}

	// A refresh of the inventory carries proof: the revision of the image that
	// came out of it. Without it the result would only say that the job did not
	// topple.
	if refresh := result.GetInventoryRefreshResult(); refresh != nil &&
		refresh.GetRevision() != "" {
		encoded, err := json.Marshal(map[string]any{
			"kind":     "inventory_refresh",
			"revision": refresh.GetRevision(),
			"changed":  refresh.GetChanged(),
			"modules":  refresh.GetModules(),
		})
		if err == nil {
			return encoded
		}
	}

	// The result of a container operation is a field of its own rather than a
	// variant of a sum: it carries the state before and after, which concerns a
	// failed operation as well.
	// The result of a Compose project is a field of its own: it carries the plan
	// or the state of the deployment, which concerns a failed operation as
	// well.
	if compose := result.GetComposeResult(); compose != nil && len(compose.GetPayload()) > 0 {
		encoded, err := json.Marshal(map[string]any{
			"kind":               "compose",
			"payload":            json.RawMessage(compose.GetPayload()),
			"unavailable_reason": compose.GetUnavailableReason(),
		})
		if err == nil {
			return encoded
		}
	}

	// The result of a name resolution test belongs to the job rather than to
	// the inventory: it is the answer to one question asked at one moment
	// rather than the state of the host.
	// The plan of the resolver is a result of the job rather than the state of
	// the host: it describes a change that has not happened yet, against the
	// profile the host has now.
	if resolver := result.GetDnsResult(); resolver != nil && len(resolver.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
		}
		_ = json.Unmarshal(resolver.GetPlan(), &plan)
		encoded, err := json.Marshal(map[string]any{
			"kind":      "dns_plan",
			"plan":      json.RawMessage(resolver.GetPlan()),
			"plan_hash": plan.PlanHash,
			"profiles":  rawJSON(resolver.GetProfiles()),
		})
		if err == nil {
			return encoded
		}
	}

	if resolver := result.GetDnsResult(); resolver != nil &&
		(len(resolver.GetQueries()) > 0 || resolver.GetRollbackId() != "") {
		encoded, err := json.Marshal(map[string]any{
			"kind":              "dns",
			"queries":           rawJSON(resolver.GetQueries()),
			"profiles":          rawJSON(resolver.GetProfiles()),
			"rollback_id":       resolver.GetRollbackId(),
			"rollback_deadline": resolver.GetRollbackDeadline(),
			"confirmed":         resolver.GetConfirmed(),
		})
		if err == nil {
			return encoded
		}
	}

	// A network plan is a result of the job rather than the state of the host:
	// it describes a change that has not happened yet, against the profile the
	// host has now.
	if siec := result.GetNetworkResult(); siec != nil && len(siec.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
		}
		_ = json.Unmarshal(siec.GetPlan(), &plan)
		encoded, err := json.Marshal(map[string]any{
			"kind":      "network_plan",
			"plan":      json.RawMessage(siec.GetPlan()),
			"plan_hash": plan.PlanHash,
			"profiles":  rawJSON(siec.GetProfiles()),
		})
		if err == nil {
			return encoded
		}
	}

	// Zmiana sieci niesie identyfikator wycofania i to, czy zdazylo je
	// disarm the confirmation of connectivity. Without that the operator does
	// not know whether the host
	// za chwile wroci do poprzedniej konfiguracji.
	if siec := result.GetNetworkResult(); siec != nil &&
		(len(siec.GetProfiles()) > 0 || siec.GetRollbackId() != "") {
		encoded, err := json.Marshal(map[string]any{
			"kind":              "network",
			"profiles":          rawJSON(siec.GetProfiles()),
			"rollback_id":       siec.GetRollbackId(),
			"rollback_deadline": siec.GetRollbackDeadline(),
			"confirmed":         siec.GetConfirmed(),
		})
		if err == nil {
			return encoded
		}
	}

	// A rule plan is a result of the job rather than the state of the host: it
	// describes a change that has not happened yet, against the set of rules
	// the host has now.
	if firewall := result.GetFirewallResult(); firewall != nil && len(firewall.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
		}
		_ = json.Unmarshal(firewall.GetPlan(), &plan)
		encoded, err := json.Marshal(map[string]any{
			"kind":      "firewall_plan",
			"plan":      json.RawMessage(firewall.GetPlan()),
			"plan_hash": plan.PlanHash,
		})
		if err == nil {
			return encoded
		}
	}

	// Zmiana zapory niesie identyfikator wycofania i digest zestawu regul.
	if firewall := result.GetFirewallResult(); firewall != nil && firewall.GetRollbackId() != "" {
		encoded, err := json.Marshal(map[string]any{
			"kind":              "firewall",
			"rollback_id":       firewall.GetRollbackId(),
			"rollback_deadline": firewall.GetRollbackDeadline(),
			"confirmed":         firewall.GetConfirmed(),
		})
		if err == nil {
			return encoded
		}
	}

	// A mount plan is a result of the job rather than the state of the host: it
	// describes a change that has not happened yet, and a source resolved to
	// the UUID of this host.
	if storage := result.GetStorageResult(); storage != nil && len(storage.GetPlan()) > 0 {
		var plan struct {
			PlanHash  string `json:"plan_hash"`
			Operation string `json:"operation"`
		}
		_ = json.Unmarshal(storage.GetPlan(), &plan)
		// A mount plan and a device plan (fsck, extension) are two shapes; the
		// kind of the result is to name that.
		kind := "mount_plan"
		if plan.Operation != "" {
			kind = "device_plan"
		}
		encoded, err := json.Marshal(map[string]any{
			"kind":      kind,
			"plan":      json.RawMessage(storage.GetPlan()),
			"plan_hash": plan.PlanHash,
		})
		if err == nil {
			return encoded
		}
	}

	// Wynik sprawdzenia filesystemu nalezy do zadania: to odpowiedz na jedno
	// question zadane w jednej chwili.
	if storage := result.GetStorageResult(); storage != nil && storage.GetOutput() != "" {
		encoded, err := json.Marshal(map[string]any{
			"kind":    "storage",
			"message": storage.GetMessage(),
			"output":  storage.GetOutput(),
		})
		if err == nil {
			return encoded
		}
	}

	// The settings that did not come into effect are the content of the result:
	// a change
	// zapisana i przeslonieta wyglada z zewnatrz tak samo jak udana.
	// An sshd plan is a result of the job rather than the state of the host: it
	// describes a change that has not happened yet, against the configuration
	// the server
	// stosuje now.
	if server := result.GetSshResult(); server != nil && len(server.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
		}
		_ = json.Unmarshal(server.GetPlan(), &plan)
		encoded, err := json.Marshal(map[string]any{
			"kind":      "ssh_plan",
			"plan":      json.RawMessage(server.GetPlan()),
			"plan_hash": plan.PlanHash,
		})
		if err == nil {
			return encoded
		}
	}

	if server := result.GetSshResult(); server != nil && len(server.GetMismatches()) > 0 {
		encoded, err := json.Marshal(map[string]any{
			"kind":       "ssh",
			"message":    server.GetMessage(),
			"mismatches": server.GetMismatches(),
		})
		if err == nil {
			return encoded
		}
	}

	// A module blacklist plan is a result of the job rather than the state of
	// the host.
	if kernel := result.GetKernelResult(); kernel != nil && len(kernel.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
		}
		_ = json.Unmarshal(kernel.GetPlan(), &plan)
		encoded, err := json.Marshal(map[string]any{
			"kind":      "kernel_module_plan",
			"plan":      json.RawMessage(kernel.GetPlan()),
			"plan_hash": plan.PlanHash,
		})
		if err == nil {
			return encoded
		}
	}

	// Ustawienia zapisane, ale nieprzyjete od reki, sa trescia wyniku:
	// zapis i skutek to dwie rozne rzeczy.
	if kernel := result.GetKernelResult(); kernel != nil &&
		(len(kernel.GetPendingReboot()) > 0 || len(kernel.GetAppliedRuntime()) > 0) {
		encoded, err := json.Marshal(map[string]any{
			"kind":            "kernel",
			"message":         kernel.GetMessage(),
			"pending_reboot":  kernel.GetPendingReboot(),
			"applied_runtime": kernel.GetAppliedRuntime(),
		})
		if err == nil {
			return encoded
		}
	}

	// Blokady wylaczenia naleza do zadania: to one mowia, dlaczego host
	// zostal na nogach albo co operator postanowil pominac.
	if power := result.GetPowerResult(); power != nil &&
		(len(power.GetInhibitors()) > 0 || power.GetScheduledAt() != "") {
		encoded, err := json.Marshal(map[string]any{
			"kind":         "power",
			"message":      power.GetMessage(),
			"inhibitors":   rawJSON(power.GetInhibitors()),
			"scheduled_at": power.GetScheduledAt(),
		})
		if err == nil {
			return encoded
		}
	}

	// The measurements of the time sources belong to the job rather than to the
	// state of the host: they are the answer to a question asked at one moment,
	// against servers the host may not be using yet.
	// A plan of the time sources is a result of the job rather than the state
	// of the host.
	if clock := result.GetTimeResult(); clock != nil && len(clock.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
		}
		_ = json.Unmarshal(clock.GetPlan(), &plan)
		encoded, err := json.Marshal(map[string]any{
			"kind":      "time_plan",
			"plan":      json.RawMessage(clock.GetPlan()),
			"plan_hash": plan.PlanHash,
		})
		if err == nil {
			return encoded
		}
	}

	if clock := result.GetTimeResult(); clock != nil && len(clock.GetProbes()) > 0 {
		encoded, err := json.Marshal(map[string]any{
			"kind":    "time",
			"message": clock.GetMessage(),
			"probes":  rawJSON(clock.GetProbes()),
		})
		if err == nil {
			return encoded
		}
	}

	// Wynik sondy nalezy do zadania: to odpowiedz uslugi z jednej chwili,
	// widziana z tego jednego hosta.
	if sonda := result.GetMonitoringResult(); sonda != nil && len(sonda.GetProbe()) > 0 {
		encoded, err := json.Marshal(map[string]any{
			"kind":    "monitoring",
			"message": sonda.GetMessage(),
			"probe":   rawJSON(sonda.GetProbe()),
		})
		if err == nil {
			return encoded
		}
	}

	// Stan repozytorium i result kopii naleza do zadania: to odpowiedz na
	// a question asked at one moment rather than the state of the host. The
	// list of the copies is also the only place the operator can pick the one
	// to restore from.
	// A backup plan is a result of the job rather than the state of the
	// repository: it describes a copy that has not happened yet, and the scope
	// of this host.
	if backup := result.GetBackupResult(); backup != nil && len(backup.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
		}
		_ = json.Unmarshal(backup.GetPlan(), &plan)
		encoded, err := json.Marshal(map[string]any{
			"kind":      "backup_plan",
			"plan":      json.RawMessage(backup.GetPlan()),
			"plan_hash": plan.PlanHash,
		})
		if err == nil {
			return encoded
		}
	}

	if backup := result.GetBackupResult(); backup != nil &&
		(len(backup.GetState()) > 0 || len(backup.GetOutcome()) > 0) {
		encoded, err := json.Marshal(map[string]any{
			"kind":    "backup",
			"message": backup.GetMessage(),
			"state":   rawJSON(backup.GetState()),
			"outcome": rawJSON(backup.GetOutcome()),
		})
		if err == nil {
			return encoded
		}
	}

	// The fingerprint of the key of a source belongs to the job: it is the only
	// moment in which
	// czlowiek moze porownac go z odciskiem podanym przez dostawce.
	if sources := result.GetRepositoryResult(); sources != nil &&
		(sources.GetGpgKeyFingerprint() != "" || sources.GetRolledBack()) {
		encoded, err := json.Marshal(map[string]any{
			"kind":                "repository",
			"message":             sources.GetMessage(),
			"gpg_key_fingerprint": sources.GetGpgKeyFingerprint(),
			"rolled_back":         sources.GetRolledBack(),
		})
		if err == nil {
			return encoded
		}
	}

	// A certificate deployment plan is a result of the job rather than the
	// state of the host: it describes a change that has not happened yet. The
	// private key is not in the plan, so it is not here either.
	if certificate := result.GetCertificateResult(); certificate != nil && len(certificate.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
			// The module names the kind of the plan. Guessing it from empty
			// fields would confuse a refused plan with a plan of another
			// kind.
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(certificate.GetPlan(), &plan)
		// An anchor plan and a deployment plan are two shapes; the kind of the
		// result is to name that, because the operator looks at them in the
		// same place.
		kind := "certificate_plan"
		switch plan.Kind {
		case "trust":
			kind = "trust_plan"
		case "renewal":
			kind = "renewal_plan"
		}
		encoded, err := json.Marshal(map[string]any{
			"kind":      kind,
			"plan":      json.RawMessage(certificate.GetPlan()),
			"plan_hash": plan.PlanHash,
			"trust":     rawJSON(certificate.GetTrust()),
		})
		if err == nil {
			return encoded
		}
	}

	// The answer of a service after a deployment belongs to the job rather than
	// to the state of the host:
	// to pomiar z jednej chwili, tuz po podmianie. Razem z nim idzie digest
	// of what really landed, and the information whether the host rolled
	// back.
	if certificate := result.GetCertificateResult(); certificate != nil &&
		(len(certificate.GetProbe()) > 0 || certificate.GetFingerprintSha256() != "" ||
			certificate.GetRolledBack()) {
		encoded, err := json.Marshal(map[string]any{
			"kind":               "certificate",
			"message":            certificate.GetMessage(),
			"fingerprint_sha256": certificate.GetFingerprintSha256(),
			"not_after":          certificate.GetNotAfter(),
			"probe":              rawJSON(certificate.GetProbe()),
			"rolled_back":        certificate.GetRolledBack(),
		})
		if err == nil {
			return encoded
		}
	}

	// A file plan is a result of the job rather than the state of the host: it
	// describes a change that has not happened yet. The digest of the plan is
	// lifted to the surface, because it is what a campaign binds the approval
	// to this specific diff by.
	if file := result.GetFileResult(); file != nil && len(file.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
		}
		_ = json.Unmarshal(file.GetPlan(), &plan)
		encoded, err := json.Marshal(map[string]any{
			"kind":      "file_plan",
			"plan":      json.RawMessage(file.GetPlan()),
			"plan_hash": plan.PlanHash,
		})
		if err == nil {
			return encoded
		}
	}

	// Tresc odczytanego pliku nalezy do zadania: to odpowiedz na question
	// asked at one moment rather than the state of the host.
	if file := result.GetFileResult(); file != nil && len(file.GetContent()) > 0 {
		encoded, err := json.Marshal(map[string]any{
			"kind":      "file",
			"content":   string(file.GetContent()),
			"sha256":    file.GetSha256(),
			"truncated": file.GetTruncated(),
		})
		if err == nil {
			return encoded
		}
	}

	if sygnal := result.GetProcessSignalResult(); sygnal != nil {
		encoded, err := json.Marshal(map[string]any{
			"kind":    "process_signal",
			"pid":     sygnal.GetPid(),
			"signal":  sygnal.GetSignal(),
			"command": sygnal.GetCommand(),
		})
		if err == nil {
			return encoded
		}
	}

	if log := result.GetLogFileResult(); log != nil {
		encoded, err := json.Marshal(map[string]any{
			"kind":       "log_file",
			"path":       log.GetPath(),
			"lines":      log.GetLines(),
			"truncated":  log.GetTruncated(),
			"size_bytes": log.GetSizeBytes(),
			"allowlist":  log.GetAllowlist(),
		})
		if err == nil {
			return encoded
		}
	}

	if docker := result.GetDockerActionResult(); docker != nil {
		encoded, err := json.Marshal(map[string]any{
			"kind":            "docker_action",
			"before":          rawJSON(docker.GetBefore()),
			"after":           rawJSON(docker.GetAfter()),
			"removed":         docker.GetRemoved(),
			"reclaimed_bytes": docker.ReclaimedBytes,
			"image_digest":    docker.GetImageDigest(),
		})
		if err == nil {
			return encoded
		}
	}

	switch detail := result.GetDetail().(type) {
	case *agentv1.TaskResult_PackagePlan:
		schedule := detail.PackagePlan
		encoded, err := json.Marshal(map[string]any{
			"kind":                 "package_plan",
			"mode":                 schedule.GetMode(),
			"removals":             schedule.GetRemovals(),
			"protected":            schedule.GetProtected(),
			"manager":              schedule.GetManager(),
			"changes":              packageChangesJSON(schedule.GetChanges()),
			"download_bytes":       schedule.GetDownloadBytes(),
			"disk_available_bytes": schedule.GetDiskAvailableBytes(),
			"plan_hash":            hex.EncodeToString(schedule.GetPlanHash()),
			"reboot_predicted":     schedule.GetRebootPredicted(),
			"metadata_refreshed":   schedule.GetMetadataRefreshed(),
			"blocked":              blockedJSON(schedule.GetBlocked()),
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

// rawJSON przenosi zakodowany state bez ponownego kodowania. Pusty zostaje
// empty: a removed container has no state after the operation.
func rawJSON(data []byte) json.RawMessage {
	if len(data) == 0 {
		return nil
	}
	return json.RawMessage(data)
}

// preflightChecksJSON zachowuje trojstanowy result sprawdzenia: przeszlo,
// did not go through or could not be established.
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

// managementAddress picks the management address of a host and says where it
// comes from.
//
// With a direct connection the panel sees the address of the host at its own
// end of the connection, and that is the strongest fact it has. Behind a relay
// it sees the address of the relay - giving it as the address of the host
// would be a falsehood, so the only source left is what the host declares
// about itself. When there is neither, the address stays undetermined; a
// previously known one is not erased.
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

// openSession records the session. relayID is empty for a direct connection;
// filled in it says which relay attested the identity of the host - without it
// the audit trail does not tell two different grounds of trust apart.
func (s *AgentService) openSession(ctx context.Context, session *Session,
	fingerprint []byte, relayID string) error {
	// The epoch number and the session row come into being in one transaction.
	// Two gateways opening a session for the same host at the same moment have
	// to get different numbers, because it is the number that settles which of
	// them is the right one.
	const query = `
		insert into agent_sessions
			(id, host_id, gateway_id, cert_fingerprint, remote_addr, agent_version, boot_id, relay_id, epoch)
		values ($1, $2, $3, $4, $5, $6, $7, nullif($8, '')::uuid,
			(select coalesce(max(epoch), 0) + 1 from agent_sessions where host_id = $2))
		returning epoch`
	if err := s.pool.QueryRow(ctx, query, session.ID, session.HostID, s.gatewayID,
		fingerprint, session.RemoteAddr, session.AgentVersion, session.BootID, relayID).
		Scan(&session.Epoch); err != nil {
		return err
	}

	// The older sessions of this host are closed in the database at once: a row
	// left open on a gateway that no longer serves the host inflates every
	// measurement that counts connections and has the scheduler send jobs into
	// the void.
	if _, err := s.pool.Exec(ctx, `
		update agent_sessions set ended_at = now(), end_reason = 'superseded'
		where host_id = $1 and epoch < $2 and ended_at is null`,
		session.HostID, session.Epoch); err != nil {
		s.log.Error("the older sessions of the host were not closed",
			"host_id", session.HostID, "err", err)
	}
	// An older local session may still be in the registry of this gateway: the
	// registry keeps one session per host, so only Add replaces it, while the
	// stream would go on and keep receiving messages.
	if previous, running := s.registry.Get(session.HostID); running && previous.Epoch < session.Epoch {
		previous.End("superseded")
	}
	// The other gateways learn about it through the database - the only point
	// that sees all of them.
	if err := announceEpoch(ctx, s.pool, session.HostID, session.Epoch, s.gatewayID); err != nil {
		s.log.Error("the epoch of the session was not announced",
			"host_id", session.HostID, "epoch", session.Epoch, "err", err)
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: session.HostID,
		Action: "agent.session.open", TargetType: "host", TargetID: session.HostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"relay_id":   nullableRelay(relayID),
			"session_id": session.ID, "gateway_id": s.gatewayID,
			"epoch":         session.Epoch,
			"agent_version": session.AgentVersion, "boot_id": session.BootID,
		},
	})
	return nil
}

func (s *AgentService) closeSession(ctx context.Context, session *Session, hostID string) {
	const query = `update agent_sessions set ended_at = now(), end_reason = $2 where id = $1`
	if _, err := s.pool.Exec(ctx, query, session.ID, "stream_closed"); err != nil {
		s.log.Error("the session was not closed", "session_id", session.ID, "err", err)
	}
	// A host is offline only when it has not managed to open a newer session.
	if _, active := s.registry.Get(hostID); !active {
		if err := s.hosts.MarkDisconnected(ctx, hostID); err != nil {
			s.log.Error("the host was not marked as offline", "host_id", hostID, "err", err)
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
	s.log.Info("the session of the agent was closed",
		"host_id", hostID, "session_id", session.ID, "sessions", s.registry.Count())
}

func (s *AgentService) denied(ctx context.Context, hostID, reason string) {
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "agent.session.open", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": reason},
	})
	s.log.Warn("the session of the agent was rejected", "host_id", hostID, "reason", reason)
}

// capabilitiesFromProto reads the registry of the adapters. An agent of an
// older version does not send the registry at all, and a fleet upgrades
// gradually - the registry is then reconstructed from the boolean fields from
// before it was introduced. Treating such a host as one without any adapters
// would cut it off from management.
func capabilitiesFromProto(caps *agentv1.Capabilities) hosts.Capabilities {
	if reported := caps.GetRegistry(); len(reported) > 0 {
		registry := make(hosts.Capabilities, 0, len(reported))
		for _, capability := range reported {
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

	// The boolean fields carried neither a reason nor features, so the
	// reconstructed registry has none either. A made-up reason would be worse
	// than none.
	beforeTheRegistry := []struct {
		name      string
		available bool
	}{
		{hosts.CapSystemd, caps.GetSystemd()},
		{hosts.CapAPT, caps.GetApt()},
		{hosts.CapDNF, caps.GetDnf()},
		{hosts.CapDocker, caps.GetDocker()},
		{hosts.CapJournald, caps.GetJournald()},
	}
	registry := make(hosts.Capabilities, 0, len(beforeTheRegistry))
	for _, entry := range beforeTheRegistry {
		registry = append(registry, hosts.Capability{
			Name: entry.name, Version: 0, Available: entry.available,
		})
	}
	return registry
}

// localAccountsFromReport moves the accounts from a report into the inventory
// model.
//
// An incremental report without a section of accounts returns nil rather than
// an empty list: missing data must not erase the last known list of the
// accounts of a host.
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

// accountSourceName odwzorowuje source konta na nazwe uzywana w bazie i API.
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

// localAccountResultJSON describes the state of an account after an operation.
// A missing account gives nil, because an account that was removed or never
// created has no state to show.
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

// relayHostHeader carries the identity of a host attested by a relay.
const relayHostHeader = "Flotestro-Relay-Host"

// identifyPeer establishes whose session it is and who vouches for it.
//
// A direct connection: the identity comes from the client certificate and is
// proof of holding the private key of the host.
//
// A connection through a relay: the certificate belongs to the relay, and the
// identity of the host is an attestation of the relay. The panel cannot check
// it cryptographically, so it checks what it can: whether the relay is known,
// not revoked, and whether the host belongs to its site. That is exactly the
// trust boundary the document speaks about - and that is why it is recorded in
// the session.
func (s *AgentService) identifyPeer(ctx context.Context, cert *x509.Certificate,
	asserted string) (hostID string, relayID string, err error) {
	if hostID, hostErr := pki.HostIDFromCert(cert); hostErr == nil {
		if asserted != "" {
			// An agent must not impersonate a relay: attesting somebody
			// else's identity is a permission of a relay rather than a header
			// to be added.
			return "", "", connect.NewError(connect.CodePermissionDenied,
				errors.New("the certificate of a host does not allow attesting other hosts"))
		}
		return hostID, "", nil
	}

	relayIdentity, relayErr := pki.RelayIDFromCert(cert)
	if relayErr != nil {
		return "", "", connect.NewError(connect.CodeUnauthenticated, relayErr)
	}
	if s.relays == nil {
		return "", "", connect.NewError(connect.CodePermissionDenied,
			errors.New("the mediation through a relay is not enabled"))
	}
	if asserted == "" {
		return "", "", connect.NewError(connect.CodeInvalidArgument,
			errors.New("a relay has to name the host in the header "+relayHostHeader))
	}

	status, err := s.relays.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return "", "", connect.NewError(connect.CodeInternal, err)
	}
	switch {
	case !status.Known:
		s.denied(ctx, relayIdentity, "unknown_relay_certificate")
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate of the relay is unknown"))
	case status.Revoked:
		s.denied(ctx, relayIdentity, "revoked_relay")
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("the relay was revoked"))
	case status.ID != relayIdentity:
		s.denied(ctx, relayIdentity, "relay_identity_mismatch")
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("the identity of the relay does not match the certificate"))
	}

	host, err := s.hosts.Get(ctx, asserted)
	if err != nil {
		s.denied(ctx, asserted, "relay_unknown_host")
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("the host is unknown"))
	}
	// A relay mediates for its own site alone. Without that one compromised
	// relay would serve the whole fleet.
	if host.Site != status.Site {
		s.denied(ctx, asserted, "relay_scope_mismatch")
		return "", "", connect.NewError(connect.CodePermissionDenied,
			errors.New("the host does not belong to the site of the relay"))
	}
	if !hosts.Active(host.LifecycleState) {
		s.denied(ctx, asserted, "lifecycle_"+host.LifecycleState)
		return "", "", connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("the host is in the state %s", host.LifecycleState))
	}
	return asserted, status.ID, nil
}

// rejectCertificate checks the state of the certificate of a host for a
// direct connection.
func (s *AgentService) rejectCertificate(ctx context.Context,
	status hosts.CertificateStatus, hostID string) error {
	switch {
	case !status.Known:
		s.denied(ctx, hostID, "unknown_certificate")
		return connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate is unknown"))
	case status.Revoked:
		s.denied(ctx, hostID, "revoked_certificate")
		return connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate was revoked"))
	case status.HostID != hostID:
		s.denied(ctx, hostID, "identity_mismatch")
		return connect.NewError(connect.CodeUnauthenticated, errors.New("the identity does not match the certificate"))
	case !hosts.Active(status.LifecycleState):
		// A quarantine, a withdrawal in progress and a withdrawal differ for
		// the operator, but for a connection they mean the same: this host has
		// no right to work.
		s.denied(ctx, hostID, "lifecycle_"+status.LifecycleState)
		return connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("the host is in the state %s", status.LifecycleState))
	}
	return nil
}

// nullableRelay returns nil for a direct connection. An empty string in the
// audit trail would look like a relay without a name rather than like its
// absence.
func nullableRelay(relayID string) any {
	if relayID == "" {
		return nil
	}
	return relayID
}

// CloseOrphanSessions closes the session rows this instance no longer keeps.
//
// A session ends with a write at the disconnect, but when the process crashes
// that write has no way of happening and the row stays open for good. Every
// measurement counting the active sessions from the database would then see a
// fictional fleet, and the audit trail - connections that do not exist.
//
// Only the sessions of one's own gateway may be closed: the sessions of
// another instance are alive, and only it knows their state.
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

// ReapOrphanSessions closes the orphaned rows at the start and periodically
// while working. A single stream can die without a write of its end also when
// the process lives on.
func (s *AgentService) ReapOrphanSessions(ctx context.Context, interval time.Duration) {
	if closed, err := s.CloseOrphanSessions(ctx); err != nil {
		s.log.Error("the orphaned sessions were not closed", "err", err)
	} else if closed > 0 {
		s.log.Info("the orphaned sessions were closed after the start", "rows", closed)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if closed, err := s.CloseOrphanSessions(ctx); err != nil {
				s.log.Error("the orphaned sessions were not closed", "err", err)
			} else if closed > 0 {
				s.log.Warn("the orphaned sessions were closed", "rows", closed)
			}
		}
	}
}

// blockedJSON describes the packages that block the package operations
// together with their configuration questions. The panel shows them to the
// operator, because it is the operator who makes the decision.
func blockedJSON(blocked []*agentv1.BlockedPackage) []map[string]any {
	result := make([]map[string]any, 0, len(blocked))
	for _, pkg := range blocked {
		questions := make([]map[string]any, 0, len(pkg.GetQuestions()))
		for _, question := range pkg.GetQuestions() {
			questions = append(questions, map[string]any{
				"name": question.GetName(), "value": question.GetValue(),
				"answered": question.Answered,
			})
		}
		result = append(result, map[string]any{
			"name": pkg.GetName(), "status": pkg.GetStatus(), "questions": questions,
		})
	}
	return result
}

// packageDatabaseState reads the state of the package database out of the
// result of a job.
//
// The second returned value says whether the result knows anything about that
// state at all. A non-package job must not lift or place this flag: missing
// knowledge is not the same as stating that the database is sound.
func packageDatabaseState(result *agentv1.TaskResult) (broken bool, known bool) {
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

// fragmentsFromReport reads the modules of a report. An agent from before the
// split does not send them; an empty list does not erase what is already known
// about the modules of a host.
func fragmentsFromReport(report *agentv1.InventoryReport) []inventory.Fragment {
	reported := report.GetFragments()
	if len(reported) == 0 {
		return nil
	}
	result := make([]inventory.Fragment, 0, len(reported))
	for _, fragment := range reported {
		result = append(result, inventory.Fragment{
			Module:            fragment.GetModule(),
			Revision:          fragment.GetRevision(),
			Source:            fragment.GetSource(),
			Payload:           fragment.GetPayload(),
			UnavailableReason: fragment.GetUnavailableReason(),
			ObservedAt:        fragment.GetObservedAt().AsTime(),
		})
	}
	return result
}

// unitStatesJSON zamienia stany jednostek na postac czytana przez interfejs.
func unitStatesJSON(stany []*agentv1.UnitState) []map[string]any {
	result := make([]map[string]any, 0, len(stany))
	for _, state := range stany {
		result = append(result, map[string]any{
			"name":            state.GetName(),
			"load_state":      state.GetLoadState(),
			"active_state":    state.GetActiveState(),
			"sub_state":       state.GetSubState(),
			"unit_file_state": state.GetUnitFileState(),
			"result":          state.GetResult(),
			"main_pid":        state.GetMainPid(),
			"n_restarts":      state.GetNRestarts(),
		})
	}
	return result
}

// versionFromLease reads the version of a secret the panel really released.
//
// An order may name "the current version"; that one is settled only when the
// job is delivered, so the desired state is recorded from the lease rather
// than from the payload.
func versionFromLease(ctx context.Context, s *AgentService, jobID, name string) int {
	if s.leases == nil {
		return 0
	}
	leases, err := s.leases.Leases(ctx, jobID)
	if err != nil {
		return 0
	}
	for _, lease := range leases {
		if lease.SecretName == name {
			return lease.Version
		}
	}
	return 0
}

// saveFileState writes the desired state of a file after a successful
// operation.
func (s *AgentService) saveFileState(ctx context.Context, hostID, jobID string) {
	job, err := s.jobs.Get(ctx, jobID)
	if err != nil {
		return
	}
	switch opspec.ActionType(job.ActionType) {
	case opspec.ActionFileEnsure, opspec.ActionFileRollback, opspec.ActionFileRemove:
	default:
		return
	}

	var payload opspec.Payload
	if err := json.Unmarshal(job.Payload, &payload); err != nil || payload.File == nil {
		return
	}
	if opspec.ActionType(job.ActionType) == opspec.ActionFileRemove {
		if err := s.files.Delete(ctx, s.pool, hostID, payload.File.Path); err != nil {
			s.log.Error("the state of the file was not removed", "host_id", hostID, "err", err)
		}
		return
	}
	state := managedfiles.DesiredState{
		HostID: hostID, Path: payload.File.Path,
		Mode: payload.File.Mode, Owner: payload.File.Owner, Group: payload.File.Group,
		Validator: payload.File.Validator, UpdatedBy: job.CreatedBy,
	}
	// A file from a secret leaves neither the content nor its digest in the
	// panel: the desired state is the name of the secret and its version. The
	// cost is that the panel will not detect a replacement of the content on
	// the host - and that is to be said outright.
	if !payload.File.ContentSecret.Empty() {
		state.SecretName = payload.File.ContentSecret.Name
		state.SecretVersion = payload.File.ContentSecret.Version
		if state.SecretVersion == 0 {
			state.SecretVersion = versionFromLease(ctx, s, jobID, state.SecretName)
		}
	} else {
		digest, err := s.files.SaveVersion(ctx, s.pool, []byte(payload.File.Content))
		if err != nil {
			s.log.Error("the version of the file was not written", "host_id", hostID, "err", err)
			return
		}
		state.SHA256 = digest
	}
	if err := s.files.Set(ctx, s.pool, state, jobID); err != nil {
		s.log.Error("the state of the file was not written", "host_id", hostID, "err", err)
	}
}

// saveCertificateDeployment adds a deployment to the history after a
// successful operation.
//
// The fingerprint is taken from the result of the host rather than from the
// payload: the panel is to record what really landed on the disk. The key is
// in the history as the name of the secret and its version alone - the value
// is neither here nor anywhere else outside the store.
func (s *AgentService) saveCertificateDeployment(ctx context.Context, hostID, jobID string,
	result *agentv1.CertificateResult) {
	if result == nil || result.GetFingerprintSha256() == "" {
		return
	}
	job, err := s.jobs.Get(ctx, jobID)
	if err != nil {
		return
	}
	switch opspec.ActionType(job.ActionType) {
	case opspec.ActionCertificateDeploy, opspec.ActionCertificateRenew:
	default:
		return
	}

	var payload opspec.Payload
	if err := json.Unmarshal(job.Payload, &payload); err != nil || payload.Certificate == nil {
		return
	}
	deployment := certyfikaty.Deployment{
		HostID:            hostID,
		Path:              payload.Certificate.Path,
		FingerprintSHA256: result.GetFingerprintSha256(),
		JobID:             jobID,
		DeployedBy:        job.CreatedBy,
	}
	if notAfter, err := time.Parse(time.RFC3339, result.GetNotAfter()); err == nil {
		deployment.NotAfter = &notAfter
	}
	// The content is recorded only for a deployment from the panel: a renewal
	// is done by a daemon of the host and the panel does not know the
	// certificate that came out of it. What is left is the digest and the date
	// alone - that is, what the host sent back.
	if payload.Certificate.Certificate != "" {
		deployment.Certificate = payload.Certificate.Certificate
		if certs, err := certmodule.ParsePEM([]byte(payload.Certificate.Certificate)); err == nil {
			deployment.Subject = certs[0].Subject.String()
			deployment.Issuer = certs[0].Issuer.String()
		}
	}
	if !payload.Certificate.KeySecret.Empty() {
		deployment.KeySecret = payload.Certificate.KeySecret.Name
		deployment.KeyVersion = payload.Certificate.KeySecret.Version
		if deployment.KeyVersion == 0 {
			deployment.KeyVersion = versionFromLease(ctx, s, jobID, deployment.KeySecret)
		}
	}
	if err := s.certificates.SaveDeployment(ctx, s.pool, deployment); err != nil {
		s.log.Error("the deployment of the certificate was not written", "host_id", hostID, "err", err)
	}
}

// mergeRepositories puts a new list of sources into the package fragment.
//
// The fragment also carries the package counters this operation did not
// concern: overwriting it as a whole would turn a change of the sources into a
// loss of the knowledge of how many packages wait for an upgrade.
func (s *AgentService) mergeRepositories(ctx context.Context, hostID string, sources []byte) error {
	fragment, err := s.inventory.Fragment(ctx, hostID, "packages")
	if err != nil {
		return err
	}
	content := map[string]json.RawMessage{}
	source := "agent/packages"
	reason := ""
	if fragment != nil {
		if len(fragment.Payload) > 0 {
			if err := json.Unmarshal(fragment.Payload, &content); err != nil {
				return err
			}
		}
		source, reason = fragment.Source, fragment.UnavailableReason
	}
	content["repositories"] = sources

	payload, err := json.Marshal(content)
	if err != nil {
		return err
	}
	return s.inventory.SaveFragment(ctx, hostID, inventory.Fragment{
		Module:            "packages",
		Revision:          fmt.Sprintf("%x", sha256.Sum256(payload)),
		Source:            source,
		Payload:           payload,
		UnavailableReason: reason,
		ObservedAt:        time.Now().UTC(),
	})
}

// backupKinds translate the type of an operation into the kind of an entry in
// the history.
var backupKinds = map[opspec.ActionType]string{
	opspec.ActionBackupPlan:    backupmodule.OperationPlan,
	opspec.ActionBackupRun:     backupmodule.OperationBackup,
	opspec.ActionBackupVerify:  backupmodule.OperationVerify,
	opspec.ActionBackupRestore: backupmodule.OperationRestore,
}

// saveBackupRun adds the result of a backup operation to the history.
//
// We record metadata rather than data: the identifier of the copy, the
// counters and when the last copy in the repository was made. The panel
// neither sees the data themselves nor is it to see them.
func (s *AgentService) saveBackupRun(ctx context.Context, hostID, jobID string,
	result *agentv1.BackupResult, succeeded bool) {
	job, err := s.jobs.Get(ctx, jobID)
	if err != nil {
		return
	}
	kind, known := backupKinds[opspec.ActionType(job.ActionType)]
	if !known {
		return
	}
	var payload opspec.Payload
	if err := json.Unmarshal(job.Payload, &payload); err != nil || payload.Backup == nil {
		return
	}

	run := backupstore.Run{
		HostID: hostID, Definition: payload.Backup.ID, Kind: kind,
		JobID: jobID, Outcome: "failed", Message: result.GetMessage(),
		StartedBy: job.CreatedBy,
	}
	if succeeded {
		run.Outcome = "succeeded"
	}

	if state, ok := backupState(result.GetState()); ok {
		count := len(state.Snapshots)
		run.Snapshots = &count
		run.LastSuccessAt = state.LastSuccessAt
		if state.TotalSizeBytes != nil {
			size := int64(*state.TotalSizeBytes)
			run.RepositorySize = &size
		}
	}
	if outcome, ok := backupOutcome(result.GetOutcome()); ok {
		run.SnapshotID = outcome.SnapshotID
		run.BytesAdded = countFromBytes(outcome.BytesAdded)
		run.TotalBytes = countFromBytes(outcome.TotalBytesProcessed)
		run.FilesNew = countFromBytes(outcome.FilesNew)
		run.DurationSeconds = outcome.DurationSeconds
		if run.Message == "" {
			run.Message = outcome.Message
		}
	}
	if err := s.backups.RecordRun(ctx, s.pool, run); err != nil {
		s.log.Error("the backup run was not written", "host_id", hostID, "err", err)
	}
}

func backupState(data []byte) (backupmodule.State, bool) {
	var state backupmodule.State
	if len(data) == 0 {
		return state, false
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, false
	}
	return state, true
}

func backupOutcome(data []byte) (backupmodule.Result, bool) {
	var result backupmodule.Result
	if len(data) == 0 {
		return result, false
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return result, false
	}
	return result, true
}

// countFromBytes turns a counter of a tool into a value writable in the
// database. A missing value stays missing rather than becoming zero.
func countFromBytes(value *uint64) *int64 {
	if value == nil {
		return nil
	}
	count := int64(*value)
	return &count
}

// savePackageList writes the full package list of a host.
//
// A partial list is worse than a missing one, because it looks like the whole
// thing, so it is written in one transaction together with its digest. A list
// that was not read leaves the reason alone - and it is the reason that later
// reaches the vulnerability assessment as an undetermined state rather than as
// a host without findings.
func (s *AgentService) savePackageList(ctx context.Context, hostID, jobID string,
	result *agentv1.InstalledPackagesResult) {
	state := vuln.PackageListState{
		HostID: hostID, Digest: result.GetDigest(),
		PackageCount: int(result.GetCount()), JobID: jobID,
		UnavailableReason: result.GetUnavailableReason(),
	}
	now := time.Now().UTC()
	state.CollectedAt = &now

	var pkgs []modulpakiety.InstalledPackage
	if len(result.GetPackages()) > 0 {
		if err := json.Unmarshal(result.GetPackages(), &pkgs); err != nil {
			s.log.Error("the package list was not recognised", "host_id", hostID, "err", err)
			return
		}
	}
	if state.UnavailableReason != "" {
		// A host whose list could not be read is not left with an old list
		// pretending to be current: we delete the rows and record the
		// reason.
		pkgs = nil
		state.PackageCount = 0
	}

	// The vendor findings known to the host are written together with the
	// list: they come from the same read and describe the same moment. An
	// error of reading them must not look like a host without findings - which
	// is why it carries a reason of its own.
	advisories, reason := advisoriesFromResult(result, now)
	advisoryState := vuln.AdvisoryState{
		HostID: hostID, JobID: jobID, CollectedAt: &now,
		AdvisoryCount: len(advisories), UnavailableReason: reason,
	}
	if reason == "" {
		advisoryState.Digest = vuln.AdvisoriesDigest(advisories)
	} else {
		advisories = nil
		advisoryState.AdvisoryCount = 0
	}

	if err := s.pkgs.ReplaceImage(ctx, hostID, pkgs, state, advisories, advisoryState); err != nil {
		s.log.Error("the image of the packages was not written", "host_id", hostID, "err", err)
		return
	}
	s.log.Info("the package list was written", "host_id", hostID,
		"packages", len(pkgs), "findings", len(advisories), "digest", state.Digest)

	// The assessment is to keep up with what settles it. A host that has just
	// answered a request for a read must not show up until the next cycle as a
	// host without a list or with findings from half a day ago.
	if s.refreshAssessment != nil {
		s.refreshAssessment(hostID)
	}
}

// advisoriesFromResult unpacks the vendor findings out of the result of a
// read.
//
// One finding usually concerns several packages; the panel keeps them per
// package, because that is how the correlation runs.
func advisoriesFromResult(result *agentv1.InstalledPackagesResult,
	now time.Time) ([]vuln.HostAdvisory, string) {
	if reason := result.GetAdvisoriesUnavailableReason(); reason != "" {
		return nil, reason
	}
	if len(result.GetAdvisories()) == 0 {
		return nil, ""
	}
	var gathered []modulpakiety.Advisory
	if err := json.Unmarshal(result.GetAdvisories(), &gathered); err != nil {
		// The metadata could not be recognised. An empty list would mean here
		// "the host has no vendor findings at all" - that is, something nobody
		// checked.
		return nil, vuln.ReasonHostAdvisoriesUnreadable
	}
	var advisories []vuln.HostAdvisory
	for _, advisory := range gathered {
		// A finding without a CVE is normal: the vendor does not always assign
		// one. The column does not take a null, though, and a missing list and
		// an empty list mean the same thing here.
		cve := advisory.CVEIDs
		if cve == nil {
			cve = []string{}
		}
		for _, pkg := range advisory.Packages {
			advisories = append(advisories, vuln.HostAdvisory{
				AdvisoryID: advisory.ID, PackageName: pkg.Name,
				Architecture: pkg.Architecture, FixedEVR: pkg.EVR,
				CVEIDs: cve, Severity: advisory.Severity,
				Title: advisory.Title, IssuedAt: advisory.IssuedAt, CollectedAt: now,
			})
		}
	}
	return advisories, ""
}

// checkRefresh confirms that the revision reported by the agent is the one
// the panel really has. Called only for the operation of refreshing the
// inventory.
//
// It returns an empty code when everything matches. A divergence is a failure
// of the job rather than of the host: the host collected the image, only the
// panel did not get it.
func (s *AgentService) checkRefresh(ctx context.Context, hostID string,
	result *agentv1.TaskResult) (code, message string) {
	refresh := result.GetInventoryRefreshResult()
	if refresh.GetRevision() == "" {
		// A success without a revision is silence: there is no telling whether
		// the image came into being.
		return "inventory_revision_missing", "the agent did not give the revision of the refreshed inventory"
	}
	revision, err := s.inventory.Latest(ctx, hostID)
	if err != nil {
		s.log.Error("the revision of the inventory was not read", "host_id", hostID, "err", err)
		return "", ""
	}
	if revision == nil || revision.Revision != refresh.GetRevision() {
		recorded := "none"
		if revision != nil {
			recorded = revision.Revision
		}
		return "inventory_revision_missing",
			fmt.Sprintf("the agent reported the revision %s, the panel has %s",
				refresh.GetRevision(), recorded)
	}
	return "", ""
}
