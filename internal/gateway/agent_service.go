package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/audit"
	backupstore "github.com/ultherego/flotestro/internal/backup"
	"github.com/ultherego/flotestro/internal/buildinfo"
	certstore "github.com/ultherego/flotestro/internal/certificates"
	"github.com/ultherego/flotestro/internal/events"
	managedfiles "github.com/ultherego/flotestro/internal/files"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/issuer"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/metrics"
	backupmodule "github.com/ultherego/flotestro/internal/modules/backup"
	certmodule "github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/monitoring"
	"github.com/ultherego/flotestro/internal/opspec"
	packagestore "github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relayproof"
	"github.com/ultherego/flotestro/internal/relays"
	"github.com/ultherego/flotestro/internal/vuln"
)

type contextKey string

const (
	clientCertKey contextKey = "flotestro.client-cert"
	remoteAddrKey contextKey = "flotestro.remote-addr"
)

// WithClientCertificate carries the client certificate from the TLS layer into
// the context, so that the handler does not have to know the details of the
// HTTP server.
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

// inventoryNormalEvery says every which periodic cycle the agent reads the
// normal modules - packages, network, storage, security.
const inventoryNormalEvery = 4

// AgentService serves the long-lived stream of an agent. The stream is the
// only channel of commands; the root helper never speaks to the centre.
type AgentService struct {
	pool      *pgxpool.Pool
	hosts     *hosts.Store
	inventory *inventory.Store
	jobs      *jobs.Store
	audit     *audit.Recorder
	registry  *Registry
	// certIssuer signs the renewals and describes whom the panel trusts.
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
	// files keeps the desired state of the configuration files.
	files *managedfiles.Store
	// certificates keeps the history of the deployed certificates.
	certificates *certstore.Store
	// backups keeps the history of the backup runs.
	backups *backupstore.Store
	// packages keep the full package lists of the hosts.
	pkgs *vuln.PackageStore
	// secrets releases the values of the secrets against a lease.
	secrets SecretIssuing
	// leases makes it possible to check which version of a secret the panel
	// really released.
	leases SecretLeases
	// samples keeps the resource samples of the hosts. Empty means a panel
	// without the built-in monitoring: the samples are then dropped.
	samples *monitoring.Store
	// attempts translates the identifier of an attempt into the identifier of an
	// operation.
	attemptsMu sync.RWMutex
	attempts   map[string]attemptContextEntry
	log        *slog.Logger
	gatewayID  string
	// clonePolicy says what the gateway does with a copied identity: the
	// empty value is the packaged default, quarantine.
	clonePolicy ClonePolicy
	// relayIdentity says what the gateway does with a session through a relay
	// that names the host without the certificate it presented: the empty value
	// is the packaged default, prefer.
	relayIdentity RelayIdentityMode
	// helperSigner signs the capabilities the root helper verifies and the trust
	// bundle every session and renewal carries down to it.
	helperSigner *helpercap.Signer
	// envelopes verifies the host's own signature on a relayed message, and
	// challenges keeps the one-time challenges of a renewal through a relay.
	envelopes  *RelayVerifier
	challenges identityChallenges

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
		certificates: certstore.NewStore(pool),
		backups:      backupstore.NewStore(pool),
		pkgs:         vuln.NewPackageStore(pool),
		audit:        recorder, registry: registry, certIssuer: certIssuer, relays: relayStore,
		log: log, gatewayID: gatewayID,
		heartbeatSeconds: heartbeatSeconds, heartbeatJitter: heartbeatJitter,
		attempts:   map[string]attemptContextEntry{},
		envelopes:  NewRelayVerifier(hostStore, hostStore, relaySequences{pool: pool}),
		challenges: identityChallenges{pool: pool},
	}
}

// SetHelperSigner connects the capability key. The session configuration
// then carries the panel's trust bundle to every host that connects.
func (s *AgentService) SetHelperSigner(signer *helpercap.Signer) { s.helperSigner = signer }

// helperTrustFor is the signed keyring for one host, or nil on a panel
// without a signing key.
func (s *AgentService) helperTrustFor(hostID string) *helperv1.HelperTrustBundle {
	if s.helperSigner == nil {
		return nil
	}
	return s.helperSigner.TrustBundle(hostID, time.Now())
}

// SetAssessmentRefresh connects the request to recompute the vulnerability
// assessment.
func (s *AgentService) SetAssessmentRefresh(refresh func(hostID string)) {
	s.refreshAssessment = refresh
}

// SetEvents connects the event bus. Without it the agent works the same, only
// the progress of a long operation does not reach the screen of the operator.
func (s *AgentService) SetEvents(bus *events.Bus) { s.events = bus }

// SetMetrics connects the store the resource samples of the hosts go to.
func (s *AgentService) SetMetrics(store *monitoring.Store) { s.samples = store }

// SetClonePolicy sets what the gateway does with a copied identity.
func (s *AgentService) SetClonePolicy(policy ClonePolicy) { s.clonePolicy = policy }

// sampleFromProto translates a sample of the agent into the stored shape. It
// returns what the panel made of the host's clock as well: the moment alone
// no longer says whether the panel supplied it.
func sampleFromProto(sample *agentv1.MetricsSample, now time.Time,
	skewLimit, maxLateness time.Duration) (monitoring.Sample, monitoring.Observation) {
	observed := monitoring.ClampObservation(
		time.Unix(sample.GetSampledAtUnix(), 0).UTC(), now, skewLimit, maxLateness)
	stored := monitoring.Sample{
		// The identity of the reading, which its clock is not.
		BootID:          sample.GetBootId(),
		Sequence:        sample.GetSequence(),
		At:              observed.At,
		ReceivedAt:      now,
		CPUPercent:      sample.GetCpuPercent(),
		Load1:           sample.GetLoad1(),
		Load5:           sample.GetLoad5(),
		Load15:          sample.GetLoad15(),
		MemoryTotal:     sample.GetMemoryTotal(),
		MemoryUsed:      sample.GetMemoryUsed(),
		MemoryAvailable: sample.GetMemoryAvailable(),
		SwapTotal:       sample.GetSwapTotal(),
		SwapUsed:        sample.GetSwapUsed(),
		UptimeSeconds:   sample.GetUptimeSeconds(),
		Filesystems:     make([]monitoring.Filesystem, 0, len(sample.GetFilesystems())),
		Interfaces:      make([]monitoring.Interface, 0, len(sample.GetInterfaces())),
		// The agent's own footprint: optional on the wire, absent when the
		// agent could not read it - an absent number is not a zero.
		AgentRSSBytes:   sample.AgentRssBytes,
		AgentCPUPercent: sample.AgentCpuPercent,
		AgentGoroutines: sample.AgentGoroutines,
		AgentOpenFDs:    sample.AgentOpenFds,
		HelperRSSBytes:  sample.HelperRssBytes,
	}
	for _, fs := range sample.GetFilesystems() {
		stored.Filesystems = append(stored.Filesystems, monitoring.Filesystem{
			Mount: fs.GetMount(), Device: fs.GetDevice(), Fstype: fs.GetFstype(),
			TotalBytes: fs.GetTotalBytes(), UsedBytes: fs.GetUsedBytes(),
			InodesTotal: fs.GetInodesTotal(), InodesUsed: fs.GetInodesUsed(),
		})
	}
	for _, iface := range sample.GetInterfaces() {
		stored.Interfaces = append(stored.Interfaces, monitoring.Interface{
			Name: iface.GetName(), RxBytes: iface.GetRxBytes(), TxBytes: iface.GetTxBytes(),
		})
	}
	return stored, observed
}

// Connect serves the session of an agent.
func (s *AgentService) Connect(ctx context.Context,
	stream *connect.BidiStream[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("missing client certificate"))
	}
	// The handshake refuses a certificate outside its validity before the request
	// exists; this is the second lock on the same door.
	if problem := s.rejectStaleCertificate(ctx, cert); problem != nil {
		return problem
	}

	// A session can come straight from an agent or through the relay of a site.
	who, err := s.identifyPeer(ctx, cert, stream.RequestHeader())
	if err != nil {
		return err
	}
	hostID, relayID := who.HostID, who.RelayID
	if relayID != "" {
		s.relays.MarkSeen(ctx, relayID)
	}

	// The certificate of a relay does not describe a host, so the state of the
	// certificate of a host is checked here only for a direct connection.
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

	// The host's own proof on a relayed session: the envelope on Hello, signed
	// with the host key, settles whether the session is end_to_end or rests on
	// the relay alone - and whether it opens at all under the mode of the.
	var relayed *relayedSession
	if relayID != "" {
		strength, err := s.admitRelayedHello(ctx, who, first)
		if err != nil {
			return err
		}
		who.Identity = strength
		metrics.RelaySessionIdentity.Inc(strength)
		relayed = &relayedSession{peer: who.Relay, endToEnd: strength == hosts.RelayIdentityEndToEnd}
	}

	// The protocol is judged by what the agent says it speaks, and by the table
	// of releases for an agent that says nothing.
	if err := buildinfo.CheckProtocolRange(hello.GetAgentVersion(),
		int(hello.GetProtocolMin()), int(hello.GetProtocolMax())); errors.Is(err, buildinfo.ErrProtocolIncompatible) {
		s.refused(ctx, hostID, opspec.RefusalProtocolIncompatible, err.Error())
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}

	caps := capabilitiesFromProto(hello.GetCapabilities())
	if err := s.hosts.ApplyHello(ctx, hostID, hello.GetAgentVersion(), hello.GetBootId(), caps); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	// What the agent says about its build and its configuration.
	var report *hosts.AgentReport
	if hello.GetProtocolMax() > 0 {
		report = &hosts.AgentReport{
			BuildCommit:         hello.GetBuildCommit(),
			ProtocolMin:         int(hello.GetProtocolMin()),
			ProtocolMax:         int(hello.GetProtocolMax()),
			ConfigFingerprint:   hello.GetConfigFingerprint(),
			ConfigSchemaVersion: int(hello.GetConfigSchemaVersion()),
		}
	}
	if err := s.hosts.RecordAgentReport(ctx, hostID, report); err != nil {
		// The session is worth more than the record: a host whose build
		// was not written down is still a host to manage.
		s.log.Error("the agent's report of its build was not recorded", "host_id", hostID, "err", err)
	}
	session := NewSession(uuid.NewString(), hostID, hello.GetAgentVersion(),
		hello.GetBootId(), remoteAddr(ctx), 32)
	session.RelayID = relayID
	session.RelayIdentity = who.Identity
	// What the host does with a signed capability decides whether the scheduler
	// mints one for it.
	session.HelperCapabilitySupported = hello.GetHelperCapabilitySupported()
	session.HelperCapabilityMode = hello.GetHelperCapabilityMode()
	if err := s.openSession(ctx, session, pki.Fingerprint(cert), relayID); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	// The return of the agent settles its replacement rather than the exit code
	// of the package manager: the process that carried the job out was replaced
	// halfway.
	s.settleAgentUpgrade(ctx, hostID, hello.GetAgentVersion(), session.Fence())
	// A restart is settled the same way and for the same reason: the host carries
	// out its own verification by coming back on another boot, and no process on
	// it survives to report that.
	s.settleReboot(ctx, hostID, hello.GetBootId(), session.Fence())
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
		session.Finish()
		// The context of the request is already cancelled, so the cleanup has
		// one of its own.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		s.closeSession(cleanupCtx, session, hostID)
	}()

	// One goroutine writes to the stream, because Send is not safe concurrently.
	sendCtx, stopSender := context.WithCancel(ctx)
	defer stopSender()
	// The claim on the host is renewed while the stream lives; a session
	// the row no longer names closes itself as superseded.
	go s.keepOwnership(sendCtx, session)
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

	// The server sends the parameters of the session back at once.
	if err := stream.Send(&agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_SessionConfig{
			SessionConfig: &agentv1.SessionConfig{
				HeartbeatSeconds:       int32(s.heartbeatSeconds),
				HeartbeatJitterSeconds: int32(s.heartbeatJitter),
				FullInventoryRequested: true,
				// The cycle itself stays the agent's: the interval comes from its
				// configuration and the hour of the full report from its identifier.
				InventoryCadence: &agentv1.InventoryCadence{
					NormalEvery: inventoryNormalEvery,
				},
				// The panel's capability keys, signed, for the helper's keyring: every
				// session refreshes them, so a rotated key reaches the host at its next
				// connection at the latest.
				HelperTrust: s.helperTrustFor(hostID),
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
			// The panel ended the session: a quarantine or a withdrawal of the host.
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
			if relayed != nil {
				switch problem := s.checkRelayedMessage(ctx, hostID, session, relayed, msg); {
				case errors.Is(problem, errMessageDropped):
					continue
				case problem != nil:
					return problem
				}
			}
			if err := s.handle(ctx, hostID, session, msg); err != nil {
				s.log.Error("an error while handling a message of the agent", "host_id", hostID, "err", err)
			}
		}
	}
}

// relayedSession is what the stream keeps of a relayed session for the
// messages after Hello: the relay and the host as identified, and whether the
// host signed its Hello - a session that did signs everything.
type relayedSession struct {
	peer     RelayPeer
	endToEnd bool
}

// errMessageDropped says a relayed message was put aside on its own without
// ending the session: a message the panel consumed already and the relay
// carried again, a sequence the session never spent, or a message without an.
var errMessageDropped = errors.New("the message was dropped")

// admitRelayedHello settles the strength of a relayed session from its Hello.
func (s *AgentService) admitRelayedHello(ctx context.Context, who peer, first *agentv1.AgentMessage) (string, error) {
	if first.GetEnvelope() == nil {
		if s.relayIdentity == RelayIdentityEnforce {
			s.refused(ctx, who.HostID, hosts.RefusalBlockedUpgradeRequired,
				"the agent does not sign the relay envelope ("+relayproof.Capability+" "+relayproof.Feature+
					"), which this installation requires; upgrade the agent")
			return "", connect.NewError(connect.CodeFailedPrecondition,
				errors.New("the agent does not sign the relay envelope; upgrade the agent"))
		}
		s.log.Info("the relayed session rests on the relay's attestation; the agent did not sign the envelope",
			"host_id", who.HostID, "relay_id", who.RelayID, "identity", who.Identity,
			"mode", string(s.relayIdentity))
		return who.Identity, nil
	}
	verified, err := s.envelopes.VerifyMessage(ctx, who.Relay, first)
	if err != nil {
		return "", s.refuseEnvelope(ctx, who.HostID, err)
	}
	s.learnPublicKey(ctx, who.HostID, verified)
	return hosts.RelayIdentityEndToEnd, nil
}

// checkRelayedMessage verifies a message after Hello on a relayed session.
func (s *AgentService) checkRelayedMessage(ctx context.Context, hostID string, session *Session,
	relayed *relayedSession, msg *agentv1.AgentMessage) error {
	if msg.GetEnvelope() == nil {
		if !relayed.endToEnd {
			return nil
		}
		s.refused(ctx, hostID, hosts.RefusalRelayEnvelopeInvalid,
			"a message without the identity envelope on a session that signed its Hello was dropped")
		metrics.RelayEnvelopeRefusal.Inc(hosts.RefusalRelayEnvelopeInvalid)
		s.log.Warn("an unsigned message on a signed relayed session was dropped",
			"host_id", hostID, "relay_id", relayed.peer.RelayID)
		// The panel will never take it, so the relay's record is freed here.
		s.acknowledge(hostID, session, nil, msg.GetRelayMessageId())
		return errMessageDropped
	}
	verified, err := s.envelopes.VerifyMessage(ctx, relayed.peer, msg)
	if err != nil {
		if refusal := RelayRefusalOf(err); refusal != nil && refusal.Code == hosts.RefusalRelaySequenceReplayed {
			if refusal.Redelivery {
				// The panel consumed this message already and the relay carried it again
				// because the acknowledgement never reached it - a link that broke while
				// the spool was draining.
				metrics.RelayEnvelopeRedelivery.Inc()
				s.acknowledge(hostID, session, msg.GetEnvelope(), msg.GetRelayMessageId())
				s.log.Debug("a relayed message the panel had consumed was carried again and acknowledged",
					"host_id", hostID, "relay_id", relayed.peer.RelayID, "detail", refusal.Detail)
				return errMessageDropped
			}
			s.refused(ctx, hostID, refusal.Code, refusal.Detail)
			metrics.RelayEnvelopeRefusal.Inc(refusal.Code)
			s.log.Warn("a relayed message was carried a second time and was dropped",
				"host_id", hostID, "relay_id", relayed.peer.RelayID, "detail", refusal.Detail)
			s.acknowledge(hostID, session, nil, msg.GetRelayMessageId())
			return errMessageDropped
		}
		return s.refuseEnvelope(ctx, hostID, err)
	}
	s.learnPublicKey(ctx, hostID, verified)
	return nil
}

// refuseEnvelope turns a failed verification into the session's refusal: the
// code on the host and the trail, the counter, and the error the stream ends
// with.
func (s *AgentService) refuseEnvelope(ctx context.Context, hostID string, err error) error {
	refusal := RelayRefusalOf(err)
	if refusal == nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	s.refused(ctx, hostID, refusal.Code, refusal.Detail)
	metrics.RelayEnvelopeRefusal.Inc(refusal.Code)
	code := connect.CodeUnauthenticated
	if refusal.Code == hosts.RefusalRelayScopeMismatch || strings.HasPrefix(refusal.Code, "lifecycle_") {
		code = connect.CodePermissionDenied
	}
	return connect.NewError(code, errors.New(refusal.Detail))
}

// learnPublicKey writes the key of an older certificate on its record once the
// relay's certificate supplied it.
func (s *AgentService) learnPublicKey(ctx context.Context, hostID string, verified *Verified) {
	if verified == nil || len(verified.LearnedKeyDER) == 0 {
		return
	}
	if err := s.hosts.RecordCertificatePublicKey(ctx, nil, verified.Serial, verified.LearnedKeyDER); err != nil {
		s.log.Error("the public key of the certificate was not recorded",
			"host_id", hostID, "serial", verified.Serial, "err", err)
	}
}

// handle consumes a message of the agent and, once it is consumed,
// acknowledges it to the relay that carried it.
func (s *AgentService) handle(ctx context.Context, hostID string, session *Session,
	msg *agentv1.AgentMessage) error {
	if err := s.consume(ctx, hostID, session, msg); err != nil {
		return err
	}
	s.acknowledge(hostID, session, msg.GetEnvelope(), msg.GetRelayMessageId())
	return nil
}

// acknowledge tells the relay the message is the panel's now: by the sequence
// of the envelope where there is one, by the relay's identifier where there is not.
func (s *AgentService) acknowledge(hostID string, session *Session,
	envelope *agentv1.RelayedEnvelope, relayMessageID string) {
	if session == nil || (envelope == nil && relayMessageID == "") {
		return
	}
	err := session.Send(&agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_MessageAck{MessageAck: &agentv1.MessageAck{
			HostId:         hostID,
			SessionId:      envelope.GetSessionId(),
			Sequence:       envelope.GetSequence(),
			RelayMessageId: relayMessageID,
		}},
	}, ackSendTimeout)
	if err != nil {
		s.log.Warn("the acknowledgement of a relayed message was not sent; the relay will carry it again",
			"host_id", hostID, "session_id", envelope.GetSessionId(),
			"sequence", envelope.GetSequence(), "relay_message_id", relayMessageID, "err", err)
	}
}

// ackSendTimeout bounds the wait for a slot in the outbound buffer of the
// session.
const ackSendTimeout = 2 * time.Second

// recordSample stores one resource sample and answers the host with what
// became of it.
func (s *AgentService) recordSample(ctx context.Context, hostID string, session *Session,
	sample *agentv1.MetricsSample) error {
	// At fleet cadence this is the call the gateway makes most often, so its
	// tail is the gateway's tail.
	started, status := time.Now(), "persisted"
	defer func() { metrics.SampleAck.Observe(time.Since(started).Seconds(), status) }()
	if s.samples == nil {
		// A gateway without a monitoring store keeps no samples at all.
		status = monitoring.ErrorSampleNotKept
		s.ackSample(hostID, session, sample,
			agentv1.MetricsAck_STATUS_REJECTED_INVALID, monitoring.ErrorSampleNotKept)
		return nil
	}
	now := time.Now().UTC()
	stored, observed := sampleFromProto(sample, now, s.samples.ClockSkewLimit(), s.samples.MaxLateness())
	if observed.TooOld {
		// Older than the panel keeps raw samples for. The refusal is written
		// down before the host is told: a hole nobody recorded reads on the
		// chart exactly like a host that was never asked to report.
		s.log.Warn("a resource sample reached the panel too late to be stored",
			"host_id", hostID, "age", (-observed.Skew).String(),
			"max_lateness", s.samples.MaxLateness().String(),
			"reason", monitoring.ErrorSampleTooOld)
		status = monitoring.ErrorSampleTooOld
		if err := s.samples.RecordRefusal(ctx, hostID, monitoring.ErrorSampleTooOld, stored.At); err != nil {
			status = "error"
			return err
		}
		s.ackSample(hostID, session, sample,
			agentv1.MetricsAck_STATUS_REJECTED_TOO_OLD, monitoring.ErrorSampleTooOld)
		return nil
	}
	if observed.Substituted {
		// The panel put its own moment on the reading, so the panel says so:
		// every point of this host is then drawn where the host did not put it.
		if err := s.samples.RecordClockSubstitution(ctx, hostID, observed.Skew); err != nil {
			status = "error"
			return err
		}
	}
	outcome, err := s.samples.Record(ctx, hostID, stored)
	if err != nil {
		status = "error"
		return err
	}
	ack := agentv1.MetricsAck_STATUS_PERSISTED
	if outcome == monitoring.OutcomeDuplicate {
		ack, status = agentv1.MetricsAck_STATUS_DUPLICATE, "duplicate"
	}
	s.ackSample(hostID, session, sample, ack, "")
	return nil
}

// ackSample tells the agent what became of one sample.
func (s *AgentService) ackSample(hostID string, session *Session, sample *agentv1.MetricsSample,
	status agentv1.MetricsAck_Status, reason string) {
	if session == nil || sample.GetBootId() == "" || sample.GetSequence() == 0 {
		return
	}
	err := session.Send(&agentv1.ServerMessage{
		Payload: &agentv1.ServerMessage_MetricsAck{MetricsAck: &agentv1.MetricsAck{
			BootId:     sample.GetBootId(),
			Sequence:   sample.GetSequence(),
			Status:     status,
			ReasonCode: reason,
		}},
	}, ackSendTimeout)
	if err != nil {
		s.log.Warn("the acknowledgement of a resource sample was not sent; the host will send it again",
			"host_id", hostID, "boot_id", sample.GetBootId(),
			"sequence", sample.GetSequence(), "err", err)
	}
}

// consume applies a message of the agent to the records of the panel.
func (s *AgentService) consume(ctx context.Context, hostID string, session *Session,
	msg *agentv1.AgentMessage) error {
	switch payload := msg.GetPayload().(type) {
	case *agentv1.AgentMessage_Heartbeat:
		// The other call every host makes on a fixed cadence; its tail says
		// whether the gateway keeps up with the fleet.
		started, outcome := time.Now(), "applied"
		defer func() { metrics.HeartbeatApply.Observe(time.Since(started).Seconds(), outcome) }()
		health := payload.Heartbeat.GetHealth()
		// The fields absent from a message mean an undetermined state and go on as a
		// missing value rather than as zero - and a heartbeat without any health at
		// all says nothing about the host rather than something about the panel.
		if health == nil {
			health = &agentv1.HealthSignals{}
		}
		if err := s.hosts.ApplyHeartbeat(ctx, hostID, hosts.Health{
			FailedUnits:            health.FailedUnits,
			RebootRequired:         health.RebootRequired,
			Load1Milli:             health.GetLoad1Milli(),
			RootFSUsedPercent:      health.GetRootFsUsedPercent(),
			UptimeSeconds:          health.GetUptimeSeconds(),
			PendingUpdates:         health.PendingUpdates,
			PendingSecurityUpdates: health.PendingSecurityUpdates,
		}); err != nil {
			outcome = "error"
			return err
		}
		const query = `update agent_sessions set last_heartbeat_at = now() where id = $1`
		_, err := s.pool.Exec(ctx, query, session.ID)
		if err != nil {
			outcome = "error"
		}
		return err

	case *agentv1.AgentMessage_Inventory:
		report := payload.Inventory
		raw := report.GetRawJson()
		if len(raw) == 0 {
			raw = []byte("{}")
		}
		// The size is checked before the JSON: validating two megabytes
		// only to refuse them is work the host should not be able to order.
		if len(raw) > inventory.MaxPayloadBytes {
			s.refuseInventory(ctx, hostID, report.GetRevision(), len(raw))
			return nil
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
		if errors.Is(err, inventory.ErrOversized) {
			s.refuseInventory(ctx, hostID, report.GetRevision(), len(raw))
			return nil
		}
		if err != nil {
			return err
		}
		if stored {
			s.log.Info("a new inventory revision",
				"host_id", hostID, "revision", report.GetRevision(), "full", report.GetFull())
		}
		s.followHostname(ctx, hostID, report)
		if stored || report.GetFull() {
			// The platform history is written from the system module: a revision seen
			// before names a pair the history already has, so only a new revision or a
			// full report is worth the write.
			s.followPlatform(ctx, hostID, report)
		}
		return nil

	case *agentv1.AgentMessage_MetricsSample:
		return s.recordSample(ctx, hostID, session, payload.MetricsSample)

	case *agentv1.AgentMessage_TaskResult:
		return s.recordTaskResult(ctx, session, payload.TaskResult)

	case *agentv1.AgentMessage_CancelAck:
		return s.recordCancelAck(ctx, session, payload.CancelAck)

	case *agentv1.AgentMessage_TaskLogLines:
		// The live view of a log goes straight to the screen of the operator and is
		// not recorded.
		lines := payload.TaskLogLines
		jobID, campaignID := s.attemptContext(ctx, lines.GetTaskId(), hostID)
		if jobID == "" {
			return nil
		}
		// A preview that still sends lines is an attempt that is alive, the
		// same as one that reports progress.
		s.keepAttemptAlive(ctx, lines.GetTaskId(), hostID)
		if s.events != nil {
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
		// recorded: it is transient by design, and what lasts is the result.
		progress := payload.TaskProgress
		// The agent knows the identifier of the attempt, and the operator looks at
		// the operation.
		jobID, campaignID := s.attemptContext(ctx, progress.GetTaskId(), hostID)
		if jobID == "" {
			return nil
		}
		// An attempt that reports is alive.
		s.keepAttemptAlive(ctx, progress.GetTaskId(), hostID)
		switch progress.GetStage() {
		case stageAccepted:
			// The agent holds the task: the dispatch lease has done its
			// work, and the attempt gets the execution lease from here.
			s.acceptAttempt(ctx, progress.GetTaskId(), hostID)
		case stageAwaitingLock:
			// The task waits on the host for a resource another task holds.
			if err := s.jobs.SetLockWait(ctx, progress.GetTaskId(), hostID, progress.GetMessage()); err != nil {
				s.log.Warn("the wait for the lock was not recorded",
					"host_id", hostID, "attempt_id", progress.GetTaskId(), "err", err)
			}
		case stageStarted:
			// The operation starts on the host this instant: the job is
			// running from here, and whatever it waited on is behind it.
			s.startAttempt(ctx, progress.GetTaskId(), hostID, progress.GetClaims())
		case stageInProgress:
			// The agent answered a redelivery: the panel gave the attempt before this
			// one up, and the host is still on the operation.
			s.log.Info("the host is still carrying the operation the redelivered attempt asks for",
				"host_id", hostID, "job_id", jobID, "attempt_id", progress.GetTaskId(),
				"previous_attempt_id", progress.GetPreviousTaskId())
		}
		if progress.GetStage() != "" && progress.GetMessage() == "" {
			// An acknowledgement carries no progress of its own; the bar on
			// the screen keeps whatever the operation last said.
			return nil
		}
		if s.events != nil {
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

	case *agentv1.AgentMessage_FinalReady:
		// The answer to the final task goes to the handshake waiting on this
		// session.
		if !session.AcceptFinalReady(payload.FinalReady) {
			s.log.Warn("an unsolicited FinalReady from the agent",
				"host_id", hostID, "session_id", session.ID)
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
// and its campaign.
func (s *AgentService) attemptContext(ctx context.Context, attemptID, hostID string) (string, string) {
	if attemptID == "" {
		return "", ""
	}
	s.attemptsMu.RLock()
	entry, known := s.attempts[attemptID]
	s.attemptsMu.RUnlock()
	if known && entry.hostID == hostID {
		return entry.jobID, entry.campaignID
	}

	jobID, campaignID, err := s.jobs.AttemptContext(ctx, attemptID, hostID)
	if err != nil {
		return "", ""
	}
	s.attemptsMu.Lock()
	// The map is cleared at the result of an attempt, but an operation can end
	// without a result - a broken session, an expired lease.
	if len(s.attempts) >= maxRememberedAttempts {
		s.attempts = map[string]attemptContextEntry{}
	}
	s.attempts[attemptID] = attemptContextEntry{jobID: jobID, campaignID: campaignID, hostID: hostID}
	s.attemptsMu.Unlock()
	return jobID, campaignID
}

// attemptContextEntry binds an attempt to the operation and the campaign it
// was created in.
type attemptContextEntry struct {
	jobID      string
	campaignID string
	hostID     string
	// leaseRenewedAt is when the lease of the attempt was last moved
	// forward on a sign of life. Zero means not yet in this gateway.
	leaseRenewedAt time.Time
}

// maxRememberedAttempts limits the memory of the attempt -> operation
// translations.
const maxRememberedAttempts = 4096

// The stages of the acknowledgement of a task (TaskProgress. stage in agent.
// proto).
const (
	stageAccepted     = "accepted"
	stageAwaitingLock = "awaiting_lock"
	stageStarted      = "started"
	stageInProgress   = "in_progress"
)

// progressLeaseExtension is how far a sign of life moves the lease of an
// attempt: as far as the delivery did (the scheduler's lease is five minutes,
// cmd/control-plane/main.
const progressLeaseExtension = 5 * time.Minute

// leaseRenewalInterval spaces the renewals of one attempt.
const leaseRenewalInterval = 30 * time.Second

// keepAttemptAlive moves the lease of an attempt forward on a report from the
// host, at most once per leaseRenewalInterval.
func (s *AgentService) keepAttemptAlive(ctx context.Context, attemptID, hostID string) {
	if !s.leaseRenewalDue(attemptID, hostID, time.Now()) {
		return
	}
	renewed, err := s.jobs.RenewAttemptLease(ctx, attemptID, hostID, progressLeaseExtension)
	if err != nil {
		s.log.Warn("the lease of a reporting attempt was not renewed",
			"host_id", hostID, "attempt_id", attemptID, "err", err)
		return
	}
	if !renewed {
		// A closed attempt keeps reporting for a moment after the panel gave up on
		// it or settled it; that is the case the renewal exists to prevent, not one
		// to be alarmed by.
		s.log.Debug("a report for an attempt without an open lease",
			"host_id", hostID, "attempt_id", attemptID)
	}
}

// acceptAttempt records the agent's word that it holds the task: the
// acceptance time on the attempt and the execution lease in place of the
// dispatch lease.
func (s *AgentService) acceptAttempt(ctx context.Context, attemptID, hostID string) {
	accepted, err := s.jobs.AcceptAttempt(ctx, attemptID, hostID, progressLeaseExtension)
	if err != nil {
		s.log.Warn("the acceptance of the attempt was not recorded",
			"host_id", hostID, "attempt_id", attemptID, "err", err)
		return
	}
	if !accepted {
		// The panel gave the attempt up before the acceptance arrived: the
		// redelivery is on its way, and the agent will answer it as in progress.
		s.log.Info("an acceptance for an attempt without an open lease",
			"host_id", hostID, "attempt_id", attemptID)
	}
}

// startAttempt moves the job to running on the agent's word that the
// operation started on the host.
func (s *AgentService) startAttempt(ctx context.Context, attemptID, hostID string, claims []string) {
	started, err := s.jobs.MarkRunning(ctx, attemptID, hostID)
	if err != nil {
		s.log.Warn("the start of the attempt was not recorded",
			"host_id", hostID, "attempt_id", attemptID, "err", err)
		return
	}
	if !started {
		// A repeated report, or an attempt the panel closed meanwhile; the
		// job keeps its state either way.
		s.log.Debug("a start for an attempt that is not dispatched",
			"host_id", hostID, "attempt_id", attemptID)
		return
	}
	s.log.Info("the operation started on the host",
		"host_id", hostID, "attempt_id", attemptID, "claims", strings.Join(claims, ","))
}

// leaseRenewalDue says whether the attempt's lease is to be renewed now and,
// when it is, stamps the time so that the next report within the interval does
// not write again.
func (s *AgentService) leaseRenewalDue(attemptID, hostID string, now time.Time) bool {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	entry, known := s.attempts[attemptID]
	if !known || entry.hostID != hostID {
		return false
	}
	if !entry.leaseRenewedAt.IsZero() && now.Sub(entry.leaseRenewedAt) < leaseRenewalInterval {
		return false
	}
	entry.leaseRenewedAt = now
	s.attempts[attemptID] = entry
	return true
}

// recordTaskResult writes the result reported by the agent and moves the job
// into a final state.
func (s *AgentService) recordTaskResult(ctx context.Context, session *Session,
	result *agentv1.TaskResult) error {
	hostID := session.HostID
	attemptID := result.GetTaskId()
	jobID, action, attemptStatus, err := s.jobs.AttemptOwner(ctx, attemptID, hostID)
	if err != nil {
		if errors.Is(err, jobs.ErrNotFound) {
			// Either the attempt never existed or it belongs to another
			// host. The second is an incident, and the audit says so.
			s.audit.Record(ctx, audit.Event{
				ActorType: audit.ActorAgent, ActorID: hostID,
				Action: "security.attempt_mismatch", TargetType: "host", TargetID: hostID,
				Outcome: audit.OutcomeDenied,
				Detail:  map[string]any{"attempt_id": attemptID, "status": result.GetStatus().String()},
			})
		}
		return fmt.Errorf("a result for the unknown attempt %s: %w", attemptID, err)
	}

	s.attemptsMu.Lock()
	delete(s.attempts, attemptID)
	s.attemptsMu.Unlock()

	// The agent delivers the result of an operation the panel redelivered under
	// both attempts, the one that did the work first.
	if attemptStatus == jobs.AttemptStatusSuperseded {
		s.log.Info("the copy of the result for the superseded attempt changes nothing",
			"job_id", jobID, "attempt_id", attemptID, "status", result.GetStatus().String())
		return nil
	}

	// A job that has finished has no reason to keep an open right to a secret.
	if s.leases != nil {
		if err := s.leases.Revoke(ctx, jobID); err != nil {
			s.log.Debug("the leases of the secrets were not closed", "job_id", jobID, "err", err)
		}
	}

	state, statusName := jobStateFor(result.GetStatus())

	// A refresh of the inventory is settled by the appearance of a revision
	// rather than by the report of the agent.
	errorCode, errorMessage := result.GetErrorCode(), result.GetMessage()
	if state == jobs.StateSucceeded && action == string(opspec.ActionInventoryRefresh) {
		if code, message := s.checkRefresh(ctx, hostID, result); code != "" {
			state, statusName = jobs.StateFailed, "failed"
			errorCode, errorMessage = code, message
		}
	}
	// A change the host never read back is not a change that landed. The agent
	// settles this for itself, so an absent verification means the block was
	// lost on the way or the read never happened; either way the panel is not
	// entitled to call it a success.
	if state == jobs.StateSucceeded && result.GetVerification() == nil &&
		verificationExpected(opspec.ActionType(action)) {
		state, statusName = jobs.StateFailed, "failed"
		errorCode = opspec.ErrorAppliedUnverified
		errorMessage = "the change was made and the result carries no read of the host afterwards"
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
		// The host's reading of itself after the change goes onto the attempt as it
		// came: without it the operator sees applied_unverified with no way to learn
		// which verifier looked, what it expected and what it found.
		Verification: verificationJSON(result.GetVerification()),
	}, state, session.Fence())
	if errors.Is(err, jobs.ErrStaleFence) {
		// The database refused the settlement: the host was claimed by a newer
		// session and this one no longer owns it.
		metrics.SessionFence.Inc("result_refused")
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: hostID,
			Action: "job.result", TargetType: "job", TargetID: jobID, Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"attempt_id": attemptID, "status": statusName, "applied": false,
				"error_code": jobs.ErrorSessionFenceStale,
				"session_id": session.ID, "fencing_token": session.FenceToken,
			},
		})
		s.log.Warn("the result was refused: the session no longer owns the host",
			"job_id", jobID, "attempt_id", attemptID, "host_id", hostID, "session_id", session.ID)
		session.End("superseded")
		return nil
	}
	if err != nil {
		return err
	}
	// Everything a result changes on the host's record - the desired state of a
	// file, a deployed certificate, a package list, a backup run, the inventory
	// fragments the agent sent back with it - follows the settlement rather than.
	if !accepted {
		s.recordUnappliedResult(ctx, hostID, jobID, attemptID, statusName, result, attemptStatus)
		return nil
	}

	// The desired state of a file is written after a successful operation rather
	// than at the ordering: the panel must not claim it manages a file the host
	// rejected.
	if result.GetStatus() == agentv1.TaskResult_STATUS_SUCCEEDED {
		// The content the host reported goes into the store of versions first: it is
		// the way back to the state from before the panel managed the file.
		var restored []byte
		if file := result.GetFileResult(); file != nil && len(file.GetContent()) > 0 &&
			!file.GetTruncated() {
			restored = file.GetContent()
			if _, err := s.files.SaveVersion(ctx, s.pool, restored); err != nil {
				s.log.Error("the version of the file that was read was not written", "host_id", hostID, "err", err)
			}
		}
		s.saveFileState(ctx, hostID, jobID, restored)
		s.saveCertificateDeployment(ctx, hostID, jobID, result.GetCertificateResult())
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
	// assessment is computed from it, so rows for joins are needed rather than a
	// blob in the inventory.
	if list := result.GetInstalledPackagesResult(); list != nil &&
		result.GetStatus() == agentv1.TaskResult_STATUS_SUCCEEDED {
		s.savePackageList(ctx, hostID, jobID, list)
	}

	// A backup run is recorded also when it failed: "the backup did not work" is
	// a more important message than "the backup worked", and without an entry in
	// the history there would be nowhere to see it.
	if backup := result.GetBackupResult(); backup != nil {
		s.saveBackupRun(ctx, hostID, jobID, backup,
			result.GetStatus() == agentv1.TaskResult_STATUS_SUCCEEDED)
	}

	// The package sources go into the inventory after every change.
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

	// The protective state goes into the inventory after every operation: a scan
	// exists exactly to refresh it on demand, and a switch of MAC is to be
	// visible in the findings at once rather than after the next cycle.
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

	// The state of time goes into the inventory after every operation.
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

	// The image of the disk space goes into the inventory: every operation sends
	// the state back after itself, so the tab does not wait for the next cycle.
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

	// The schedules go into the inventory module: the tab asks about the state of
	// the host, and every operation sends the full image back after a change
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

	// The snapshot of the processes goes into an inventory module, like the state
	// of the containers and the list of the units: the tab asks about the state
	// of the host rather than about the history of the jobs.
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
	// reason as the state of the containers: the tab asks about the state of the
	// host rather than about the history of the jobs.
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
	// than only as the result of an operation.
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

	// An operation on an account changes the state of the host at once, while the
	// full inventory report comes only in a dozen or so minutes.
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
	// A deleted account has no state to read back: the row goes, so the panel
	// does not show an account the host no longer has until the next full report.
	if user, ok := result.GetDetail().(*agentv1.TaskResult_LocalUser); ok &&
		state == jobs.StateSucceeded && action == string(opspec.ActionLocalUserDelete) &&
		user.LocalUser.GetAccount() == nil && user.LocalUser.GetName() != "" {
		if err := s.inventory.DeleteLocalAccount(ctx, hostID, user.LocalUser.GetName()); err != nil {
			s.log.Error("the deleted account was not removed from the inventory",
				"host_id", hostID, "account", user.LocalUser.GetName(), "err", err)
		}
	}

	// The state of the package database is updated by every result that knows it:
	// a transaction, a plan and a repair.
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
	// A result on an attempt the scheduler had given up on is the host finishing
	// what it was carrying all along; the trail says so, because the attempt rows
	// alone read as a lease that ran out.
	afterLeaseExpiry := attemptStatus == jobs.AttemptStatusLeaseExpired
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "job.result", TargetType: "job", TargetID: jobID, Outcome: outcome,
		Detail: map[string]any{
			"attempt_id": attemptID, "status": statusName,
			"exit_code": result.GetExitCode(), "error_code": result.GetErrorCode(),
			"replayed": result.GetReplayed(), "applied": true,
			"after_lease_expiry": afterLeaseExpiry,
		},
	})
	s.log.Info("the result of the job was written",
		"job_id", jobID, "host_id", hostID, "status", statusName,
		"exit_code", result.GetExitCode(), "replayed", result.GetReplayed(),
		"after_lease_expiry", afterLeaseExpiry)
	return nil
}

// recordUnappliedResult puts a result the store did not accept on the trail.
func (s *AgentService) recordUnappliedResult(ctx context.Context, hostID, jobID, attemptID,
	statusName string, result *agentv1.TaskResult, attemptStatus string) {
	afterLeaseExpiry := attemptStatus == jobs.AttemptStatusLeaseExpired
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "job.result", TargetType: "job", TargetID: jobID, Outcome: audit.OutcomeFailure,
		Detail: map[string]any{
			"attempt_id": attemptID, "status": statusName,
			"exit_code": result.GetExitCode(), "error_code": result.GetErrorCode(),
			"replayed": result.GetReplayed(), "applied": false,
			"after_lease_expiry": afterLeaseExpiry,
		},
	})
	s.log.Warn("the result did not change the state of the job and was not applied to the host",
		"job_id", jobID, "attempt_id", attemptID, "host_id", hostID, "status", statusName,
		"after_lease_expiry", afterLeaseExpiry)
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

// resultDetailJSON writes the result proper for the type of the operation.
func resultDetailJSON(result *agentv1.TaskResult) json.RawMessage {
	// The event log is the answer to a question from one moment rather than the
	// state of the host: it stays in the result of the job and does not reach the
	// inventory.
	if dockerEvents := result.GetDockerEventsResult(); dockerEvents != nil &&
		(len(dockerEvents.GetEvents()) > 0 || dockerEvents.GetUnavailableReason() != "") {
		// An unavailable engine carries no log at all, and the result is to come
		// into being anyway: it is what tells the operator why they see nothing.
		eventsJSON := json.RawMessage(dockerEvents.GetEvents())
		if len(eventsJSON) == 0 {
			eventsJSON = json.RawMessage("{}")
		}
		encoded, err := json.Marshal(map[string]any{
			"kind":               "docker_events",
			"events":             eventsJSON,
			"truncated":          dockerEvents.GetTruncated(),
			"truncated_reason":   dockerEvents.GetTruncatedReason(),
			"unavailable_reason": dockerEvents.GetUnavailableReason(),
		})
		if err == nil {
			return encoded
		}
	}

	// The tail of a container log is the answer to a question from one moment,
	// like the event log: it stays in the result of the job.
	if logs := result.GetDockerLogsResult(); logs != nil &&
		(logs.GetContainerId() != "" || logs.GetUnavailableReason() != "") {
		lines := logs.GetLines()
		if lines == nil {
			lines = []string{}
		}
		encoded, err := json.Marshal(map[string]any{
			"kind":               "docker_logs",
			"container_id":       logs.GetContainerId(),
			"container_name":     logs.GetContainerName(),
			"lines":              lines,
			"truncated":          logs.GetTruncated(),
			"truncated_reason":   logs.GetTruncatedReason(),
			"unavailable_reason": logs.GetUnavailableReason(),
		})
		if err == nil {
			return encoded
		}
	}

	// A rename carries the preflight checks whether it happened or not: the
	// operator is to see what was checked, including a refused one.
	if rename := result.GetHostnameResult(); rename != nil &&
		(rename.GetCurrent() != "" || len(rename.GetChecks()) > 0) {
		encoded, err := json.Marshal(map[string]any{
			"kind":               "hostname",
			"previous":           rename.GetPrevious(),
			"current":            rename.GetCurrent(),
			"changed":            rename.GetChanged(),
			"hosts_file_updated": rename.GetHostsFileUpdated(),
			"checks":             preflightChecksJSON(rename.GetChecks()),
		})
		if err == nil {
			return encoded
		}
	}

	// A keytab renewal names the principal and the key versions on both
	// sides of it; an unknown version before stays unknown, not zero.
	if keytab := result.GetKeytabRenewResult(); keytab != nil && keytab.GetPrincipal() != "" {
		detail := map[string]any{
			"kind":       "keytab_renew",
			"principal":  keytab.GetPrincipal(),
			"kvno_after": keytab.GetKvnoAfter(),
		}
		if keytab.GetKvnoBeforeKnown() {
			detail["kvno_before"] = keytab.GetKvnoBefore()
		}
		if encoded, err := json.Marshal(detail); err == nil {
			return encoded
		}
	}

	// A SMART report is a reading from one moment, and a device the tool cannot
	// read reports unsupported with the tool's own words: the panel shows that
	// reason, never an invented healthy disk.
	if smart := result.GetSmartResult(); smart != nil && smart.GetDevice() != "" {
		encoded, err := json.Marshal(smartResultJSON(smart))
		if err == nil {
			return encoded
		}
	}

	// A refresh of the inventory carries proof: the revision of the image that
	// came out of it.
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

	// The plan of a declared object, or what the change did to it.
	if declared := result.GetDockerEnsureResult(); declared != nil && len(declared.GetPayload()) > 0 {
		encoded, err := json.Marshal(map[string]any{
			"kind":               "docker_declaration",
			"payload":            json.RawMessage(declared.GetPayload()),
			"unavailable_reason": declared.GetUnavailableReason(),
		})
		if err == nil {
			return encoded
		}
	}

	// The result of a name resolution test belongs to the job rather than to the
	// inventory: it is the answer to one question asked at one moment rather than
	// the state of the host.
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

	// A network plan is a result of the job rather than the state of the host: it
	// describes a change that has not happened yet, against the profile the host
	// has now.
	if network := result.GetNetworkResult(); network != nil && len(network.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
		}
		_ = json.Unmarshal(network.GetPlan(), &plan)
		encoded, err := json.Marshal(map[string]any{
			"kind":      "network_plan",
			"plan":      json.RawMessage(network.GetPlan()),
			"plan_hash": plan.PlanHash,
			"profiles":  rawJSON(network.GetProfiles()),
		})
		if err == nil {
			return encoded
		}
	}

	// A network change carries the rollback identifier and whether the
	// connectivity confirmation managed to disarm it.
	if network := result.GetNetworkResult(); network != nil &&
		(len(network.GetProfiles()) > 0 || network.GetRollbackId() != "") {
		encoded, err := json.Marshal(map[string]any{
			"kind":              "network",
			"profiles":          rawJSON(network.GetProfiles()),
			"rollback_id":       network.GetRollbackId(),
			"rollback_deadline": network.GetRollbackDeadline(),
			"confirmed":         network.GetConfirmed(),
		})
		if err == nil {
			return encoded
		}
	}

	// A rule plan is a result of the job rather than the state of the host: it
	// describes a change that has not happened yet, against the set of rules the
	// host has now.
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

	// A firewall change carries the rollback identifier and the digest of
	// the rule set.
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
	// describes a change that has not happened yet, and a source resolved to the
	// UUID of this host.
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

	// A filesystem check result belongs to the job: it is the answer to one
	// question asked at one moment.
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

	// The settings that did not come into effect are the content of the result: a
	// change written and shadowed looks from the outside exactly like a
	// successful one.
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

	// Settings written but not taken immediately are the content of the
	// result: the write and the effect are two different things.
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

	// Shutdown inhibitors belong to the job: they say why the host stayed
	// up or what the operator decided to override.
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

	// A probe result belongs to the job: it is the service's answer from one
	// moment, seen from this one host.
	if probe := result.GetMonitoringResult(); probe != nil && len(probe.GetProbe()) > 0 {
		encoded, err := json.Marshal(map[string]any{
			"kind":    "monitoring",
			"message": probe.GetMessage(),
			"probe":   rawJSON(probe.GetProbe()),
		})
		if err == nil {
			return encoded
		}
	}

	// The repository state and the backup result belong to the job: they are the
	// answer to a question asked at one moment rather than the state of the host.
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

	// The fingerprint of a source's key belongs to the job: it is the only moment
	// in which a human can compare it with the fingerprint given by the vendor.
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

	// A certificate deployment plan is a result of the job rather than the state
	// of the host: it describes a change that has not happened yet.
	if certificate := result.GetCertificateResult(); certificate != nil && len(certificate.GetPlan()) > 0 {
		var plan struct {
			PlanHash string `json:"plan_hash"`
			// The module names the kind of the plan. Guessing it from empty fields
			// would confuse a refused plan with a plan of another kind.
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(certificate.GetPlan(), &plan)
		// An anchor plan and a deployment plan are two shapes; the kind of the
		// result is to name that, because the operator looks at them in the same
		// place.
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
	// to the state of the host: it is a measurement from one moment, right after
	// the swap.
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
	// describes a change that has not happened yet.
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

	// The content of a read file belongs to the job: it is the answer to a
	// question asked at one moment rather than the state of the host.
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

	// The preview of a schedule is the answer to one question - when would this
	// expression run here - computed in the host's own zone.
	if schedule := result.GetScheduleResult(); schedule != nil && len(schedule.GetPreview()) > 0 {
		encoded, err := json.Marshal(schedulePreviewJSON(schedule.GetPreview()))
		if err == nil {
			return encoded
		}
	}

	if signal := result.GetProcessSignalResult(); signal != nil {
		encoded, err := json.Marshal(map[string]any{
			"kind":    "process_signal",
			"pid":     signal.GetPid(),
			"signal":  signal.GetSignal(),
			"command": signal.GetCommand(),
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
			"space":                spaceJSON(schedule.GetSpace()),
			"schema_version":       schedule.GetSchemaVersion(),
			"planner_version":      schedule.GetPlannerVersion(),
			"host_id":              schedule.GetHostId(),
			"inventory_revision":   schedule.GetInventoryRevision(),
			"resource_revision":    schedule.GetResourceRevision(),
			"expires_at":           unixRFC3339(schedule.GetExpiresAtUnix()),
			"description":          schedule.GetDescription(),
			"rollback": map[string]any{
				"mechanism": schedule.GetRollbackMechanism(), "id": schedule.GetRollbackId(),
				"available": schedule.GetRollbackAvailable(), "reason": schedule.GetRollbackReason(),
			},
			"envelope": rawJSONOrNil(schedule.GetEnvelope()),
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
		// The detail of a few units and the listing of the host are two shapes under
		// one result: the detail is the answer to an opened row, so it gets a kind
		// of its own and the panel reads it typed rather than parsing stdout.
		if details := detail.UnitStatus.GetDetails(); len(details) > 0 {
			encoded, err := json.Marshal(map[string]any{
				"kind":  "unit_detail",
				"units": unitDetailsJSON(details),
			})
			if err != nil {
				return nil
			}
			return encoded
		}
		units := make([]map[string]any, 0)
		for _, unit := range detail.UnitStatus.GetUnits() {
			units = append(units, unitStateFields(unit))
		}
		encoded, err := json.Marshal(map[string]any{"kind": "unit_status", "units": units})
		if err != nil {
			return nil
		}
		return encoded

	case *agentv1.TaskResult_PackageApply:
		apply := detail.PackageApply
		// The settled effects of an approved plan travel among the applied changes;
		// the record keeps them apart, achieved and missed with the version observed
		// after the transaction.
		var applied, effects []*agentv1.PackageChange
		for _, change := range apply.GetApplied() {
			if change.GetEffect() != "" {
				effects = append(effects, change)
			} else {
				applied = append(applied, change)
			}
		}
		encoded, err := json.Marshal(map[string]any{
			"kind":                       "package_apply",
			"manager":                    apply.GetManager(),
			"applied":                    packageChangesJSON(applied),
			"effects":                    packageChangesJSON(effects),
			"reboot_required":            apply.GetRebootRequired(),
			"services_needing_restart":   apply.GetServicesNeedingRestart(),
			"package_database_broken":    apply.GetPackageDatabaseBroken(),
			"packages_needing_attention": apply.GetPackagesNeedingAttention(),
			"self_repair":                apply.GetSelfRepair(),
			"output":                     apply.GetOutput(),
			"scriptlet_errors":           apply.GetScriptletErrors(),
		})
		if err != nil {
			return nil
		}
		return encoded

	default:
		return nil
	}
}

// unitStateFields writes the state of one unit the way the listing, the
// detail and the before/after of an operation all show it.
func unitStateFields(unit *agentv1.UnitState) map[string]any {
	return map[string]any{
		"name":            unit.GetName(),
		"load_state":      unit.GetLoadState(),
		"active_state":    unit.GetActiveState(),
		"sub_state":       unit.GetSubState(),
		"unit_file_state": unit.GetUnitFileState(),
		"result":          unit.GetResult(),
		"main_pid":        unit.GetMainPid(),
		"n_restarts":      unit.GetNRestarts(),
	}
}

// unitDetailsJSON writes the full picture of the units a detail read returned:
// the dependencies, the drop-ins with their content, the last journal lines
// and the cursor to continue from.
func unitDetailsJSON(details []*agentv1.UnitDetail) []map[string]any {
	items := make([]map[string]any, 0, len(details))
	for _, detail := range details {
		dropIns := make([]map[string]any, 0, len(detail.GetDropIns()))
		for _, dropIn := range detail.GetDropIns() {
			dropIns = append(dropIns, map[string]any{
				"path":      dropIn.GetPath(),
				"content":   dropIn.GetContent(),
				"truncated": dropIn.GetTruncated(),
				"error":     dropIn.GetError(),
			})
		}
		items = append(items, map[string]any{
			"state":             unitStateFields(detail.GetState()),
			"description":       detail.GetDescription(),
			"fragment_path":     detail.GetFragmentPath(),
			"requires":          stringList(detail.GetRequires()),
			"wants":             stringList(detail.GetWants()),
			"after":             stringList(detail.GetAfter()),
			"before":            stringList(detail.GetBefore()),
			"binds_to":          stringList(detail.GetBindsTo()),
			"part_of":           stringList(detail.GetPartOf()),
			"triggered_by":      stringList(detail.GetTriggeredBy()),
			"triggers":          stringList(detail.GetTriggers()),
			"drop_ins":          dropIns,
			"exec_main_start":   detail.GetExecMainStart(),
			"journal_lines":     stringList(detail.GetJournalLines()),
			"journal_cursor":    detail.GetJournalCursor(),
			"journal_truncated": detail.GetJournalTruncated(),
			"journal_error":     detail.GetJournalError(),
		})
	}
	return items
}

// stringList keeps an absent list as an empty one: the panel tells "no
// dependencies" from "not read" by the kind of the result, not by null.
func stringList(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

// schedulePreviewJSON lifts the preview the agent computed into the shape of
// an attempt detail.
func schedulePreviewJSON(preview []byte) map[string]any {
	var parsed struct {
		Expression string   `json:"expression"`
		Timezone   string   `json:"timezone"`
		NextRuns   []string `json:"next_runs"`
		Error      string   `json:"error"`
		// The plan of a timer: what systemd would be told and the two unit
		// files that would be written. A cron preview has neither.
		Calendar string `json:"calendar"`
		Units    []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"units"`
	}
	if err := json.Unmarshal(preview, &parsed); err != nil {
		return map[string]any{
			"kind":     "schedule_preview",
			"runs":     []string{},
			"timezone": "",
			"error":    "the preview of the host could not be read: " + err.Error(),
			"raw":      string(preview),
		}
	}
	detail := map[string]any{
		"kind":       "schedule_preview",
		"expression": parsed.Expression,
		"runs":       stringList(parsed.NextRuns),
		"timezone":   parsed.Timezone,
		"error":      parsed.Error,
	}
	if parsed.Calendar != "" {
		detail["calendar"] = parsed.Calendar
	}
	if len(parsed.Units) > 0 {
		units := make([]map[string]any, 0, len(parsed.Units))
		for _, unit := range parsed.Units {
			units = append(units, map[string]any{"path": unit.Path, "content": unit.Content})
		}
		detail["units"] = units
	}
	return detail
}

// rawJSON carries an encoded state without re-encoding it. Empty stays
// empty: a removed container has no state after the operation.
func rawJSON(data []byte) json.RawMessage {
	if len(data) == 0 {
		return nil
	}
	return json.RawMessage(data)
}

// preflightChecksJSON keeps the three-state check result: passed, did not
// pass or could not be established.
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
		item := map[string]any{
			"name":                  change.GetName(),
			"current_version":       change.GetCurrentVersion(),
			"candidate_version":     change.GetCandidateVersion(),
			"origin":                change.GetOrigin(),
			"security":              change.GetSecurity(),
			"architecture":          change.GetArchitecture(),
			"action":                change.GetAction(),
			"reason":                change.GetReason(),
			"blocked":               change.GetBlocked(),
			"protected":             change.GetProtected(),
			"installed_delta_bytes": change.GetInstalledDeltaBytes(),
			"installed_delta_known": change.GetInstalledDeltaKnown(),
			"digest":                change.GetDigest(),
		}
		if change.GetEffect() != "" {
			item["effect"] = change.GetEffect()
			item["observed_version"] = change.GetObservedVersion()
		}
		items = append(items, item)
	}
	return items
}

// unixRFC3339 spells a moment exactly as the panel will carry it back in a
// payload (RFC 3339, UTC); empty when unknown.
func unixRFC3339(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// rawJSONOrNil keeps a document the host sent as it is when it parses,
// and drops it otherwise rather than break the record around it.
func rawJSONOrNil(raw []byte) any {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil
	}
	return json.RawMessage(raw)
}

func unitStateJSON(state *agentv1.UnitState) json.RawMessage {
	if state == nil {
		return nil
	}
	encoded, err := json.Marshal(unitStateFields(state))
	if err != nil {
		return nil
	}
	return encoded
}

// managementAddress picks the management address of a host and says where it
// comes from.
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

// openSession records the session.
func (s *AgentService) countReconnect(ctx context.Context, session *Session) {
	var family string
	err := s.pool.QueryRow(ctx, `
		select coalesce(h.os_family, '')
		from agent_sessions p join hosts h on h.id = p.host_id
		where p.host_id = $1 and p.epoch < $2 and p.ended_at > now() - interval '10 minutes'
		limit 1`, session.HostID, session.Epoch).Scan(&family)
	if err != nil {
		return
	}
	if family == "" {
		family = "unknown"
	}
	metrics.AgentReconnect.Inc(family)
}

func (s *AgentService) openSession(ctx context.Context, session *Session,
	fingerprint []byte, relayID string) error {
	// The epoch number and the session row come into being in one statement.
	const query = `
		insert into agent_sessions
			(id, host_id, gateway_id, cert_fingerprint, remote_addr, agent_version, boot_id, relay_id, epoch,
			 auth_strength)
		values ($1, $2, $3, $4, $5, $6, $7, nullif($8, '')::uuid,
			(select coalesce(max(epoch), 0) + 1 from agent_sessions where host_id = $2),
			nullif($9, ''))
		returning epoch`
	var err error
	for attempt := 0; attempt < sessionEpochAttempts; attempt++ {
		err = s.pool.QueryRow(ctx, query, session.ID, session.HostID, s.gatewayID,
			fingerprint, session.RemoteAddr, session.AgentVersion, session.BootID, relayID,
			hosts.AuthStrength(session.RelayIdentity)).
			Scan(&session.Epoch)
		if err == nil {
			break
		}
		if !epochTaken(err) {
			return err
		}
		s.log.Info("the session epoch was taken by another gateway; trying the next one",
			"host_id", session.HostID, "attempt", attempt+1)
	}
	if err != nil {
		return fmt.Errorf("opening the session after %d attempts at an epoch: %w", sessionEpochAttempts, err)
	}
	// The session claims the host: the token it gets is what every delivery and
	// every result on this session carries, and the claim always takes the host -
	// it does not guess whether the previous instance is really gone.
	token, err := s.jobs.ClaimSession(ctx, session.HostID, session.ID, jobs.InstanceID(), jobs.OwnerLeaseTTL)
	if err != nil {
		return fmt.Errorf("claiming the host for the session: %w", err)
	}
	session.FenceToken, session.OwnerInstanceID = token, jobs.InstanceID()

	s.detectDuplicateIdentity(ctx, session, fingerprint)
	s.countReconnect(ctx, session)

	// The certificate that opened this session is the identity of the host from
	// now on.
	if relayID == "" {
		revoked, err := s.hosts.RevokeSupersededCertificates(ctx, session.HostID, fingerprint, "replaced")
		if err != nil {
			s.log.Error("the superseded certificates were not revoked",
				"host_id", session.HostID, "err", err)
		} else if revoked > 0 {
			s.log.Info("the older certificates of the host were revoked",
				"host_id", session.HostID, "revoked", revoked)
			s.audit.Record(ctx, audit.Event{
				ActorType: audit.ActorAgent, ActorID: session.HostID,
				Action: "host.certificate.replaced", TargetType: "host", TargetID: session.HostID,
				Outcome: audit.OutcomeSuccess,
				Detail: map[string]any{
					"revoked": revoked, "reason": "replaced", "session_id": session.ID,
				},
			})
		}
		// A recovery ends when the new key has proven it works - that is, here, with
		// the first session it opened.
		recovered, err := s.hosts.LeaveRecovery(ctx, session.HostID, fingerprint)
		if err != nil {
			s.log.Error("the recovery state was not left", "host_id", session.HostID, "err", err)
		} else if recovered {
			s.log.Info("the identity of the host was recovered", "host_id", session.HostID)
			s.audit.Record(ctx, audit.Event{
				ActorType: audit.ActorAgent, ActorID: session.HostID,
				Action: "host.identity.recovered", TargetType: "host", TargetID: session.HostID,
				Outcome: audit.OutcomeSuccess,
				Detail: map[string]any{
					"state": hosts.StateActive, "session_id": session.ID,
					"cert_fingerprint": hex.EncodeToString(fingerprint),
				},
			})
		}
	}

	// The older sessions of this host are closed in the database at once: a row
	// left open on a gateway that no longer serves the host inflates every
	// measurement that counts connections and has the scheduler send jobs into.
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
	// How the host was identified is a fact of the newest session and is written
	// on the host: a session on the relay's word alone is the operator's
	// business, and the host page is where they look.
	if err := s.hosts.RecordRelayIdentity(ctx, session.HostID, session.RelayIdentity); err != nil {
		s.log.Error("the identity strength of the session was not recorded on the host",
			"host_id", session.HostID, "err", err)
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
			"relay_identity": nullableRelay(session.RelayIdentity),
			"auth_strength":  nullableRelay(hosts.AuthStrength(session.RelayIdentity)),
		},
	})
	return nil
}

// sessionEpochAttempts bounds how many times a session tries to take the
// next epoch of its host when another gateway takes it first.
const sessionEpochAttempts = 5

// epochTaken says whether an insert of a session row was refused because
// another gateway took the same epoch of the host a moment earlier.
func epochTaken(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" &&
		pgErr.ConstraintName == "agent_sessions_host_epoch_key"
}

// ClonePolicy says what the gateway does once it sees the same identity
// alive on two boots at once.
type ClonePolicy string

const (
	// CloneReport records the incident and counts it, and lets the newer session
	// stand: the epoch rule has closed the older one already.
	CloneReport ClonePolicy = "report"
	// CloneQuarantine cuts the host off: both sessions end, the host goes into
	// quarantine, and its queued tasks are canceled.
	CloneQuarantine ClonePolicy = "quarantine"
)

// ParseClonePolicy reads the policy out of the configuration.
func ParseClonePolicy(value string) (ClonePolicy, error) {
	switch ClonePolicy(strings.ToLower(strings.TrimSpace(value))) {
	case "":
		return CloneQuarantine, nil
	case CloneReport:
		return CloneReport, nil
	case CloneQuarantine:
		return CloneQuarantine, nil
	}
	return "", fmt.Errorf("unknown clone policy %q: report or quarantine", value)
}

// cloneReaction is what the gateway does about a detected clone beyond the
// record and the count that every policy makes.
type cloneReaction struct {
	// Policy is the policy applied, as the audit trail names it.
	Policy ClonePolicy
	// Quarantine puts the host into quarantine and cancels its queued
	// tasks.
	Quarantine bool
	// EndSessions ends both sessions of the identity, the older and the
	// one that has just opened.
	EndSessions bool
}

// cloneSighting is what the detection saw.
type cloneSighting struct {
	// Detected says the same certificate was alive on another boot.
	Detected bool
	// SameAddress says the older session came from the address the new one comes
	// from.
	SameAddress bool
}

// reactToClone decides the reaction from the policy and the sighting.
func reactToClone(policy ClonePolicy, sighting cloneSighting) cloneReaction {
	if policy == "" {
		policy = CloneQuarantine
	}
	reaction := cloneReaction{Policy: policy}
	if !sighting.Detected || sighting.SameAddress {
		return reaction
	}
	if policy == CloneQuarantine {
		reaction.Quarantine = true
		reaction.EndSessions = true
	}
	return reaction
}

// sameAddress compares the hosts of two session addresses: the port is
// the connection's, not the machine's, and differs every time.
func sameAddress(a, b string) bool {
	host := func(address string) string {
		if h, _, err := net.SplitHostPort(address); err == nil {
			return h
		}
		return address
	}
	return a != "" && host(a) == host(b)
}

// CloneEndReason is the reason both sessions of a copied identity end with.
const CloneEndReason = "duplicate_identity"

// detectDuplicateIdentity looks for a clone: the same certificate alive on a
// different boot at the same time.
func (s *AgentService) detectDuplicateIdentity(ctx context.Context, session *Session, fingerprint []byte) {
	// Two heartbeat intervals with the jitter: a session silent for longer
	// is a session that died without saying so.
	alive := time.Duration(2*(s.heartbeatSeconds+s.heartbeatJitter)) * time.Second
	if alive <= 0 {
		alive = 2 * time.Minute
	}
	const query = `
		select id, boot_id, coalesce(remote_addr, ''), coalesce(last_heartbeat_at, started_at)
		from agent_sessions
		where host_id = $1 and epoch < $2 and ended_at is null
		  and cert_fingerprint = $3 and boot_id <> $4
		  and coalesce(last_heartbeat_at, started_at) > now() - $5::interval
		order by epoch desc limit 1`
	var (
		previousID, previousBoot, previousAddr string
		lastSeen                               time.Time
	)
	err := s.pool.QueryRow(ctx, query, session.HostID, session.Epoch, fingerprint, session.BootID,
		alive).Scan(&previousID, &previousBoot, &previousAddr, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return
	}
	if err != nil {
		s.log.Error("the duplicate identity check failed", "host_id", session.HostID, "err", err)
		return
	}
	metrics.DuplicateIdentity.Inc(s.gatewayID)
	reaction := reactToClone(s.clonePolicy,
		cloneSighting{Detected: true, SameAddress: sameAddress(previousAddr, session.RemoteAddr)})
	s.log.Warn("the same identity is alive on two boots",
		"host_id", session.HostID, "previous_session", previousID, "previous_boot_id", previousBoot,
		"previous_addr", previousAddr, "new_session", session.ID, "new_boot_id", session.BootID,
		"new_addr", session.RemoteAddr, "policy", string(reaction.Policy))
	detail := map[string]any{
		"previous_session": previousID, "previous_boot_id": previousBoot,
		"previous_addr": previousAddr, "previous_seen_at": lastSeen.UTC().Format(time.RFC3339),
		"session_id": session.ID, "boot_id": session.BootID, "remote_addr": session.RemoteAddr,
		"gateway_id": s.gatewayID,
		"policy":     string(reaction.Policy),
		"action":     "the older session was superseded; assess the host and quarantine it if the identity was copied",
	}
	if reaction.Policy == CloneQuarantine && !reaction.Quarantine {
		detail["action"] = "the older session spoke from the same address, so the host was left in the fleet: " +
			"a machine back from a crash looks like this; assess it and quarantine it if the identity was copied"
	}
	if reaction.Quarantine {
		detail["action"] = "the host was quarantined and both sessions ended; " +
			"order an identity recovery for the machine that is the host, or release it once the copy is gone"
		detail["quarantined"] = s.quarantineClone(ctx, session, previousID)
	}
	if reaction.EndSessions {
		s.endCloneSessions(ctx, session, previousID)
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: session.HostID,
		Action: "security.duplicate_identity", TargetType: "host", TargetID: session.HostID,
		Outcome: audit.OutcomeDenied,
		Detail:  detail,
	})
}

// quarantineClone cuts the host off the way the quarantine API does, in one
// transaction: the lifecycle state, the queued tasks and the trail.
func (s *AgentService) quarantineClone(ctx context.Context, session *Session, previousID string) bool {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.log.Error("the clone was not quarantined", "host_id", session.HostID, "err", err)
		return false
	}
	defer func() { _ = tx.Rollback(ctx) }()

	reason := "duplicate identity: the same certificate was alive on two boots at once"
	err = s.hosts.ChangeLifecycleState(ctx, tx, session.HostID,
		[]string{hosts.StateActive, hosts.StateRecovery}, hosts.StateQuarantined, reason, s.gatewayID)
	if errors.Is(err, hosts.ErrForbiddenTransition) {
		s.log.Info("the clone's host is already out of the fleet", "host_id", session.HostID)
		return false
	}
	if err != nil {
		s.log.Error("the clone was not quarantined", "host_id", session.HostID, "err", err)
		return false
	}
	canceled, err := s.jobs.CancelUndelivered(ctx, tx, session.HostID, s.gatewayID, CloneEndReason)
	if err != nil {
		s.log.Error("the clone's queued tasks were not canceled", "host_id", session.HostID, "err", err)
		return false
	}
	if err := s.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: s.gatewayID,
		Action: "host.quarantine", TargetType: "host", TargetID: session.HostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"reason": reason, "state": hosts.StateQuarantined, "policy": string(CloneQuarantine),
			"jobs_canceled": canceled, "certificates_revoked": 0,
			"session_id": session.ID, "previous_session": previousID,
		},
	}); err != nil {
		s.log.Error("the clone's quarantine was not recorded", "host_id", session.HostID, "err", err)
		return false
	}
	if err := tx.Commit(ctx); err != nil {
		s.log.Error("the clone was not quarantined", "host_id", session.HostID, "err", err)
		return false
	}
	return true
}

// endCloneSessions ends both sessions of the identity.
func (s *AgentService) endCloneSessions(ctx context.Context, session *Session, previousID string) {
	session.End(CloneEndReason)
	if previous, running := s.registry.Get(session.HostID); running && previous.ID != session.ID {
		previous.End(CloneEndReason)
	}
	if _, err := s.pool.Exec(ctx, `
		update agent_sessions set ended_at = now(), end_reason = $2
		where id = $1 and ended_at is null`, previousID, CloneEndReason); err != nil {
		s.log.Error("the clone's session was not closed", "session_id", previousID, "err", err)
	}
}

// newerSessionOpen says whether the host has a session of a higher epoch that
// is still open.
func (s *AgentService) newerSessionOpen(ctx context.Context, session *Session) bool {
	var open bool
	err := s.pool.QueryRow(ctx, `
		select exists (select 1 from agent_sessions
		               where host_id = $1 and epoch > $2 and ended_at is null)`,
		session.HostID, session.Epoch).Scan(&open)
	if err != nil {
		s.log.Error("the newer sessions of the host were not read", "host_id", session.HostID, "err", err)
		return false
	}
	return open
}

// keepOwnership renews the session's claim on its host every jobs.
// OwnerRenewEvery until the stream ends.
func (s *AgentService) keepOwnership(ctx context.Context, session *Session) {
	ticker := time.NewTicker(jobs.OwnerRenewEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-session.Closed():
			return
		case <-ticker.C:
			err := s.jobs.RenewOwnership(ctx, session.HostID, session.ID, session.OwnerInstanceID,
				session.FenceToken, jobs.OwnerLeaseTTL)
			if errors.Is(err, jobs.ErrStaleFence) {
				metrics.SessionFence.Inc("renewal_lost")
				s.log.Info("the session no longer owns the host and is closed",
					"host_id", session.HostID, "session_id", session.ID, "fencing_token", session.FenceToken)
				session.End("superseded")
				return
			}
			if err != nil && ctx.Err() == nil {
				s.log.Error("the ownership of the host was not renewed",
					"host_id", session.HostID, "session_id", session.ID, "err", err)
			}
		}
	}
}

func (s *AgentService) closeSession(ctx context.Context, session *Session, hostID string) {
	// A session the panel ended keeps the reason it was ended with; one
	// the agent closed, or the link dropped, is a closed stream.
	reason := session.CloseReason()
	if reason == "" {
		reason = "stream_closed"
	}
	const query = `update agent_sessions set ended_at = now(), end_reason = $2
		where id = $1 and ended_at is null`
	if _, err := s.pool.Exec(ctx, query, session.ID, reason); err != nil {
		s.log.Error("the session was not closed", "session_id", session.ID, "err", err)
	}
	// The host is given up with the session; a session that was superseded
	// gives up nothing, because the row is the newer session's already.
	if session.FenceToken > 0 {
		if err := s.jobs.ReleaseOwnership(ctx, hostID, session.ID, session.FenceToken); err != nil &&
			!errors.Is(err, jobs.ErrStaleFence) {
			s.log.Error("the ownership of the host was not released", "host_id", hostID, "session_id", session.ID, "err", err)
		}
	}
	// A host is offline only when it has not managed to open a newer session.
	if _, active := s.registry.Get(hostID); !active && !s.newerSessionOpen(ctx, session) {
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

// refuseInventory records a report the panel would not take.
func (s *AgentService) refuseInventory(ctx context.Context, hostID, revision string, size int) {
	s.log.Warn("an inventory report was refused for its size",
		"host_id", hostID, "revision", revision, "size_bytes", size,
		"limit_bytes", inventory.MaxPayloadBytes)
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "inventory.oversized", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeDenied,
		Detail: map[string]any{
			"reason": "payload_too_large", "revision": revision,
			"size_bytes": size, "limit_bytes": inventory.MaxPayloadBytes,
		},
	})
}

func (s *AgentService) denied(ctx context.Context, hostID, reason string) {
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "agent.session.open", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeDenied, Detail: map[string]any{"reason": reason},
	})
	s.log.Warn("the session of the agent was rejected", "host_id", hostID, "reason", reason)
}

// refused is a denial the host page is to show: the trail entry as always, and
// the reason written on the host, so an operator looking at an offline machine
// sees why the gateway would not have it rather than a silence.
func (s *AgentService) refused(ctx context.Context, hostID, code, detail string) {
	s.denied(ctx, hostID, code)
	if _, err := s.hosts.RecordConnectionRefusal(ctx, hostID, code, detail); err != nil {
		s.log.Error("the refusal was not recorded on the host", "host_id", hostID, "reason", code, "err", err)
	}
}

// rejectStaleCertificate refuses a certificate outside its validity at the
// session layer, whatever the listener did with it.
func (s *AgentService) rejectStaleCertificate(ctx context.Context, cert *x509.Certificate) error {
	now := time.Now()
	var code, message string
	switch {
	case now.Before(cert.NotBefore):
		code = hosts.RefusalCertificateNotYetValid
		message = "the certificate is not valid before " + cert.NotBefore.UTC().Format(time.RFC3339)
	case now.After(cert.NotAfter):
		code = hosts.RefusalCertificateExpired
		message = "the certificate expired at " + cert.NotAfter.UTC().Format(time.RFC3339)
	default:
		return nil
	}
	detail := fmt.Sprintf("serial %s valid from %s to %s", cert.SerialNumber,
		cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
	if hostID, err := pki.HostIDFromCert(cert); err == nil {
		s.refused(ctx, hostID, code, detail)
	} else {
		s.log.Warn("a certificate outside its validity reached the session layer",
			"reason", code, "serial", cert.SerialNumber.String(), "subject", cert.Subject.CommonName)
	}
	return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("%s: %s", code, message))
}

// capabilitiesFromProto reads the registry of the adapters.
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
	// reconstructed registry has none either.
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
			ExpiresAt:         account.GetExpiresAt(),
			UnavailableReason: account.GetUnavailableReason(),
		})
	}
	return accounts
}

// accountSourceName maps the account source to the name used in the database
// and the API.
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

// The headers a relay attests a host's session with.
const (
	relayHostHeader            = "Flotestro-Relay-Host"
	relayHostFingerprintHeader = "Flotestro-Relay-Host-Fingerprint"
	relayHostSerialHeader      = "Flotestro-Relay-Host-Serial"
	// relayHostCertificateHeader carries the certificate itself, as DER in
	// base64.
	relayHostCertificateHeader = "Flotestro-Relay-Host-Certificate"
)

// RelayIdentityMode says what the gateway does with a session through a relay
// in which the host did not sign its own envelope: one the relay attests with
// the certificate it saw, or one the relay names the host alone in.
type RelayIdentityMode string

const (
	// RelayIdentityObserve lets a session without the host's envelope in, counts
	// it and marks the host as attested or weak: for an installation taking stock
	// of its relays and agents before asking anything.
	RelayIdentityObserve RelayIdentityMode = "observe"
	// RelayIdentityPrefer lets a session without the host's envelope in, counts
	// it, and marks the host as attested or weak so the operator sees which
	// relays and agents are due for an upgrade.
	RelayIdentityPrefer RelayIdentityMode = "prefer"
	// RelayIdentityEnforce requires the host's envelope on a relayed session: a
	// relay that names the host alone is refused as relay_identity_missing, and
	// an agent that does not sign behind a relay that attests as.
	RelayIdentityEnforce RelayIdentityMode = "enforce"
)

// ParseRelayIdentityMode reads the mode from configuration; empty is the
// packaged default.
func ParseRelayIdentityMode(value string) (RelayIdentityMode, error) {
	switch RelayIdentityMode(strings.ToLower(strings.TrimSpace(value))) {
	case "":
		return RelayIdentityPrefer, nil
	case RelayIdentityObserve:
		return RelayIdentityObserve, nil
	case RelayIdentityPrefer:
		return RelayIdentityPrefer, nil
	case RelayIdentityEnforce:
		return RelayIdentityEnforce, nil
	}
	return "", fmt.Errorf("unknown relay identity mode %q: observe, prefer or enforce", value)
}

// SetRelayIdentityMode sets what the gateway does with a relayed session
// without the certificate of the host.
func (s *AgentService) SetRelayIdentityMode(mode RelayIdentityMode) { s.relayIdentity = mode }

// hostAttestation is what a relay said about the certificate of the host
// it forwards: the fingerprint and the serial from the headers, decoded.
type hostAttestation struct {
	Fingerprint []byte
	Serial      string
	// Certificate is the certificate itself when the relay sent it, nil for a
	// relay from before it did.
	Certificate *x509.Certificate
}

// peer is who a session belongs to and on what grounds.
type peer struct {
	HostID  string
	RelayID string
	// Identity is how the host was identified through a relay - attested or weak
	// from the headers, end_to_end once the envelope verified - and empty for a
	// direct connection.
	Identity string
	// Relay is the relay and the host as the envelope verifier needs
	// them; zero for a direct connection.
	Relay RelayPeer
}

// identifyPeer establishes whose session it is and who vouches for it.
func (s *AgentService) identifyPeer(ctx context.Context, cert *x509.Certificate,
	headers http.Header) (peer, error) {
	asserted := headers.Get(relayHostHeader)
	if hostID, hostErr := pki.HostIDFromCert(cert); hostErr == nil {
		if asserted != "" {
			// An agent must not impersonate a relay: attesting somebody else's identity
			// is a permission of a relay rather than a header to be added.
			return peer{}, connect.NewError(connect.CodePermissionDenied,
				errors.New("the certificate of a host does not allow attesting other hosts"))
		}
		return peer{HostID: hostID}, nil
	}

	relayIdentity, relayErr := pki.RelayIDFromCert(cert)
	if relayErr != nil {
		return peer{}, connect.NewError(connect.CodeUnauthenticated, relayErr)
	}
	if s.relays == nil {
		return peer{}, connect.NewError(connect.CodePermissionDenied,
			errors.New("the mediation through a relay is not enabled"))
	}
	if asserted == "" {
		return peer{}, connect.NewError(connect.CodeInvalidArgument,
			errors.New("a relay has to name the host in the header "+relayHostHeader))
	}

	status, err := s.relays.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return peer{}, connect.NewError(connect.CodeInternal, err)
	}
	switch {
	case !status.Known:
		s.denied(ctx, relayIdentity, "unknown_relay_certificate")
		return peer{}, connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate of the relay is unknown"))
	case status.Revoked:
		s.denied(ctx, relayIdentity, "revoked_relay")
		return peer{}, connect.NewError(connect.CodeUnauthenticated, errors.New("the relay was revoked"))
	case status.ID != relayIdentity:
		s.denied(ctx, relayIdentity, "relay_identity_mismatch")
		return peer{}, connect.NewError(connect.CodeUnauthenticated, errors.New("the identity of the relay does not match the certificate"))
	}

	host, err := s.hosts.Get(ctx, asserted)
	if err != nil {
		s.denied(ctx, asserted, "relay_unknown_host")
		return peer{}, connect.NewError(connect.CodeUnauthenticated, errors.New("the host is unknown"))
	}
	// A relay mediates for its own site alone, and for its own environment when
	// it has one.
	if host.Site != status.Site {
		s.refused(ctx, asserted, hosts.RefusalRelayScopeMismatch,
			"relay "+status.Name+" serves site "+status.Site+", the host is in site "+host.Site)
		return peer{}, connect.NewError(connect.CodePermissionDenied,
			errors.New("the host does not belong to the site of the relay"))
	}
	if status.Environment != "" && host.Environment != status.Environment {
		s.refused(ctx, asserted, hosts.RefusalRelayScopeMismatch,
			"relay "+status.Name+" serves environment "+status.Environment+", the host is in environment "+host.Environment)
		return peer{}, connect.NewError(connect.CodePermissionDenied,
			errors.New("the host does not belong to the environment of the relay"))
	}
	if !hosts.Connectable(host.LifecycleState, host.LifecycleChangedAt, time.Now()) {
		s.denied(ctx, asserted, "lifecycle_"+host.LifecycleState)
		return peer{}, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("the host is in the state %s", host.LifecycleState))
	}

	attestation, err := readRelayAttestation(headers)
	if err != nil {
		s.refused(ctx, asserted, hosts.RefusalRelayIdentityInvalid, err.Error())
		return peer{}, connect.NewError(connect.CodeInvalidArgument, err)
	}
	relayPeer := RelayPeer{
		RelayID: status.ID, Site: status.Site, Environment: status.Environment,
		Revoked: status.Revoked, HostID: asserted,
	}
	if attestation == nil {
		// The relay named the host alone. Whether its word is enough is the
		// installation's decision; what it is not is invisible.
		if s.relayIdentity == RelayIdentityEnforce {
			s.refused(ctx, asserted, hosts.RefusalRelayIdentityMissing,
				"relay "+status.Name+" did not attest the certificate of the host; upgrade the relay")
			return peer{}, connect.NewError(connect.CodePermissionDenied,
				errors.New("the relay did not attest the certificate of the host"))
		}
		s.log.Warn("the relay named the host without its certificate; the session rests on the relay's word",
			"host_id", asserted, "relay_id", status.ID, "relay", status.Name,
			"mode", string(s.relayIdentity))
		return peer{HostID: asserted, RelayID: status.ID, Identity: hosts.RelayIdentityWeak, Relay: relayPeer}, nil
	}
	relayPeer.HostCertificate = attestation.Certificate

	// The certificate the host presented to the relay goes through the same
	// checks as one in a direct handshake: on record, not revoked, within its
	// validity, and the host's own.
	certificate, err := s.hosts.LookupCertificate(ctx, attestation.Fingerprint)
	if err != nil {
		return peer{}, connect.NewError(connect.CodeInternal, err)
	}
	if problem := s.rejectCertificate(ctx, certificate, asserted); problem != nil {
		return peer{}, problem
	}
	if attestation.Serial != "" && attestation.Serial != certificate.Serial {
		s.refused(ctx, asserted, hosts.RefusalRelayIdentityInvalid,
			"the relay names serial "+attestation.Serial+", the fingerprint is on record with serial "+certificate.Serial)
		return peer{}, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the serial named by the relay does not match the certificate"))
	}
	return peer{HostID: asserted, RelayID: status.ID, Identity: hosts.RelayIdentityAttested, Relay: relayPeer}, nil
}

// identifyCaller establishes whose unary call it is - a renewal, a secret
// fetch, a challenge - the way Connect establishes whose session it is.
func (s *AgentService) identifyCaller(ctx context.Context, headers http.Header) (peer, *x509.Certificate, error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return peer{}, nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no client certificate"))
	}
	if problem := s.rejectStaleCertificate(ctx, cert); problem != nil {
		return peer{}, nil, problem
	}
	who, err := s.identifyPeer(ctx, cert, headers)
	if err != nil {
		return peer{}, nil, err
	}
	if who.RelayID == "" {
		status, err := s.hosts.LookupCertificate(ctx, pki.Fingerprint(cert))
		if err != nil {
			return peer{}, nil, connect.NewError(connect.CodeInternal, err)
		}
		if problem := s.rejectCertificate(ctx, status, who.HostID); problem != nil {
			return peer{}, nil, problem
		}
	}
	return who, cert, nil
}

// readRelayAttestation decodes what the relay said about the certificate of
// the host.
func readRelayAttestation(headers http.Header) (*hostAttestation, error) {
	encoded := strings.TrimSpace(headers.Get(relayHostFingerprintHeader))
	serial := strings.TrimSpace(headers.Get(relayHostSerialHeader))
	certificate := strings.TrimSpace(headers.Get(relayHostCertificateHeader))
	if encoded == "" {
		if serial != "" || certificate != "" {
			return nil, errors.New("the relay named the certificate of the host without its fingerprint")
		}
		return nil, nil
	}
	fingerprint, err := hex.DecodeString(encoded)
	if err != nil || len(fingerprint) != sha256.Size {
		return nil, errors.New("the fingerprint named by the relay is not a SHA-256 in hex")
	}
	attestation := &hostAttestation{Fingerprint: fingerprint, Serial: serial}
	if certificate != "" {
		der, err := base64.StdEncoding.DecodeString(certificate)
		if err != nil {
			return nil, errors.New("the certificate presented by the relay is not DER in base64")
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("the certificate presented by the relay does not parse")
		}
		if sum := sha256.Sum256(parsed.Raw); subtle.ConstantTimeCompare(sum[:], fingerprint) != 1 {
			return nil, errors.New("the certificate presented by the relay is not the one of the fingerprint it named")
		}
		attestation.Certificate = parsed
	}
	return attestation, nil
}

// rejectCertificate checks the state of the certificate of a host for a
// direct connection.
func (s *AgentService) rejectCertificate(ctx context.Context,
	status hosts.CertificateStatus, hostID string) error {
	code, detail := certificateStatusRefusal(status, hostID, time.Now())
	if code == "" {
		return nil
	}
	if code == "lifecycle_"+hosts.StateRetired {
		// A retired host decommissioned while offline may have kept a valid
		// certificate when the operator chose not to revoke blind.
		s.revokeOnContact(ctx, hostID)
	}
	s.refused(ctx, hostID, code, detail)
	switch code {
	case hosts.RefusalUnknownCertificate:
		return connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate is unknown"))
	case hosts.RefusalRevokedCertificate:
		return connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate was revoked"))
	case hosts.RefusalIdentityMismatch:
		return connect.NewError(connect.CodeUnauthenticated, errors.New("the identity does not match the certificate"))
	default:
		return connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("the host is in the state %s", status.LifecycleState))
	}
}

// certificateStatusRefusal names the refusal of a certificate the handshake
// let through, from what the record says about it.
func certificateStatusRefusal(status hosts.CertificateStatus, hostID string, now time.Time) (code, detail string) {
	switch {
	case !status.Known:
		return hosts.RefusalUnknownCertificate, "no certificate of this fingerprint is on record"
	case status.Revoked:
		return hosts.RefusalRevokedCertificate, "serial " + status.Serial + " was revoked"
	case status.HostID != hostID:
		return hosts.RefusalIdentityMismatch, "serial " + status.Serial + " is on record for host " + status.HostID
	case !status.NotBefore.IsZero() && now.Before(status.NotBefore):
		// The validity from the record.
		return hosts.RefusalCertificateNotYetValid, "serial " + status.Serial + " is not valid before " +
			status.NotBefore.UTC().Format(time.RFC3339)
	case !status.NotAfter.IsZero() && now.After(status.NotAfter):
		return hosts.RefusalCertificateExpired, "serial " + status.Serial + " expired at " +
			status.NotAfter.UTC().Format(time.RFC3339)
	case !hosts.Connectable(status.LifecycleState, status.LifecycleChangedAt, now):
		// A quarantine, a withdrawal in progress and a withdrawal differ for the
		// operator, but for a connection they mean the same: this host has no right
		// to work.
		return "lifecycle_" + status.LifecycleState, "the host is " + status.LifecycleState
	}
	return "", ""
}

// revokeOnContact revokes the live certificates of a retired host that has
// just tried to connect.
func (s *AgentService) revokeOnContact(ctx context.Context, hostID string) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.log.Error("the certificates of the retired host were not revoked", "host_id", hostID, "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	revoked, err := s.hosts.RevokeCertificates(ctx, tx, hostID, "retired host made contact")
	if err == nil && revoked > 0 {
		err = s.audit.RecordTx(ctx, tx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: hostID,
			Action: "host.certificate.revoke", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"reason": "retired_host_contact", "certificates_revoked": revoked,
			},
		})
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		s.log.Error("the certificates of the retired host were not revoked", "host_id", hostID, "err", err)
		return
	}
	if revoked > 0 {
		s.log.Warn("a retired host made contact with a live certificate; it was revoked",
			"host_id", hostID, "revoked", revoked)
	}
}

// nullableRelay returns nil for a direct connection.
func nullableRelay(relayID string) any {
	if relayID == "" {
		return nil
	}
	return relayID
}

// CloseOrphanSessions closes the session rows this instance no longer keeps.
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
// while working.
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
// together with their configuration questions.
func spaceJSON(facts []*agentv1.SpaceFact) []map[string]any {
	out := make([]map[string]any, 0, len(facts))
	for _, fact := range facts {
		out = append(out, map[string]any{
			"path":            fact.GetPath(),
			"filesystem":      fact.GetFilesystem(),
			"available_bytes": fact.GetAvailableBytes(),
			"needed_bytes":    fact.GetNeededBytes(),
			"purpose":         fact.GetPurpose(),
			"basis":           fact.GetBasis(),
		})
	}
	return out
}

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
			"kind": blockKind(pkg.GetKind()),
		})
	}
	return result
}

// blockKind names the kind of a block, reading an agent that does not name
// one as the database fault every block used to be.
func blockKind(kind string) string {
	if kind == "" {
		return packagestore.BlockedDatabase
	}
	return kind
}

// databaseBlocks counts the blocks a repair would fix. An update no advisory
// classifies is not one: the database is intact.
func databaseBlocks(blocked []*agentv1.BlockedPackage) int {
	count := 0
	for _, pkg := range blocked {
		if blockKind(pkg.GetKind()) == packagestore.BlockedDatabase {
			count++
		}
	}
	return count
}

// packageDatabaseState reads the state of the package database out of the
// result of a job.
func packageDatabaseState(result *agentv1.TaskResult) (broken bool, known bool) {
	switch detail := result.GetDetail().(type) {
	case *agentv1.TaskResult_PackageApply:
		return detail.PackageApply.GetPackageDatabaseBroken(), true
	case *agentv1.TaskResult_PackagePlan:
		return databaseBlocks(detail.PackagePlan.GetBlocked()) > 0, true
	case *agentv1.TaskResult_PackageRepair:
		return databaseBlocks(detail.PackageRepair.GetStillBlocked()) > 0, true
	}
	return false, false
}

// followHostname keeps the name of the host in step with what the host reports
// for itself.
func (s *AgentService) followHostname(ctx context.Context, hostID string, report *agentv1.InventoryReport) {
	hostname := reportedHostname(report)
	if hostname == "" {
		return
	}
	previous, changed, err := s.hosts.Rename(ctx, hostID, hostname)
	if err != nil {
		s.log.Error("the hostname was not written after the inventory", "host_id", hostID, "err", err)
		return
	}
	if !changed {
		return
	}
	s.log.Info("the host reports a new name", "host_id", hostID, "previous", previous, "current", hostname)
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "host.renamed", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail:  map[string]any{"previous": previous, "current": hostname, "revision": report.GetRevision()},
	})
}

// followPlatform keeps the history of the kernels and releases a host was seen
// on.
func (s *AgentService) followPlatform(ctx context.Context, hostID string, report *agentv1.InventoryReport) {
	entry, ok := reportedPlatform(report)
	if !ok {
		return
	}
	created, err := s.hosts.RecordSystemHistory(ctx, hostID, entry)
	if err != nil {
		s.log.Error("the platform history was not written after the inventory", "host_id", hostID, "err", err)
		return
	}
	if created {
		s.log.Info("the host reports a platform not seen before",
			"host_id", hostID, "kernel", entry.Kernel,
			"distribution", entry.Distribution, "version", entry.DistributionVersion)
	}
}

// reportedPlatform reads the kernel and the release from the system module of
// a report.
func reportedPlatform(report *agentv1.InventoryReport) (hosts.SystemHistoryEntry, bool) {
	var facts struct {
		OS struct {
			Kernel       string `json:"kernel"`
			Distribution string `json:"distribution"`
			Version      string `json:"version"`
		} `json:"os"`
	}
	for _, fragment := range report.GetFragments() {
		if fragment.GetModule() != "system" || fragment.GetUnavailableReason() != "" {
			continue
		}
		if err := json.Unmarshal(fragment.GetPayload(), &facts); err != nil {
			return hosts.SystemHistoryEntry{}, false
		}
		if facts.OS.Kernel == "" && facts.OS.Distribution == "" {
			return hosts.SystemHistoryEntry{}, false
		}
		seen := time.Now().UTC()
		if observed := fragment.GetObservedAt(); observed != nil {
			seen = observed.AsTime().UTC()
		}
		return hosts.SystemHistoryEntry{
			Kernel:              facts.OS.Kernel,
			Distribution:        facts.OS.Distribution,
			DistributionVersion: facts.OS.Version,
			FirstSeenAt:         seen,
			LastSeenAt:          seen,
		}, true
	}
	return hosts.SystemHistoryEntry{}, false
}

// reportedHostname reads the name from the system module of a report.
func reportedHostname(report *agentv1.InventoryReport) string {
	var facts struct {
		Hostname string `json:"hostname"`
	}
	for _, fragment := range report.GetFragments() {
		if fragment.GetModule() != "system" || fragment.GetUnavailableReason() != "" {
			continue
		}
		if err := json.Unmarshal(fragment.GetPayload(), &facts); err == nil {
			return strings.TrimSpace(facts.Hostname)
		}
	}
	if err := json.Unmarshal(report.GetRawJson(), &facts); err == nil {
		return strings.TrimSpace(facts.Hostname)
	}
	return ""
}

// smartResultJSON turns a SMART report into the form the interface reads.
func smartResultJSON(smart *agentv1.SmartResult) map[string]any {
	attributes := make([]map[string]any, 0, len(smart.GetAttributes()))
	for _, attribute := range smart.GetAttributes() {
		attributes = append(attributes, map[string]any{
			"id":         attribute.GetId(),
			"name":       attribute.GetName(),
			"value":      attribute.GetValue(),
			"worst":      attribute.GetWorst(),
			"threshold":  attribute.GetThreshold(),
			"raw":        attribute.GetRaw(),
			"raw_string": attribute.GetRawString(),
			"failing":    attribute.GetFailing(),
		})
	}
	encoded := map[string]any{
		"kind":               "smart",
		"device":             smart.GetDevice(),
		"model":              smart.GetModel(),
		"serial":             smart.GetSerial(),
		"health":             smart.GetHealth(),
		"health_reason":      smart.GetHealthReason(),
		"attributes":         attributes,
		"unsupported":        smart.GetUnsupported(),
		"unsupported_reason": smart.GetUnsupportedReason(),
		"output":             smart.GetOutput(),
	}
	if smart.TemperatureC != nil {
		encoded["temperature_c"] = smart.GetTemperatureC()
	}
	if smart.PowerOnHours != nil {
		encoded["power_on_hours"] = smart.GetPowerOnHours()
	}
	if smart.ReallocatedSectors != nil {
		encoded["reallocated_sectors"] = smart.GetReallocatedSectors()
	}
	if smart.PendingSectors != nil {
		encoded["pending_sectors"] = smart.GetPendingSectors()
	}
	if smart.WearPercent != nil {
		encoded["wear_percent"] = smart.GetWearPercent()
	}
	return encoded
}

// fragmentsFromReport reads the modules of a report.
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

// unitStatesJSON turns the unit states into the form the interface reads.
func unitStatesJSON(states []*agentv1.UnitState) []map[string]any {
	result := make([]map[string]any, 0, len(states))
	for _, state := range states {
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
func (s *AgentService) saveFileState(ctx context.Context, hostID, jobID string, restored []byte) {
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
	// panel: the desired state is the name of the secret and its version.
	if !payload.File.ContentSecret.Empty() {
		state.SecretName = payload.File.ContentSecret.Name
		state.SecretVersion = payload.File.ContentSecret.Version
		if state.SecretVersion == 0 {
			state.SecretVersion = versionFromLease(ctx, s, jobID, state.SecretName)
		}
	} else {
		content := []byte(payload.File.Content)
		if len(content) == 0 && payload.File.VersionSHA256 != "" {
			// A return to a version only the host kept: the panel had no copy to send,
			// so what it records is the content the host put back.
			content = restored
		}
		digest, err := s.files.SaveVersion(ctx, s.pool, content)
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
	deployment := certstore.Deployment{
		HostID:            hostID,
		Path:              payload.Certificate.Path,
		FingerprintSHA256: result.GetFingerprintSha256(),
		JobID:             jobID,
		DeployedBy:        job.CreatedBy,
	}
	if notAfter, err := time.Parse(time.RFC3339, result.GetNotAfter()); err == nil {
		deployment.NotAfter = &notAfter
	}
	// The content is recorded only for a deployment from the panel: a renewal is
	// done by a daemon of the host and the panel does not know the certificate
	// that came out of it.
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
func (s *AgentService) savePackageList(ctx context.Context, hostID, jobID string,
	result *agentv1.InstalledPackagesResult) {
	state := vuln.PackageListState{
		HostID: hostID, Digest: result.GetDigest(),
		PackageCount: int(result.GetCount()), JobID: jobID,
		UnavailableReason: result.GetUnavailableReason(),
	}
	now := time.Now().UTC()
	state.CollectedAt = &now

	var pkgs []packagestore.InstalledPackage
	if len(result.GetPackages()) > 0 {
		if err := json.Unmarshal(result.GetPackages(), &pkgs); err != nil {
			s.log.Error("the package list was not recognised", "host_id", hostID, "err", err)
			return
		}
	}
	if state.UnavailableReason != "" {
		// A host whose list could not be read is not left with an old list
		// pretending to be current: we delete the rows and record the reason.
		pkgs = nil
		state.PackageCount = 0
	}

	// The vendor findings known to the host are written together with the list:
	// they come from the same read and describe the same moment.
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

	// The assessment is to keep up with what settles it.
	if s.refreshAssessment != nil {
		s.refreshAssessment(hostID)
	}
}

// advisoriesFromResult unpacks the vendor findings out of the result of a
// read.
func advisoriesFromResult(result *agentv1.InstalledPackagesResult,
	now time.Time) ([]vuln.HostAdvisory, string) {
	if reason := result.GetAdvisoriesUnavailableReason(); reason != "" {
		return nil, reason
	}
	if len(result.GetAdvisories()) == 0 {
		return nil, ""
	}
	var gathered []packagestore.Advisory
	if err := json.Unmarshal(result.GetAdvisories(), &gathered); err != nil {
		// The metadata could not be recognised. An empty list would mean here "the
		// host has no vendor findings at all" - that is, something nobody checked.
		return nil, vuln.ReasonHostAdvisoriesUnreadable
	}
	var advisories []vuln.HostAdvisory
	for _, advisory := range gathered {
		// A finding without a CVE is normal: the vendor does not always assign one.
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

// checkRefresh confirms that the revision reported by the agent is the one the
// panel really has.
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
