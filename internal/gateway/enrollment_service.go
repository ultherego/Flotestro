package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/enrollment"
	"github.com/ultherego/flotestro/internal/events"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/issuer"
	"github.com/ultherego/flotestro/internal/relays"
)

// EnrollmentService accepts the hosts that have no identity yet. It is the
// only endpoint available without a client certificate.
type EnrollmentService struct {
	// certIssuer signs the identity certificates.
	certIssuer issuer.Issuer
	relays     *relays.Store
	hosts      *hosts.Store
	tokens     *enrollment.Store
	audit      *audit.Recorder
	log        *slog.Logger
	// The limits of the public door: per source address and per machine
	// identifier, so neither a guessing client nor a looping installer gets more
	// than a few attempts a minute.
	perIP      *rateLimiter
	perMachine *rateLimiter
	// helperSigner signs the trust bundle a new host hands to its root helper:
	// the host identifier and the panel's capability keys.
	helperSigner *helpercap.Signer
}

// SetHelperSigner connects the capability key.
func (s *EnrollmentService) SetHelperSigner(signer *helpercap.Signer) { s.helperSigner = signer }

// helperTrustFor is the signed keyring for one host, or nil on a panel
// without a signing key.
func (s *EnrollmentService) helperTrustFor(hostID string) *helperv1.HelperTrustBundle {
	if s.helperSigner == nil {
		return nil
	}
	return s.helperSigner.TrustBundle(hostID, time.Now())
}

func NewEnrollmentService(certIssuer issuer.Issuer, hostStore *hosts.Store,
	relayStore *relays.Store, tokens *enrollment.Store, recorder *audit.Recorder,
	log *slog.Logger) *EnrollmentService {
	return &EnrollmentService{certIssuer: certIssuer, hosts: hostStore, relays: relayStore,
		tokens: tokens, audit: recorder, log: log,
		perIP:      newRateLimiter(enrollPerIPPerMinute),
		perMachine: newRateLimiter(enrollPerMachinePerMinute)}
}

// ErrTooManyAttempts is the answer of the public door to a client that
// knocks too often. It says nothing about the token.
var ErrTooManyAttempts = errors.New("too many enrollment attempts; try again in a minute")

// throttle applies the limits of the public door.
func (s *EnrollmentService) throttle(ctx context.Context, req *connect.Request[agentv1.EnrollRequest]) error {
	ip := peerHost(req.Peer().Addr)
	machineID := req.Msg.GetMachineId()
	checks := []struct {
		limiter *rateLimiter
		key     string
		kind    string
	}{
		{s.perIP, ip, "source_ip"},
		{s.perMachine, machineID, "machine_id"},
	}
	for _, check := range checks {
		if check.key == "" {
			continue
		}
		allowed, record := check.limiter.allow(check.key)
		if allowed {
			continue
		}
		if record {
			s.audit.Record(ctx, audit.Event{
				ActorType: audit.ActorAgent, ActorID: machineID,
				Action: "host.enroll", Outcome: audit.OutcomeDenied,
				Detail: map[string]any{
					"reason": "rate_limited", "limit": check.kind, "remote_addr": ip,
					"hostname": req.Msg.GetHostname(),
				},
			})
			s.log.Warn("enrollment attempts are being throttled",
				"limit", check.kind, "remote_addr", ip, "machine_id", machineID)
		}
		return connect.NewError(connect.CodeResourceExhausted, ErrTooManyAttempts)
	}
	return nil
}

// peerHost strips the port off a peer address. A limit per address has to
// key on the address alone: every connection has a port of its own.
func peerHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// relayAttestation describes the relay that forwarded the registration of a
// host.
type relayAttestation struct {
	ID   string
	Site string
	Name string
}

// Enroll exchanges a valid token and a CSR for the certificate of an agent.
func (s *EnrollmentService) Enroll(ctx context.Context,
	req *connect.Request[agentv1.EnrollRequest]) (*connect.Response[agentv1.EnrollResponse], error) {
	if err := s.throttle(ctx, req); err != nil {
		return nil, err
	}
	response, err := s.enrollThroughRelay(ctx, req.Msg, relayAttestation{})
	if err == nil {
		// The address paid for a guess and made none: a fleet behind one NAT
		// registers at the panel's pace, not at ten hosts a minute.
		s.perIP.refund(peerHost(req.Peer().Addr))
	}
	return response, err
}

// enrollThroughRelay handles the registration of a host.
func (s *EnrollmentService) enrollThroughRelay(ctx context.Context,
	msg *agentv1.EnrollRequest, viaRelay relayAttestation,
) (*connect.Response[agentv1.EnrollResponse], error) {
	if msg.GetMachineId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("machine_id is missing"))
	}
	if len(msg.GetCsrPem()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the CSR is missing"))
	}

	tx, err := s.hosts.Pool().Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	attempt := enrollment.AttemptInput{
		Token:           msg.GetEnrollmentToken(),
		MachineID:       msg.GetMachineId(),
		ClientRequestID: msg.GetClientRequestId(),
		CSR:             msg.GetCsrPem(),
	}
	result, err := s.tokens.Redeem(ctx, tx, attempt)
	if err != nil {
		if errors.Is(err, enrollment.ErrInvalidToken) {
			// A refusal is an audit event just as a success is.
			var denial *enrollment.Denial
			if !errors.As(err, &denial) {
				denial = &enrollment.Denial{Code: "invalid_token"}
			}
			s.deny(ctx, msg, denial.RequestID, denial.Code, denialMessage(denial.Code), nil)
			return nil, connect.NewError(connect.CodePermissionDenied, enrollment.ErrInvalidToken)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	scope := result.Scope

	// The route of a registration is part of the scope rather than a detail of
	// the network.
	if err := checkRoute(scope, viaRelay); err != nil {
		s.deny(ctx, msg, scope.TokenID, enrollment.DenialRelayScope, err.Error(),
			map[string]any{"relay_id": nullableRelay(viaRelay.ID)})
		return nil, connect.NewError(connect.CodePermissionDenied, enrollment.ErrInvalidToken)
	}

	// A repeat of an attempt whose answer was lost in the network: the agent gets
	// the same certificate that has already been issued for it.
	if replayed := result.Replay; replayed != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
			Action: "host.enroll", TargetType: "host", TargetID: replayed.HostID,
			Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"replay": true, "token_id": scope.TokenID,
				"cert_serial": replayed.CertificateSerial,
			},
		})
		s.log.Info("a repeated enrollment attempt", "host_id", replayed.HostID,
			"machine_id", msg.GetMachineId())
		return connect.NewResponse(&agentv1.EnrollResponse{
			HostId:         replayed.HostID,
			CertificatePem: replayed.CertificatePEM,
			CaBundlePem:    replayed.CABundlePEM,
			HelperTrust:    s.helperTrustFor(replayed.HostID),
		}), nil
	}

	// The token settles what comes into being.
	if scope.Kind == enrollment.KindRelay {
		return s.enrollRelay(ctx, tx, msg, scope)
	}

	// The purpose of the order settles what may be done with a machine the panel
	// already knows.
	if err := s.checkPurpose(ctx, tx, msg, scope); err != nil {
		s.deny(ctx, msg, scope.TokenID, purposeDenialCode(err), err.Error(),
			map[string]any{"purpose": scope.Purpose})
		return nil, connect.NewError(connect.CodePermissionDenied, enrollment.ErrInvalidToken)
	}

	build := msg.GetBuild()
	identity := hosts.Identity{
		MachineID:    msg.GetMachineId(),
		Hostname:     msg.GetHostname(),
		Site:         scope.Site,
		Environment:  scope.Environment,
		OSFamily:     build.GetOsFamily(),
		OSVersion:    build.GetOsVersion(),
		Architecture: build.GetArchitecture(),
		AgentVersion: build.GetAgentVersion(),
	}
	var (
		hostID  string
		created bool
	)
	if scope.Purpose == enrollment.PurposeReplace {
		// Recovering an identity does not create a new host: a reinstalled
		// machine comes back to the same row, with the same history.
		hostID = scope.ExpectedHostID
		if err := s.hosts.AdoptMachine(ctx, tx, hostID, identity); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	} else {
		hostID, created, err = s.hosts.Upsert(ctx, tx, identity)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	// The owner and the tags of the order land with the host row: the operator
	// wrote them when ordering the installation, so the host is somebody's and
	// tagged from its first second in the fleet.
	if err := s.hosts.ApplyEnrollmentFacts(ctx, tx, hostID, scope.Owner, scope.Tags); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	issued, err := s.certIssuer.SignHost(ctx, msg.GetCsrPem(), hostID)
	if err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
			Action: "host.enroll", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
		// The order is what the operator watches: a refused CSR is to show up on the
		// installation screen, not only under a host that does not exist yet.
		s.deny(ctx, msg, scope.TokenID, enrollment.DenialCSRInvalid,
			"the certificate request was refused", map[string]any{"host_id": hostID})
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// The trust bundle goes in the same answer as the certificate: without it
	// the host does not know whom to trust and will not establish a session.
	trust, err := s.certIssuer.Trust(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := s.hosts.SaveCertificate(ctx, tx, hostID, issued.Serial, issued.CommonName,
		issued.Fingerprint, issued.NotBefore, issued.NotAfter,
		issued.IssuerSubject, issued.IssuerSerial, issued.IssuerID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// The public key goes on the record with the certificate: the envelopes
	// of the host's sessions through a relay are checked against it.
	if der, err := publicKeyDER(issued.PEM); err != nil {
		s.log.Error("the public key of the issued certificate was not read", "host_id", hostID, "err", err)
	} else if err := s.hosts.RecordCertificatePublicKey(ctx, tx, issued.Serial, der); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// The attempt is written in the same transaction as the host and the
	// certificate: a write after the commit might not arrive, and the idempotence
	// would then be only apparent.
	if err := s.tokens.RecordAttempt(ctx, tx, scope.TokenID, attempt, enrollment.Replay{
		HostID: hostID, CertificatePEM: issued.PEM, CABundlePEM: trust,
		CertificateSerial: issued.Serial,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := s.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
		Action: "host.enroll", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"created":       created,
			"purpose":       scope.Purpose,
			"hostname":      msg.GetHostname(),
			"site":          scope.Site,
			"environment":   scope.Environment,
			"token_id":      scope.TokenID,
			"cert_serial":   issued.Serial,
			"agent_version": build.GetAgentVersion(),
		},
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// The screen of the order is told in the same transaction: the notification
	// leaves with the commit and never for a registration that was rolled back.
	s.announce(ctx, tx, events.EnrollmentChange{
		RequestID: scope.TokenID, Change: events.EnrollmentRedeemed,
		Site: scope.Site, Environment: scope.Environment,
		Kind: enrollment.KindAgent, HostID: hostID,
	})

	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.log.Info("the host was registered",
		"host_id", hostID, "hostname", msg.GetHostname(), "site", scope.Site, "created", created)

	return connect.NewResponse(&agentv1.EnrollResponse{
		HostId:         hostID,
		CertificatePem: issued.PEM,
		CaBundlePem:    trust,
		NotAfter:       timestamppb.New(issued.NotAfter),
		// The helper of the new host takes its identity and the panel's capability
		// keys from this bundle, signed, rather than from what the agent says about
		// itself.
		HelperTrust: s.helperTrustFor(hostID),
	}), nil
}

// enrollRelay registers the relay of a site and issues a certificate for it.
func (s *EnrollmentService) enrollRelay(ctx context.Context, tx pgx.Tx,
	msg *agentv1.EnrollRequest, scope enrollment.Scope,
) (*connect.Response[agentv1.EnrollResponse], error) {
	name := msg.GetHostname()
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("a relay requires a name"))
	}

	relayID, err := s.relays.Upsert(ctx, tx, name, scope.Site, scope.Environment)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	issued, err := s.certIssuer.SignRelay(ctx, msg.GetCsrPem(), relayID, nil)
	if err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: name,
			Action: "relay.enroll", TargetType: "relay", TargetID: relayID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
		s.deny(ctx, msg, scope.TokenID, enrollment.DenialCSRInvalid,
			"the certificate request was refused", map[string]any{"relay_id": relayID})
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	trust, err := s.certIssuer.Trust(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.relays.SaveCertificate(ctx, tx, relayID, issued.Serial,
		issued.Fingerprint, issued.NotAfter); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// The network names from the first CSR become a record in the registry.
	if err := s.relays.SaveNames(ctx, tx, relayID, networkNames(issued)); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := s.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: name,
		Action: "relay.enroll", TargetType: "relay", TargetID: relayID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"name": name, "site": scope.Site, "environment": scope.Environment,
			"token_id": scope.TokenID, "cert_serial": issued.Serial,
		},
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.announce(ctx, tx, events.EnrollmentChange{
		RequestID: scope.TokenID, Change: events.EnrollmentRedeemed,
		Site: scope.Site, Environment: scope.Environment,
		Kind: enrollment.KindRelay, HostID: relayID,
	})
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.log.Info("the relay was registered", "relay_id", relayID, "name", name, "site", scope.Site)
	return connect.NewResponse(&agentv1.EnrollResponse{
		HostId:         relayID,
		CertificatePem: issued.PEM,
		CaBundlePem:    trust,
		NotAfter:       timestamppb.New(issued.NotAfter),
	}), nil
}

// checkPurpose guards that the order matches what is really happening. The
// distinction is the whole point of this function.
func (s *EnrollmentService) checkPurpose(ctx context.Context, tx pgx.Tx,
	msg *agentv1.EnrollRequest, scope enrollment.Scope) error {
	existing, err := s.hosts.IDByMachineID(ctx, tx, msg.GetMachineId())
	if err != nil {
		return err
	}
	switch scope.Purpose {
	case enrollment.PurposeNew:
		if existing != "" {
			// A retired host holds its machine identifier for the retention period: the
			// machine that left the fleet does not come back as a new host on the
			// strength of a token alone.
			retired, until, err := s.hosts.RetiredMachine(ctx, tx, existing)
			if err != nil {
				return err
			}
			if !retired {
				return errors.New("machine_id_known")
			}
			if time.Now().Before(until) {
				return errors.New(enrollment.DenialMachineRetired)
			}
			if err := s.hosts.ReleaseMachineID(ctx, tx, existing); err != nil {
				return err
			}
			s.log.Info("a retired host released its machine identifier to a new enrollment",
				"retired_host_id", existing, "machine_id", msg.GetMachineId())
		}
	case enrollment.PurposeReplace:
		if scope.ExpectedHostID == "" {
			return errors.New("recovery_without_host")
		}
		// A withdrawn host does not come back to the fleet through a recovery of its
		// identity.
		host, err := s.hosts.Get(ctx, scope.ExpectedHostID)
		if err != nil {
			return err
		}
		if host == nil {
			return errors.New("recovery_host_missing")
		}
		if host.LifecycleState == hosts.StateRetired {
			return errors.New("host_retired")
		}
		// A machine unknown to the panel is fine here: after a reinstall a host has
		// a new machine_id, and we recover the identity by the named host_id.
		if existing != "" && existing != scope.ExpectedHostID {
			return errors.New("machine_id_other_host")
		}
	case enrollment.PurposeRelay:
		return errors.New("relay_purpose_for_host")
	default:
		return errors.New("unknown_purpose")
	}
	return nil
}

// deny records a refused attempt against the order it was made with.
func (s *EnrollmentService) deny(ctx context.Context, msg *agentv1.EnrollRequest,
	requestID, code, message string, extra map[string]any) {
	detail := map[string]any{
		"reason": code, "message": message, "hostname": msg.GetHostname(),
	}
	for key, value := range extra {
		detail[key] = value
	}
	event := audit.Event{
		ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
		Action: "host.enroll", Outcome: audit.OutcomeDenied, Detail: detail,
	}
	if requestID != "" {
		detail["token_id"] = requestID
		event.TargetType, event.TargetID = "enrollment_request", requestID
	}
	s.audit.Record(ctx, event)
	// The order's screen hears of the refusal at once.
	if requestID == "" || s.hosts == nil {
		return
	}
	change := events.EnrollmentChange{RequestID: requestID, Change: events.EnrollmentRefused, Code: code}
	if order, err := s.tokens.Request(ctx, requestID); err == nil && order != nil {
		change.Site, change.Environment, change.Kind = order.Site, order.Environment, order.Kind
	}
	s.announce(ctx, s.hosts.Pool(), change)
}

// announce tells the open screens that an order turned.
func (s *EnrollmentService) announce(ctx context.Context, through events.Notifier, change events.EnrollmentChange) {
	if err := events.PublishEnrollment(ctx, through, change); err != nil {
		s.log.Debug("the turn of an installation order was not announced",
			"request_id", change.RequestID, "change", change.Change, "err", err)
	}
}

// denialMessage puts a token refusal into words the operator can act on.
func denialMessage(code string) string {
	switch code {
	case enrollment.DenialTokenExpired:
		return "the token expired before the host used it"
	case enrollment.DenialTokenRevoked:
		return "the order was revoked before the host used it"
	case enrollment.DenialRequestReused:
		return "the order was already used up; another host needs another order"
	case enrollment.DenialMachineMismatch:
		return "the machine is not the one the order was bound to"
	case enrollment.DenialTokenUnknown:
		return "the token matched no order"
	case enrollment.DenialMachineRetired:
		return "the machine belongs to a retired host and is held back; a new-host token does not fit it yet"
	default:
		return "the token was refused"
	}
}

// purposeDenialCode names a purpose refusal the way the installation screen
// does.
func purposeDenialCode(err error) string {
	switch err.Error() {
	case "machine_id_known", "machine_id_other_host":
		return enrollment.DenialDuplicateMachine
	default:
		return err.Error()
	}
}

// networkNames gathers the names the panel issued in the certificate of a
// relay.
func networkNames(issued *issuer.Certificate) []string {
	names := append([]string{}, issued.DNSNames...)
	return append(names, issued.IPAddresses...)
}

// checkRoute guards that a registration arrived over a path the order allows.
// A relay terminates TLS, so it sees the token of its site.
func checkRoute(scope enrollment.Scope, viaRelay relayAttestation) error {
	if viaRelay.ID == "" {
		// A direct registration. An order tied to a relay must not go this
		// way: otherwise the tie would mean nothing.
		if scope.RelayID != "" {
			return errors.New("the order requires a registration through a relay")
		}
		return nil
	}
	if scope.RelayID != "" && scope.RelayID != viaRelay.ID {
		return errors.New("the order belongs to another relay")
	}
	if scope.Site != "" && viaRelay.Site != "" && scope.Site != viaRelay.Site {
		return errors.New("the order belongs to another site")
	}
	return nil
}
