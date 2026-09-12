package gateway

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/enrollment"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/issuer"
	"github.com/ultherego/flotestro/internal/relays"
)

// EnrollmentService accepts the hosts that have no identity yet. It is the
// only endpoint available without a client certificate.
type EnrollmentService struct {
	// certIssuer signs the identity certificates. An interface rather than an
	// authority: moving the CA key into an HSM is to change the
	// implementation rather than this service and the protocol of the
	// agent.
	certIssuer issuer.Issuer
	relays     *relays.Store
	hosts      *hosts.Store
	tokens     *enrollment.Store
	audit      *audit.Recorder
	log        *slog.Logger
}

func NewEnrollmentService(certIssuer issuer.Issuer, hostStore *hosts.Store,
	relayStore *relays.Store, tokens *enrollment.Store, recorder *audit.Recorder,
	log *slog.Logger) *EnrollmentService {
	return &EnrollmentService{certIssuer: certIssuer, hosts: hostStore, relays: relayStore,
		tokens: tokens, audit: recorder, log: log}
}

// relayAttestation describes the relay that forwarded the registration of a
// host.
//
// Empty means a direct registration. The distinction matters: a token tied to
// a site must not work outside it, and a token without a tie works the same
// way over both paths.
type relayAttestation struct {
	ID   string
	Site string
	Name string
}

// Enroll exchanges a valid token and a CSR for the certificate of an agent.
func (s *EnrollmentService) Enroll(ctx context.Context,
	req *connect.Request[agentv1.EnrollRequest]) (*connect.Response[agentv1.EnrollResponse], error) {
	return s.enrollThroughRelay(ctx, req.Msg, relayAttestation{})
}

// enrollThroughRelay handles the registration of a host. The whole operation
// is one transaction: the token, the host, the certificate and the audit event
// either come into being together or not at all.
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
			// A refusal is an audit event just as a success is. The reason
			// stays in the audit of the server; the agent always gets the same
			// answer, so that tokens cannot be guessed from it.
			s.audit.Record(ctx, audit.Event{
				ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
				Action: "host.enroll", Outcome: audit.OutcomeDenied,
				Detail: map[string]any{"reason": "invalid_token", "hostname": msg.GetHostname()},
			})
			return nil, connect.NewError(connect.CodePermissionDenied, enrollment.ErrInvalidToken)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	scope := result.Scope

	// The route of a registration is part of the scope rather than a detail of
	// the network. A token tied to a relay and carried to another site must
	// not register anything; a token without a tie works the same way over
	// both paths.
	if err := checkRoute(scope, viaRelay); err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
			Action: "host.enroll", Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": err.Error(), "token_id": scope.TokenID,
				"relay_id": nullableRelay(viaRelay.ID), "hostname": msg.GetHostname(),
			},
		})
		return nil, connect.NewError(connect.CodePermissionDenied, enrollment.ErrInvalidToken)
	}

	// A repeat of an attempt whose answer was lost in the network: the agent
	// gets the same certificate that has already been issued for it. Nothing
	// is used up and nothing comes into being a second time.
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
		}), nil
	}

	// The token settles what comes into being. Registering a relay with a
	// token issued for an agent would be a silent change of a trust boundary:
	// a relay terminates the sessions of the agents and attests their
	// identity.
	if scope.Kind == enrollment.KindRelay {
		return s.enrollRelay(ctx, tx, msg, scope)
	}

	// The purpose of the order settles what may be done with a machine the
	// panel already knows. Without it every token would be a key to taking
	// over the identity of a running host.
	if err := s.checkPurpose(ctx, tx, msg, scope); err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
			Action: "host.enroll", Outcome: audit.OutcomeDenied,
			Detail: map[string]any{
				"reason": err.Error(), "purpose": scope.Purpose,
				"hostname": msg.GetHostname(), "token_id": scope.TokenID,
			},
		})
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

	issued, err := s.certIssuer.SignHost(ctx, msg.GetCsrPem(), hostID)
	if err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
			Action: "host.enroll", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
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
		issued.IssuerSubject, issued.IssuerSerial); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// The attempt is written in the same transaction as the host and the
	// certificate: a write after the commit might not arrive, and the
	// idempotence would then be only apparent.
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
	}), nil
}

// enrollRelay registers the relay of a site and issues a certificate for it.
//
// A relay gets an identity of a kind other than a host: the panel reads the
// kind from the URI SAN, so a certificate of a relay cannot impersonate an
// agent or the other way round. The scope of a relay comes from the token and
// limits which hosts it may mediate for.
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
	// From then on the panel says which names the relay attests; a renewal
	// does not change them.
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

// checkPurpose guards that the order matches what is really happening.
//
// The distinction is the whole point of this function. "A new host" means a
// machine the panel does not know: a token with that purpose must not take
// over the identity of a running machine, even when somebody gives its
// machine_id. "A replacement of an identity" means the specific host named
// when ordering - and only it.
func (s *EnrollmentService) checkPurpose(ctx context.Context, tx pgx.Tx,
	msg *agentv1.EnrollRequest, scope enrollment.Scope) error {
	existing, err := s.hosts.IDByMachineID(ctx, tx, msg.GetMachineId())
	if err != nil {
		return err
	}
	switch scope.Purpose {
	case enrollment.PurposeNew:
		if existing != "" {
			return errors.New("machine_id_known")
		}
	case enrollment.PurposeReplace:
		if scope.ExpectedHostID == "" {
			return errors.New("recovery_without_host")
		}
		// A withdrawn host does not come back to the fleet through a recovery
		// of its identity. The loss of trust is a decision of the operator and
		// is taken back in the panel rather than with a token on the host.
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
		// A machine unknown to the panel is fine here: after a reinstall a
		// host has a new machine_id, and we recover the identity by the named
		// host_id. A known machine has to be the same host.
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

// networkNames gathers the names the panel issued in the certificate of a
// relay.
//
// The source is the issued certificate rather than the request: it is the
// certificate that settles what the relay really attests towards the agents of
// its site.
func networkNames(issued *issuer.Certificate) []string {
	names := append([]string{}, issued.DNSNames...)
	return append(names, issued.IPAddresses...)
}

// checkRoute guards that a registration arrived over a path the order allows.
//
// A relay terminates TLS, so it sees the token of its site. That is the price
// of registering in an isolated site, and that is why the scope of a token is
// to be narrow: an order tied to a relay works through it alone, and an order
// of a site does not pass through the relay of another site.
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
