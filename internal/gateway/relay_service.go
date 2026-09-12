package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/issuer"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relays"
)

// RelayService serves the relays of the sites.
//
// It is a separate service, because a relay is a separate trust boundary. The
// certificate of a relay lives shorter than that of a host and has a server
// role towards the agents of its site, so a renewal has to check something
// other than the renewal of a host. A shared RPC would mean one set of
// conditions for two different permissions.
type RelayService struct {
	relays     *relays.Store
	certIssuer issuer.Issuer
	audit      *audit.Recorder
	registry   *Registry
	// enrollment serves the registrations of hosts from isolated sites. A
	// relay signs nothing itself, so a registration goes to the same service
	// that serves direct connections - with one difference: it is known which
	// relay attests it.
	enrollment *EnrollmentService
	log        *slog.Logger
}

func NewRelayService(relayStore *relays.Store, certIssuer issuer.Issuer,
	recorder *audit.Recorder, registry *Registry,
	enrollmentService *EnrollmentService, log *slog.Logger) *RelayService {
	return &RelayService{
		relays: relayStore, certIssuer: certIssuer, audit: recorder,
		registry: registry, enrollment: enrollmentService, log: log,
	}
}

// ProxyEnroll accepts the registration of a host forwarded by a relay.
//
// A host in an isolated site does not see the centre and registers through a
// relay. A relay terminates TLS, so it sees the token; that is why the
// registration goes over its mTLS channel rather than over the public
// endpoint. The centre then checks two things the public endpoint cannot:
// whether the order belongs to the site of this relay and whether it is not
// tied to another relay.
func (s *RelayService) ProxyEnroll(ctx context.Context,
	req *connect.Request[agentv1.ProxyEnrollRequest],
) (*connect.Response[agentv1.EnrollResponse], error) {
	if s.enrollment == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("this installation does not accept registrations through a relay"))
	}
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("no client certificate"))
	}
	relayID, err := pki.RelayIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	status, err := s.relays.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !status.Known || status.Revoked || status.ID != relayID {
		s.refuse(ctx, relayID, "relay_not_active")
		return nil, connect.NewError(connect.CodeUnauthenticated,
			fmt.Errorf("the relay %s is not active", relayID))
	}
	registration := req.Msg.GetEnrollment()
	if registration == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the registration of the host is missing"))
	}
	s.relays.MarkSeen(ctx, relayID)

	return s.enrollment.enrollThroughRelay(ctx, registration, relayAttestation{
		ID: relayID, Site: status.Site, Name: status.Name,
	})
}

// RenewCertificate exchanges the CSR of a relay for a new certificate.
//
// The identity comes from the current client certificate alone. The network
// names come from the registry rather than from the request: could a relay
// choose them itself, a renewal would be a way of presenting itself to the
// agents under somebody else's name.
func (s *RelayService) RenewCertificate(ctx context.Context,
	req *connect.Request[agentv1.RenewRelayCertificateRequest],
) (*connect.Response[agentv1.RenewRelayCertificateResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("no client certificate"))
	}
	// The certificate of a host will not pass here: the kind of the identity
	// is in the URI SAN, so an agent will not renew itself a certificate with
	// a server role.
	relayID, err := pki.RelayIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	if len(req.Msg.GetCsrPem()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the CSR is missing"))
	}

	status, err := s.relays.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	switch {
	case !status.Known:
		s.refuse(ctx, relayID, "unknown_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate is unknown"))
	case status.Revoked:
		// A revoked relay must not renew itself. Without that a revocation
		// would be a break until the next renewal rather than a cut-off.
		s.refuse(ctx, relayID, "revoked_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate was revoked"))
	case status.ID != relayID:
		s.refuse(ctx, relayID, "identity_mismatch")
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the identity does not match the certificate"))
	}

	names, err := s.relays.Names(ctx, relayID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(names) == 0 {
		// A relay without recorded names has nothing to attest to the agents.
		// Silently issuing a certificate without names would give a relay no
		// agent accepts - and nobody would know why.
		s.refuse(ctx, relayID, "advertised_names_missing")
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the relay has no recorded network names"))
	}
	// The wish of the relay is noted but not granted: a divergence means the
	// configuration of the site has drifted apart from the registry of the
	// panel and the operator is to see it before the agents start rejecting
	// connections.
	if extra := extraNames(req.Msg.GetAdvertisedNames(), names); len(extra) > 0 {
		s.log.Warn("the relay asks for names from outside the registry",
			"relay_id", relayID, "names", extra, "issued", names)
	}

	issued, err := s.certIssuer.SignRelay(ctx, req.Msg.GetCsrPem(), relayID, names)
	if err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: relayID,
			Action: "relay.certificate.renew", TargetType: "relay", TargetID: relayID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	trust, err := s.certIssuer.Trust(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	tx, err := s.relays.Pool().Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	// The previous certificate stops being the one the panel recognises the
	// relay by, but stays valid until the end of its term: the relay switches
	// the listener without tearing down the sessions of the agents.
	if err := s.relays.SaveCertificate(ctx, tx, relayID, issued.Serial,
		issued.Fingerprint, issued.NotAfter); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.relays.RecordRenewal(ctx, tx, relayID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: relayID,
		Action: "relay.certificate.renew", TargetType: "relay", TargetID: relayID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"cert_serial": issued.Serial, "not_after": issued.NotAfter,
			"advertised_names": names,
			"agent_version":    req.Msg.GetBuild().GetAgentVersion(),
		},
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.log.Info("the certificate of the relay was renewed",
		"relay_id", relayID, "name", status.Name, "expires", issued.NotAfter)
	return connect.NewResponse(&agentv1.RenewRelayCertificateResponse{
		CertificatePem:    issued.PEM,
		ClientCaBundlePem: trust,
		NotAfter:          timestamppb.New(issued.NotAfter),
	}), nil
}

// Ping confirms the connectivity of a relay with the centre and refreshes its
// presence.
//
// The answer carries the number of sessions the centre sees through this
// relay. A divergence from the local number is the first symptom of a session
// hanging on one side - and that cannot be seen from either side alone.
func (s *RelayService) Ping(ctx context.Context,
	req *connect.Request[agentv1.RelayPingRequest],
) (*connect.Response[agentv1.RelayPingResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("no client certificate"))
	}
	relayID, err := pki.RelayIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	status, err := s.relays.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !status.Known || status.Revoked || status.ID != relayID {
		s.refuse(ctx, relayID, "relay_not_active")
		return nil, connect.NewError(connect.CodeUnauthenticated,
			fmt.Errorf("the relay %s is not active", relayID))
	}
	s.relays.MarkSeen(ctx, relayID)

	return connect.NewResponse(&agentv1.RelayPingResponse{
		ServerTime: timestamppb.Now(),
		Sessions:   uint32(s.registry.RelaySessions(relayID)),
	}), nil
}

// refuse records the rejection of a relay. Silence here would leave the
// operator with a relay that "just does not work".
func (s *RelayService) refuse(ctx context.Context, relayID, reason string) {
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: relayID,
		Action: "relay.identity.denied", TargetType: "relay", TargetID: relayID,
		Outcome: audit.OutcomeDenied,
		Detail:  map[string]any{"reason": reason},
	})
	s.log.Warn("the relay was rejected", "relay_id", relayID, "reason", reason)
}

// extraNames returns the names requested by a relay that are not in the
// registry.
func extraNames(requested, recorded []string) []string {
	if len(requested) == 0 {
		return nil
	}
	known := make(map[string]bool, len(recorded))
	for _, name := range recorded {
		known[name] = true
	}
	var extra []string
	for _, name := range requested {
		if !known[name] {
			extra = append(extra, name)
		}
	}
	return extra
}
