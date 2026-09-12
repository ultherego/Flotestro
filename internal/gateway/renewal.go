package gateway

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/pki"
)

// RenewCertificate exchanges a CSR for a new certificate of a host.
//
// The identity comes from the current client certificate alone, never from the
// content of the request. A renewal does not use the enrollment token: the
// token is a one-time entry for a host without an identity, and a host that
// already has one proves itself with its private key in the TLS handshake.
//
// The previous certificate stays valid until the end of its term. Revoking it
// here would tear down the running session of the agent at the moment of the
// renewal, and a renewal is to be an act invisible to the operations.
func (s *AgentService) RenewCertificate(ctx context.Context,
	req *connect.Request[agentv1.RenewCertificateRequest],
) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no client certificate"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	if len(req.Msg.GetCsrPem()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the CSR is missing"))
	}

	// A host that is revoked or in quarantine does not get a fresh identity.
	// Without that revoking a certificate would be only a momentary break: the
	// host would renew itself and come back to the fleet.
	status, err := s.hosts.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	switch {
	case !status.Known:
		s.denied(ctx, hostID, "unknown_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate is unknown"))
	case status.Revoked:
		s.denied(ctx, hostID, "revoked_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate was revoked"))
	case status.HostID != hostID:
		s.denied(ctx, hostID, "identity_mismatch")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the identity does not match the certificate"))
	case !hosts.Active(status.LifecycleState):
		// Renewing the certificate of a host in quarantine or withdrawn would
		// extend exactly the trust that has been taken back.
		s.denied(ctx, hostID, "lifecycle_"+status.LifecycleState)
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("the host is in the state %s", status.LifecycleState))
	}

	issued, err := s.certIssuer.SignHost(ctx, req.Msg.GetCsrPem(), hostID)
	if err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: hostID,
			Action: "host.certificate.renew", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// The trust bundle goes together with the certificate: after a rotation of
	// the CA the host has to get the new set before the old issuer stops
	// holding.
	trust, err := s.certIssuer.Trust(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	tx, err := s.hosts.Pool().Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.hosts.SaveCertificate(ctx, tx, hostID, issued.Serial, issued.CommonName,
		issued.Fingerprint, issued.NotBefore, issued.NotAfter,
		issued.IssuerSubject, issued.IssuerSerial); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("writing the certificate: %w", err))
	}
	if err := s.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "host.certificate.renew", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"cert_serial":   issued.Serial,
			"not_after":     issued.NotAfter,
			"agent_version": req.Msg.GetBuild().GetAgentVersion(),
			"previous":      status.Serial,
		},
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.log.Info("the certificate of the host was renewed",
		"host_id", hostID, "serial", issued.Serial, "not_after", issued.NotAfter)

	return connect.NewResponse(&agentv1.RenewCertificateResponse{
		CertificatePem: issued.PEM,
		// The bundle carries every trusted CA, so the agent learns about a new
		// CA at an ordinary renewal, without a separate distribution.
		CaBundlePem: trust,
		NotAfter:    timestamppb.New(issued.NotAfter),
	}), nil
}

// Ping confirms the connectivity with the centre. It changes nothing and does
// not look into the database: it is to answer also when the panel is under
// load.
func (s *AgentService) Ping(ctx context.Context,
	_ *connect.Request[agentv1.PingRequest],
) (*connect.Response[agentv1.PingResponse], error) {
	if _, ok := clientCertificate(ctx); !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no client certificate"))
	}
	return connect.NewResponse(&agentv1.PingResponse{
		ServerTime: timestamppb.Now(),
		GatewayId:  s.gatewayID,
	}), nil
}
