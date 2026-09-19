package gateway

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/metrics"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relayproof"
)

// RenewCertificate exchanges a CSR for a new certificate of a host.
func (s *AgentService) RenewCertificate(ctx context.Context,
	req *connect.Request[agentv1.RenewCertificateRequest],
) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no client certificate"))
	}
	if len(req.Msg.GetCsrPem()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the CSR is missing"))
	}
	if _, err := pki.RelayIDFromCert(cert); err == nil {
		return s.renewThroughRelay(ctx, req)
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	// A host that is revoked or in quarantine does not get a fresh identity.
	status, err := s.hosts.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return s.issueRenewal(ctx, req, hostID, status)
}

// renewThroughRelay is the relayed half of RenewCertificate: the relay
// names the host, the envelope and the proof name the key.
func (s *AgentService) renewThroughRelay(ctx context.Context,
	req *connect.Request[agentv1.RenewCertificateRequest],
) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	who, _, err := s.identifyCaller(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	hostID := who.HostID
	if req.Msg.GetIdentity() == nil || len(req.Msg.GetProof()) == 0 || len(req.Msg.GetServerChallenge()) == 0 {
		// A renewal through a relay was never possible without the proof, so
		// requiring it under every mode takes nothing from anyone: an agent from
		// before the proof renews directly, as it always did.
		s.refused(ctx, hostID, hosts.RefusalBlockedUpgradeRequired,
			"a renewal through relay "+who.RelayID+" without the host's proof ("+relayproof.Capability+" "+
				relayproof.Feature+"); upgrade the relay and the agent, or let the host renew directly")
		metrics.AgentRenewal.Inc("refused")
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("a renewal through a relay needs the host's proof"))
	}
	// The envelope signs the request with its identity field cleared.
	body := proto.Clone(req.Msg).(*agentv1.RenewCertificateRequest)
	body.Identity = nil
	verified, err := s.envelopes.VerifyRequest(ctx, who.Relay, req.Msg.GetIdentity(),
		relayproof.KindRenewCertificate, body)
	if err != nil {
		metrics.AgentRenewal.Inc("refused")
		return nil, s.refuseEnvelope(ctx, hostID, err)
	}
	s.learnPublicKey(ctx, hostID, verified)

	// The challenge, one-time, for this host and this relay.
	spent, err := s.challenges.Consume(ctx, hostID, who.RelayID,
		relayproof.ChallengeDigest(req.Msg.GetServerChallenge()))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !spent {
		s.refused(ctx, hostID, hosts.RefusalRelayEnvelopeInvalid,
			"the renewal names a challenge the panel did not issue for this host and relay, or one already spent or expired")
		metrics.AgentRenewal.Inc("refused")
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the renewal challenge is not one the panel issued, or was spent"))
	}
	block, _ := pem.Decode(req.Msg.GetCsrPem())
	if block == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the CSR is not PEM"))
	}
	if err := relayproof.VerifyRenewalProof(verified.PublicKey, block.Bytes, req.Msg.GetServerChallenge(),
		who.RelayID, req.Msg.GetProof()); err != nil {
		s.refused(ctx, hostID, hosts.RefusalRelayHostSignatureInvalid,
			"the renewal proof does not verify under certificate "+verified.Serial+": "+err.Error())
		metrics.RelayEnvelopeRefusal.Inc(hosts.RefusalRelayHostSignatureInvalid)
		metrics.AgentRenewal.Inc("refused")
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("the renewal proof does not verify under the host's certificate"))
	}
	// The certificate the envelope named passed the same checks as a presented
	// one; the lifecycle rule of a renewal is applied below on its record, as for
	// a direct renewal.
	status, err := s.hosts.LookupCertificateBySerial(ctx, verified.Serial)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return s.issueRenewal(ctx, req, hostID, status)
}

// issueRenewal is the common tail of a renewal once the host is known:
// the lifecycle rule, the issue, the record and the answer.
func (s *AgentService) issueRenewal(ctx context.Context,
	req *connect.Request[agentv1.RenewCertificateRequest], hostID string, status hosts.CertificateStatus,
) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	switch {
	case !status.Known:
		s.denied(ctx, hostID, "unknown_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate is unknown"))
	case status.Revoked:
		s.denied(ctx, hostID, "revoked_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the certificate was revoked"))
	case status.HostID != hostID:
		s.denied(ctx, hostID, "identity_mismatch")
		metrics.AgentRenewal.Inc("refused")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the identity does not match the certificate"))
	case !hosts.Active(status.LifecycleState):
		// Renewing the certificate of a host in quarantine or withdrawn would
		// extend exactly the trust that has been taken back.
		s.denied(ctx, hostID, "lifecycle_"+status.LifecycleState)
		metrics.AgentRenewal.Inc("refused")
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("the host is in the state %s", status.LifecycleState))
	}

	issued, err := s.certIssuer.SignHost(ctx, req.Msg.GetCsrPem(), hostID)
	if err != nil {
		metrics.AgentRenewal.Inc("failed")
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: hostID,
			Action: "host.certificate.renew", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// The trust bundle goes together with the certificate: after a rotation of
	// the CA the host has to get the new set before the old issuer stops holding.
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
		issued.IssuerSubject, issued.IssuerSerial, issued.IssuerID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("writing the certificate: %w", err))
	}
	// The public key goes on the record with the certificate: the envelopes of
	// the host's next sessions through a relay are checked against it, and the
	// gateway never sees the certificate itself there.
	if der, err := publicKeyDER(issued.PEM); err != nil {
		s.log.Error("the public key of the issued certificate was not read",
			"host_id", hostID, "serial", issued.Serial, "err", err)
	} else if err := s.hosts.RecordCertificatePublicKey(ctx, tx, issued.Serial, der); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
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

	metrics.AgentRenewal.Inc("renewed")
	s.log.Info("the certificate of the host was renewed",
		"host_id", hostID, "serial", issued.Serial, "not_after", issued.NotAfter)

	return connect.NewResponse(&agentv1.RenewCertificateResponse{
		CertificatePem: issued.PEM,
		// The bundle carries every trusted CA, so the agent learns about a new
		// CA at an ordinary renewal, without a separate distribution.
		CaBundlePem: trust,
		NotAfter:    timestamppb.New(issued.NotAfter),
		// The capability keys travel the same way, for the same reason.
		HelperTrust: s.helperTrustFor(hostID),
	}), nil
}

// publicKeyDER reads the SubjectPublicKeyInfo of an issued certificate.
func publicKeyDER(certificatePEM []byte) ([]byte, error) {
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return nil, errors.New("the certificate is not PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return parsed.RawSubjectPublicKeyInfo, nil
}

// RequestIdentityChallenge hands out the one-time challenge a host signs into
// its renewal proof through a relay.
func (s *AgentService) RequestIdentityChallenge(ctx context.Context,
	req *connect.Request[agentv1.IdentityChallengeRequest],
) (*connect.Response[agentv1.IdentityChallengeResponse], error) {
	who, _, err := s.identifyCaller(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	challenge, err := relayproof.NewChallenge()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	expires := time.Now().Add(relayproof.ChallengeTTL)
	if err := s.challenges.Issue(ctx, who.HostID, who.RelayID, relayproof.ChallengeDigest(challenge), expires); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&agentv1.IdentityChallengeResponse{
		Challenge:     challenge,
		ExpiresAtUnix: expires.Unix(),
		RelayId:       who.RelayID,
	}), nil
}

// Ping confirms the connectivity with the centre.
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
