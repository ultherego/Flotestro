package gateway

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/pki"
)

// RenewCertificate wymienia CSR na nowy certyfikat hosta.
//
// Tozsamosc pochodzi wylacznie z obecnego certyfikatu klienta, nigdy z tresci
// zadania. Odnowienie nie uzywa tokenu enrollmentu: token jest jednorazowym
// wejsciem dla hosta bez tozsamosci, a host, ktory juz ja ma, potwierdza sie
// kluczem prywatnym w uscisku TLS.
//
// Poprzedni certyfikat pozostaje wazny do konca swojego terminu. Uniewaznienie
// go tutaj zrywaloby trwajaca sesje agenta w chwili odnowienia, a odnowienie
// ma byc czynnoscia niewidoczna dla operacji.
func (s *AgentService) RenewCertificate(ctx context.Context,
	req *connect.Request[agentv1.RenewCertificateRequest],
) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("brak certyfikatu klienta"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	if len(req.Msg.GetCsrPem()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("brak CSR"))
	}

	// Host odwolany albo w kwarantannie nie dostaje swiezej tozsamosci.
	// Bez tego odwolanie certyfikatu bylo by tylko chwilowa przerwa: host
	// odnowilby sie sam i wrocil do floty.
	status, err := s.hosts.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	switch {
	case !status.Known:
		s.denied(ctx, hostID, "unknown_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("certyfikat nieznany"))
	case status.Revoked:
		s.denied(ctx, hostID, "revoked_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("certyfikat odwolany"))
	case status.HostID != hostID:
		s.denied(ctx, hostID, "identity_mismatch")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("tozsamosc nie zgadza sie z certyfikatem"))
	case status.LifecycleState == "quarantined":
		s.denied(ctx, hostID, "quarantined")
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("host jest w kwarantannie"))
	}

	issued, err := s.trust.Active().SignAgentCSR(req.Msg.GetCsrPem(), hostID)
	if err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: hostID,
			Action: "host.certificate.renew", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	tx, err := s.hosts.Pool().Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.hosts.SaveCertificate(ctx, tx, hostID, issued.Serial, issued.CommonName,
		issued.Fingerprint, issued.NotBefore, issued.NotAfter,
		issued.IssuerSubject, issued.IssuerSerial); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("zapis certyfikatu: %w", err))
	}
	if err := s.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "host.certificate.renew", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"cert_serial":   issued.Serial,
			"not_after":     issued.NotAfter,
			"agent_version": req.Msg.GetBuild().GetAgentVersion(),
			"poprzedni":     status.Serial,
		},
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.log.Info("certyfikat hosta odnowiony",
		"host_id", hostID, "serial", issued.Serial, "not_after", issued.NotAfter)

	return connect.NewResponse(&agentv1.RenewCertificateResponse{
		CertificatePem: issued.PEM,
		// Bundle niesie wszystkie uznawane CA, wiec agent poznaje nowe CA
		// przy zwyklym odnowieniu, bez osobnej dystrybucji.
		CaBundlePem: s.trust.Bundle(),
		NotAfter:    timestamppb.New(issued.NotAfter),
	}), nil
}

// Ping potwierdza lacznosc z centrala. Nie zmienia niczego i nie zaglada do
// bazy: ma odpowiedziec takze wtedy, gdy panel jest pod obciazeniem.
func (s *AgentService) Ping(ctx context.Context,
	_ *connect.Request[agentv1.PingRequest],
) (*connect.Response[agentv1.PingResponse], error) {
	if _, ok := clientCertificate(ctx); !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("brak certyfikatu klienta"))
	}
	return connect.NewResponse(&agentv1.PingResponse{
		ServerTime: timestamppb.Now(),
		GatewayId:  s.gatewayID,
	}), nil
}
