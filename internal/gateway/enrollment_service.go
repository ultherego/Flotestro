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
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relays"
)

// EnrollmentService przyjmuje hosty, ktore nie maja jeszcze tozsamosci.
// Jest to jedyny endpoint dostepny bez certyfikatu klienta.
type EnrollmentService struct {
	trust  *pki.Trust
	relays *relays.Store
	hosts  *hosts.Store
	tokens *enrollment.TokenStore
	audit  *audit.Recorder
	log    *slog.Logger
}

func NewEnrollmentService(trust *pki.Trust, hostStore *hosts.Store, relayStore *relays.Store,
	tokens *enrollment.TokenStore, recorder *audit.Recorder, log *slog.Logger) *EnrollmentService {
	return &EnrollmentService{trust: trust, hosts: hostStore, relays: relayStore,
		tokens: tokens, audit: recorder, log: log}
}

// Enroll wymienia wazny token i CSR na certyfikat agenta. Cala operacja jest
// jedna transakcja: token, host, certyfikat i zdarzenie audytowe albo powstaja
// razem, albo wcale.
func (s *EnrollmentService) Enroll(ctx context.Context,
	req *connect.Request[agentv1.EnrollRequest]) (*connect.Response[agentv1.EnrollResponse], error) {
	msg := req.Msg
	if msg.GetMachineId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("brak machine_id"))
	}
	if len(msg.GetCsrPem()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("brak CSR"))
	}

	tx, err := s.hosts.Pool().Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	scope, err := s.tokens.Redeem(ctx, tx, msg.GetEnrollmentToken())
	if err != nil {
		if errors.Is(err, enrollment.ErrInvalidToken) {
			// Odmowa jest zdarzeniem audytowym tak samo jak sukces.
			s.audit.Record(ctx, audit.Event{
				ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
				Action: "host.enroll", Outcome: audit.OutcomeDenied,
				Detail: map[string]any{"reason": "invalid_token", "hostname": msg.GetHostname()},
			})
			return nil, connect.NewError(connect.CodePermissionDenied, enrollment.ErrInvalidToken)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Token rozstrzyga, co powstaje. Rejestracja relaya tokenem wystawionym
	// dla agenta bylaby cicha zmiana granicy zaufania: relay konczy sesje
	// agentow i poswiadcza ich tozsamosc.
	if scope.Kind == enrollment.KindRelay {
		return s.enrollRelay(ctx, tx, msg, scope)
	}

	build := msg.GetBuild()
	hostID, created, err := s.hosts.Upsert(ctx, tx, hosts.Identity{
		MachineID:    msg.GetMachineId(),
		Hostname:     msg.GetHostname(),
		Site:         scope.Site,
		Environment:  scope.Environment,
		OSFamily:     build.GetOsFamily(),
		OSVersion:    build.GetOsVersion(),
		Architecture: build.GetArchitecture(),
		AgentVersion: build.GetAgentVersion(),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	issued, err := s.trust.Active().SignAgentCSR(msg.GetCsrPem(), hostID)
	if err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
			Action: "host.enroll", TargetType: "host", TargetID: hostID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if err := s.hosts.SaveCertificate(ctx, tx, hostID, issued.Serial, issued.CommonName,
		issued.Fingerprint, issued.NotBefore, issued.NotAfter,
		issued.IssuerSubject, issued.IssuerSerial); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := s.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
		Action: "host.enroll", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"created":       created,
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

	s.log.Info("host zarejestrowany",
		"host_id", hostID, "hostname", msg.GetHostname(), "site", scope.Site, "created", created)

	return connect.NewResponse(&agentv1.EnrollResponse{
		HostId:         hostID,
		CertificatePem: issued.PEM,
		CaBundlePem:    s.trust.Bundle(),
		NotAfter:       timestamppb.New(issued.NotAfter),
	}), nil
}

// enrollRelay rejestruje relay lokalizacji i wystawia mu certyfikat.
//
// Relay dostaje tozsamosc innego rodzaju niz host: panel czyta rodzaj z URI
// SAN, wiec certyfikatem relaya nie da sie podszyc pod agenta ani odwrotnie.
// Zakres relaya pochodzi z tokenu i ogranicza, za ktore hosty wolno mu
// posredniczyc.
func (s *EnrollmentService) enrollRelay(ctx context.Context, tx pgx.Tx,
	msg *agentv1.EnrollRequest, scope enrollment.Scope,
) (*connect.Response[agentv1.EnrollResponse], error) {
	name := msg.GetHostname()
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("relay wymaga nazwy"))
	}

	relayID, err := s.relays.Upsert(ctx, tx, name, scope.Site, scope.Environment)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	issued, err := s.trust.Active().SignRelayCSR(msg.GetCsrPem(), relayID)
	if err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: name,
			Action: "relay.enroll", TargetType: "relay", TargetID: relayID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.relays.SaveCertificate(ctx, tx, relayID, issued.Serial,
		issued.Fingerprint, issued.NotAfter); err != nil {
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

	s.log.Info("relay zarejestrowany", "relay_id", relayID, "nazwa", name, "site", scope.Site)
	return connect.NewResponse(&agentv1.EnrollResponse{
		HostId:         relayID,
		CertificatePem: issued.PEM,
		CaBundlePem:    s.trust.Bundle(),
		NotAfter:       timestamppb.New(issued.NotAfter),
	}), nil
}
