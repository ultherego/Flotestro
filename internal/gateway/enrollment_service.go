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
	tokens *enrollment.Store
	audit  *audit.Recorder
	log    *slog.Logger
}

func NewEnrollmentService(trust *pki.Trust, hostStore *hosts.Store, relayStore *relays.Store,
	tokens *enrollment.Store, recorder *audit.Recorder, log *slog.Logger) *EnrollmentService {
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

	proba := enrollment.ProbaWejscie{
		Token:           msg.GetEnrollmentToken(),
		MachineID:       msg.GetMachineId(),
		ClientRequestID: msg.GetClientRequestId(),
		CSR:             msg.GetCsrPem(),
	}
	wynik, err := s.tokens.Redeem(ctx, tx, proba)
	if err != nil {
		if errors.Is(err, enrollment.ErrInvalidToken) {
			// Odmowa jest zdarzeniem audytowym tak samo jak sukces. Powod
			// zostaje w audycie serwera; agent dostaje zawsze te sama
			// odpowiedz, zeby nie dalo sie po niej zgadywac tokenow.
			s.audit.Record(ctx, audit.Event{
				ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
				Action: "host.enroll", Outcome: audit.OutcomeDenied,
				Detail: map[string]any{"reason": "invalid_token", "hostname": msg.GetHostname()},
			})
			return nil, connect.NewError(connect.CodePermissionDenied, enrollment.ErrInvalidToken)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	scope := wynik.Scope

	// Powtorzenie proby, ktorej odpowiedz zginela w sieci: agent dostaje ten
	// sam certyfikat, ktory juz zostal dla niego wydany. Nic sie nie zuzywa
	// i nic nie powstaje po raz drugi.
	if powtorzone := wynik.Powtorzenie; powtorzone != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: msg.GetMachineId(),
			Action: "host.enroll", TargetType: "host", TargetID: powtorzone.HostID,
			Outcome: audit.OutcomeSuccess,
			Detail: map[string]any{
				"replay": true, "token_id": scope.TokenID,
				"cert_serial": powtorzone.CertificateSerial,
			},
		})
		s.log.Info("powtorzona proba enrollmentu", "host_id", powtorzone.HostID,
			"machine_id", msg.GetMachineId())
		return connect.NewResponse(&agentv1.EnrollResponse{
			HostId:         powtorzone.HostID,
			CertificatePem: powtorzone.CertificatePEM,
			CaBundlePem:    powtorzone.CABundlePEM,
		}), nil
	}

	// Token rozstrzyga, co powstaje. Rejestracja relaya tokenem wystawionym
	// dla agenta bylaby cicha zmiana granicy zaufania: relay konczy sesje
	// agentow i poswiadcza ich tozsamosc.
	if scope.Kind == enrollment.KindRelay {
		return s.enrollRelay(ctx, tx, msg, scope)
	}

	// Cel zamowienia rozstrzyga, co wolno zrobic z maszyna, ktora panel juz
	// zna. Bez tego kazdy token bylby kluczem do przejecia tozsamosci
	// dzialajacego hosta.
	if err := s.sprawdzCel(ctx, tx, msg, scope); err != nil {
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
	tozsamosc := hosts.Identity{
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
	if scope.Purpose == enrollment.CelWymiana {
		// Odtworzenie tozsamosci nie zaklada nowego hosta: przeinstalowana
		// maszyna wraca do tego samego wiersza, z ta sama historia.
		hostID = scope.ExpectedHostID
		if err := s.hosts.PrzejmijMaszyne(ctx, tx, hostID, tozsamosc); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	} else {
		hostID, created, err = s.hosts.Upsert(ctx, tx, tozsamosc)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
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

	// Proba zapisuje sie w tej samej transakcji co host i certyfikat: zapis
	// po commicie moglby nie dojsc, a wtedy idempotencja bylaby pozorna.
	if err := s.tokens.ZapiszProbe(ctx, tx, scope.TokenID, proba, enrollment.Powtorzenie{
		HostID: hostID, CertificatePEM: issued.PEM, CABundlePEM: s.trust.Bundle(),
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

// sprawdzCel pilnuje, ze zamowienie pasuje do tego, co naprawde sie dzieje.
//
// Rozroznienie jest calym sensem tej funkcji. "Nowy host" oznacza maszyne,
// ktorej panel nie zna: token o tym celu nie moze przejac tozsamosci
// dzialajacej maszyny, nawet gdy ktos poda jej machine_id. "Wymiana
// tozsamosci" oznacza konkretnego hosta wskazanego przy zamawianiu - i tylko
// jego.
func (s *EnrollmentService) sprawdzCel(ctx context.Context, tx pgx.Tx,
	msg *agentv1.EnrollRequest, scope enrollment.Scope) error {
	istniejacy, err := s.hosts.IDPoMachineID(ctx, tx, msg.GetMachineId())
	if err != nil {
		return err
	}
	switch scope.Purpose {
	case enrollment.CelNowy:
		if istniejacy != "" {
			return errors.New("machine_id_known")
		}
	case enrollment.CelWymiana:
		if scope.ExpectedHostID == "" {
			return errors.New("recovery_without_host")
		}
		// Maszyna nieznana panelowi jest tu w porzadku: po przeinstalowaniu
		// host ma nowe machine_id, a tozsamosc odtwarzamy po wskazanym
		// host_id. Znana maszyna musi byc tym samym hostem.
		if istniejacy != "" && istniejacy != scope.ExpectedHostID {
			return errors.New("machine_id_other_host")
		}
	case enrollment.CelRelay:
		return errors.New("relay_purpose_for_host")
	default:
		return errors.New("unknown_purpose")
	}
	return nil
}
