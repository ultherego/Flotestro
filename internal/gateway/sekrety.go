package gateway

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/ultherego/flotestro/internal/audit"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/secrets"
)

// SekretyWydawane opisuje to, co gateway musi umiec z magazynem sekretow.
//
// Interfejs zamiast konkretnego magazynu: gateway ma wydac wartosc na podstawie
// dzierzawy, a nie wiedziec, jak sekrety sa przechowywane.
type SekretyWydawane interface {
	Wydaj(ctx context.Context, jobID, hostID, nazwa string, wersja int) ([]byte, int, error)
}

// SekretyDzierzawione opisuje dzierzawy wystawione dla zadania.
type SekretyDzierzawione interface {
	Dzierzawy(ctx context.Context, jobID string) ([]secrets.Dzierzawa, error)
	// Uniewaznij zamyka dzierzawy zadania, ktore sie skonczylo.
	Uniewaznij(ctx context.Context, jobID string) error
}

// SetSecrets podlacza magazyn sekretow.
func (s *AgentService) SetSecrets(store SekretyWydawane) { s.secrets = store }

// SetSecretLeases podlacza odczyt dzierzaw.
func (s *AgentService) SetSecretLeases(store SekretyDzierzawione) { s.leases = store }

// FetchSecret wydaje wartosc sekretu na czas wykonania jednego zadania.
//
// Wartosc nie jedzie w kopercie zadania. Host dostaje odnosnik i siega po
// tresc dopiero wtedy, gdy zaczyna operacje - a wydanie jest mozliwe tylko
// wtedy, gdy panel sam wystawil dzierzawe: dla tego hosta, dla tego zadania
// i na krotka chwile. Dzierzawa jest jednorazowa.
//
// Tozsamosc hosta pochodzi z certyfikatu klienta, nigdy z tresci zadania:
// inaczej wystarczyloby znac cudzy identyfikator proby.
func (s *AgentService) FetchSecret(ctx context.Context,
	req *connect.Request[agentv1.FetchSecretRequest],
) (*connect.Response[agentv1.FetchSecretResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("brak certyfikatu klienta"))
	}
	hostID, err := pki.HostIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	if s.secrets == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("ten panel nie ma magazynu sekretow"))
	}

	nazwa := req.Msg.GetSecretName()
	if nazwa == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("brak nazwy sekretu"))
	}
	// Agent zna identyfikator proby; dzierzawa jest wystawiona na operacje.
	jobID, _ := s.kontekstProby(ctx, req.Msg.GetTaskId())
	if jobID == "" {
		s.odmowaSekretu(ctx, hostID, nazwa, "unknown_task")
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("nieznane zadanie"))
	}

	wartosc, wersja, err := s.secrets.Wydaj(ctx, jobID, hostID, nazwa, int(req.Msg.GetSecretVersion()))
	switch {
	case errors.Is(err, secrets.ErrNoLease):
		s.odmowaSekretu(ctx, hostID, nazwa, "no_lease")
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, secrets.ErrNotFound), errors.Is(err, secrets.ErrDestroyed),
		errors.Is(err, secrets.ErrRetired):
		s.odmowaSekretu(ctx, hostID, nazwa, "unavailable")
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Audyt notuje fakt wydania: kto, co, ktora wersje i w ramach ktorej
	// operacji. Wartosci nie ma tu ani w zadnym innym zapisie.
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "secret.fetch", TargetType: "secret", TargetID: nazwa,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"job_id": jobID, "host_id": hostID, "version": wersja,
			"size_bytes": len(wartosc),
		},
	})
	return connect.NewResponse(&agentv1.FetchSecretResponse{
		Value: wartosc, Version: uint32(wersja), Sha256: secrets.Odcisk(wartosc),
	}), nil
}

// odmowaSekretu zapisuje odmowe wraz z powodem.
func (s *AgentService) odmowaSekretu(ctx context.Context, hostID, nazwa, powod string) {
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "secret.fetch", TargetType: "secret", TargetID: nazwa,
		Outcome: audit.OutcomeDenied,
		Detail:  map[string]any{"host_id": hostID, "reason": powod},
	})
	s.log.Warn("odmowa wydania sekretu", "host_id", hostID, "secret", nazwa, "powod", powod)
}
