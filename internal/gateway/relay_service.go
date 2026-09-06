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
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relays"
)

// RelayService obsluguje relaye lokalizacji.
//
// Jest osobna usluga, bo relay jest osobna granica zaufania. Certyfikat relaya
// zyje krocej niz certyfikat hosta i ma role serwerowa wobec agentow swojej
// lokalizacji, wiec odnowienie musi sprawdzic co innego niz odnowienie hosta.
// Wspolne RPC oznaczaloby jeden zbior warunkow dla dwoch roznych uprawnien.
type RelayService struct {
	relays   *relays.Store
	trust    *pki.Trust
	audit    *audit.Recorder
	registry *Registry
	// enrollment obsluguje zgloszenia hostow z izolowanych lokalizacji.
	// Relay nie podpisuje niczego sam, wiec zgloszenie idzie do tej samej
	// uslugi, ktora obsluguje polaczenia bezposrednie - z jedna roznica:
	// wiadomo, ktory relay je poswiadcza.
	enrollment *EnrollmentService
	log        *slog.Logger
}

func NewRelayService(relayStore *relays.Store, trust *pki.Trust,
	recorder *audit.Recorder, registry *Registry,
	enrollmentService *EnrollmentService, log *slog.Logger) *RelayService {
	return &RelayService{
		relays: relayStore, trust: trust, audit: recorder,
		registry: registry, enrollment: enrollmentService, log: log,
	}
}

// ProxyEnroll przyjmuje zgloszenie hosta przekazane przez relay.
//
// Host w izolowanej lokalizacji nie widzi centrali i rejestruje sie przez
// relay. Relay jest terminatorem TLS, wiec widzi token; dlatego zgloszenie
// idzie jego kanalem mTLS, a nie publicznym endpointem. Centrala sprawdza
// wtedy dwie rzeczy, ktorych publiczny endpoint sprawdzic nie moze: czy
// zamowienie nalezy do lokalizacji tego relaya i czy nie jest zwiazane
// z innym relayem.
func (s *RelayService) ProxyEnroll(ctx context.Context,
	req *connect.Request[agentv1.ProxyEnrollRequest],
) (*connect.Response[agentv1.EnrollResponse], error) {
	if s.enrollment == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("ta instalacja nie przyjmuje zgloszen przez relay"))
	}
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("brak certyfikatu klienta"))
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
		s.odmowa(ctx, relayID, "relay_not_active")
		return nil, connect.NewError(connect.CodeUnauthenticated,
			fmt.Errorf("relay %s nie jest aktywny", relayID))
	}
	zgloszenie := req.Msg.GetEnrollment()
	if zgloszenie == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("brak zgloszenia hosta"))
	}
	s.relays.MarkSeen(ctx, relayID)

	return s.enrollment.enrollZaRelayem(ctx, zgloszenie, poswiadczenieRelaya{
		ID: relayID, Site: status.Site, Nazwa: status.Name,
	})
}

// RenewCertificate wymienia CSR relaya na nowy certyfikat.
//
// Tozsamosc pochodzi wylacznie z obecnego certyfikatu klienta. Nazwy sieciowe
// pochodza z rejestru, a nie z zadania: gdyby relay mogl je sobie wybrac,
// odnowienie bylo by droga do wystawienia sie agentom pod cudza nazwa.
func (s *RelayService) RenewCertificate(ctx context.Context,
	req *connect.Request[agentv1.RenewRelayCertificateRequest],
) (*connect.Response[agentv1.RenewRelayCertificateResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("brak certyfikatu klienta"))
	}
	// Certyfikat hosta nie przejdzie tedy: rodzaj tozsamosci jest w URI SAN,
	// wiec agent nie odnowi sobie certyfikatu z rola serwerowa.
	relayID, err := pki.RelayIDFromCert(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	if len(req.Msg.GetCsrPem()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("brak CSR"))
	}

	status, err := s.relays.LookupCertificate(ctx, pki.Fingerprint(cert))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	switch {
	case !status.Known:
		s.odmowa(ctx, relayID, "unknown_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("certyfikat nieznany"))
	case status.Revoked:
		// Odwolany relay nie moze sie odnowic. Bez tego odwolanie bylo by
		// przerwa do najblizszego odnowienia, a nie odcieciem.
		s.odmowa(ctx, relayID, "revoked_certificate")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("certyfikat odwolany"))
	case status.ID != relayID:
		s.odmowa(ctx, relayID, "identity_mismatch")
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("tozsamosc nie zgadza sie z certyfikatem"))
	}

	nazwy, err := s.relays.Nazwy(ctx, relayID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(nazwy) == 0 {
		// Relay bez zapisanych nazw nie ma czego poswiadczyc agentom.
		// Milczace wystawienie certyfikatu bez nazw dalo by relay, ktorego
		// zaden agent nie przyjmie - i nikt nie wiedzialby dlaczego.
		s.odmowa(ctx, relayID, "advertised_names_missing")
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("relay nie ma zapisanych nazw sieciowych"))
	}
	// Zyczenie relaya odnotowujemy, ale go nie spelniamy: rozjazd znaczy, ze
	// konfiguracja lokalizacji rozeszla sie z rejestrem panelu i operator ma
	// to zobaczyc, zanim agenci zaczna odrzucac polaczenia.
	if roznica := nowe(req.Msg.GetAdvertisedNames(), nazwy); len(roznica) > 0 {
		s.log.Warn("relay prosi o nazwy spoza rejestru",
			"relay_id", relayID, "nazwy", roznica, "wystawione", nazwy)
	}

	issued, err := s.trust.Active().SignRelayCSRZNazwami(req.Msg.GetCsrPem(), relayID, nazwy)
	if err != nil {
		s.audit.Record(ctx, audit.Event{
			ActorType: audit.ActorAgent, ActorID: relayID,
			Action: "relay.certificate.renew", TargetType: "relay", TargetID: relayID,
			Outcome: audit.OutcomeFailure,
			Detail:  map[string]any{"reason": "invalid_csr", "error": err.Error()},
		})
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	tx, err := s.relays.Pool().Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	// Poprzedni certyfikat przestaje byc tym, po ktorym panel rozpoznaje
	// relay, ale zostaje wazny do konca swojego terminu: relay przelacza
	// listener bez zrywania sesji agentow.
	if err := s.relays.SaveCertificate(ctx, tx, relayID, issued.Serial,
		issued.Fingerprint, issued.NotAfter); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.relays.OdnotujOdnowienie(ctx, tx, relayID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.audit.RecordTx(ctx, tx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: relayID,
		Action: "relay.certificate.renew", TargetType: "relay", TargetID: relayID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"cert_serial": issued.Serial, "not_after": issued.NotAfter,
			"advertised_names": nazwy,
			"agent_version":    req.Msg.GetBuild().GetAgentVersion(),
		},
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	s.log.Info("certyfikat relaya odnowiony",
		"relay_id", relayID, "nazwa", status.Name, "wygasa", issued.NotAfter)
	return connect.NewResponse(&agentv1.RenewRelayCertificateResponse{
		CertificatePem:    issued.PEM,
		ClientCaBundlePem: s.trust.Bundle(),
		NotAfter:          timestamppb.New(issued.NotAfter),
	}), nil
}

// Ping potwierdza lacznosc relaya z centrala i odswieza jego obecnosc.
//
// Odpowiedz niesie liczbe sesji, ktore centrala widzi przez ten relay.
// Rozjazd z liczba lokalna jest pierwszym objawem sesji, ktora zawisla po
// jednej stronie - a tego nie widac z zadnej strony osobno.
func (s *RelayService) Ping(ctx context.Context,
	req *connect.Request[agentv1.RelayPingRequest],
) (*connect.Response[agentv1.RelayPingResponse], error) {
	cert, ok := clientCertificate(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("brak certyfikatu klienta"))
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
		s.odmowa(ctx, relayID, "relay_not_active")
		return nil, connect.NewError(connect.CodeUnauthenticated,
			fmt.Errorf("relay %s nie jest aktywny", relayID))
	}
	s.relays.MarkSeen(ctx, relayID)

	return connect.NewResponse(&agentv1.RelayPingResponse{
		ServerTime: timestamppb.Now(),
		Sessions:   uint32(s.registry.SesjeRelaya(relayID)),
	}), nil
}

// odmowa zapisuje odrzucenie relaya. Cisza w tym miejscu zostawialaby
// operatora z relayem, ktory "po prostu nie dziala".
func (s *RelayService) odmowa(ctx context.Context, relayID, powod string) {
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: relayID,
		Action: "relay.identity.denied", TargetType: "relay", TargetID: relayID,
		Outcome: audit.OutcomeDenied,
		Detail:  map[string]any{"reason": powod},
	})
	s.log.Warn("relay odrzucony", "relay_id", relayID, "powod", powod)
}

// nowe zwraca nazwy zadane przez relay, ktorych nie ma w rejestrze.
func nowe(zadane, zapisane []string) []string {
	if len(zadane) == 0 {
		return nil
	}
	znane := make(map[string]bool, len(zapisane))
	for _, nazwa := range zapisane {
		znane[nazwa] = true
	}
	var roznica []string
	for _, nazwa := range zadane {
		if !znane[nazwa] {
			roznica = append(roznica, nazwa)
		}
	}
	return roznica
}
