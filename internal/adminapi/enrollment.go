package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/enrollment"
	"github.com/ultherego/flotestro/internal/hosts"
)

// zamowienieRequest jest trescia zamowienia enrollmentu.
type zamowienieRequest struct {
	Description string `json:"description"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	// Kind rozstrzyga, co wolno zarejestrowac: agenta czy relay.
	Kind string `json:"kind"`
	// Purpose rozstrzyga, co wolno zrobic z maszyna, ktora panel juz zna.
	// Puste znaczy nowy host - i taki token nie przejmie tozsamosci
	// dzialajacej maszyny.
	Purpose           string `json:"purpose"`
	ExpectedMachineID string `json:"expected_machine_id"`
	// RelayID zamyka zamowienie w jednej lokalizacji: token zadziala
	// wylacznie przez ten relay. Puste znaczy bez ograniczenia trasy - i tak
	// zostaje dla instalacji bez relayow.
	RelayID    string `json:"relay_id"`
	MaxUses    int    `json:"max_uses"`
	TTLMinutes int    `json:"ttl_minutes"`
}

// handleCreateEnrollmentRequest wystawia zamowienie i pokazuje token raz.
func (s *Server) handleCreateEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermHostEnrollCreate, authz.GlobalScope,
		"enrollment_request", "")
	if !ok {
		return
	}
	var req zamowienieRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	// Odtworzenie tozsamosci ma wlasne wejscie na hoscie i wlasne prawo:
	// tutaj przyjmujemy wylacznie zamowienia nowych maszyn i relayow.
	if req.Purpose == enrollment.CelWymiana {
		problem(w, http.StatusBadRequest, "purpose_not_allowed",
			"identity recovery is requested on the host itself")
		return
	}

	zamowienie, err := s.tworzZamowienie(r, req, principal.Subject, "")
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.enrollment.create", TargetType: "enrollment_request",
		TargetID: zamowienie.ID, Outcome: audit.OutcomeSuccess,
		// Wartosc tokenu nie trafia do audytu: jest sekretem, a audyt czyta
		// wiecej osob niz ta, ktora zamowila instalacje.
		Detail: map[string]any{
			"site": zamowienie.Site, "environment": zamowienie.Environment,
			"kind": zamowienie.Kind, "purpose": zamowienie.Purpose,
			"relay_id": zamowienie.RelayID,
			"max_uses": zamowienie.MaxUses, "expires_at": zamowienie.ExpiresAt,
		},
	})
	writeJSON(w, http.StatusCreated, zamowienie)
}

// tworzZamowienie sklada wejscie magazynu z zadania HTTP.
func (s *Server) tworzZamowienie(r *http.Request, req zamowienieRequest, aktor,
	hostID string) (*enrollment.Zamowienie, error) {
	if req.Site == "" {
		req.Site = "default"
	}
	if req.Environment == "" {
		req.Environment = "unassigned"
	}
	ttl := time.Duration(req.TTLMinutes) * time.Minute
	if req.TTLMinutes <= 0 {
		ttl = 15 * time.Minute
	}
	return s.tokens.Create(r.Context(), enrollment.TworzenieWejscie{
		Description: req.Description, Site: req.Site, Environment: req.Environment,
		Kind: req.Kind, Purpose: req.Purpose,
		ExpectedMachineID: req.ExpectedMachineID, ExpectedHostID: hostID,
		RelayID: req.RelayID,
		MaxUses: req.MaxUses, TTL: ttl, CreatedBy: aktor,
	})
}

// krokInstalacji jest jednym etapem widocznym na ekranie instalacji.
//
// Etapy sa osobne, bo kazdy z nich zawodzi z innego powodu i inaczej sie go
// naprawia: token moze wygasnac, certyfikat moze zostac odrzucony przy bledzie
// CSR, sesja moze nie dojsc przez zaporę, a inwentarz moze nie przyjsc, gdy
// agent nie ma jeszcze zdolnosci.
type krokInstalacji struct {
	Key   string `json:"key"`
	State string `json:"state"`
}

// Etapy instalacji hosta.
const (
	KrokToken      = "token"
	KrokCertyfikat = "certificate"
	KrokPolaczenie = "connected"
	KrokInwentarz  = "inventory"
	StanCzeka      = "waiting"
	StanZrobione   = "done"
	StanNieudany   = "failed"
)

// zamowienieZKrokami dokleda do zamowienia postep instalacji.
type zamowienieZKrokami struct {
	*enrollment.Zamowienie
	Steps []krokInstalacji `json:"steps"`
}

// krokiInstalacji liczy postep instalacji z tego, co panel naprawde widzi.
//
// Nic tu nie jest deklaracja agenta: token zuzyty wynika z licznika uzyc,
// certyfikat z zapisanego hosta, sesja ze stanu polaczenia, a inwentarz
// z fragmentow, ktore juz doszly.
func (s *Server) krokiInstalacji(r *http.Request,
	zamowienie *enrollment.Zamowienie) []krokInstalacji {
	nieudane := zamowienie.Status == enrollment.StatusWygasl ||
		zamowienie.Status == enrollment.StatusUniewazniony ||
		zamowienie.Status == enrollment.StatusNieudany

	stanKroku := func(zrobiony bool) string {
		switch {
		case zrobiony:
			return StanZrobione
		case nieudane:
			// Zamowienie zamkniete bez tego kroku juz go nie wykona.
			return StanNieudany
		default:
			return StanCzeka
		}
	}

	kroki := []krokInstalacji{
		{Key: KrokToken, State: stanKroku(zamowienie.Uses > 0)},
		{Key: KrokCertyfikat, State: stanKroku(zamowienie.EnrolledHostID != "")},
	}
	polaczony, zInwentarzem := false, false
	if zamowienie.EnrolledHostID != "" {
		if host, err := s.hosts.Get(r.Context(), zamowienie.EnrolledHostID); err == nil && host != nil {
			polaczony = host.ConnectionState == "online"
			zInwentarzem = host.CurrentInventoryRevision != ""
		}
	}
	kroki = append(kroki,
		krokInstalacji{Key: KrokPolaczenie, State: stanKroku(polaczony)},
		krokInstalacji{Key: KrokInwentarz, State: stanKroku(zInwentarzem)})
	return kroki
}

// handleListEnrollmentRequests pokazuje oczekujace i zamkniete instalacje.
func (s *Server) handleListEnrollmentRequests(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermHostEnrollRead, authz.GlobalScope,
		"enrollment_request", ""); !ok {
		return
	}
	zamowienia, err := s.tokens.List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": zamowienia, "count": len(zamowienia)})
}

// handleGetEnrollmentRequest pokazuje jedno zamowienie.
func (s *Server) handleGetEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, authz.PermHostEnrollRead, authz.GlobalScope,
		"enrollment_request", r.PathValue("id")); !ok {
		return
	}
	zamowienie, err := s.tokens.Zamowienie(r.Context(), r.PathValue("id"))
	if errors.Is(err, enrollment.ErrNieznaneZamowienie) {
		problem(w, http.StatusNotFound, "not_found", "enrollment request not found")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, zamowienieZKrokami{
		Zamowienie: zamowienie, Steps: s.krokiInstalacji(r, zamowienie),
	})
}

// handleRevokeEnrollmentRequest natychmiast blokuje pozostale uzycia.
func (s *Server) handleRevokeEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorize(w, r, authz.PermHostEnrollRevoke, authz.GlobalScope,
		"enrollment_request", r.PathValue("id"))
	if !ok {
		return
	}
	err := s.tokens.Uniewaznij(r.Context(), r.PathValue("id"))
	if errors.Is(err, enrollment.ErrNieznaneZamowienie) {
		problem(w, http.StatusNotFound, "not_found", "enrollment request not found")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.enrollment.revoke", TargetType: "enrollment_request",
		TargetID: r.PathValue("id"), Outcome: audit.OutcomeSuccess,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleIdentityRecovery zamawia odtworzenie tozsamosci istniejacego hosta.
//
// Osobne wejscie i osobne prawo, bo to nie jest zaproszenie nowej maszyny:
// token z tego zamowienia pasuje wylacznie do wskazanego hosta i wraca on do
// panelu z ta sama historia, a nie jako drugi wiersz obok martwego bliznika.
func (s *Server) handleIdentityRecovery(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermHostIdentityReplace, scope, "host", hostID)
	if !ok {
		return
	}

	// Host wycofany nie wraca do floty tokenem. Zamowienie, ktorego i tak nie
	// da sie uzyc, byloby obietnica bez pokrycia - powrot zaczyna sie od
	// cofniecia decyzji o wycofaniu.
	if host.LifecycleState == hosts.StanWycofany {
		problem(w, http.StatusConflict, "host_retired",
			"a retired host cannot be brought back with a recovery token")
		return
	}

	var req zamowienieRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
			return
		}
	}
	// Zakres bierze sie z hosta, a nie z zadania: odtworzenie tozsamosci nie
	// jest okazja do przeniesienia hosta do innego site albo srodowiska.
	req.Site, req.Environment = host.Site, host.Environment
	req.Kind, req.Purpose = enrollment.KindAgent, enrollment.CelWymiana
	req.MaxUses = 1

	zamowienie, err := s.tworzZamowienie(r, req, principal.Subject, hostID)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "host.identity.recovery", TargetType: "host", TargetID: hostID,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"request_id": zamowienie.ID, "expires_at": zamowienie.ExpiresAt,
			"expected_machine_id": zamowienie.ExpectedMachineID,
		},
	})
	writeJSON(w, http.StatusCreated, zamowienie)
}
