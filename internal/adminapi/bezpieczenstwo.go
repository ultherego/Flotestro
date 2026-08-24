package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/compliance"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/remediation"
)

// handleHostSecurity zwraca ustalenia zgodnosci hosta wraz z planem naprawy.
//
// Ocena powstaje w panelu z faktow, ktore host i tak zglasza w inwentarzu:
// nie ma tu przebiegu po flocie ani skryptu wykonywanego na hoscie. Dzieki
// temu wynik da sie powtorzyc, a dwa hosty ocenia to samo sprawdzenie w tej
// samej wersji.
func (s *Server) handleHostSecurity(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermSecurityRead, scope, "host", hostID); !ok {
		return
	}

	raport, err := s.ocenZgodnosc(r, host)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raport)
}

// LimitHostowNaSprawdzenie ogranicza liste hostow przy jednym sprawdzeniu.
// Liczba jest dokladna; lista jest probka, zeby ekran floty nie stal sie
// wydrukiem calego inwentarza.
const LimitHostowNaSprawdzenie = 50

// widokSprawdzenia zbiera jedno sprawdzenie w skali floty.
type widokSprawdzenia struct {
	CheckID  string `json:"check_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Expected string `json:"expected"`
	Failed   int    `json:"failed"`
	Passed   int    `json:"passed"`
	Unknown  int    `json:"unknown"`
	// NotApplicable liczy hosty, ktorych sprawdzenie nie dotyczy. Bez tej
	// kolumny host bez SELinuksa wygladalby na niezgodny albo na zgodnego.
	NotApplicable int `json:"not_applicable"`
	// Hosts wylicza hosty, ktore sprawdzenia nie przeszly.
	Hosts []hostZUstaleniem `json:"hosts,omitempty"`
	// Fixable mowi, ile z nich ma za soba operacje naprawcza.
	Fixable int `json:"fixable"`
}

type hostZUstaleniem struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Observed string `json:"observed"`
	Action   string `json:"action,omitempty"`
}

// handleFleetSecurity zwraca zgodnosc calej widocznej floty.
//
// Widok floty jest podstawowym trybem tego modulu: jedno zle ustawienie na
// stu hostach jest jednym problemem, a nie stoma - i widac to dopiero wtedy,
// gdy ustalenia stoja obok siebie.
func (s *Server) handleFleetSecurity(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermSecurityRead, "fleet")
	if !ok {
		return
	}
	lista, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	widoczne := make([]hosts.Host, 0, len(lista))
	identyfikatory := make([]string, 0, len(lista))
	for _, host := range lista {
		if principal.Can(authz.PermSecurityRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			widoczne = append(widoczne, host)
			identyfikatory = append(identyfikatory, host.ID)
		}
	}

	fragmenty, err := s.inventory.FragmentyHostow(r.Context(), identyfikatory)
	if err != nil {
		s.fail(w, err)
		return
	}

	teraz := time.Now().UTC()
	sprawdzenia := map[string]*widokSprawdzenia{}
	kolejnosc := make([]string, 0, len(compliance.Checks))
	for _, check := range compliance.Checks {
		sprawdzenia[check.ID] = &widokSprawdzenia{
			CheckID: check.ID, Title: check.Title,
			Severity: check.Severity, Expected: check.Expected,
		}
		kolejnosc = append(kolejnosc, check.ID)
	}

	for _, host := range widoczne {
		raport := compliance.Ocen(host.ID, wejscieHosta(host, fragmenty[host.ID]), teraz)
		for _, ustalenie := range raport.Findings {
			widok, ok := sprawdzenia[ustalenie.CheckID]
			if !ok {
				continue
			}
			switch {
			case !ustalenie.Applicable:
				widok.NotApplicable++
			case ustalenie.Unknown:
				widok.Unknown++
			case ustalenie.Passed:
				widok.Passed++
			default:
				widok.Failed++
				if ustalenie.Remediation != nil && ustalenie.Remediation.Action != "" {
					widok.Fixable++
				}
				if len(widok.Hosts) < LimitHostowNaSprawdzenie {
					widok.Hosts = append(widok.Hosts, hostZUstaleniem{
						HostID: host.ID, Hostname: host.Hostname, Observed: ustalenie.Observed,
						Action: akcjaNaprawy(ustalenie),
					})
				}
			}
		}
	}

	wyniki := make([]widokSprawdzenia, 0, len(kolejnosc))
	for _, id := range kolejnosc {
		wyniki = append(wyniki, *sprawdzenia[id])
	}
	sort.SliceStable(wyniki, func(i, j int) bool {
		if wyniki[i].Failed != wyniki[j].Failed {
			return wyniki[i].Failed > wyniki[j].Failed
		}
		return wyniki[i].CheckID < wyniki[j].CheckID
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts": len(widoczne), "checks": wyniki, "generated_at": teraz,
	})
}

func akcjaNaprawy(ustalenie compliance.Ustalenie) string {
	if ustalenie.Remediation == nil {
		return ""
	}
	return ustalenie.Remediation.Action
}

// naprawaRequest opisuje zlecenie naprawy.
type naprawaRequest struct {
	// PlanHash wiaze zlecenie ze stanem, ktory operator ogladal.
	PlanHash string `json:"plan_hash"`
	// CheckIDs wylicza ustalenia do naprawy. Pusta lista nie znaczy
	// "wszystko": panel nie ma przycisku napraw wszystko.
	CheckIDs []string `json:"check_ids"`
	Reason   string   `json:"reason"`
	// StopOnFailure domyslnie wlaczone: kolejne kroki zakladaja, ze
	// poprzednie sie udaly.
	StopOnFailure *bool `json:"stop_on_failure,omitempty"`
}

// handleHostRemediation zaklada plan naprawy wskazanych ustalen.
//
// Naprawa nie jest osobna operacja na hoscie. Kazdy krok to zwykle zadanie
// modulu, ktory za dana rzecz odpowiada - z jego uprawnieniem, jego ryzykiem
// i jego zatwierdzeniem. Uprawnienie do naprawy nie zastepuje uprawnien tych
// modulow, tylko dokłada sie do nich.
//
// Kroki ida po kolei, bo kazdy zaklada stan zostawiony przez poprzedni; plan
// zatrzymuje sie po bledzie, a to, co zdazylo sie wykonac, zostaje widoczne.
func (s *Server) handleHostRemediation(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermSecurityRemediate, scope, "host", hostID)
	if !ok {
		return
	}
	if s.remediation == nil {
		problem(w, http.StatusServiceUnavailable, "remediation_disabled",
			"remediation plans are not enabled in this installation")
		return
	}

	var request naprawaRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	if len(request.CheckIDs) == 0 {
		problem(w, http.StatusBadRequest, "no_checks",
			"list the findings to fix; there is no fix-all")
		return
	}

	raport, err := s.ocenZgodnosc(r, host)
	if err != nil {
		s.fail(w, err)
		return
	}
	// Plan liczony teraz musi byc tym samym planem, ktory operator zatwierdzil.
	// Stan hosta zmienia sie sam - miedzy obejrzeniem planu a klinieciem host
	// mogl zostac naprawiony recznie albo zepsuty dalej.
	if request.PlanHash == "" || request.PlanHash != raport.PlanHash {
		problem(w, http.StatusConflict, "plan_stale",
			"the host state changed since this plan was computed; review the findings again")
		return
	}

	wybrane := map[string]bool{}
	for _, id := range request.CheckIDs {
		wybrane[id] = true
	}
	kroki := make([]compliance.Ustalenie, 0, len(request.CheckIDs))
	for _, ustalenie := range raport.Findings {
		if wybrane[ustalenie.CheckID] {
			kroki = append(kroki, ustalenie)
		}
	}
	if len(kroki) != len(wybrane) {
		problem(w, http.StatusBadRequest, "unknown_check",
			"one of the listed findings does not exist in this plan")
		return
	}

	ulozony, err := remediation.Ulozenie(kroki)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_plan", err.Error())
		return
	}

	// Uprawnienia sprawdzamy dla calego planu przed zalozeniem czegokolwiek:
	// polowa naprawy jest gorsza niz zadna, bo zostawia host w stanie,
	// ktorego nikt nie planowal.
	wymagaSwiezosci := false
	for _, krok := range ulozony.Kroki {
		akcja := opspec.ActionType(krok.ActionType)
		if _, ok := s.authorize(w, r, authz.Permission(akcja.Permission()), scope, "host", hostID); !ok {
			return
		}
		if akcja.RequiresTargetConfirmation() {
			problem(w, http.StatusBadRequest, "not_a_remediation",
				"finding "+krok.CheckID+" maps to an irreversible operation; run it host by host")
			return
		}
		if capability := akcja.RequiredCapability(); !hostHasCapability(host, capability) {
			problem(w, http.StatusConflict, "capability_missing",
				"finding "+krok.CheckID+" needs capability "+capability)
			return
		}
		if akcja.RequiresFreshAuth() {
			wymagaSwiezosci = true
		}
	}

	// Plan siegajacy po operacje najwyzszego ryzyka wymaga swiezego
	// uwierzytelnienia tak samo jak ta operacja zlecona wprost.
	var dowodStepUp map[string]any
	if wymagaSwiezosci {
		dowod, ok := s.requireStepUp(w, r, principal, request.Reason,
			"security.remediation.apply", "host", hostID)
		if !ok {
			return
		}
		dowodStepUp = dowod
	}

	zatrzymajPoBledzie := true
	if request.StopOnFailure != nil {
		zatrzymajPoBledzie = *request.StopOnFailure
	}

	tx, err := s.remediation.Pool().Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	plan, err := s.remediation.Zaloz(r.Context(), tx, remediation.Spec{
		HostID:          hostID,
		PlanHash:        raport.PlanHash,
		PlanHashVersion: raport.PlanHashVersion,
		Reason:          request.Reason,
		CreatedBy:       principal.Subject,
		StopOnFailure:   zatrzymajPoBledzie,
		BootIDBefore:    host.BootID,
	}, ulozony.Kroki)
	if errors.Is(err, remediation.ErrPlanWToku) {
		problem(w, http.StatusConflict, "plan_in_progress",
			"a remediation plan is already running on this host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "security.remediate", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"plan_id": plan.ID, "plan_hash": raport.PlanHash,
			"plan_hash_version": raport.PlanHashVersion,
			"steps":             nazwyKrokow(ulozony.Kroki), "skipped": ulozony.Pominiete,
			"stop_on_failure": zatrzymajPoBledzie, "reason": request.Reason,
			"step_up": dowodStepUp,
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"plan": plan, "skipped": ulozony.Pominiete,
	})
}

// handleListRemediation zwraca ostatnie plany naprawy hosta.
func (s *Server) handleListRemediation(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermSecurityRead, scope, "host", hostID); !ok {
		return
	}
	if s.remediation == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "count": 0})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	plany, err := s.remediation.Hosta(r.Context(), hostID, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	if plany == nil {
		plany = []remediation.Plan{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": plany, "count": len(plany)})
}

// handleStopRemediation zatrzymuje plan w toku.
//
// Krok juz dostarczony hostowi konczy sie po swojemu - panel nie udaje, ze
// odwolal cos, co host wlasnie wykonuje - ale jego zadanie jest anulowane,
// a kroki jeszcze nierozpoczete nie ruszaja.
func (s *Server) handleStopRemediation(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermSecurityRemediate, scope, "host", hostID)
	if !ok {
		return
	}
	if s.remediation == nil {
		problem(w, http.StatusServiceUnavailable, "remediation_disabled",
			"remediation plans are not enabled in this installation")
		return
	}

	plan, err := s.remediation.Plan(r.Context(), r.PathValue("plan"))
	if errors.Is(err, remediation.ErrNotFound) || (plan != nil && plan.HostID != hostID) {
		problem(w, http.StatusNotFound, "plan_not_found", "no such remediation plan on this host")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if plan.State != remediation.StanWToku {
		problem(w, http.StatusConflict, "plan_finished", "this plan is already finished")
		return
	}

	if biezacy := plan.Biezacy(); biezacy != nil && biezacy.JobID != "" {
		tx, err := s.jobs.Pool().Begin(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()
		if _, err := s.jobs.Cancel(r.Context(), tx, biezacy.JobID, principal.Subject,
			"plan naprawy zatrzymany"); err == nil {
			_ = tx.Commit(r.Context())
		}
	}
	if err := s.remediation.PomijPozostale(r.Context(), plan.ID, "plan zatrzymany przez operatora"); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.remediation.ZamknijPlan(r.Context(), plan.ID, remediation.StanZatrzymany); err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "security.remediate.stop", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"plan_id": plan.ID},
	})

	zaktualizowany, err := s.remediation.Plan(r.Context(), plan.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, zaktualizowany)
}

func nazwyKrokow(kroki []remediation.Krok) []string {
	nazwy := make([]string, 0, len(kroki))
	for _, krok := range kroki {
		nazwy = append(nazwy, krok.CheckID+":"+krok.ActionType)
	}
	return nazwy
}

// ocenZgodnosc liczy ustalenia dla hosta z fragmentow inwentarza.
func (s *Server) ocenZgodnosc(r *http.Request, host *hosts.Host) (compliance.Raport, error) {
	fragmenty, err := s.inventory.Fragments(r.Context(), host.ID)
	if err != nil {
		return compliance.Raport{}, err
	}
	return compliance.Ocen(host.ID, wejscieHosta(*host, fragmenty), time.Now().UTC()), nil
}

// wejscieHosta sklada wszystko, z czego licza sie sprawdzenia.
func wejscieHosta(host hosts.Host, fragmenty []inventory.Fragment) compliance.Wejscie {
	wejscie := compliance.Wejscie{
		Host: compliance.Host{
			Hostname:               host.Hostname,
			OSFamily:               host.OSFamily,
			PendingSecurityUpdates: host.PendingSecurityUpdates,
			RebootRequired:         host.RebootRequired,
		},
		Fragmenty: map[string]compliance.Fragment{},
	}
	for _, fragment := range fragmenty {
		wejscie.Fragmenty[fragment.Module] = przenies(fragment)
	}
	return wejscie
}

func przenies(fragment inventory.Fragment) compliance.Fragment {
	return compliance.Fragment{
		Module:            fragment.Module,
		Revision:          fragment.Revision,
		Payload:           fragment.Payload,
		ObservedAt:        fragment.ObservedAt,
		UnavailableReason: strings.TrimSpace(fragment.UnavailableReason),
	}
}
