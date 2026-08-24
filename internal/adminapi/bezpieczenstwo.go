package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/compliance"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
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
}

// wynikNaprawy opisuje jeden krok planu po zleceniu.
type wynikNaprawy struct {
	CheckID string `json:"check_id"`
	Action  string `json:"action,omitempty"`
	JobID   string `json:"job_id,omitempty"`
	State   string `json:"state,omitempty"`
	// Skipped mowi, dlaczego kroku nie zlecono.
	Skipped string `json:"skipped,omitempty"`
}

// handleHostRemediation zleca naprawe wskazanych ustalen.
//
// Naprawa nie jest osobna operacja na hoscie. Kazdy krok to zwykle zadanie
// modulu, ktory za dana rzecz odpowiada - z jego uprawnieniem, jego ryzykiem
// i jego zatwierdzeniem. Uprawnienie do naprawy nie zastepuje uprawnien tych
// modulow, tylko dokłada sie do nich.
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

	// Uprawnienia sprawdzamy dla calego planu przed zleceniem czegokolwiek:
	// polowa naprawy jest gorsza niz zadna, bo zostawia host w stanie,
	// ktorego nikt nie planowal.
	najwyzszeRyzyko := opspec.RiskLow
	for _, krok := range kroki {
		if krok.Remediation == nil || krok.Remediation.Action == "" {
			continue
		}
		akcja := opspec.ActionType(krok.Remediation.Action)
		if !akcja.Known() {
			problem(w, http.StatusBadRequest, "unknown_action",
				"finding "+krok.CheckID+" maps to an operation this panel does not know")
			return
		}
		if _, ok := s.authorize(w, r, authz.Permission(akcja.Permission()), scope, "host", hostID); !ok {
			return
		}
		if akcja.RequiresTargetConfirmation() {
			problem(w, http.StatusBadRequest, "not_a_remediation",
				"finding "+krok.CheckID+" maps to an irreversible operation; run it host by host")
			return
		}
		if akcja.RequiresFreshAuth() {
			najwyzszeRyzyko = opspec.RiskCritical
		}
	}

	// Naprawa siegajaca po operacje najwyzszego ryzyka wymaga swiezego
	// uwierzytelnienia tak samo jak ta operacja zlecona wprost.
	var dowodStepUp map[string]any
	if najwyzszeRyzyko == opspec.RiskCritical {
		dowod, ok := s.requireStepUp(w, r, principal, request.Reason,
			"security.remediation.apply", "host", hostID)
		if !ok {
			return
		}
		dowodStepUp = dowod
	}

	wyniki := make([]wynikNaprawy, 0, len(kroki))
	for _, krok := range kroki {
		wynik := wynikNaprawy{CheckID: krok.CheckID}
		switch {
		case !krok.Wymaga():
			wynik.Skipped = "ustalenie nie wymaga dzialania"
		case krok.Remediation == nil || krok.Remediation.Action == "":
			wynik.Skipped = "to ustalenie nie ma operacji naprawczej"
			if krok.Remediation != nil {
				wynik.Skipped = krok.Remediation.Note
			}
		default:
			job, err := s.zlecNaprawe(r, host, krok, raport.PlanHash, principal.Subject, request.Reason, dowodStepUp)
			if err != nil {
				problem(w, http.StatusBadRequest, "invalid_operation", err.Error())
				return
			}
			wynik.Action = krok.Remediation.Action
			wynik.JobID = job.ID
			wynik.State = string(job.State)
		}
		wyniki = append(wyniki, wynik)
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"host_id": hostID, "plan_hash": raport.PlanHash, "steps": wyniki,
	})
}

// zlecNaprawe tworzy zadanie jednego kroku planu.
func (s *Server) zlecNaprawe(r *http.Request, host *hosts.Host, krok compliance.Ustalenie,
	planHash, actor, powod string, dowodStepUp map[string]any) (*jobs.Job, error) {
	akcja := opspec.ActionType(krok.Remediation.Action)
	var payload opspec.Payload
	if len(krok.Remediation.Payload) > 0 {
		if err := json.Unmarshal(krok.Remediation.Payload, &payload); err != nil {
			return nil, err
		}
	}
	if err := opspec.Validate(akcja, payload); err != nil {
		return nil, err
	}
	if capability := akcja.RequiredCapability(); !hostHasCapability(host, capability) {
		return nil, errors.New("host nie ma zdolnosci " + capability)
	}

	tx, err := s.jobs.Pool().Begin(r.Context())
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	job, err := s.jobs.Create(r.Context(), tx, jobs.Spec{
		HostID:  host.ID,
		Action:  akcja,
		Payload: payload,
		// Klucz idempotencji wiaze zadanie z planem: powtorzone zlecenie tego
		// samego planu nie tworzy drugiego zadania na ten sam krok.
		IdempotencyKey:  "remediation:" + host.ID + ":" + krok.CheckID + ":" + planHash[:16],
		RequiresApprova: akcja.Mutating(),
		CreatedBy:       actor,
		RequestID:       requestIDOf(r),
		Preconditions: jobs.Preconditions{
			OSFamily:             host.OSFamily,
			RequiredCapabilities: []string{akcja.RequiredCapability()},
		},
	})
	if err != nil {
		return nil, err
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: actor,
		Action: "security.remediate", TargetType: "job", TargetID: job.ID,
		RequestID: job.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": host.ID, "check_id": krok.CheckID,
			"check_version": krok.CheckVersion, "action_type": job.ActionType,
			"plan_hash": planHash, "reason": powod, "step_up": dowodStepUp,
		},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(r.Context()); err != nil {
		return nil, err
	}
	return job, nil
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
