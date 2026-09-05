package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	kopie "github.com/ultherego/flotestro/internal/backup"
	"github.com/ultherego/flotestro/internal/hosts"
	modul "github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/secrets"
)

// definicjaWidok laczy definicje kopii z tym, co o niej wiadomo z przebiegow.
//
// Sama definicja nie odpowiada na pytanie operatora. Pytanie brzmi: czy kopia
// jest aktualna, czy ktokolwiek ja kiedykolwiek sprawdzil i ile zajmuje. Na to
// odpowiada dopiero historia przebiegow.
type definicjaWidok struct {
	kopie.Definicja
	// Status jest ocena panelu, a nie faktem z hosta.
	Status string `json:"status"`
	// LastSuccessAt jest czasem ostatniej udanej kopii - z planu, czyli
	// z repozytorium, a nie z tego, co panel zlecil.
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	AgeHours      *float64   `json:"age_hours,omitempty"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastVerifyAt  *time.Time `json:"last_verify_at,omitempty"`
	// Unverified mowi, ze kopii dawno nikt nie odczytal. Backup, ktorego
	// nikt nie sprawdzil, jest obietnica, a nie zabezpieczeniem.
	Unverified     bool   `json:"unverified"`
	Snapshots      *int   `json:"snapshots,omitempty"`
	RepositorySize *int64 `json:"repository_size,omitempty"`
}

// raportKopii jest odpowiedzia zakladki hosta.
type raportKopii struct {
	HostID      string           `json:"host_id"`
	Definitions []definicjaWidok `json:"definitions"`
	Status      string           `json:"status"`
	// Tools mowi, czym host moze zrobic kopie. Bez narzedzia definicja jest
	// planem, ktorego nikt nie wykona.
	Tools json.RawMessage `json:"tools,omitempty"`
}

// handleHostBackups zwraca definicje kopii hosta wraz z ich stanem.
func (s *Server) handleHostBackups(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermBackupRead, scope, "host", hostID); !ok {
		return
	}

	definicje, err := s.kopie.Definicje(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	ostatnie, err := s.kopie.Ostatnie(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}

	teraz := time.Now().UTC()
	raport := raportKopii{HostID: hostID, Definitions: []definicjaWidok{}}
	for _, definicja := range definicje {
		widok := definicjaWidok{Definicja: definicja}
		przebiegi := ostatnie[definicja.Name]

		// Czas ostatniej udanej kopii bierzemy z planu, bo plan czyta
		// repozytorium: kopia moze powstac takze poza panelem, z crona.
		if plan, znany := przebiegi[modul.OperacjaPlan]; znany {
			widok.LastSuccessAt = plan.LastSuccessAt
			widok.Snapshots = plan.Snapshots
			widok.RepositorySize = plan.RepositorySize
		}
		if uruchomienie, znane := przebiegi[modul.OperacjaBackup]; znane {
			czas := uruchomienie.RecordedAt.UTC()
			widok.LastRunAt = &czas
			// Panel widzial udana kopie, ale planu jeszcze nie bylo -
			// wtedy to jest najlepsza wiedza, jaka mamy.
			if widok.LastSuccessAt == nil {
				widok.LastSuccessAt = &czas
			}
		}
		if sprawdzenie, znane := przebiegi[modul.OperacjaSprawdz]; znane {
			czas := sprawdzenie.RecordedAt.UTC()
			widok.LastVerifyAt = &czas
		}

		widok.Status = kopie.Stan(widok.LastSuccessAt, teraz)
		if widok.LastSuccessAt != nil {
			wiek := teraz.Sub(*widok.LastSuccessAt).Hours()
			widok.AgeHours = &wiek
		}
		widok.Unverified = kopie.Niesprawdzona(widok.LastVerifyAt, teraz)
		raport.Status = kopie.Gorszy(raport.Status, widok.Status)
		raport.Definitions = append(raport.Definitions, widok)
	}

	// Narzedzia bierzemy z inwentarza: to fakt o hoscie, ktory host zglasza
	// bez poswiadczen.
	if fragment, err := s.inventory.Fragment(r.Context(), hostID, "backups"); err == nil &&
		fragment != nil && len(fragment.Payload) > 0 {
		raport.Tools = json.RawMessage(fragment.Payload)
	}
	writeJSON(w, http.StatusOK, raport)
}

// zadanieDefinicji opisuje definicje kopii przychodzaca z panelu.
type zadanieDefinicji struct {
	Name           string            `json:"name"`
	Tool           string            `json:"tool"`
	Repository     string            `json:"repository,omitempty"`
	Paths          []string          `json:"paths,omitempty"`
	Excludes       []string          `json:"excludes,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	KeepLast       int               `json:"keep_last,omitempty"`
	KeepDaily      int               `json:"keep_daily,omitempty"`
	KeepWeekly     int               `json:"keep_weekly,omitempty"`
	KeepMonthly    int               `json:"keep_monthly,omitempty"`
	Prune          bool              `json:"prune,omitempty"`
	Runbook        string            `json:"runbook,omitempty"`
	Initialize     bool              `json:"initialize,omitempty"`
	PasswordSecret string            `json:"password_secret,omitempty"`
	EnvSecrets     map[string]string `json:"env_secrets,omitempty"`
	Note           string            `json:"note,omitempty"`
}

// handleSetBackupDefinition zaklada albo zmienia definicje kopii.
//
// To nie jest operacja na hoscie i nie idzie przez opspec: opisuje, co panel
// ma backupowac, a nie zmienia stanu maszyny. Host dowiaduje sie o definicji
// dopiero wtedy, gdy ktos zleci kopie.
func (s *Server) handleSetBackupDefinition(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermBackupRun, scope, "host", hostID)
	if !ok {
		return
	}

	var zadanie zadanieDefinicji
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&zadanie); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	// Ta sama walidacja, ktora obowiazuje host: definicja, ktorej host by nie
	// przyjal, nie moze czekac w panelu do pierwszej proby backupu.
	definicja := modul.Definicja{
		ID: zadanie.Name, Tool: zadanie.Tool, Repository: zadanie.Repository,
		Paths: zadanie.Paths, Excludes: zadanie.Excludes, Tags: zadanie.Tags,
		KeepLast: zadanie.KeepLast, KeepDaily: zadanie.KeepDaily,
		KeepWeekly: zadanie.KeepWeekly, KeepMonthly: zadanie.KeepMonthly,
		Prune: zadanie.Prune, Runbook: zadanie.Runbook, Initialize: zadanie.Initialize,
	}
	if err := definicja.Waliduj(); err != nil {
		problem(w, http.StatusBadRequest, "invalid_definition", err.Error())
		return
	}
	nazwyZmiennych := make([]string, 0, len(zadanie.EnvSecrets))
	for nazwa := range zadanie.EnvSecrets {
		nazwyZmiennych = append(nazwyZmiennych, nazwa)
	}
	if err := modul.WalidujSrodowisko(nazwyZmiennych); err != nil {
		problem(w, http.StatusBadRequest, "invalid_environment", err.Error())
		return
	}
	// Sekret wskazany w definicji musi istniec: inaczej blad wyszedlby dopiero
	// przy pierwszej kopii, czyli w najgorszym momencie.
	nazwySekretow := append([]string{}, zadanie.PasswordSecret)
	for _, nazwa := range zadanie.EnvSecrets {
		nazwySekretow = append(nazwySekretow, nazwa)
	}
	for _, nazwa := range nazwySekretow {
		if nazwa == "" {
			continue
		}
		if s.secrets == nil {
			problem(w, http.StatusServiceUnavailable, "secrets_disabled",
				"this installation has no secret store")
			return
		}
		if _, err := s.secrets.Sekret(r.Context(), nazwa); errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusBadRequest, "secret_not_found", "no secret named "+nazwa)
			return
		} else if err != nil {
			s.fail(w, err)
			return
		}
	}

	zapisana, err := s.kopie.Ustaw(r.Context(), kopie.Definicja{
		HostID: hostID, Name: zadanie.Name, Tool: zadanie.Tool,
		Repository: zadanie.Repository, Paths: zadanie.Paths,
		Excludes: zadanie.Excludes, Tags: zadanie.Tags,
		KeepLast: zadanie.KeepLast, KeepDaily: zadanie.KeepDaily,
		KeepWeekly: zadanie.KeepWeekly, KeepMonthly: zadanie.KeepMonthly,
		Prune: zadanie.Prune, Runbook: zadanie.Runbook, Initialize: zadanie.Initialize,
		PasswordSecret: zadanie.PasswordSecret, EnvSecrets: zadanie.EnvSecrets,
		Note: zadanie.Note, UpdatedBy: principal.Subject,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "backup.definition.set", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"name": zapisana.Name, "tool": zapisana.Tool,
			"repository": zapisana.Repository, "password_secret": zapisana.PasswordSecret,
		},
	})
	writeJSON(w, http.StatusOK, zapisana)
}

// handleDeleteBackupDefinition kasuje definicje. Historia przebiegow zostaje.
func (s *Server) handleDeleteBackupDefinition(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermBackupRun, scope, "host", hostID)
	if !ok {
		return
	}
	nazwa := r.URL.Query().Get("name")
	if nazwa == "" {
		problem(w, http.StatusBadRequest, "name_required", "name query parameter is required")
		return
	}
	err := s.kopie.Usun(r.Context(), hostID, nazwa)
	if errors.Is(err, kopie.ErrNieZnaleziono) {
		problem(w, http.StatusNotFound, "definition_not_found", "no such backup definition")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "backup.definition.remove", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": nazwa},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleBackupRuns zwraca historie przebiegow kopii hosta.
func (s *Server) handleBackupRuns(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermBackupRead, scope, "host", hostID); !ok {
		return
	}
	przebiegi, err := s.kopie.Przebiegi(r.Context(), hostID, r.URL.Query().Get("definition"), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	if przebiegi == nil {
		przebiegi = []kopie.Przebieg{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": przebiegi, "count": len(przebiegi)})
}

// kopiaFloty opisuje jedna definicje w skali floty.
type kopiaFloty struct {
	HostID        string     `json:"host_id"`
	Hostname      string     `json:"hostname"`
	Definition    string     `json:"definition"`
	Tool          string     `json:"tool"`
	Repository    string     `json:"repository,omitempty"`
	Status        string     `json:"status"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	AgeHours      *float64   `json:"age_hours,omitempty"`
	Unverified    bool       `json:"unverified"`
}

// handleFleetBackups zwraca stan kopii calej widocznej floty.
//
// To jest podstawowy tryb tego modulu. Backup psuje sie cicho: nikt nie
// zauwaza, ze od trzech tygodni nie ma nowej kopii, dopoki nie trzeba jej
// odtworzyc. Jedyna obrona jest lista, na ktorej wiek wszystkich kopii stoi
// obok siebie.
func (s *Server) handleFleetBackups(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermBackupRead, "fleet")
	if !ok {
		return
	}
	lista, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	nazwy := map[string]string{}
	identyfikatory := make([]string, 0, len(lista))
	for _, host := range lista {
		if principal.Can(authz.PermBackupRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			nazwy[host.ID] = host.Hostname
			identyfikatory = append(identyfikatory, host.ID)
		}
	}

	definicje, err := s.kopie.DefinicjeFloty(r.Context(), identyfikatory)
	if err != nil {
		s.fail(w, err)
		return
	}
	plany, err := s.kopie.OstatnieWeFlocie(r.Context(), identyfikatory, modul.OperacjaPlan)
	if err != nil {
		s.fail(w, err)
		return
	}
	sprawdzenia, err := s.kopie.OstatnieWeFlocie(r.Context(), identyfikatory, modul.OperacjaSprawdz)
	if err != nil {
		s.fail(w, err)
		return
	}
	uruchomienia, err := s.kopie.OstatnieWeFlocie(r.Context(), identyfikatory, modul.OperacjaBackup)
	if err != nil {
		s.fail(w, err)
		return
	}

	klucz := func(hostID, definicja string) string { return hostID + "\x1f" + definicja }
	ostatniPlan := map[string]kopie.Przebieg{}
	for _, plan := range plany {
		ostatniPlan[klucz(plan.HostID, plan.Definition)] = plan
	}
	ostatnieSprawdzenie := map[string]kopie.Przebieg{}
	for _, sprawdzenie := range sprawdzenia {
		ostatnieSprawdzenie[klucz(sprawdzenie.HostID, sprawdzenie.Definition)] = sprawdzenie
	}
	ostatnieUruchomienie := map[string]kopie.Przebieg{}
	for _, uruchomienie := range uruchomienia {
		ostatnieUruchomienie[klucz(uruchomienie.HostID, uruchomienie.Definition)] = uruchomienie
	}

	teraz := time.Now().UTC()
	pozycje := make([]kopiaFloty, 0, len(definicje))
	liczby := map[string]int{}
	niesprawdzone := 0
	for _, definicja := range definicje {
		pozycja := kopiaFloty{
			HostID: definicja.HostID, Hostname: nazwy[definicja.HostID],
			Definition: definicja.Name, Tool: definicja.Tool,
			Repository: definicja.Repository,
		}
		identyfikator := klucz(definicja.HostID, definicja.Name)
		if plan, znany := ostatniPlan[identyfikator]; znany {
			pozycja.LastSuccessAt = plan.LastSuccessAt
		}
		if pozycja.LastSuccessAt == nil {
			if uruchomienie, znane := ostatnieUruchomienie[identyfikator]; znane {
				czas := uruchomienie.RecordedAt.UTC()
				pozycja.LastSuccessAt = &czas
			}
		}
		var sprawdzone *time.Time
		if sprawdzenie, znane := ostatnieSprawdzenie[identyfikator]; znane {
			czas := sprawdzenie.RecordedAt.UTC()
			sprawdzone = &czas
		}
		pozycja.Status = kopie.Stan(pozycja.LastSuccessAt, teraz)
		if pozycja.LastSuccessAt != nil {
			wiek := teraz.Sub(*pozycja.LastSuccessAt).Hours()
			pozycja.AgeHours = &wiek
		}
		pozycja.Unverified = kopie.Niesprawdzona(sprawdzone, teraz)
		if pozycja.Unverified {
			niesprawdzone++
		}
		liczby[pozycja.Status]++
		pozycje = append(pozycje, pozycja)
	}

	// Najgorsze na gorze: lista, ktora zaczyna sie od kopii sprzed miesiaca,
	// odpowiada na pytanie operatora bez przewijania.
	sort.SliceStable(pozycje, func(i, j int) bool {
		if pozycje[i].Status != pozycje[j].Status {
			return kopie.Gorszy(pozycje[i].Status, pozycje[j].Status) == pozycje[i].Status
		}
		if (pozycje[i].LastSuccessAt == nil) != (pozycje[j].LastSuccessAt == nil) {
			return pozycje[i].LastSuccessAt == nil
		}
		if pozycje[i].LastSuccessAt == nil {
			return pozycje[i].Hostname < pozycje[j].Hostname
		}
		return pozycje[i].LastSuccessAt.Before(*pozycje[j].LastSuccessAt)
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"items": pozycje, "counts": liczby, "unverified": niesprawdzone,
		"hosts_total": len(identyfikatory),
		"thresholds": map[string]int{
			"warning_hours":     int(kopie.ProgOstrzezenia.Hours()),
			"critical_hours":    int(kopie.ProgPilny.Hours()),
			"verification_days": int(kopie.ProgWeryfikacji.Hours() / 24),
		},
	})
}
