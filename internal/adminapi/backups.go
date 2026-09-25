package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	backupstore "github.com/ultherego/flotestro/internal/backup"
	"github.com/ultherego/flotestro/internal/budgets"
	backupmodule "github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/secrets"
)

// definitionView joins a backup definition with what is known about it from
// the runs.
type definitionView struct {
	backupstore.Definition
	// Status is the panel's judgement, not a fact from the host.
	Status string `json:"status"`
	// LastSuccessAt is the time of the last successful copy - from the
	// plan, that is from the repository, not from what the panel ordered.
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	AgeHours      *float64   `json:"age_hours,omitempty"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastVerifyAt  *time.Time `json:"last_verify_at,omitempty"`
	// Unverified says nobody has read the copy for a long time. A backup
	// nobody checked is a promise, not a safeguard.
	Unverified     bool   `json:"unverified"`
	Snapshots      *int   `json:"snapshots,omitempty"`
	RepositorySize *int64 `json:"repository_size,omitempty"`
}

// backupReport is the answer of the host tab.
type backupReport struct {
	HostID      string           `json:"host_id"`
	Definitions []definitionView `json:"definitions"`
	Status      string           `json:"status"`
	// Tools says what the host can make a copy with. Without a tool the
	// definition is a plan nobody executes.
	Tools json.RawMessage `json:"tools,omitempty"`
}

// handleHostBackups returns the backup definitions of a host together with
// their state.
func (s *Server) handleHostBackups(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermBackupRead, scope, "host", hostID); !ok {
		return
	}

	definitions, err := s.backups.Definitions(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	// The tag covers the definitions of the host as a set: a write names one of
	// them by its name in the body, and what an editor read was the whole list.
	setETag(w, backupDefinitionsTag(definitions))
	latest, err := s.backups.Latest(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}

	now := time.Now().UTC()
	report := backupReport{HostID: hostID, Definitions: []definitionView{}}
	for _, definition := range definitions {
		view := definitionView{Definition: definition}
		runs := latest[definition.Name]

		// The time of the last successful copy is taken from the plan, because the
		// plan reads the repository: a copy may also be made outside the panel, from
		// cron.
		if plan, known := runs[backupmodule.OperationPlan]; known {
			view.LastSuccessAt = plan.LastSuccessAt
			view.Snapshots = plan.Snapshots
			view.RepositorySize = plan.RepositorySize
		}
		if run, present := runs[backupmodule.OperationBackup]; present {
			moment := run.RecordedAt.UTC()
			view.LastRunAt = &moment
			// The panel saw a successful copy, but there was no plan yet - then
			// this is the best knowledge there is.
			if view.LastSuccessAt == nil {
				view.LastSuccessAt = &moment
			}
		}
		if verification, present := runs[backupmodule.OperationVerify]; present {
			moment := verification.RecordedAt.UTC()
			view.LastVerifyAt = &moment
		}

		view.Status = backupstore.State(view.LastSuccessAt, now)
		if view.LastSuccessAt != nil {
			age := now.Sub(*view.LastSuccessAt).Hours()
			view.AgeHours = &age
		}
		view.Unverified = backupstore.Unverified(view.LastVerifyAt, now)
		report.Status = backupstore.Worse(report.Status, view.Status)
		report.Definitions = append(report.Definitions, view)
	}

	// The tools are taken from the inventory: it is a fact about the host
	// the host reports without credentials.
	if fragment, err := s.inventory.Fragment(r.Context(), hostID, "backups"); err == nil &&
		fragment != nil && len(fragment.Payload) > 0 {
		report.Tools = json.RawMessage(fragment.Payload)
	}
	writeJSON(w, http.StatusOK, report)
}

// backupDefinitionsTag is the entity tag of a host's backup definitions: it
// moves when a definition is added, changed or removed.
func backupDefinitionsTag(definitions []backupstore.Definition) string {
	parts := make([]string, 0, len(definitions)*2)
	for _, definition := range definitions {
		parts = append(parts, definition.Name, definition.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	return etagOf(parts...)
}

// requireBackupDefinitionsMatch enforces If-Match against the current set
// of the host's definitions.
func (s *Server) requireBackupDefinitionsMatch(w http.ResponseWriter, r *http.Request, hostID string) bool {
	if r.Header.Get("If-Match") == "" {
		return true
	}
	definitions, err := s.backups.Definitions(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return false
	}
	return requireMatch(w, r, backupDefinitionsTag(definitions))
}

// setBackupDefinitionsTag puts the tag of the set after a write on the
// answer, so an editor can go on without reading the list again.
func (s *Server) setBackupDefinitionsTag(w http.ResponseWriter, r *http.Request, hostID string) {
	if definitions, err := s.backups.Definitions(r.Context(), hostID); err == nil {
		setETag(w, backupDefinitionsTag(definitions))
	}
}

// definitionRequest describes a backup definition coming from the panel.
type definitionRequest struct {
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

// handleSetBackupDefinition creates or changes a backup definition.
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

	var request definitionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	// The same validation that binds the host: a definition the host would
	// not accept must not wait in the panel until the first backup attempt.
	definition := backupmodule.Definition{
		ID: request.Name, Tool: request.Tool, Repository: request.Repository,
		Paths: request.Paths, Excludes: request.Excludes, Tags: request.Tags,
		KeepLast: request.KeepLast, KeepDaily: request.KeepDaily,
		KeepWeekly: request.KeepWeekly, KeepMonthly: request.KeepMonthly,
		Prune: request.Prune, Runbook: request.Runbook, Initialize: request.Initialize,
	}
	if err := definition.Validate(); err != nil {
		problem(w, http.StatusBadRequest, "invalid_definition", err.Error())
		return
	}
	variableNames := make([]string, 0, len(request.EnvSecrets))
	for name := range request.EnvSecrets {
		variableNames = append(variableNames, name)
	}
	if err := backupmodule.ValidateEnvironment(variableNames); err != nil {
		problem(w, http.StatusBadRequest, "invalid_environment", err.Error())
		return
	}
	// The secret named in the definition must exist: otherwise the error
	// would come out only at the first copy, that is at the worst moment.
	secretNames := append([]string{}, request.PasswordSecret)
	for _, name := range request.EnvSecrets {
		secretNames = append(secretNames, name)
	}
	for _, name := range secretNames {
		if name == "" {
			continue
		}
		if s.secrets == nil {
			problem(w, http.StatusServiceUnavailable, "secrets_disabled",
				"this installation has no secret store")
			return
		}
		if _, err := s.secrets.Secret(r.Context(), name); errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusBadRequest, "secret_not_found", "no secret named "+name)
			return
		} else if err != nil {
			s.fail(w, err)
			return
		}
	}

	if !s.requireBackupDefinitionsMatch(w, r, hostID) {
		return
	}
	// The definition and the entry naming who changed it go in together: a
	// definition that commits without its trail is a change nobody made.
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	saved, err := s.backups.Set(r.Context(), tx, backupstore.Definition{
		HostID: hostID, Name: request.Name, Tool: request.Tool,
		Repository: request.Repository, Paths: request.Paths,
		Excludes: request.Excludes, Tags: request.Tags,
		KeepLast: request.KeepLast, KeepDaily: request.KeepDaily,
		KeepWeekly: request.KeepWeekly, KeepMonthly: request.KeepMonthly,
		Prune: request.Prune, Runbook: request.Runbook, Initialize: request.Initialize,
		PasswordSecret: request.PasswordSecret, EnvSecrets: request.EnvSecrets,
		Note: request.Note, UpdatedBy: principal.Subject,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "backup.definition.set", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"name": saved.Name, "tool": saved.Tool,
			"repository": saved.Repository, "password_secret": saved.PasswordSecret,
		},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	s.setBackupDefinitionsTag(w, r, hostID)
	writeJSON(w, http.StatusOK, saved)
}

// handleDeleteBackupDefinition deletes a definition. The run history stays.
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
	name := r.URL.Query().Get("name")
	if name == "" {
		problem(w, http.StatusBadRequest, "name_required", "name query parameter is required")
		return
	}
	if !s.requireBackupDefinitionsMatch(w, r, hostID) {
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	err = s.backups.Delete(r.Context(), tx, hostID, name)
	if errors.Is(err, backupstore.ErrNotFound) {
		problem(w, http.StatusNotFound, "definition_not_found", "no such backup definition")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.audit.RecordTx(r.Context(), tx, audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "backup.definition.remove", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"name": name},
	}); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	s.setBackupDefinitionsTag(w, r, hostID)
	w.WriteHeader(http.StatusNoContent)
}

// handleBackupRuns returns the backup run history of a host.
func (s *Server) handleBackupRuns(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermBackupRead, scope, "host", hostID); !ok {
		return
	}
	runs, err := s.backups.Runs(r.Context(), hostID, r.URL.Query().Get("definition"), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	if runs == nil {
		runs = []backupstore.Run{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": runs, "count": len(runs)})
}

// fleetBackup describes one definition at fleet scale.
type fleetBackup struct {
	HostID string `json:"host_id"`
	// LastRestoreAt is the date of the last successful restore attempt.
	LastRestoreAt *time.Time `json:"last_restore_at,omitempty"`
	Hostname      string     `json:"hostname"`
	Definition    string     `json:"definition"`
	Tool          string     `json:"tool"`
	Repository    string     `json:"repository,omitempty"`
	Status        string     `json:"status"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	AgeHours      *float64   `json:"age_hours,omitempty"`
	Unverified    bool       `json:"unverified"`
}

// fleetBackupOf judges one definition at the moment now, the way the
// host tab judges it.
func fleetBackupOf(row backupstore.FleetRow, now time.Time) fleetBackup {
	item := fleetBackup{
		HostID: row.HostID, Hostname: row.Hostname, Definition: row.Definition,
		Tool: row.Tool, Repository: row.Repository, LastSuccessAt: row.LastSuccessAt,
		LastRestoreAt: row.RestoredAt,
	}
	item.Status = backupstore.State(item.LastSuccessAt, now)
	if item.LastSuccessAt != nil {
		age := now.Sub(*item.LastSuccessAt).Hours()
		item.AgeHours = &age
	}
	item.Unverified = backupstore.Unverified(row.VerifiedAt, now)
	return item
}

// fleetBackupsView is the answer of the fleet screen: the coverage of the
// fleet, the counts over every definition in scope, the backends and one page
// of the list.
type fleetBackupsView struct {
	fleetCoverage
	Items      []fleetBackup  `json:"items"`
	Count      int            `json:"count"`
	Total      int            `json:"total"`
	NextCursor string         `json:"next_cursor,omitempty"`
	Counts     map[string]int `json:"counts"`
	Unverified int            `json:"unverified"`
	// NeverRestored counts the definitions nobody has ever restored: a
	// copy nobody has read back is hope, not a copy.
	NeverRestored int              `json:"never_restored"`
	Repositories  []repositoryLoad `json:"repositories"`
	// HostsTotal keeps the name the screen read before the coverage head.
	HostsTotal int            `json:"hosts_total"`
	Thresholds map[string]int `json:"thresholds"`
}

// handleFleetBackups returns the backup state of the whole visible fleet. This
// is the basic mode of this module.
func (s *Server) handleFleetBackups(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermBackupRead, "fleet")
	if !ok {
		return
	}
	asCSV, ok := exportFormat(w, r)
	if !ok {
		return
	}
	limit, cursorText, ok := parseFleetPage(w, r)
	if !ok {
		return
	}
	cursor, err := backupstore.ParseFleetCursor(cursorText)
	if err != nil {
		invalidCursor(w, err)
		return
	}
	scopes := principal.ScopesFor(authz.PermBackupRead)
	now := time.Now().UTC()
	if asCSV {
		s.writeBackupsCSV(w, r, scopes, now)
		return
	}
	// The pages after the first are judged at the moment of the first, so
	// a copy keeps its state from one page to the next.
	if cursor.Set {
		now = cursor.Now
	}
	summary, err := s.backups.FleetSummary(r.Context(), scopes, now)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows, next, err := s.backups.FleetPage(r.Context(), scopes, cursor, limit, now)
	if err != nil {
		s.fail(w, err)
		return
	}
	items := make([]fleetBackup, 0, len(rows))
	for _, row := range rows {
		items = append(items, fleetBackupOf(row, now))
	}
	loads, err := s.backups.RepositoryLoads(r.Context(), scopes, now)
	if err != nil {
		s.fail(w, err)
		return
	}

	coverage := fleetCoverage{
		TotalHosts: summary.Hosts, EvaluatedHosts: summary.HostsWithDefinitions,
		UnknownHosts:   max(summary.Hosts-summary.HostsWithDefinitions, 0),
		UnknownReasons: map[string]int{},
	}
	if coverage.UnknownHosts > 0 {
		coverage.UnknownReasons[unknownNoDefinition] = coverage.UnknownHosts
	}
	writeJSON(w, http.StatusOK, fleetBackupsView{
		fleetCoverage: coverage,
		Items:         items, Count: len(items), Total: summary.Definitions, NextCursor: next,
		Counts: summary.Counts, Unverified: summary.Unverified, NeverRestored: summary.NeverRestored,
		Repositories: s.repositoryLoads(r.Context(), loads),
		HostsTotal:   summary.Hosts,
		Thresholds: map[string]int{
			"warning_hours":     int(backupstore.WarningThreshold.Hours()),
			"critical_hours":    int(backupstore.CriticalThreshold.Hours()),
			"verification_days": int(backupstore.VerificationThreshold.Hours() / 24),
		},
	})
}

// backupsCSVColumns is the header of the fleet export. The order is fixed:
// a sheet built against one export reads the next one.
var backupsCSVColumns = []string{
	"hostname", "host_id", "definition", "tool", "repository", "status", "last_success_at", "age_hours",
	"unverified", "last_restore_at",
}

// writeBackupsCSV streams every backup definition of the visible fleet, the
// worst first and from the same cursor the screen pages with, so the two agree.
func (s *Server) writeBackupsCSV(w http.ResponseWriter, r *http.Request, scopes []authz.Scope, now time.Time) {
	s.writeCSV(w, r, exportFileName("backups", now), backupsCSVColumns, func(yield func([]string) bool) error {
		cursor := backupstore.FleetCursor{}
		for {
			rows, next, err := s.backups.FleetPage(r.Context(), scopes, cursor, backupstore.MaxPage, now)
			if err != nil {
				return err
			}
			for _, row := range rows {
				if !yield(fleetBackupCSVRow(fleetBackupOf(row, now))) {
					return nil
				}
			}
			if next == "" {
				return nil
			}
			if cursor, err = backupstore.ParseFleetCursor(next); err != nil {
				return err
			}
		}
	})
}

// fleetBackupCSVRow renders one definition in the order of
// backupsCSVColumns.
func fleetBackupCSVRow(item fleetBackup) []string {
	age := ""
	if item.AgeHours != nil {
		age = csvFloat(*item.AgeHours)
	}
	return []string{
		item.Hostname, item.HostID, item.Definition, item.Tool, item.Repository, item.Status,
		formatTime(item.LastSuccessAt), age, strconv.FormatBool(item.Unverified), formatTime(item.LastRestoreAt),
	}
}

// repositoryLoad describes one backend seen from the whole fleet.
type repositoryLoad struct {
	Repository string `json:"repository"`
	Hosts      int    `json:"hosts"`
	Unverified int    `json:"unverified"`
	// OldestAgeHours is the age of the oldest copy in this repository. A
	// repository is as good as its worst copy.
	OldestAgeHours *float64 `json:"oldest_age_hours,omitempty"`
	// BudgetKey, Capacity and Used describe the budget of this backend.
	BudgetKey string `json:"budget_key"`
	Capacity  *int   `json:"capacity,omitempty"`
	Used      *int   `json:"used,omitempty"`
	Claimants *int   `json:"claimants,omitempty"`
}

// repositoryLoads attaches the budget of every backend the database grouped
// the fleet copies by.
func (s *Server) repositoryLoads(ctx context.Context, grouped []backupstore.RepositoryLoad) []repositoryLoad {
	loads := make([]repositoryLoad, 0, len(grouped))
	for _, group := range grouped {
		loads = append(loads, repositoryLoad{
			Repository: group.Repository, BudgetKey: budgets.BackendKey(group.Repository),
			Hosts: group.Definitions, Unverified: group.Unverified, OldestAgeHours: group.OldestAgeHours,
		})
	}
	if len(loads) == 0 {
		return loads
	}

	// Budgets are optional: an installation without them still shows the
	// backends, only without their capacity.
	if s.budgets != nil {
		if states, err := s.budgets.States(ctx); err == nil {
			byKey := map[string]budgets.State{}
			for _, state := range states {
				byKey[state.Key] = state
			}
			for i := range loads {
				entry := &loads[i]
				state, present := byKey[entry.BudgetKey]
				if !present {
					// The default policy for all backends counts the same as one
					// described separately.
					state, present = byKey[budgets.Pattern(entry.BudgetKey)]
				}
				if !present {
					continue
				}
				capacity, used, claimants := state.Capacity, state.Used, state.Claimants
				entry.Capacity, entry.Used, entry.Claimants = &capacity, &used, &claimants
			}
		}
	}
	return loads
}
