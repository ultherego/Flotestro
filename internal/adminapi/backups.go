package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	backupstore "github.com/ultherego/flotestro/internal/backup"
	"github.com/ultherego/flotestro/internal/budgets"
	"github.com/ultherego/flotestro/internal/hosts"
	backupmodule "github.com/ultherego/flotestro/internal/modules/backup"
	"github.com/ultherego/flotestro/internal/secrets"
)

// definitionView joins a backup definition with what is known about it
// from the runs.
//
// The definition alone does not answer the operator's question. The
// question is: is the copy current, has anybody ever checked it and how
// much does it take. Only the run history answers that.
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

		// The time of the last successful copy is taken from the plan,
		// because the plan reads the repository: a copy may also be made
		// outside the panel, from cron.
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
//
// This is not an operation on the host and does not go through opspec: it
// describes what the panel is to back up, it does not change the machine
// state. The host learns about the definition only when somebody orders a
// copy.
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

	saved, err := s.backups.Set(r.Context(), backupstore.Definition{
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
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "backup.definition.set", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"name": saved.Name, "tool": saved.Tool,
			"repository": saved.Repository, "password_secret": saved.PasswordSecret,
		},
	})
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
	err := s.backups.Delete(r.Context(), hostID, name)
	if errors.Is(err, backupstore.ErrNotFound) {
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
		Detail: map[string]any{"name": name},
	})
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
	// LastRestoreAt is the date of the last successful restore attempt. No
	// value means "never restored", not "the restore failed" - these are
	// two different answers and both are worth seeing.
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

// handleFleetBackups returns the backup state of the whole visible fleet.
//
// This is the basic mode of this module. Backups break quietly: nobody
// notices there has been no new copy for three weeks until it has to be
// restored. The only defence is a list on which the age of all the copies
// stands side by side.
func (s *Server) handleFleetBackups(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermBackupRead, "fleet")
	if !ok {
		return
	}
	list, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	names := map[string]string{}
	ids := make([]string, 0, len(list))
	for _, host := range list {
		if principal.Can(authz.PermBackupRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			names[host.ID] = host.Hostname
			ids = append(ids, host.ID)
		}
	}

	definitions, err := s.backups.FleetDefinitions(r.Context(), ids)
	if err != nil {
		s.fail(w, err)
		return
	}
	plans, err := s.backups.LatestInFleet(r.Context(), ids, backupmodule.OperationPlan)
	if err != nil {
		s.fail(w, err)
		return
	}
	verifications, err := s.backups.LatestInFleet(r.Context(), ids, backupmodule.OperationVerify)
	if err != nil {
		s.fail(w, err)
		return
	}
	backupRuns, err := s.backups.LatestInFleet(r.Context(), ids, backupmodule.OperationBackup)
	if err != nil {
		s.fail(w, err)
		return
	}
	// A copy nobody has ever restored is hope, not a copy. The panel does
	// not force a restore attempt, but is meant to say when the last one was
	// - and when there never was one.
	restores, err := s.backups.LatestInFleet(r.Context(), ids, backupmodule.OperationRestore)
	if err != nil {
		s.fail(w, err)
		return
	}

	key := func(hostID, definition string) string { return hostID + "\x1f" + definition }
	latestPlan := map[string]backupstore.Run{}
	for _, plan := range plans {
		latestPlan[key(plan.HostID, plan.Definition)] = plan
	}
	latestVerification := map[string]backupstore.Run{}
	for _, verification := range verifications {
		latestVerification[key(verification.HostID, verification.Definition)] = verification
	}
	latestRun := map[string]backupstore.Run{}
	for _, run := range backupRuns {
		latestRun[key(run.HostID, run.Definition)] = run
	}
	latestRestore := map[string]backupstore.Run{}
	for _, restore := range restores {
		latestRestore[key(restore.HostID, restore.Definition)] = restore
	}

	now := time.Now().UTC()
	neverRestored := 0
	items := make([]fleetBackup, 0, len(definitions))
	counts := map[string]int{}
	unverified := 0
	for _, definition := range definitions {
		item := fleetBackup{
			HostID: definition.HostID, Hostname: names[definition.HostID],
			Definition: definition.Name, Tool: definition.Tool,
			Repository: definition.Repository,
		}
		id := key(definition.HostID, definition.Name)
		if plan, known := latestPlan[id]; known {
			item.LastSuccessAt = plan.LastSuccessAt
		}
		if item.LastSuccessAt == nil {
			if run, present := latestRun[id]; present {
				moment := run.RecordedAt.UTC()
				item.LastSuccessAt = &moment
			}
		}
		var verified *time.Time
		if verification, present := latestVerification[id]; present {
			moment := verification.RecordedAt.UTC()
			verified = &moment
		}
		item.Status = backupstore.State(item.LastSuccessAt, now)
		if item.LastSuccessAt != nil {
			age := now.Sub(*item.LastSuccessAt).Hours()
			item.AgeHours = &age
		}
		item.Unverified = backupstore.Unverified(verified, now)
		if item.Unverified {
			unverified++
		}
		if restore, present := latestRestore[id]; present {
			moment := restore.RecordedAt.UTC()
			item.LastRestoreAt = &moment
		} else {
			neverRestored++
		}
		counts[item.Status]++
		items = append(items, item)
	}

	// The worst on top: a list that starts with a month-old copy answers
	// the operator's question without scrolling.
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Status != items[j].Status {
			return backupstore.Worse(items[i].Status, items[j].Status) == items[i].Status
		}
		if (items[i].LastSuccessAt == nil) != (items[j].LastSuccessAt == nil) {
			return items[i].LastSuccessAt == nil
		}
		if items[i].LastSuccessAt == nil {
			return items[i].Hostname < items[j].Hostname
		}
		return items[i].LastSuccessAt.Before(*items[j].LastSuccessAt)
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "counts": counts, "unverified": unverified,
		"never_restored": neverRestored,
		"repositories":   s.repositoryLoads(r.Context(), items),
		"hosts_total":    len(ids),
		"thresholds": map[string]int{
			"warning_hours":     int(backupstore.WarningThreshold.Hours()),
			"critical_hours":    int(backupstore.CriticalThreshold.Hours()),
			"verification_days": int(backupstore.VerificationThreshold.Hours() / 24),
		},
	})
}

// repositoryLoad describes one backend seen from the whole fleet.
type repositoryLoad struct {
	Repository string `json:"repository"`
	Hosts      int    `json:"hosts"`
	Unverified int    `json:"unverified"`
	// OldestAgeHours is the age of the oldest copy in this repository. A
	// repository is as good as its worst copy.
	OldestAgeHours *float64 `json:"oldest_age_hours,omitempty"`
	// BudgetKey, Capacity and Used describe the budget of this backend. An
	// unset capacity is a missing policy, not zero: then nothing bounds the
	// concurrency here and that has to be visible.
	BudgetKey string `json:"budget_key"`
	Capacity  *int   `json:"capacity,omitempty"`
	Used      *int   `json:"used,omitempty"`
	Claimants *int   `json:"claimants,omitempty"`
}

// repositoryLoads groups the fleet copies by backend and attaches the
// budget.
//
// The copy list says which host has an old copy. It does not say which
// backend is the bottleneck - and that is what decides how many copies can
// go at once. Without it the operator sees a slow campaign and does not
// know what holds it.
func (s *Server) repositoryLoads(ctx context.Context,
	items []fleetBackup) []repositoryLoad {
	order := []string{}
	by := map[string]*repositoryLoad{}
	for _, item := range items {
		if item.Repository == "" {
			continue
		}
		entry, present := by[item.Repository]
		if !present {
			entry = &repositoryLoad{
				Repository: item.Repository,
				BudgetKey:  budgets.BackendKey(item.Repository),
			}
			by[item.Repository] = entry
			order = append(order, item.Repository)
		}
		entry.Hosts++
		if item.Unverified {
			entry.Unverified++
		}
		if item.AgeHours != nil && (entry.OldestAgeHours == nil || *item.AgeHours > *entry.OldestAgeHours) {
			age := *item.AgeHours
			entry.OldestAgeHours = &age
		}
	}
	if len(order) == 0 {
		return []repositoryLoad{}
	}

	// Budgets are optional: an installation without them still shows the
	// backends, only without their capacity.
	if s.budgets != nil {
		if states, err := s.budgets.States(ctx); err == nil {
			byKey := map[string]budgets.State{}
			for _, state := range states {
				byKey[state.Key] = state
			}
			for _, entry := range by {
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

	// The backends with the oldest copy first: they are the ones that need
	// attention.
	loads := make([]repositoryLoad, 0, len(order))
	for _, repository := range order {
		loads = append(loads, *by[repository])
	}
	sort.SliceStable(loads, func(i, j int) bool {
		if (loads[i].OldestAgeHours == nil) != (loads[j].OldestAgeHours == nil) {
			return loads[j].OldestAgeHours == nil
		}
		if loads[i].OldestAgeHours == nil {
			return loads[i].Repository < loads[j].Repository
		}
		return *loads[i].OldestAgeHours > *loads[j].OldestAgeHours
	})
	return loads
}
