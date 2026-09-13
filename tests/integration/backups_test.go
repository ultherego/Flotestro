//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const backupReason = "integration test of the backup module"

type backupDefinitionView struct {
	Name           string   `json:"name"`
	Tool           string   `json:"tool"`
	Repository     string   `json:"repository"`
	Paths          []string `json:"paths"`
	PasswordSecret string   `json:"password_secret"`
	Initialize     bool     `json:"initialize"`
	Status         string   `json:"status"`
	LastSuccessAt  *string  `json:"last_success_at"`
	AgeHours       *float64 `json:"age_hours"`
	LastVerifyAt   *string  `json:"last_verify_at"`
	Unverified     bool     `json:"unverified"`
	Snapshots      *int     `json:"snapshots"`
	RepositorySize *int64   `json:"repository_size"`
}

type backupReportView struct {
	Definitions []backupDefinitionView `json:"definitions"`
	Status      string                 `json:"status"`
	Tools       struct {
		Tools []struct {
			Name      string `json:"name"`
			Available bool   `json:"available"`
			Version   string `json:"version"`
		} `json:"tools"`
		RunbooksKnown bool `json:"runbooks_known"`
	} `json:"tools"`
}

type backupDetailView struct {
	Kind  string `json:"kind"`
	State struct {
		Snapshots []struct {
			ID    string   `json:"id"`
			Time  string   `json:"time"`
			Paths []string `json:"paths"`
		} `json:"snapshots"`
		TotalSizeBytes    *uint64 `json:"total_size_bytes"`
		UnavailableReason string  `json:"unavailable_reason"`
	} `json:"state"`
	Outcome struct {
		SnapshotID string  `json:"snapshot_id"`
		BytesAdded *uint64 `json:"bytes_added"`
	} `json:"outcome"`
}

// hostBackups reads the backups tab of a host.
func hostBackups(h *harness, hostID string) backupReportView {
	h.t.Helper()
	var report backupReportView
	h.get("/api/v1/hosts/"+hostID+"/backups", &report)
	return report
}

// hostWithRestic picks a host that has something to make a copy with.
func hostWithRestic(t *testing.T, h *harness) hostView {
	t.Helper()
	for _, family := range []string{"debian", "rhel"} {
		host := h.hostByFamily(family)
		for _, tool := range hostBackups(h, host.ID).Tools.Tools {
			if tool.Name == "restic" && tool.Available {
				return host
			}
		}
	}
	t.Skip("no host of the test fleet has restic")
	return hostView{}
}

// TestBackupFullCycle walks the whole path of the module: a definition, a
// copy, reading the repository, verification and a restore into a working
// directory.
func TestBackupFullCycle(t *testing.T) {
	h := newHarness(t)
	host := hostWithRestic(t, h)
	stamp := time.Now().UnixNano()
	name := fmt.Sprintf("integration-%d", stamp%100000)
	repository := fmt.Sprintf("/srv/flotestro-test-%d", stamp%100000)
	target := fmt.Sprintf("/srv/flotestro-test-%d-restore", stamp%100000)
	password := fmt.Sprintf("repository-password-%d", stamp)
	secret := newSecret(t, h, password)

	definition := map[string]any{
		"name": name, "tool": "restic", "repository": repository,
		"paths": []string{"/etc/flotestro"}, "keep_last": 2,
		"initialize": true, "password_secret": secret.Name,
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", definition, nil, http.StatusOK)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/backups?name="+name, nil, nil, 0)
	})

	order := map[string]any{
		"id": name, "tool": "restic", "repository": repository,
		"paths": []string{"/etc/flotestro"}, "keep_last": 2, "initialize": true,
		"password_secret": map[string]any{"name": secret.Name},
	}

	// The copy initialises the repository, because the definition allows
	// it.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "backup.run", "reason": backupReason,
		"payload": map[string]any{"backup": order},
	}, 10*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the copy ended in state %s: %+v", job.State, attempts)
	}

	// The plan reads the repository: that is where it is known when the
	// copy was really made - also when cron made it, not the panel.
	plan, attempts := h.runOperation(host.ID, map[string]any{
		"action": "backup.plan", "reason": backupReason,
		"payload": map[string]any{"backup": order},
	}, 5*time.Minute)
	if plan.State != "succeeded" {
		t.Fatalf("reading the repository ended in state %s: %+v", plan.State, attempts)
	}
	detail := backupDetail(t, h, plan.ID)
	if len(detail.State.Snapshots) == 0 {
		t.Fatalf("the repository reports no copy at all: %+v", detail.State)
	}
	snapshot := detail.State.Snapshots[len(detail.State.Snapshots)-1]
	if snapshot.ID == "" || len(snapshot.Paths) == 0 {
		t.Fatalf("the copy described as %+v", snapshot)
	}

	// Verification with a data read: only that says the copy can be
	// restored, not only that the index adds up.
	verification := map[string]any{}
	for key, value := range order {
		verification[key] = value
	}
	verification["read_data"] = true
	check, attempts := h.runOperation(host.ID, map[string]any{
		"action": "backup.verify", "reason": backupReason,
		"payload": map[string]any{"backup": verification},
	}, 10*time.Minute)
	if check.State != "succeeded" {
		t.Fatalf("the verification ended in state %s: %+v", check.State, attempts)
	}

	// The panel now knows the age of the copy and that somebody checked it.
	report := hostBackups(h, host.ID)
	var view *backupDefinitionView
	for i := range report.Definitions {
		if report.Definitions[i].Name == name {
			view = &report.Definitions[i]
		}
	}
	if view == nil {
		t.Fatalf("definition %s is not in the tab: %+v", name, report.Definitions)
	}
	if view.Status != "ok" || view.LastSuccessAt == nil {
		t.Errorf("the copy state described as %+v", view)
	}
	if view.Unverified || view.LastVerifyAt == nil {
		t.Errorf("a verified copy described as unverified: %+v", view)
	}
	if view.Snapshots == nil || *view.Snapshots == 0 {
		t.Errorf("the panel does not know the number of copies: %+v", view)
	}

	// A restore into a working directory. The panel does not restore
	// straight into system trees and does not restore into the helper's
	// private /tmp.
	restore := map[string]any{}
	for key, value := range order {
		restore[key] = value
	}
	restore["snapshot_id"] = snapshot.ID
	restore["target"] = target
	restore["overwrite"] = "empty-target"
	restoration, attempts := h.runOperation(host.ID, map[string]any{
		"action": "backup.restore", "reason": backupReason,
		"payload": map[string]any{"backup": restore},
	}, 10*time.Minute)
	if restoration.State != "succeeded" {
		t.Fatalf("the restore ended in state %s: %+v", restoration.State, attempts)
	}

	// A second restore into the same directory falls out: the directory is
	// no longer empty, and the overwrite policy does not allow that.
	repeated, attempts := h.runOperation(host.ID, map[string]any{
		"action": "backup.restore", "reason": backupReason,
		"payload": map[string]any{"backup": restore},
	}, 10*time.Minute)
	if repeated.State == "succeeded" {
		t.Fatal("a restore into a non-empty directory passed despite the 'empty target' policy")
	}
	if len(attempts) == 0 || !strings.Contains(attempts[len(attempts)-1].Message, "is not empty") {
		t.Fatalf("the refusal does not say what it is about: %+v", attempts)
	}

	// The repository password must be nowhere but the store - also not in
	// the tool output the panel keeps in the job result.
	assertValueAbsent(t, h, password)
}

// TestBackupGuardsTheRestoreTarget guards the boundary that tells a restore
// from unpacking an old state onto a running system.
func TestBackupGuardsTheRestoreTarget(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	base := map[string]any{
		"id": "integration-boundaries", "tool": "restic", "repository": "/srv/flotestro-test",
		"paths": []string{"/etc/flotestro"}, "snapshot_id": "abc123",
	}

	bad := map[string]map[string]any{
		"system directory":            {"target": "/etc", "overwrite": "empty-target"},
		"inside a system directory":   {"target": "/etc/nginx", "overwrite": "empty-target"},
		"root":                        {"target": "/", "overwrite": "empty-target"},
		"the helper's private tmp":    {"target": "/var/tmp/backup", "overwrite": "empty-target"},
		"without an overwrite policy": {"target": "/srv/backup"},
		"relative path":               {"target": "srv/backup", "overwrite": "empty-target"},
		"without naming the copy":     {"target": "/srv/backup", "overwrite": "empty-target", "snapshot_id": ""},
	}
	for name, extras := range bad {
		t.Run(name, func(t *testing.T) {
			payload := map[string]any{}
			for key, value := range base {
				payload[key] = value
			}
			for key, value := range extras {
				payload[key] = value
			}
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
				"action": "backup.restore", "reason": backupReason,
				"payload": map[string]any{"backup": payload},
			}, nil, http.StatusBadRequest)
		})
	}
}

// TestBackupDefinitionRequiresAnExistingSecret guards that a typo in the
// secret name falls out when the definition is saved, not at the first copy
// - that is at the worst moment.
func TestBackupDefinitionRequiresAnExistingSecret(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": "integration-no-secret", "tool": "restic",
		"repository": "/srv/flotestro-test", "paths": []string{"/etc/flotestro"},
		"password_secret": "no.such.secret",
	}, nil, http.StatusBadRequest)

	// A definition without a tool or with a name escaping the directory
	// falls out too.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": "integration", "tool": "tar", "repository": "/srv/flotestro-test",
	}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": "../escape", "tool": "restic", "repository": "/srv/flotestro-test",
	}, nil, http.StatusBadRequest)
}

// backupDetail reads the operation result from the last attempt of the job.
func backupDetail(t *testing.T, h *harness, jobID string) backupDetailView {
	t.Helper()
	var result struct {
		Items []struct {
			Detail backupDetailView `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &result)
	if len(result.Items) == 0 {
		t.Fatalf("job %s has no attempts", jobID)
	}
	return result.Items[len(result.Items)-1].Detail
}

// TestBackupViewShowsTheBackendLoad checks what the copy list does not say:
// which backend is the bottleneck. Copies go from many hosts to one
// repository, and that is what decides how many of them go at once.
func TestBackupViewShowsTheBackendLoad(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	name := fmt.Sprintf("load-%d", time.Now().UnixNano())
	repository := "/srv/" + name
	secret := newSecret(t, h, "password-"+name)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": name, "tool": "restic", "repository": repository,
		"paths": []string{"/etc/flotestro"}, "keep_last": 1,
		"initialize": true, "password_secret": secret.Name,
	}, nil, http.StatusOK)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/backups?name="+name, nil, nil, 0)
	})

	// The backend budget is a panel policy, not a host state: the view is
	// to show it also when no copy has gone to the repository yet.
	h.setBudget("backend:"+repository+":backup", 2, 50)

	var view struct {
		NeverRestored int `json:"never_restored"`
		Items         []struct {
			Definition    string  `json:"definition"`
			LastRestoreAt *string `json:"last_restore_at"`
		} `json:"items"`
		Repositories []struct {
			Repository     string   `json:"repository"`
			Hosts          int      `json:"hosts"`
			BudgetKey      string   `json:"budget_key"`
			Capacity       *int     `json:"capacity"`
			Used           *int     `json:"used"`
			OldestAgeHours *float64 `json:"oldest_age_hours"`
		} `json:"repositories"`
	}
	h.get("/api/v1/backups", &view)

	var found bool
	for _, item := range view.Repositories {
		if item.Repository != repository {
			continue
		}
		found = true
		if item.Hosts != 1 {
			t.Errorf("the repository described for %d hosts", item.Hosts)
		}
		if item.BudgetKey != "backend:"+repository+":backup" {
			t.Errorf("budget key = %q", item.BudgetKey)
		}
		// The capacity set by the operator is to reach the view: without it
		// there is no seeing what bounds the copy concurrency.
		if item.Capacity == nil || *item.Capacity != 2 {
			t.Errorf("backend capacity = %v", item.Capacity)
		}
		if item.Used == nil {
			t.Error("the view does not say how many backend tokens are taken")
		}
	}
	if !found {
		t.Fatalf("the backup view does not know the repository %s: %+v", repository, view.Repositories)
	}

	// A copy nobody has ever restored is hope, not a copy. The definition
	// created a moment ago has never been restored and the view is to say
	// so outright, not stay quiet.
	var described bool
	for _, item := range view.Items {
		if item.Definition != name {
			continue
		}
		described = true
		if item.LastRestoreAt != nil {
			t.Errorf("a new definition has a restore date: %v", *item.LastRestoreAt)
		}
	}
	if !described {
		t.Errorf("the view does not know the definition %s", name)
	}
	if view.NeverRestored == 0 {
		t.Error("the view does not count copies that were never restored")
	}
}
