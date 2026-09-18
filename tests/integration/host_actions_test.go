//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
)

// The action preview of a host answers what the order would: a viewer is
// refused every change with permission_denied, a host that announced no
// adapter refuses every change that needs one with capability_missing, and
// an administrator on a host of the lab is allowed the restart the
// screens draw a button for. The preview is read with host.read, so the
// viewer reads their own refusals.

type hostActionView struct {
	Action            string `json:"action"`
	Permission        string `json:"permission"`
	Mutating          bool   `json:"mutating"`
	Allowed           bool   `json:"allowed"`
	ReasonCode        string `json:"reason_code"`
	Reason            string `json:"reason"`
	MissingPermission string `json:"missing_permission"`
	Note              string `json:"note"`
}

// catalogueEntry is the part of GET /api/v1/actions the test reads: which
// operations need an adapter at all.
type catalogueEntry struct {
	Action             string `json:"action"`
	Mutating           bool   `json:"mutating"`
	RequiredCapability string `json:"required_capability"`
}

func (h *harness) hostActions(hostID string) map[string]hostActionView {
	h.t.Helper()
	var response struct {
		Items []hostActionView `json:"items"`
	}
	h.get("/api/v1/hosts/"+hostID+"/actions", &response)
	if len(response.Items) == 0 {
		h.t.Fatalf("the action preview of %s is empty", hostID)
	}
	byAction := make(map[string]hostActionView, len(response.Items))
	for _, item := range response.Items {
		byAction[item.Action] = item
	}
	return byAction
}

func TestAViewerIsRefusedEveryChangeBeforeTheClick(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	viewer := h.withToken(h.createPrincipal(uniqueSubject("viewer-actions"), []map[string]string{
		{"role": "viewer", "site": host.Site, "environment": host.Environment},
	}))
	actions := viewer.hostActions(host.ID)

	restart, ok := actions["unit.restart"]
	if !ok {
		t.Fatal("unit.restart is not in the preview")
	}
	if restart.Allowed || restart.ReasonCode != "permission_denied" || restart.MissingPermission != "unit.restart" {
		t.Fatalf("a viewer's unit.restart: %+v", restart)
	}
	if !strings.Contains(restart.Reason, "unit.restart") {
		t.Errorf("the reason does not name the permission: %q", restart.Reason)
	}
	// The viewer holds unit.status and not job.create: the order of a read
	// is refused too, and the preview says which right is missing.
	status := actions["unit.status"]
	if status.Allowed || status.ReasonCode != "permission_denied" || status.MissingPermission != "job.create" {
		t.Fatalf("a viewer's unit.status: %+v", status)
	}
	for action, verdict := range actions {
		if verdict.Mutating && verdict.Allowed {
			t.Errorf("a viewer is allowed the change %s", action)
		}
	}

	// The preview only describes: the order itself is still refused by the
	// order's own gate, whatever the preview said.
	viewer.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "unit.restart", "payload": unitPayload("cron.service")},
		nil, http.StatusForbidden)
}

func TestAHostWithoutAdaptersRefusesEveryChangeThatNeedsOne(t *testing.T) {
	h := newHarness(t)
	host := h.enrollSyntheticHost(t)

	var catalogue struct {
		Items []catalogueEntry `json:"items"`
	}
	h.get("/api/v1/actions", &catalogue)
	actions := h.hostActions(host.ID)

	checked := 0
	for _, entry := range catalogue.Items {
		if !entry.Mutating || entry.RequiredCapability == "" {
			continue
		}
		verdict, ok := actions[entry.Action]
		if !ok {
			t.Errorf("%s is in the catalogue and not in the preview", entry.Action)
			continue
		}
		if verdict.Allowed || verdict.ReasonCode != "capability_missing" {
			t.Errorf("%s on a host without adapters: %+v", entry.Action, verdict)
		}
		if !strings.Contains(verdict.Reason, entry.RequiredCapability) {
			t.Errorf("%s: the reason does not name the missing capability %s: %q", entry.Action, entry.RequiredCapability, verdict.Reason)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("the catalogue names no mutating operation with a capability; the test checked nothing")
	}
	// The host never connected: a read has nothing to answer with, and the
	// preview says so rather than letting the order sit in the queue.
	if list := actions["process.list"]; list.Allowed || list.ReasonCode != "host_offline" {
		t.Errorf("a read from a host that never connected: %+v", list)
	}
}

func TestAnAdministratorMayRestartAUnitOnALabHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	admin := h.withToken(h.createPrincipal(uniqueSubject("admin-actions"), []map[string]string{
		{"role": "platform_admin", "site": host.Site, "environment": host.Environment},
	}))
	actions := admin.hostActions(host.ID)

	restart := actions["unit.restart"]
	if !restart.Allowed || restart.ReasonCode != "" || restart.Reason != "" {
		t.Fatalf("an administrator's unit.restart on %s: %+v", host.Hostname, restart)
	}
	if status := actions["unit.status"]; !status.Allowed {
		t.Fatalf("an administrator's unit.status on %s: %+v", host.Hostname, status)
	}
	// A shutdown is allowed and announces the confirmation it will ask
	// for; the note is information, not a refusal.
	if shutdown := actions["system.shutdown"]; !shutdown.Allowed || shutdown.Note == "" {
		t.Fatalf("an administrator's system.shutdown on %s: %+v", host.Hostname, shutdown)
	}
}

func TestTheActionPreviewNeedsHostRead(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// A viewer of another site reads nothing about this host, its actions
	// included: not knowing the host must not become a list of its rights.
	elsewhere := h.withToken(h.createPrincipal(uniqueSubject("viewer-elsewhere"), []map[string]string{
		{"role": "viewer", "site": "nowhere-" + host.Site, "environment": host.Environment},
	}))
	elsewhere.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/actions", nil, nil, http.StatusForbidden)
	h.do(http.MethodGet, "/api/v1/hosts/00000000-0000-0000-0000-000000000000/actions", nil, nil, http.StatusNotFound)
}
