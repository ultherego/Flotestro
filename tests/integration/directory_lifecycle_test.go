//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// The lifecycle of a directory account and of a host group membership, as
// the panel carries them out: plan, a second person, execution phase by
// phase, and the directory read back afterwards.

const directoryLifecycleReason = "integration test of the directory lifecycle"

type directoryUserView struct {
	UID                string   `json:"uid"`
	Groups             []string `json:"groups"`
	Disabled           bool     `json:"disabled"`
	PrincipalExpiresAt *string  `json:"principal_expires_at"`
	PasswordExpiresAt  *string  `json:"password_expires_at"`
	Preserved          bool     `json:"preserved"`
	Shell              string   `json:"shell"`
}

type directoryHostGroupView struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

// directoryUser reads one account from the live or the preserved list.
func directoryUser(t *testing.T, h *harness, uid string, preserved bool) *directoryUserView {
	t.Helper()
	path := "/api/v1/identity/users"
	if preserved {
		path += "?preserved=true"
	}
	var users struct {
		Items []directoryUserView `json:"items"`
	}
	h.get(path, &users)
	for index := range users.Items {
		if users.Items[index].UID == uid {
			return &users.Items[index]
		}
	}
	return nil
}

// orderAndRun plans a change, checks the plan is not blocked, approves it
// as the second person and waits for the executor.
func orderAndRun(t *testing.T, h, approver *harness, action string, payload map[string]any) ruleChange {
	t.Helper()
	var change ruleChange
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": action, "reason": directoryLifecycleReason, "payload": payload,
	}, &change, http.StatusCreated)
	if len(change.Plan.Conflicts) > 0 {
		t.Fatalf("the plan of %s has conflicts: %v", action, change.Plan.Conflicts)
	}
	final := approveAndRun(t, h, approver, change)
	if final.State != "succeeded" {
		t.Fatalf("%s finished as %s: %s", action, final.State, final.ResultMessage)
	}
	return final
}

// TestDirectoryUserLifecycleExpiresResetsAndPreservesAnAccount walks a
// test account through the lifecycle the document names: creation, an
// expiration set and cleared, a password reset whose one-time value the
// requester reads once, and the removal that keeps the entry.
//
// The preserved entry stays in the lab directory: that is the point of
// preserving, and the adapter has no command that would erase it.
func TestDirectoryUserLifecycleExpiresResetsAndPreservesAnAccount(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	approver := secondPerson(t, h)
	uid := fmt.Sprintf("ftest-%d", time.Now().UnixNano()%1000000000)

	orderAndRun(t, h, approver, "identity.user.create", map[string]any{
		"user": map[string]any{"uid": uid, "first_name": "Integration", "last_name": "Test"},
	})
	if directoryUser(t, h, uid, false) == nil {
		t.Fatalf("the directory does not list the account %s after its creation", uid)
	}
	// Whatever happens below, the account ends preserved rather than left
	// live in the lab directory.
	t.Cleanup(func() {
		if directoryUser(t, h, uid, false) == nil {
			return
		}
		var change ruleChange
		h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
			"action": "identity.user.preserve", "reason": directoryLifecycleReason,
			"payload": map[string]any{"reference": map[string]any{"uid": uid}},
		}, &change, http.StatusCreated)
		approveAndRun(t, h, approver, change)
	})

	// An expiration in the future: the plan names the date and the
	// directory reads it back.
	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	var change ruleChange
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.user.expire", "reason": directoryLifecycleReason,
		"payload": map[string]any{"expiry": map[string]any{"uid": uid, "principal_expires_at": expires}},
	}, &change, http.StatusCreated)
	if !strings.Contains(strings.Join(change.Plan.Steps, "\n"), "2030-01-01T00:00:00Z") {
		t.Fatalf("the plan does not name the expiration: %v", change.Plan.Steps)
	}
	if final := approveAndRun(t, h, approver, change); final.State != "succeeded" {
		t.Fatalf("the expiry change finished as %s: %s", final.State, final.ResultMessage)
	}
	user := directoryUser(t, h, uid, false)
	if user == nil || user.PrincipalExpiresAt == nil || !strings.HasPrefix(*user.PrincipalExpiresAt, "2030-01-01T00:00:00") {
		t.Fatalf("the account after the expiry change: %+v", user)
	}

	// An empty string clears the expiration: "never expires" is ordered,
	// not left over.
	orderAndRun(t, h, approver, "identity.user.expire", map[string]any{
		"expiry": map[string]any{"uid": uid, "principal_expires_at": ""},
	})
	if user := directoryUser(t, h, uid, false); user == nil || user.PrincipalExpiresAt != nil {
		t.Fatalf("the expiration was not cleared: %+v", user)
	}

	// A POSIX edit: the shell, read back from the directory.
	orderAndRun(t, h, approver, "identity.user.posix", map[string]any{
		"posix": map[string]any{"uid": uid, "shell": "/bin/sh"},
	})
	if user := directoryUser(t, h, uid, false); user == nil || user.Shell != "/bin/sh" {
		t.Fatalf("the shell after the POSIX change: %+v", user)
	}

	// The password reset: the value reaches the requester once, nobody
	// else, and never the audit trail.
	reset := orderAndRun(t, h, approver, "identity.user.password.reset", map[string]any{
		"reference": map[string]any{"uid": uid},
	})
	var detail struct {
		SecretAvailable bool `json:"secret_available"`
	}
	h.get("/api/v1/identity/changes/"+reset.ID, &detail)
	if !detail.SecretAvailable {
		t.Fatal("the change does not say a one-time value waits for the requester")
	}
	// The approver is not the requester and gets nothing.
	approver.do(http.MethodPost, "/api/v1/identity/changes/"+reset.ID+"/reveal",
		map[string]any{"reason": directoryLifecycleReason}, nil, http.StatusForbidden)
	var revealed struct {
		UID                 string `json:"uid"`
		OneTimePassword     string `json:"one_time_password"`
		ExpiresOnFirstLogin bool   `json:"expires_on_first_login"`
	}
	h.do(http.MethodPost, "/api/v1/identity/changes/"+reset.ID+"/reveal",
		map[string]any{"reason": directoryLifecycleReason}, &revealed, http.StatusOK)
	if revealed.UID != uid || revealed.OneTimePassword == "" || !revealed.ExpiresOnFirstLogin {
		t.Fatalf("the reveal answered %+v", revealed)
	}
	// Once. The second read is told the value is gone, not that it never was.
	var gone struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/identity/changes/"+reset.ID+"/reveal",
		map[string]any{"reason": directoryLifecycleReason}, &gone, http.StatusGone)
	if gone.Code != "secret_consumed" {
		t.Fatalf("the second reveal answered with the code %q", gone.Code)
	}
	// A fresh variable: the flag is absent from the answer once the value
	// is gone, and a decode into the earlier struct would keep it true.
	var afterReveal struct {
		SecretAvailable bool `json:"secret_available"`
	}
	h.get("/api/v1/identity/changes/"+reset.ID, &afterReveal)
	if afterReveal.SecretAvailable {
		t.Fatal("the change still says a value waits after it was read")
	}
	// Neither the change record nor the audit trail carries the value.
	var record struct {
		Phases        []map[string]any `json:"phases"`
		ResultMessage string           `json:"result_message"`
	}
	h.get("/api/v1/identity/changes/"+reset.ID, &record)
	if strings.Contains(fmt.Sprint(record.Phases), revealed.OneTimePassword) ||
		strings.Contains(record.ResultMessage, revealed.OneTimePassword) {
		t.Fatal("the change record carries the one-time password")
	}
	var audit struct {
		Items []struct {
			Action string         `json:"action"`
			Detail map[string]any `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?target_id="+reset.ID+"&limit=50", &audit)
	revealRecorded := false
	for _, event := range audit.Items {
		if strings.Contains(fmt.Sprint(event.Detail), revealed.OneTimePassword) {
			t.Fatalf("the audit event %s carries the one-time password", event.Action)
		}
		if event.Action == "directory_change.reveal" {
			revealRecorded = true
		}
	}
	if !revealRecorded {
		t.Fatal("the audit trail does not record that the value was read")
	}

	// The removal that keeps the entry: gone from the live list, present
	// among the preserved accounts, and the plan said it cannot be undone.
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.user.preserve", "reason": directoryLifecycleReason,
		"payload": map[string]any{"reference": map[string]any{"uid": uid, "reason": directoryLifecycleReason}},
	}, &change, http.StatusCreated)
	if !strings.Contains(strings.Join(change.Plan.Warnings, "\n"), "cannot be brought back") {
		t.Fatalf("the plan does not warn that a preservation is final: %v", change.Plan.Warnings)
	}
	final := approveAndRun(t, h, approver, change)
	if final.State == "partially_applied" && preserveRefusedByTheDirectory(t, h, final.ID) {
		// Moving an entry into the preserved container is a "moddn" right
		// that FreeIPA grants to no built-in privilege below admin, and
		// the connector role of the lab has only the built-in ones. The
		// product answered truthfully - partially applied, the directory's
		// words in the phase - and that is what the assertion checks here.
		t.Logf("the directory refused the preservation to the connector role: %s", final.ResultMessage)
		return
	}
	if final.State != "succeeded" {
		t.Fatalf("the preservation finished as %s: %s", final.State, final.ResultMessage)
	}
	if directoryUser(t, h, uid, false) != nil {
		t.Fatalf("the account %s is still among the live accounts", uid)
	}
	preserved := directoryUser(t, h, uid, true)
	if preserved == nil || !preserved.Preserved {
		t.Fatalf("the account %s is not among the preserved accounts: %+v", uid, preserved)
	}
}

// labHostGroup picks a host group the test may change: never the group of
// the directory servers, whose membership decides where the directory
// itself runs.
func labHostGroup(t *testing.T, h *harness) directoryHostGroupView {
	t.Helper()
	var groups struct {
		Items []directoryHostGroupView `json:"items"`
	}
	h.get("/api/v1/identity/host-groups", &groups)
	candidates := slices.DeleteFunc(groups.Items, func(group directoryHostGroupView) bool {
		return group.Name == "ipaservers"
	})
	if len(candidates) == 0 {
		t.Skip("the directory has no host group the test may change")
	}
	// A group without hosts first: adding is the simpler half to undo.
	slices.SortFunc(candidates, func(a, b directoryHostGroupView) int { return len(a.Hosts) - len(b.Hosts) })
	return candidates[0]
}

// TestDirectoryHostGroupMembershipRoundTrip moves the joined lab host into
// a host group and out again - or out and back in when it already belongs
// - and reads the group back from the directory after each half.
func TestDirectoryHostGroupMembershipRoundTrip(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	approver := secondPerson(t, h)
	host := labDirectoryHost(t, h)
	group := labHostGroup(t, h)
	member := slices.ContainsFunc(group.Hosts, func(name string) bool { return strings.EqualFold(name, host) })

	readGroup := func() directoryHostGroupView {
		var groups struct {
			Items []directoryHostGroupView `json:"items"`
		}
		h.get("/api/v1/identity/host-groups", &groups)
		index := slices.IndexFunc(groups.Items, func(item directoryHostGroupView) bool { return item.Name == group.Name })
		if index < 0 {
			t.Fatalf("the directory no longer lists the host group %s", group.Name)
		}
		return groups.Items[index]
	}
	contains := func(view directoryHostGroupView) bool {
		return slices.ContainsFunc(view.Hosts, func(name string) bool { return strings.EqualFold(name, host) })
	}
	move := func(add bool) ruleChange {
		key := "remove"
		if add {
			key = "add"
		}
		var change ruleChange
		h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
			"action": "identity.hostgroup.members", "reason": directoryLifecycleReason,
			"payload": map[string]any{"host_group": map[string]any{"group": group.Name, key: []string{host}}},
		}, &change, http.StatusCreated)
		return change
	}

	// A short name is refused before any plan: the directory knows hosts
	// by FQDN.
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.hostgroup.members", "reason": directoryLifecycleReason,
		"payload": map[string]any{"host_group": map[string]any{"group": group.Name, "add": []string{"web1"}}},
	}, nil, http.StatusBadRequest)
	// Without a reason the order is refused: a host's groups decide which
	// rules reach it.
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action":  "identity.hostgroup.members",
		"payload": map[string]any{"host_group": map[string]any{"group": group.Name, "add": []string{host}}},
	}, nil, http.StatusBadRequest)

	first := move(!member)
	if len(first.Plan.Conflicts) > 0 {
		// Taking the host out of this group would leave the administrator
		// without a way in; the lab is then not in a shape the test may
		// change, and it says so instead of forcing it.
		h.do(http.MethodPost, "/api/v1/identity/changes/"+first.ID+"/cancel",
			map[string]any{"reason": "the lab refuses the change"}, nil, 0)
		t.Skipf("the plan refuses to move %s: %v", host, first.Plan.Conflicts)
	}
	if !slices.Contains(first.Plan.ReachableHosts, host) {
		t.Fatalf("the plan does not name the host it moves: %+v", first.Plan)
	}
	t.Cleanup(func() {
		// The group is left as it was found, whichever half failed.
		if contains(readGroup()) == member {
			return
		}
		change := move(member)
		if len(change.Plan.Conflicts) == 0 {
			approveAndRun(t, h, approver, change)
		}
	})
	if final := approveAndRun(t, h, approver, first); final.State != "succeeded" {
		t.Fatalf("the first half finished as %s: %s", final.State, final.ResultMessage)
	}
	if contains(readGroup()) == member {
		t.Fatalf("the directory did not move %s (member before: %v)", host, member)
	}

	second := move(member)
	if len(second.Plan.Conflicts) > 0 {
		t.Fatalf("the way back has conflicts: %v", second.Plan.Conflicts)
	}
	if final := approveAndRun(t, h, approver, second); final.State != "succeeded" {
		t.Fatalf("the second half finished as %s: %s", final.State, final.ResultMessage)
	}
	if contains(readGroup()) != member {
		t.Fatalf("the directory did not move %s back (member before: %v)", host, member)
	}
}

// TestDirectoryServicesAndHealthAreReadable checks the two read-only
// views added for the panel: the service principals, and the connector's
// account of itself.
func TestDirectoryServicesAndHealthAreReadable(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	var services struct {
		Items []struct {
			Principal string   `json:"principal"`
			Service   string   `json:"service"`
			Host      string   `json:"host"`
			HasKeytab *bool    `json:"has_keytab"`
			ManagedBy []string `json:"managed_by"`
		} `json:"items"`
	}
	h.get("/api/v1/identity/services", &services)
	if len(services.Items) == 0 {
		t.Fatal("a directory always has its own service principals; none were read")
	}
	for _, service := range services.Items {
		if service.Principal == "" || service.Service == "" || service.Host == "" {
			t.Fatalf("a service was read without its principal, service or host: %+v", service)
		}
	}

	var status struct {
		Configured bool `json:"configured"`
		Reachable  bool `json:"reachable"`
		Connector  struct {
			Principal      string `json:"principal"`
			KeytabReadable bool   `json:"keytab_readable"`
			KeytabEntries  []struct {
				Principal string `json:"principal"`
				KVNO      int    `json:"kvno"`
			} `json:"keytab_entries"`
			LastSuccessAt *string `json:"last_success_at"`
			CacheEntries  int     `json:"cache_entries"`
		} `json:"connector"`
	}
	h.get("/api/v1/identity/status", &status)
	if status.Connector.Principal == "" {
		t.Fatal("the status does not name the connector's principal")
	}
	if !status.Connector.KeytabReadable || len(status.Connector.KeytabEntries) == 0 {
		t.Fatalf("a connector that logged in has a keytab it read: %+v", status.Connector)
	}
	// The ping the status just made is the call it reports.
	if status.Connector.LastSuccessAt == nil {
		t.Fatal("the status does not record the ping it just made as a successful call")
	}
}

// preserveRefusedByTheDirectory says whether the preservation failed on
// the directory's "moddn" right, the one phase the lab role cannot pass.
// The phases are read from the change again: the view the approval
// returns carries the summary alone.
func preserveRefusedByTheDirectory(t *testing.T, h *harness, changeID string) bool {
	t.Helper()
	var detail struct {
		Phases []struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"phases"`
	}
	h.get("/api/v1/identity/changes/"+changeID, &detail)
	for _, phase := range detail.Phases {
		if phase.Status == "failed" && strings.Contains(phase.Message, "moddn") {
			return true
		}
	}
	return false
}

// TestServiceKeytabRotationIsASeparateRightAndRunsOnTheHost guards the
// rotation the architecture document names as "keytab rotation per
// separate permission": an operator of the fleet is refused with the
// permission named, the plan names the two halves and the host, and - on
// a fleet with a service principal to rotate - the directory retires the
// keytab while the host of that name fetches a new one and reports the
// key version going up.
//
// The lab rarely has such a principal on a fleet host: the directory's own
// services live on the directory server, and the panel's principal is the
// connector's, which the test must not retire from under itself. The test
// then ends after the refusal and the plan, with the reason.
func TestServiceKeytabRotationIsASeparateRightAndRunsOnTheHost(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	reason := "integration test of the service keytab rotation"

	// The operator runs hosts and orders campaigns, and holds no half of
	// a rotation: the refusal names the right that is missing.
	operator := h.withToken(h.createPrincipal(uniqueSubject("operator-keytab"),
		[]map[string]string{{"role": "operator", "scope": "*"}}))
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	operator.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.keytab.rotate", "reason": reason,
		"payload": map[string]any{"keytab": map[string]any{"principal": "HTTP/nobody.flotestro.test"}},
	}, &problem, http.StatusForbidden)
	if problem.Code != "permission_denied" || !strings.Contains(problem.Detail, "identity.keytab.rotate") {
		t.Fatalf("the operator's order: code=%q detail=%q, expected permission_denied naming identity.keytab.rotate", problem.Code, problem.Detail)
	}

	// The host's own principal is refused by name, before any plan: its
	// keytab is replaced by a re-join.
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.keytab.rotate", "reason": reason,
		"payload": map[string]any{"keytab": map[string]any{"principal": "host/nobody.flotestro.test"}},
	}, &problem, http.StatusBadRequest)
	if problem.Code != "invalid_payload" {
		t.Errorf("the host principal: code=%q, expected invalid_payload", problem.Code)
	}

	// The plan of a principal the directory does not know: the two halves
	// and the host are named, and the conflict blocks the approval.
	var blocked ruleChange
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.keytab.rotate", "reason": reason,
		"payload": map[string]any{"keytab": map[string]any{"principal": "HTTP/nobody.flotestro.test"}},
	}, &blocked, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/identity/changes/"+blocked.ID+"/cancel",
			map[string]any{"reason": "the plan was the point of the test"}, nil, 0)
	})
	if len(blocked.Plan.Steps) != 2 || !strings.Contains(blocked.Plan.Steps[0], "retiring") ||
		!strings.Contains(blocked.Plan.Steps[1], "identity.keytab.renew") {
		t.Errorf("the plan steps: %v", blocked.Plan.Steps)
	}
	if !slices.Contains(blocked.Plan.ReachableHosts, "nobody.flotestro.test") {
		t.Errorf("the plan names the hosts %v", blocked.Plan.ReachableHosts)
	}
	if len(blocked.Plan.Conflicts) == 0 || !strings.Contains(blocked.Plan.Conflicts[0], "HTTP/nobody.flotestro.test") {
		t.Errorf("an unknown principal is not a conflict: %v", blocked.Plan.Conflicts)
	}
	if !strings.Contains(strings.Join(blocked.Plan.Warnings, "\n"), "cannot authenticate") {
		t.Errorf("the plan does not warn about the gap: %v", blocked.Plan.Warnings)
	}

	// A principal to rotate for real: a service of a connected fleet host
	// that is neither the host's own nor the panel's connector.
	var status struct {
		Connector struct {
			Principal string `json:"principal"`
		} `json:"connector"`
	}
	h.get("/api/v1/identity/status", &status)
	var services struct {
		Items []struct {
			Principal string `json:"principal"`
			Service   string `json:"service"`
			Host      string `json:"host"`
			HasKeytab *bool  `json:"has_keytab"`
		} `json:"items"`
	}
	h.get("/api/v1/identity/services", &services)
	fleet := map[string]hostView{}
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			fleet[strings.ToLower(host.Hostname)] = host
		}
	}
	principal, hostname := "", ""
	for _, service := range services.Items {
		if strings.EqualFold(service.Service, "host") || strings.EqualFold(service.Service, "flotestro") ||
			strings.EqualFold(service.Principal, status.Connector.Principal) {
			continue
		}
		if service.HasKeytab == nil || !*service.HasKeytab {
			continue
		}
		if host, ok := fleet[strings.ToLower(service.Host)]; ok {
			principal, hostname = service.Principal, host.Hostname
			break
		}
	}
	if principal == "" {
		t.Skip("no connected fleet host carries a service principal with a keytab beyond host/ and the panel's own; the rotation itself is not exercised")
	}

	approver := secondPerson(t, h)
	final := orderAndRun(t, h, approver, "identity.keytab.rotate",
		map[string]any{"keytab": map[string]any{"principal": principal}})
	var detail struct {
		Phases []struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"phases"`
	}
	h.get("/api/v1/identity/changes/"+final.ID, &detail)
	if len(detail.Phases) != 3 {
		t.Fatalf("the rotation ran %d phases: %+v", len(detail.Phases), detail.Phases)
	}
	if !strings.Contains(detail.Phases[0].Message, hostname) {
		t.Errorf("the first phase does not name the fleet host: %q", detail.Phases[0].Message)
	}
	// The last phase names the task on the host; the task's own result
	// carries the key versions.
	fields := strings.Fields(strings.TrimPrefix(detail.Phases[2].Message, "task "))
	if len(fields) == 0 {
		t.Fatalf("the ordering phase names no task: %q", detail.Phases[2].Message)
	}
	jobID := strings.TrimSuffix(fields[0], ":")
	job := h.awaitTerminal(jobID, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the renewal on %s ended as %s", hostname, job.State)
	}
	attempts := h.attempts(jobID)
	if len(attempts) == 0 || !strings.Contains(attempts[len(attempts)-1].Message, "key version") {
		t.Errorf("the renewal does not report the key versions: %+v", attempts)
	}
}
