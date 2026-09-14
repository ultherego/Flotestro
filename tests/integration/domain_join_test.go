//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The mandatory scenario of chapter 23: a host joins the domain through the
// panel and leaves it, and a join that cannot work stops at the preflight
// with the failed conditions named. The lab's directory is FreeIPA on
// ipa.flotestro.test; Vagrant/lab-ipa-client.sh puts the client packages
// and the names in place on the debian-family hosts, and the panel does
// the rest - installing directory packages is a decision about trust, so
// the test does not do it either.

const domainJoinReason = "integration test of the domain join and leave"

const (
	labDomain          = "flotestro.test"
	labRealm           = "FLOTESTRO.TEST"
	labDirectoryServer = "ipa.flotestro.test"
)

// identityFacts mirrors the identity inventory module as the agent reports
// it: the join is settled by these facts, not by the tool exiting zero.
type identityFacts struct {
	Enrolled          bool   `json:"enrolled"`
	Domain            string `json:"domain"`
	Realm             string `json:"realm"`
	SSSDInstalled     bool   `json:"sssd_installed"`
	SSSDRunning       bool   `json:"sssd_running"`
	SSSDOnline        *bool  `json:"sssd_online"`
	HostPrincipal     string `json:"host_principal"`
	UnavailableReason string `json:"unavailable_reason"`
}

// domainCheck is one condition before the join or one verification after
// it. Passed is nil when the host could not tell.
type domainCheck struct {
	Name     string `json:"name"`
	Passed   *bool  `json:"passed"`
	Detail   string `json:"detail"`
	Blocking bool   `json:"blocking"`
}

// domainDetail is the typed result of a join, a preflight and a leave: the
// leave answers in the same shape with enrolled = false.
type domainDetail struct {
	Kind          string        `json:"kind"`
	Enrolled      bool          `json:"enrolled"`
	HostPrincipal string        `json:"host_principal"`
	Checks        []domainCheck `json:"checks"`
	Verifications []domainCheck `json:"verifications"`
}

// identityOf reads the identity facts the panel holds for the host.
func identityOf(t *testing.T, h *harness, hostID string) identityFacts {
	t.Helper()
	var fragment struct {
		Payload identityFacts `json:"payload"`
	}
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/identity", nil, &fragment, http.StatusOK)
	return fragment.Payload
}

// domainResult reads the typed result of the last attempt of a job.
func domainResult(t *testing.T, h *harness, jobID string) domainDetail {
	t.Helper()
	var response struct {
		Items []struct {
			Detail domainDetail `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+jobID+"/attempts", nil, &response, http.StatusOK)
	if len(response.Items) == 0 {
		t.Fatalf("job %s has no attempts", jobID)
	}
	return response.Items[len(response.Items)-1].Detail
}

func checkNamed(checks []domainCheck, name string) *domainCheck {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}

func failedChecks(checks []domainCheck) []string {
	var failed []string
	for _, item := range checks {
		if item.Blocking && (item.Passed == nil || !*item.Passed) {
			failed = append(failed, item.Name)
		}
	}
	return failed
}

// refreshIdentity orders a read of the identity module and waits for the
// panel to hold it: the facts after a join or a leave have to come from
// after the change, not from the last inventory cycle.
func refreshIdentity(t *testing.T, h *harness, hostID string) identityFacts {
	t.Helper()
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "inventory.refresh", "reason": domainJoinReason,
		"payload": map[string]any{"inventory": map[string]any{"modules": []string{"identity"}}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the identity refresh ended in state %s: %s", job.State, lastMessage(attempts))
	}
	return identityOf(t, h, hostID)
}

// awaitSSSDOnline refreshes the identity facts until SSSD reports itself
// connected to the directory. Right after a join SSSD may still be coming
// up; a state it has not reported is unknown, not offline, so the wait is
// bounded and the last facts are returned either way.
func awaitSSSDOnline(t *testing.T, h *harness, hostID string, limit time.Duration) identityFacts {
	t.Helper()
	deadline := time.Now().Add(limit)
	facts := refreshIdentity(t, h, hostID)
	for time.Now().Before(deadline) {
		if facts.SSSDOnline != nil && *facts.SSSDOnline {
			return facts
		}
		time.Sleep(10 * time.Second)
		facts = refreshIdentity(t, h, hostID)
	}
	return facts
}

// candidateForJoin picks a connected debian-family host that is in no
// domain and has the IPA client installed. The lab joins agent-fedora by
// hand, so it never qualifies; agent-debian and agent-ubuntu do once
// Vagrant/lab-ipa-client.sh ran. A host without the client is not a
// failure of the product: the panel does not install directory packages.
func candidateForJoin(t *testing.T, h *harness) (hostView, string) {
	t.Helper()
	var skipped []string
	for _, host := range h.hosts() {
		if host.OSFamily != "debian" || host.ConnectionState != "online" {
			continue
		}
		facts := identityOf(t, h, host.ID)
		if facts.Enrolled {
			skipped = append(skipped, host.Hostname+": already in "+facts.Realm)
			continue
		}
		// The preflight is the host's own word on whether the client is
		// there: the identity facts of a host outside a domain say nothing
		// about ipa-client-install.
		job, attempts := h.runOperation(host.ID, map[string]any{
			"action": "identity.host.preflight", "reason": domainJoinReason,
			"payload": map[string]any{"domain_enroll": map[string]any{
				"domain": labDomain, "realm": labRealm, "server": labDirectoryServer,
				"hostname": fqdnOf(host.Hostname),
			}},
		}, 3*time.Minute)
		detail := domainResult(t, h, job.ID)
		if client := checkNamed(detail.Checks, "ipa_client"); client == nil || client.Passed == nil || !*client.Passed {
			skipped = append(skipped, host.Hostname+": no ipa-client-install (run Vagrant/lab-ipa-client.sh)")
			continue
		}
		if job.State != "succeeded" {
			// The client is there and something else blocks the join: that
			// is what the negative half of the scenario is about, so the
			// test says what it is instead of running the join blind.
			skipped = append(skipped, host.Hostname+": preflight "+strings.Join(failedChecks(detail.Checks), ", ")+
				" ("+lastMessage(attempts)+")")
			continue
		}
		return host, fqdnOf(host.Hostname)
	}
	t.Skipf("no debian-family host can join the domain: %s", strings.Join(skipped, "; "))
	return hostView{}, ""
}

// fqdnOf qualifies the lab's short host names; a host that already carries
// the domain keeps its name.
func fqdnOf(hostname string) string {
	if strings.Contains(hostname, ".") {
		return hostname
	}
	return hostname + "." + labDomain
}

// currentHostname re-reads the host: the join renames it to its FQDN and
// the leave restores the short name, and the typed target has to be the
// name the panel holds at the moment of the order.
func currentHostname(t *testing.T, h *harness, hostID string) string {
	t.Helper()
	for _, host := range h.hosts() {
		if host.ID == hostID {
			return host.Hostname
		}
	}
	t.Fatalf("host %s disappeared from the fleet", hostID)
	return ""
}

// leaveDomain orders the leave with the typed target and waits for it.
func leaveDomain(t *testing.T, h *harness, hostID string) (jobView, []attemptView) {
	t.Helper()
	return h.runOperation(hostID, map[string]any{
		"action": "identity.host.leave", "reason": domainJoinReason,
		"target_confirmation": currentHostname(t, h, hostID),
		"payload":             map[string]any{"domain_leave": map[string]any{"domain": labDomain, "realm": labRealm}},
	}, 10*time.Minute)
}

// TestAHostJoinsTheDomainThroughThePanelAndLeavesIt runs the join end to
// end: the panel fetches the one-time password from the directory at
// dispatch, the host joins, the verifications after the join pass and the
// identity inventory shows the realm with SSSD online. The host then
// leaves through the panel and is in no domain again - also in t.Cleanup,
// so a failed assertion does not leave the lab host joined. Last, a join
// with a server that does not exist stops at the preflight with the
// unreachable ports named and changes nothing.
func TestAHostJoinsTheDomainThroughThePanelAndLeavesIt(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection; the panel cannot fetch a join password")
	}
	host, fqdn := candidateForJoin(t, h)

	// The leave is the cleanup whatever happens after the join: a host
	// left in the domain would fail every later run of this test.
	t.Cleanup(func() {
		if identityOf(t, h, host.ID).Enrolled {
			job, attempts := leaveDomain(t, h, host.ID)
			if job.State != "succeeded" {
				t.Errorf("cleanup: the leave ended in state %s: %s", job.State, lastMessage(attempts))
			}
			refreshIdentity(t, h, host.ID)
		}
	})

	t.Run("join", func(t *testing.T) {
		job, attempts := h.runOperation(host.ID, map[string]any{
			"action": "identity.host.enroll", "reason": domainJoinReason,
			"target_confirmation": host.Hostname,
			"payload": map[string]any{"domain_enroll": map[string]any{
				"domain": labDomain, "realm": labRealm, "server": labDirectoryServer, "hostname": fqdn,
			}},
		}, 15*time.Minute)
		detail := domainResult(t, h, job.ID)
		if job.State != "succeeded" {
			t.Fatalf("the join ended in state %s (%s): checks failed %v, verifications failed %v",
				job.State, lastMessage(attempts), failedChecks(detail.Checks), failedChecks(detail.Verifications))
		}
		if detail.Kind != "domain_enroll" || !detail.Enrolled {
			t.Fatalf("the result does not report the host as enrolled: %+v", detail)
		}
		if len(detail.Verifications) == 0 {
			t.Fatal("the join reports no verifications; the command exiting is not the host being in the domain")
		}
		for _, name := range []string{"keytab", "sssd", "nss"} {
			item := checkNamed(detail.Verifications, name)
			if item == nil {
				t.Errorf("the verification %s is missing", name)
			} else if item.Passed == nil || !*item.Passed {
				t.Errorf("the verification %s did not pass: %s", name, item.Detail)
			}
		}
		if !strings.HasPrefix(detail.HostPrincipal, "host/"+fqdn+"@") {
			t.Errorf("host principal = %q, expected host/%s@%s", detail.HostPrincipal, fqdn, labRealm)
		}

		facts := awaitSSSDOnline(t, h, host.ID, 3*time.Minute)
		if !facts.Enrolled || facts.Realm != labRealm || facts.Domain != labDomain {
			t.Errorf("the identity inventory does not show the domain: %+v", facts)
		}
		if facts.SSSDOnline == nil || !*facts.SSSDOnline {
			t.Errorf("SSSD is not online after the join: %+v", facts)
		}
		if !facts.SSSDRunning {
			t.Errorf("SSSD is not running after the join: %+v", facts)
		}
	})

	t.Run("leave", func(t *testing.T) {
		if !identityOf(t, h, host.ID).Enrolled {
			t.Skip("the host is not in the domain; nothing to leave")
		}
		// A click is not the decision: the leave cuts every directory
		// account off the host, so it requires the typed target.
		var problem struct {
			Code string `json:"code"`
		}
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
			"action": "identity.host.leave", "reason": domainJoinReason,
			"payload": map[string]any{"domain_leave": map[string]any{"domain": labDomain, "realm": labRealm}},
		}, &problem, http.StatusBadRequest)
		if problem.Code != "target_confirmation_required" {
			t.Errorf("a leave without the typed target got %q, expected target_confirmation_required", problem.Code)
		}

		job, attempts := leaveDomain(t, h, host.ID)
		detail := domainResult(t, h, job.ID)
		if job.State != "succeeded" {
			t.Fatalf("the leave ended in state %s (%s): checks failed %v, verifications failed %v",
				job.State, lastMessage(attempts), failedChecks(detail.Checks), failedChecks(detail.Verifications))
		}
		if detail.Enrolled {
			t.Error("the leave reports the host as still enrolled")
		}
		// The configuration must be gone; the keytab is reported, since the
		// uninstall leaves the file on some clients (the lab's Debian one).
		item := checkNamed(detail.Verifications, "ipa_config")
		if item == nil || item.Passed == nil || !*item.Passed {
			t.Errorf("the verification ipa_config did not pass: %+v", item)
		}
		if keytab := checkNamed(detail.Verifications, "keytab"); keytab == nil {
			t.Error("the leave does not report the keytab")
		} else if keytab.Passed != nil && !*keytab.Passed {
			t.Logf("the keytab stayed after the leave: %s", keytab.Detail)
		}

		facts := refreshIdentity(t, h, host.ID)
		if facts.Enrolled {
			t.Errorf("the identity inventory still shows the host in the domain: %+v", facts)
		}

		// A second leave has nothing to leave and says so before the tool
		// runs: the host is refused, not silently "left" again.
		again, _ := leaveDomain(t, h, host.ID)
		if again.State == "succeeded" || again.ResultErrorCode != "preflight_failed" {
			t.Errorf("a leave of a host in no domain ended %s with the code %q, expected preflight_failed",
				again.State, again.ResultErrorCode)
		}
		if enrolled := checkNamed(domainResult(t, h, again.ID).Checks, "enrolled"); enrolled == nil || enrolled.Passed == nil || *enrolled.Passed {
			t.Errorf("the refused leave does not name the enrolled check: %+v", enrolled)
		}
	})

	t.Run("wrong server stops at the preflight", func(t *testing.T) {
		if identityOf(t, h, host.ID).Enrolled {
			t.Skip("the host is still in the domain; the negative preflight needs a host outside it")
		}
		job, attempts := h.runOperation(host.ID, map[string]any{
			"action": "identity.host.enroll", "reason": domainJoinReason,
			"target_confirmation": currentHostname(t, h, host.ID),
			"payload": map[string]any{"domain_enroll": map[string]any{
				"domain": labDomain, "realm": labRealm, "server": "nowhere." + labDomain, "hostname": fqdn,
			}},
		}, 5*time.Minute)
		if job.State == "succeeded" {
			t.Fatal("a join against a server that does not exist succeeded")
		}
		if job.ResultErrorCode != "preflight_failed" {
			t.Fatalf("code = %q, expected preflight_failed (%s)", job.ResultErrorCode, lastMessage(attempts))
		}
		detail := domainResult(t, h, job.ID)
		if detail.Enrolled {
			t.Error("a join stopped at the preflight reports the host as enrolled")
		}
		// The directory server is probed on every port the join needs, one
		// verdict per port, so the operator sees which rule is missing.
		failed := failedChecks(detail.Checks)
		for _, port := range []string{"port_88", "port_389", "port_443"} {
			if !containsString(failed, port) {
				t.Errorf("the preflight does not name %s among the failed conditions: %v", port, failed)
			}
		}
		if item := checkNamed(detail.Checks, "port_88"); item == nil || !strings.Contains(item.Detail, "nowhere."+labDomain) {
			t.Errorf("the port check does not name the server: %+v", item)
		}
		// The host's own name was fine: the failure is the server, and the
		// checks say so instead of blaming the resolution of the host.
		if forward := checkNamed(detail.Checks, "dns_forward"); forward == nil || forward.Passed == nil || !*forward.Passed {
			t.Errorf("the forward lookup of %s failed although the host is set up: %+v", fqdn, forward)
		}
		if identityOf(t, h, host.ID).Enrolled {
			t.Error("the host is in the domain after a join that stopped at the preflight")
		}
	})
}
