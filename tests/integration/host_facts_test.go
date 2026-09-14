//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// hostFactsView is the part of a host the fact tests read.
type hostFactsView struct {
	ID                      string   `json:"id"`
	Hostname                string   `json:"hostname"`
	Owner                   string   `json:"owner"`
	Tags                    []string `json:"tags"`
	ManagementAddress       string   `json:"management_address"`
	ManagementAddressSource string   `json:"management_address_source"`
}

// readHostFacts reads a host with the entity tag of its hand-recorded facts.
func readHostFacts(t *testing.T, h *harness, hostID string) (hostFactsView, string) {
	t.Helper()
	response, body := h.request(http.MethodGet, "/api/v1/hosts/"+hostID, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET the host: status %d; body: %s", response.StatusCode, body)
	}
	var host hostFactsView
	if err := json.Unmarshal(body, &host); err != nil {
		t.Fatalf("the host does not decode: %v", err)
	}
	return host, response.Header.Get("ETag")
}

// TestOwnerAndManualAddressRoundTrip guards the facts an operator records
// about a host by hand: the owner and the management address go in with
// the entity tag of the host, a stale tag is refused with the current
// one, the address is marked manual, and an empty address takes the
// manual value away again.
func TestOwnerAndManualAddressRoundTrip(t *testing.T) {
	h := newHarness(t)
	host := h.enrollSyntheticHost(t)
	path := "/api/v1/hosts/" + host.ID

	_, fresh := readHostFacts(t, h, host.ID)
	if fresh == "" {
		t.Fatal("the host read carries no ETag")
	}

	// A stale tag is refused, and the refusal names the current version.
	stale := map[string]string{"If-Match": `W/"0000000000000000"`}
	response, body := h.request(http.MethodPut, path+"/owner",
		map[string]any{"owner": "stale team", "reason": "stale write"}, stale)
	if response.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("a stale If-Match answered %d; body: %s", response.StatusCode, body)
	}
	if got := response.Header.Get("ETag"); got != fresh {
		t.Errorf("the refusal names ETag %q, the read gave %q", got, fresh)
	}

	// The fresh tag lets the owner through, and the answer carries the
	// next version.
	response, body = h.request(http.MethodPut, path+"/owner",
		map[string]any{"owner": "  platform team ", "reason": "handover"}, map[string]string{"If-Match": fresh})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the owner write answered %d; body: %s", response.StatusCode, body)
	}
	var after hostFactsView
	if err := json.Unmarshal(body, &after); err != nil {
		t.Fatal(err)
	}
	if after.Owner != "platform team" {
		t.Errorf("the owner is %q after the write", after.Owner)
	}
	next := response.Header.Get("ETag")
	if next == "" || next == fresh {
		t.Errorf("after the write the ETag is %q, before it was %q", next, fresh)
	}

	// The two facts share one tag: the version read before the owner
	// changed no longer names the host for the address either.
	response, body = h.request(http.MethodPut, path+"/management-address",
		map[string]any{"address": "10.9.8.7"}, map[string]string{"If-Match": fresh})
	if response.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("the address write on the old tag answered %d; body: %s", response.StatusCode, body)
	}
	response, body = h.request(http.MethodPut, path+"/management-address",
		map[string]any{"address": " Db01.Lab.Internal ", "reason": "reachable by name only"}, map[string]string{"If-Match": next})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the address write answered %d; body: %s", response.StatusCode, body)
	}
	if err := json.Unmarshal(body, &after); err != nil {
		t.Fatal(err)
	}
	if after.ManagementAddress != "db01.lab.internal" || after.ManagementAddressSource != "manual" {
		t.Errorf("after the write the address is %q from %q", after.ManagementAddress, after.ManagementAddressSource)
	}

	// The host read shows the same, with the same tag the write returned.
	read, tag := readHostFacts(t, h, host.ID)
	if read.Owner != "platform team" || read.ManagementAddress != "db01.lab.internal" || read.ManagementAddressSource != "manual" {
		t.Errorf("the read shows owner %q, address %q from %q", read.Owner, read.ManagementAddress, read.ManagementAddressSource)
	}
	if tag != response.Header.Get("ETag") {
		t.Errorf("the read gives ETag %q, the write gave %q", tag, response.Header.Get("ETag"))
	}

	// What is not an owner or an address is refused before the row.
	h.do(http.MethodPut, path+"/owner", map[string]any{"owner": strings.Repeat("x", 129)}, nil, http.StatusBadRequest)
	h.do(http.MethodPut, path+"/management-address", map[string]any{"address": "http://db01"}, nil, http.StatusBadRequest)
	h.do(http.MethodPut, path+"/management-address", map[string]any{"address": "10.0.0.1:22"}, nil, http.StatusBadRequest)

	// An empty address forgets the manual one. The synthetic host never
	// connected, so nothing observed stands behind it and the field is
	// empty rather than a leftover.
	// Fresh variables: a cleared field is absent from the answer, and a
	// decode into the earlier struct would keep the old value in it.
	var forgotten hostFactsView
	h.do(http.MethodPut, path+"/management-address", map[string]any{"address": ""}, &forgotten, http.StatusOK)
	if forgotten.ManagementAddress != "" || forgotten.ManagementAddressSource != "" {
		t.Errorf("after forgetting, the address is %q from %q", forgotten.ManagementAddress, forgotten.ManagementAddressSource)
	}
	// An empty owner hands the host back to nobody.
	var nobody hostFactsView
	h.do(http.MethodPut, path+"/owner", map[string]any{"owner": ""}, &nobody, http.StatusOK)
	if nobody.Owner != "" {
		t.Errorf("after clearing, the owner is %q", nobody.Owner)
	}

	// The trail keeps both sides of every change and the reason given.
	var trail auditPage
	h.get("/api/v1/audit?target_id="+host.ID+"&action=host.owner&limit=10", &trail)
	found := false
	for _, event := range trail.Items {
		if event.Detail["after"] == "platform team" {
			found = true
			if event.Detail["before"] != "" || event.Detail["reason"] != "handover" {
				t.Errorf("the owner event has detail %v", event.Detail)
			}
		}
	}
	if !found {
		t.Error("the owner change is not on the trail")
	}
	h.get("/api/v1/audit?target_id="+host.ID+"&action=host.management_address&limit=10", &trail)
	if len(trail.Items) < 2 {
		t.Errorf("the address changes left %d events on the trail", len(trail.Items))
	}
}

// TestHostListFactFilters guards the filters over what the hosts
// reported: a host that has not said whether it needs a reboot or how
// many security updates wait is in neither the "yes" nor the "no" list,
// and a domain filter answers with the hosts of that domain alone.
func TestHostListFactFilters(t *testing.T) {
	h := newHarness(t)
	host := h.enrollSyntheticHost(t)

	listed := func(query string) bool {
		t.Helper()
		var page struct {
			Items []hostFactsView `json:"items"`
		}
		h.get("/api/v1/hosts?limit=500&"+query, &page)
		for _, item := range page.Items {
			if item.ID == host.ID {
				return true
			}
		}
		return false
	}
	if !listed("") {
		t.Fatal("the synthetic host is not on the plain list")
	}
	// The synthetic host reported nothing: unknown is not "no".
	for _, query := range []string{
		"reboot_required=true", "reboot_required=false",
		"security_updates=true", "security_updates=false",
		"identity_domain=nowhere.invalid",
	} {
		if listed(query) {
			t.Errorf("the filter %s lists a host that reported nothing", query)
		}
	}
	// The fleet hosts that reported are on exactly one side of each.
	var page struct {
		Items []struct {
			ID                     string `json:"id"`
			RebootRequired         *bool  `json:"reboot_required"`
			PendingSecurityUpdates *int   `json:"pending_security_updates"`
			Identity               struct {
				Enrolled bool   `json:"enrolled"`
				Domain   string `json:"domain"`
			} `json:"identity"`
		} `json:"items"`
	}
	h.get("/api/v1/hosts?limit=500", &page)
	ids := func(query string) map[string]bool {
		t.Helper()
		var answer struct {
			Items []hostFactsView `json:"items"`
		}
		h.get("/api/v1/hosts?limit=500&"+query, &answer)
		set := map[string]bool{}
		for _, item := range answer.Items {
			set[item.ID] = true
		}
		return set
	}
	rebootYes, rebootNo := ids("reboot_required=true"), ids("reboot_required=false")
	securityYes, securityNo := ids("security_updates=true"), ids("security_updates=false")
	for _, item := range page.Items {
		if item.RebootRequired != nil {
			if rebootYes[item.ID] != *item.RebootRequired || rebootNo[item.ID] == *item.RebootRequired {
				t.Errorf("host %s with reboot_required=%t is listed yes=%t no=%t", item.ID, *item.RebootRequired, rebootYes[item.ID], rebootNo[item.ID])
			}
		}
		if item.PendingSecurityUpdates != nil {
			waiting := *item.PendingSecurityUpdates > 0
			if securityYes[item.ID] != waiting || securityNo[item.ID] == waiting {
				t.Errorf("host %s with %d security updates is listed yes=%t no=%t", item.ID, *item.PendingSecurityUpdates, securityYes[item.ID], securityNo[item.ID])
			}
		}
		if item.Identity.Enrolled && item.Identity.Domain != "" {
			inDomain := ids("identity_domain=" + url.QueryEscape(item.Identity.Domain))
			if !inDomain[item.ID] {
				t.Errorf("host %s of domain %s is not listed under its domain", item.ID, item.Identity.Domain)
			}
		}
	}
	// A value that is not a boolean is refused rather than read as false.
	h.do(http.MethodGet, "/api/v1/hosts?reboot_required=maybe", nil, nil, http.StatusBadRequest)
	h.do(http.MethodGet, "/api/v1/hosts?security_updates=some", nil, nil, http.StatusBadRequest)
}

// TestEnrollmentOrderCarriesOwnerAndTags guards the facts an order
// carries onto the host: the owner and the tags typed when ordering the
// installation are on the host the moment it enrolls, and an order with
// a tag the tag editor would refuse is refused at ordering time.
func TestEnrollmentOrderCarriesOwnerAndTags(t *testing.T) {
	h := newHarness(t)

	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "synthetic test host", "site": "lab", "environment": "test",
		"tags": []string{"Not A Tag"},
	}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "synthetic test host", "site": "lab", "environment": "test",
		"owner": strings.Repeat("o", 129),
	}, nil, http.StatusBadRequest)

	var order struct {
		ID    string   `json:"id"`
		Token string   `json:"token"`
		Owner string   `json:"owner"`
		Tags  []string `json:"tags"`
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "synthetic test host", "site": "lab", "environment": "test",
		"owner": "storage team", "tags": []string{"tier=gold", "role=db", "role=db"},
	}, &order, http.StatusCreated)
	if order.Owner != "storage team" || strings.Join(order.Tags, " ") != "role=db tier=gold" {
		t.Fatalf("the order carries owner %q and tags %v", order.Owner, order.Tags)
	}
	// The listing shows the facts without the token.
	var listed struct {
		Owner string   `json:"owner"`
		Tags  []string `json:"tags"`
		Token string   `json:"token"`
	}
	h.get("/api/v1/enrollment-requests/"+order.ID, &listed)
	if listed.Owner != "storage team" || len(listed.Tags) != 2 || listed.Token != "" {
		t.Errorf("the order reads back as owner %q, tags %v, token %q", listed.Owner, listed.Tags, listed.Token)
	}

	host := h.enrollSyntheticHostWithToken(t, order.Token)
	facts, _ := readHostFacts(t, h, host.ID)
	if facts.Owner != "storage team" {
		t.Errorf("the enrolled host has owner %q", facts.Owner)
	}
	if strings.Join(facts.Tags, " ") != "role=db tier=gold" {
		t.Errorf("the enrolled host has tags %v", facts.Tags)
	}
	// The tag filter finds it at once: the host is inside the campaigns
	// its tags select from its first second.
	var page struct {
		Items []hostFactsView `json:"items"`
	}
	h.get("/api/v1/hosts?tag=tier%3Dgold&tag=role%3Ddb&owner="+url.QueryEscape("storage team"), &page)
	found := false
	for _, item := range page.Items {
		found = found || item.ID == host.ID
	}
	if !found {
		t.Error("the enrolled host is not found by its owner and tags")
	}
}
