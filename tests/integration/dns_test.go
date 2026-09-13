//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type dnsLinkView struct {
	Name         string   `json:"name"`
	Servers      []string `json:"servers"`
	Domains      []string `json:"domains"`
	DefaultRoute *bool    `json:"default_route"`
}

type dnsSnapshot struct {
	Owner             string        `json:"owner"`
	Mode              string        `json:"mode"`
	ResolvConf        string        `json:"resolv_conf"`
	Servers           []string      `json:"servers"`
	SearchDomains     []string      `json:"search_domains"`
	Links             []dnsLinkView `json:"links"`
	Writable          bool          `json:"writable"`
	WriteAdapter      string        `json:"write_adapter"`
	ReadOnlyReason    string        `json:"read_only_reason"`
	UnavailableReason string        `json:"unavailable_reason"`
}

type queryView struct {
	Name       string   `json:"name"`
	Addresses  []string `json:"addresses"`
	Server     string   `json:"server"`
	Error      string   `json:"error"`
	TookMillis int64    `json:"took_millis"`
}

// TestResolverHasAnOwnerAndAReadOnlyReason checks the thing that decides
// every DNS change: who writes the resolver file. A file owned by a service
// gets overwritten, so a write into it would vanish on its own.
func TestResolverHasAnOwnerAndAReadOnlyReason(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostDNSSnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the resolver state was not read: %s", state.UnavailableReason)
			}
			if state.Owner == "" {
				t.Error("the host did not say who writes its resolv.conf")
			}
			if len(state.Servers) == 0 {
				t.Error("the host reported no DNS server at all")
			}
			// A read-only host is to say why instead of staying quiet.
			if !state.Writable && state.ReadOnlyReason == "" {
				t.Error("a host without write support does not explain why")
			}
			if state.Writable && state.WriteAdapter == "" {
				t.Error("a host with write support did not name the mechanism")
			}
		})
	}
}

// TestResolveTestAsksFromTheHost checks that the answer comes from the host
// and carries a reason when a name cannot be resolved. Silence in place of
// an answer would look like a name without an address.
func TestResolveTestAsksFromTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "dns.resolve.test",
		"payload": map[string]any{"dns": map[string]any{
			"names": []string{"ipa.flotestro.test", "no-such-name.flotestro.test"}}},
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("resolve test: state = %s, %s", job.State, lastMessage(attempts))
	}

	queries := jobQueries(t, h, job.ID)
	if len(queries) != 2 {
		t.Fatalf("queries = %d", len(queries))
	}
	byName := map[string]queryView{}
	for _, query := range queries {
		byName[query.Name] = query
	}
	resolved := byName["ipa.flotestro.test"]
	if len(resolved.Addresses) == 0 {
		t.Errorf("the domain name was not resolved: %+v", resolved)
	}
	// The source of the answer is half of the answer here: in a DNS
	// diagnosis the question is "who told me that".
	if resolved.Server == "" {
		t.Error("the answer does not say where it came from")
	}
	unresolved := byName["no-such-name.flotestro.test"]
	if len(unresolved.Addresses) != 0 {
		t.Errorf("a non-existent name got an address: %+v", unresolved)
	}
	if unresolved.Error == "" {
		t.Error("unresolved name without a reason")
	}
	// An exit status is not a reason: the operator is to read what the
	// resolver said.
	if strings.Contains(unresolved.Error, "exit status") {
		t.Errorf("reason without the resolver's words: %q", unresolved.Error)
	}
}

// TestBadResolverDoesNotReachTheHost guards that a configuration which
// would cut the host off from the directory and Kerberos is rejected when
// ordered.
func TestBadResolverDoesNotReachTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	const reason = "integration test of the resolver module"

	cases := []struct {
		change map[string]any
		why    string
	}{
		{map[string]any{"interface": "enp0s8"}, "change without a server"},
		{map[string]any{"interface": "enp0s8", "servers": []string{"not-an-address"}}, "server that is not an address"},
		{map[string]any{"interface": "../etc", "servers": []string{"192.168.56.50"}}, "interface name with a path"},
		{map[string]any{"interface": "enp0s8", "servers": []string{"192.168.56.50"},
			"search_domains": []string{"bad domain"}}, "domain with whitespace"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "dns.host.apply", "reason": reason,
					"payload": map[string]any{"dns": tc.change}},
				nil, http.StatusBadRequest)
		})
	}

	// A host without a write mechanism refuses when ordered, not after
	// delivery.
	debian := h.hostByFamily("debian")
	if state := hostDNSSnapshot(t, h, debian.ID); !state.Writable {
		h.do(http.MethodPost, "/api/v1/hosts/"+debian.ID+"/operations",
			map[string]any{"action": "dns.host.apply", "reason": reason,
				"payload": map[string]any{"dns": map[string]any{
					"interface": "eth1", "servers": []string{"192.168.56.50"}}}},
			nil, http.StatusConflict)
	}
}

func hostDNSSnapshot(t *testing.T, h *harness, hostID string) dnsSnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/dns", nil, &fragment, http.StatusOK)
	var state dnsSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("resolver snapshot: %v", err)
	}
	return state
}

// jobQueries reads the test result from the last attempt. The result
// belongs to the attempt, because it is what knows what the host answered
// and when.
func jobQueries(t *testing.T, h *harness, jobID string) []queryView {
	t.Helper()
	var response struct {
		Items []struct {
			Detail struct {
				Queries struct {
					Queries []queryView `json:"queries"`
				} `json:"queries"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.do(http.MethodGet, "/api/v1/jobs/"+jobID+"/attempts", nil, &response, http.StatusOK)
	if len(response.Items) == 0 {
		t.Fatal("job without attempts")
	}
	return response.Items[len(response.Items)-1].Detail.Queries.Queries
}
