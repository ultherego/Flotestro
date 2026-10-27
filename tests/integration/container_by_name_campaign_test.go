//go:build integration

package integration

import (
	"net/url"
	"testing"
	"time"
)

// TestACampaignNamesAContainerOnceAndEveryHostSettlesIt is the case of a fleet in which some hosts
// have docker and not all of those run the container: the order names the container by its
// exact name, once; the preview says on which hosts the panel has seen it, and each host resolves
// the name itself when the order arrives - the host that runs it restarts it, the host whose engine
// answered and has no such container is skipped with the reason, not failed, and the hosts
// without docker take no part.
func TestACampaignNamesAContainerOnceAndEveryHostSettlesIt(t *testing.T) {
	h := newHarness(t)

	var withEngine struct {
		Items []hostView `json:"items"`
	}
	h.get("/api/v1/hosts?capability=docker&limit=200", &withEngine)
	var online []hostView
	for _, host := range withEngine.Items {
		if host.ConnectionState == "online" {
			online = append(online, host)
		}
	}
	if len(online) < 2 {
		absent(t, "the fleet has fewer than two connected hosts with a container engine")
	}

	// Each engine is read in full, which is also the evidence the preview speaks from.
	has := map[string]map[string]bool{}
	for _, host := range online {
		names := map[string]bool{}
		for _, container := range hostEngineState(t, h, host.ID).Containers {
			names[container.Name] = true
		}
		has[host.ID] = names
	}
	name := ""
	for candidate := range has[online[0].ID] {
		for _, other := range online[1:] {
			if !has[other.ID][candidate] {
				name = candidate
			}
		}
		if name != "" {
			break
		}
	}
	if name == "" {
		for _, host := range online[1:] {
			for candidate := range has[host.ID] {
				if !has[online[0].ID][candidate] {
					name = candidate
				}
			}
		}
	}
	if name == "" {
		absent(t, "no container runs on some of the docker hosts and not on others")
	}

	// The capability is what makes a host eligible; what the panel has seen of the container is said apart.
	var preview struct {
		Eligible  int `json:"eligible"`
		Container struct {
			Present struct {
				Sample []string `json:"sample"`
			} `json:"present"`
			Absent struct {
				Sample []string `json:"sample"`
			} `json:"absent"`
		} `json:"container"`
	}
	query := url.Values{"action": {"docker.container.restart"}, "site": {"lab"}, "container_name": {name}}
	h.get("/api/v1/campaigns/preview?"+query.Encode(), &preview)
	seenOn, notSeenOn := map[string]bool{}, map[string]bool{}
	for _, host := range preview.Container.Present.Sample {
		seenOn[host] = true
	}
	for _, host := range preview.Container.Absent.Sample {
		notSeenOn[host] = true
	}
	for _, host := range online {
		switch {
		case has[host.ID][name] && !seenOn[host.Hostname]:
			t.Errorf("the preview does not say the container %q was seen on %s", name, host.Hostname)
		case !has[host.ID][name] && !notSeenOn[host.Hostname]:
			t.Errorf("the preview does not say the container %q was not seen on %s", name, host.Hostname)
		}
	}

	campaign := h.createCampaign(map[string]any{
		"name": "a-container-by-name", "action": "docker.container.restart",
		"payload":                    map[string]any{"docker_container": map[string]any{"name": name, "timeout_seconds": 10}},
		"selector":                   map[string]any{"site": "lab"},
		"canary_size":                0,
		"wave_size":                  len(online),
		"max_concurrent":             len(online),
		"failure_threshold_absolute": 0,
		"failure_threshold_percent":  0,
		"reboot_policy":              "never",
		"reason":                     "a container named once, settled on every host",
	})
	h.approveCampaign(campaign)
	final := h.awaitCampaign(campaign.ID,
		map[string]bool{"completed": true, "completed_with_issues": true, "failed": true}, 5*time.Minute)
	// An agent older than the rest of the fleet does not resolve a name: the panel leaves it
	// out of the campaign with its reason instead of sending it an order it would refuse.
	newest := ""
	for _, host := range online {
		newest = max(newest, host.AgentVersion)
	}
	older := map[string]bool{}
	for _, host := range online {
		older[host.ID] = host.AgentVersion < newest
	}
	if final.State != "completed" {
		t.Fatalf("the campaign ended in state %s (%s)", final.State, h.whyItEnded(final))
	}

	settled := map[string]campaignTargetView{}
	for _, target := range h.campaignTargets(campaign.ID) {
		settled[target.HostID] = target
	}
	for _, host := range online {
		target, listed := settled[host.ID]
		if !listed {
			t.Errorf("%s was not in the campaign", host.Hostname)
			continue
		}
		if older[host.ID] {
			if target.State != "ineligible" || target.ErrorCode != "agent_too_old" {
				t.Errorf("%s runs an older agent that cannot resolve a name and ended %s (%s): it is left out as too old",
					host.Hostname, target.State, target.ErrorCode)
			}
			continue
		}
		if has[host.ID][name] {
			if target.State != "succeeded" {
				t.Errorf("%s runs the container and ended %s (%s %s)", host.Hostname, target.State, target.ErrorCode, target.Message)
			}
			continue
		}
		if target.State != "skipped" || target.ErrorCode != "container_not_found" {
			t.Errorf("%s has no container %q and ended %s (%s): it is skipped for that reason, not failed",
				host.Hostname, name, target.State, target.ErrorCode)
		}
	}
	// The hosts that cannot run the operation took no part.
	for _, host := range h.hosts() {
		if _, inDocker := has[host.ID]; inDocker {
			continue
		}
		if target, listed := settled[host.ID]; listed && target.State != "ineligible" && target.State != "excluded" {
			t.Errorf("%s has no container engine and ended %s", host.Hostname, target.State)
		}
	}
}
