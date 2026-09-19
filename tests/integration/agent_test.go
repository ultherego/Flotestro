//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"testing"
)

// channelHostView is the part of a host the channel tests read.
type channelHostView struct {
	ID             string `json:"id"`
	Hostname       string `json:"hostname"`
	ReleaseChannel string `json:"release_channel"`
}

// setChannel moves a host to a release channel and moves it back when the test
// ends: the lab fleet is shared, and a host left on beta would be the first
// wave of somebody else's upgrade.
func (h *harness) setChannel(hostID, channel string) channelHostView {
	h.t.Helper()
	var before channelHostView
	h.get("/api/v1/hosts/"+hostID, &before)
	previous := before.ReleaseChannel
	h.t.Cleanup(func() {
		h.do(http.MethodPut, "/api/v1/hosts/"+hostID+"/channel", map[string]any{"channel": previous}, nil, 0)
	})
	var after channelHostView
	h.do(http.MethodPut, "/api/v1/hosts/"+hostID+"/channel", map[string]any{"channel": channel}, &after, http.StatusOK)
	return after
}

// TestHostReleaseChannelIsSetAndFilteredOn: a host is on stable until an
// operator moves it, the move comes back in the host record, the list filters
// on it, and a channel that is not a channel is refused.
func TestHostReleaseChannelIsSetAndFilteredOn(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) == 0 {
		t.Skip("no host in the lab")
	}
	host := lab[0]

	var initial channelHostView
	h.get("/api/v1/hosts/"+host.ID, &initial)
	if initial.ReleaseChannel != "stable" && initial.ReleaseChannel != "beta" {
		t.Fatalf("the host is on channel %q, expected stable or beta", initial.ReleaseChannel)
	}

	moved := h.setChannel(host.ID, "beta")
	if moved.ID != host.ID || moved.ReleaseChannel != "beta" {
		t.Fatalf("after the move the host is %+v, expected beta", moved)
	}
	var read channelHostView
	h.get("/api/v1/hosts/"+host.ID, &read)
	if read.ReleaseChannel != "beta" {
		t.Fatalf("the host record says channel %q after the move to beta", read.ReleaseChannel)
	}

	// The list filter: the host is among the beta hosts and not among the
	// stable ones.
	found := false
	for _, item := range h.hostsByQuery(url.Values{"channel": {"beta"}}) {
		if item.ID == host.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("the beta filter does not list %s", host.Hostname)
	}
	for _, item := range h.hostsByQuery(url.Values{"channel": {"stable"}}) {
		if item.ID == host.ID {
			t.Errorf("the stable filter still lists %s", host.Hostname)
		}
	}

	// The name is normalised, and a channel the panel does not have is
	// refused rather than stored.
	var back channelHostView
	h.do(http.MethodPut, "/api/v1/hosts/"+host.ID+"/channel",
		map[string]any{"channel": " Stable "}, &back, http.StatusOK)
	if back.ReleaseChannel != "stable" {
		t.Errorf("a padded name gave channel %q", back.ReleaseChannel)
	}
	h.do(http.MethodPut, "/api/v1/hosts/"+host.ID+"/channel",
		map[string]any{"channel": "nightly"}, nil, http.StatusBadRequest)
	h.do(http.MethodGet, "/api/v1/hosts?channel=nightly", nil, nil, http.StatusBadRequest)
	h.do(http.MethodPut, "/api/v1/hosts/00000000-0000-4000-8000-000000000000/channel",
		map[string]any{"channel": "beta"}, nil, http.StatusNotFound)
}

// TestAgentUpgradeIsCampaignReady: replacing the agent is offered in bulk with
// the same payload everywhere, verified by the host coming back, and the
// catalogue carries a template for it.
func TestAgentUpgradeIsCampaignReady(t *testing.T) {
	h := newHarness(t)
	var catalogue struct {
		Items []struct {
			Action          string         `json:"action"`
			CampaignMode    string         `json:"campaign_mode"`
			CampaignReady   bool           `json:"campaign_ready"`
			CampaignRefusal string         `json:"campaign_refusal"`
			Verification    string         `json:"verification"`
			PayloadTemplate map[string]any `json:"payload_template"`
		} `json:"items"`
	}
	h.get("/api/v1/actions", &catalogue)
	for _, item := range catalogue.Items {
		if item.Action != "agent.upgrade" {
			continue
		}
		if !item.CampaignReady || item.CampaignMode != "same_payload" {
			t.Fatalf("agent.upgrade is not campaign-ready: mode %q, refusal %q",
				item.CampaignMode, item.CampaignRefusal)
		}
		if item.Verification != "custom" {
			t.Errorf("agent.upgrade is verified by %q, expected the host coming back (custom)", item.Verification)
		}
		if _, ok := item.PayloadTemplate["agent_upgrade"]; !ok {
			t.Errorf("the template of agent.upgrade names no agent_upgrade payload: %v", item.PayloadTemplate)
		}
		return
	}
	t.Fatal("agent.upgrade is not in the catalogue")
}

// TestAgentUpgradeRefusesAVersionWithoutAProtocol: a target that is not a
// release version has no protocol the panel could check, so the order is
// refused before it is queued.
func TestAgentUpgradeRefusesAVersionWithoutAProtocol(t *testing.T) {
	h := newHarness(t)
	lab := h.hosts()
	if len(lab) == 0 {
		t.Skip("no host in the lab")
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+lab[0].ID+"/operations", map[string]any{
		"action":  "agent.upgrade",
		"payload": map[string]any{"agent_upgrade": map[string]any{"target_version": "latest"}},
	}, nil, http.StatusBadRequest)
}
