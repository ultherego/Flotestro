//go:build integration

package integration

import (
	"testing"

	"github.com/ultherego/flotestro/internal/buildinfo"
)

// helloView is the part of the host record the Hello of the agent fills in
// beyond the version: the sources of the binary, the protocols it speaks and
// the configuration it runs on.
type helloView struct {
	ID                  string `json:"id"`
	Hostname            string `json:"hostname"`
	ConnectionState     string `json:"connection_state"`
	AgentVersion        string `json:"agent_version"`
	AgentBuildCommit    string `json:"agent_build_commit"`
	AgentProtocolMin    *int   `json:"agent_protocol_min"`
	AgentProtocolMax    *int   `json:"agent_protocol_max"`
	ConfigFingerprint   string `json:"config_fingerprint"`
	ConfigSchemaVersion *int   `json:"config_schema_version"`
	ConfigLegacy        *bool  `json:"config_legacy"`
}

// TestEveryOnlineHostReportsItsBuildAndConfiguration: an agent that introduces
// itself tells the panel its commit, its protocols and its configuration.
func TestEveryOnlineHostReportsItsBuildAndConfiguration(t *testing.T) {
	h := newHarness(t)
	var listing struct {
		Items []helloView `json:"items"`
	}
	h.get("/api/v1/hosts", &listing)

	checked := 0
	for _, host := range listing.Items {
		if host.ConnectionState != "online" {
			continue
		}
		if !buildinfo.ReportsBuild(host.AgentVersion) {
			t.Logf("%s runs the agent %q, from before the build report; skipped", host.Hostname, host.AgentVersion)
			continue
		}
		checked++
		t.Run(host.Hostname, func(t *testing.T) {
			if host.AgentBuildCommit == "" {
				t.Errorf("no build commit; the agent %s reports one", host.AgentVersion)
			}
			if host.AgentProtocolMin == nil || host.AgentProtocolMax == nil {
				t.Fatalf("no protocol range; the agent %s announces one", host.AgentVersion)
			}
			if *host.AgentProtocolMin < 1 || *host.AgentProtocolMin > *host.AgentProtocolMax {
				t.Errorf("the protocol range %d..%d is not a range", *host.AgentProtocolMin, *host.AgentProtocolMax)
			}
			if err := buildinfo.CheckProtocolRange(host.AgentVersion, *host.AgentProtocolMin, *host.AgentProtocolMax); err != nil {
				t.Errorf("the panel would refuse the range it opened a session for: %v", err)
			}
			if host.ConfigSchemaVersion == nil || host.ConfigLegacy == nil {
				t.Fatalf("no configuration schema; the agent %s reports one", host.AgentVersion)
			}
			if *host.ConfigSchemaVersion == 0 {
				// The environment file of the old flow: no file, no fingerprint, and the
				// panel says so rather than showing a blank as the current configuration.
				if !*host.ConfigLegacy {
					t.Error("a host on no configuration file is not shown as a legacy configuration")
				}
				if host.ConfigFingerprint != "" {
					t.Errorf("a host on no configuration file has the fingerprint %q", host.ConfigFingerprint)
				}
				t.Logf("%s runs on the environment file; migrate it with flotestro-agentctl config migrate", host.Hostname)
				return
			}
			if len(host.ConfigFingerprint) != 64 {
				t.Errorf("the configuration fingerprint is %q, expected a hex sha256", host.ConfigFingerprint)
			}
			if *host.ConfigLegacy {
				t.Errorf("a host on the schema %d is shown as a legacy configuration", *host.ConfigSchemaVersion)
			}
		})
	}
	if checked == 0 {
		t.Skip("no online host runs an agent that reports its build")
	}
}
