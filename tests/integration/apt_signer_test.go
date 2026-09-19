//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

// errorGuideView is one entry of the guide to error codes as the panel serves
// it.
type errorGuideView struct {
	Code    string `json:"code"`
	Stage   string `json:"stage"`
	Meaning string `json:"meaning"`
	Action  string `json:"action"`
}

// The reasons an apt host gives when it cannot establish the origin of a
// package file. Every one of them is a code the operator can look up.
var aptProofReasons = []string{
	"apt_repository_unsigned",
	"apt_index_key_untrusted",
	"apt_index_unreadable",
	"apt_artefact_origin_unknown",
	"apt_index_digest_mismatch",
}

// TestAPlanForAnAptHostDoesNotNameAPackageSigner: a .deb carries no signature,
// so a plan naming a key is refused by the panel rather than sent to the host.
func TestAPlanForAnAptHostDoesNotNameAPackageSigner(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var before agentHostView
	h.get("/api/v1/hosts/"+host.ID, &before)
	if before.AgentVersion == "" {
		t.Skip("the host does not report the version of its agent")
	}

	// A well-formed fingerprint of a key no Debian package could ever carry.
	fingerprint := strings.Repeat("A1B2", 10)
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "agent.upgrade",
		"payload": map[string]any{
			"agent_upgrade": map[string]any{
				"target_version": before.AgentVersion,
				"package_sha256": strings.Repeat("9f", 32),
				"package_signer": fingerprint,
			},
		},
	}, 4*time.Minute)

	if job.State == "succeeded" {
		t.Fatalf("a plan naming a signer for an apt host succeeded: %s", job.ResultMessage)
	}
	if job.ResultErrorCode != "agent_package_signer_not_applicable" {
		t.Fatalf("the plan was refused as %q (%s), expected agent_package_signer_not_applicable",
			job.ResultErrorCode, job.ResultMessage)
	}
	// The refusal says what the operator is to do instead: the proof on that
	// family is the repository index, not the file.
	if !strings.Contains(job.ResultMessage, "signature") {
		t.Errorf("the refusal %q does not say why the key cannot be carried", job.ResultMessage)
	}
	for _, attempt := range attempts {
		if attempt.Status == "succeeded" {
			t.Errorf("attempt %d succeeded although the plan could not be satisfied", attempt.Number)
		}
	}

	// The host was never asked: a demand nobody can meet is settled on the
	// panel, and the fleet keeps its agent.
	h.awaitConnection(host.ID, 2*time.Minute)
	var after agentHostView
	h.get("/api/v1/hosts/"+host.ID, &after)
	if after.AgentVersion != before.AgentVersion {
		t.Fatalf("the host runs the agent %s after a refused plan, it ran %s",
			after.AgentVersion, before.AgentVersion)
	}
}

// TestTheGuideExplainsWhatProvesAPackageOnEachFamily: a typed reason an
// operator cannot look up is a code they have to guess at.
func TestTheGuideExplainsWhatProvesAPackageOnEachFamily(t *testing.T) {
	h := newHarness(t)
	var guide struct {
		Items []errorGuideView `json:"items"`
	}
	h.get("/api/v1/errors", &guide)

	known := map[string]errorGuideView{}
	for _, item := range guide.Items {
		known[item.Code] = item
	}
	expected := append([]string{"agent_package_signer_not_applicable"}, aptProofReasons...)
	for _, code := range expected {
		entry, ok := known[code]
		if !ok {
			t.Errorf("the guide does not explain %q", code)
			continue
		}
		if entry.Meaning == "" || entry.Action == "" {
			t.Errorf("the entry for %q says nothing the operator can act on", code)
		}
	}
	// The one that names the decision has to name the proof that replaces it.
	if entry := known["agent_package_signer_not_applicable"]; !strings.Contains(
		strings.ToLower(entry.Action), "repository index") {
		t.Errorf("the guide for the refusal does not name the proof that stands instead: %q",
			entry.Action)
	}
}
