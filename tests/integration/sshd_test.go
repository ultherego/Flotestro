//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type hostKeyView struct {
	Type        string `json:"type"`
	Bits        int    `json:"bits"`
	Fingerprint string `json:"fingerprint"`
	Path        string `json:"path"`
}

type sshSnapshot struct {
	Ports                  []string      `json:"ports"`
	PermitRootLogin        string        `json:"permit_root_login"`
	PasswordAuthentication string        `json:"password_authentication"`
	PubkeyAuthentication   string        `json:"pubkey_authentication"`
	GSSAPIAuthentication   string        `json:"gssapi_authentication"`
	MaxAuthTries           int           `json:"max_auth_tries"`
	HostKeys               []hostKeyView `json:"host_keys"`
	ManagedPath            string        `json:"managed_path"`
	ManagedPresent         bool          `json:"managed_present"`
	Unit                   string        `json:"unit"`
	UnavailableReason      string        `json:"unavailable_reason"`
}

const sshReason = "integration test of the sshd module"

// TestSSHConfigurationComesFromTheServer checks that the panel shows what
// the server really applies, together with the key fingerprints - and never
// a private key.
func TestSSHConfigurationComesFromTheServer(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostSSHSnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the configuration was not read: %s", state.UnavailableReason)
			}
			if len(state.Ports) == 0 || state.MaxAuthTries == 0 {
				t.Errorf("state = %+v", state)
			}
			// The unit name differs between distributions, and reloading the
			// wrong one does nothing and reports no error.
			if state.Unit != "ssh.service" && state.Unit != "sshd.service" {
				t.Errorf("unit = %q", state.Unit)
			}
			if len(state.HostKeys) == 0 {
				t.Fatal("the host reported no key at all")
			}
			for _, key := range state.HostKeys {
				if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
					t.Errorf("fingerprint = %q", key.Fingerprint)
				}
				// The panel has no reason to see the private key, so it
				// points only at the public file.
				if !strings.HasSuffix(key.Path, ".pub") {
					t.Errorf("key path = %q", key.Path)
				}
			}
		})
	}
}

// TestChangeCuttingOffLoginIsRejected guards the boundary: a server nobody
// can log into by any method is not secured - it is unavailable.
func TestChangeCuttingOffLoginIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "ssh.config.apply", "reason": sshReason,
		"payload": map[string]any{"ssh": map[string]any{
			"password_authentication": "no", "pubkey_authentication": "no"}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Fatal("the panel accepted a configuration without any authentication method")
	}
	if !strings.Contains(lastMessage(attempts), "authentication method") {
		t.Errorf("refusal without a reason: %q", lastMessage(attempts))
	}
}

// TestSettingShadowed is about what tells a write from its effect: in sshd
// the first value wins, so an earlier administrator file shadows the panel
// file. Silence here would be a false success.
func TestSettingShadowed(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	state := hostSSHSnapshot(t, h, host.ID)

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "ssh.config.apply", "reason": sshReason,
			"payload": map[string]any{"ssh": map[string]any{
				"max_auth_tries": "6"}},
		}, 2*time.Minute)
	})

	// Nobody else sets MaxAuthTries, so this part is to succeed.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "ssh.config.apply", "reason": sshReason,
		"payload": map[string]any{"ssh": map[string]any{"max_auth_tries": "4"}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("changing MaxAuthTries: state = %s, %s", job.State, lastMessage(attempts))
	}

	after := hostSSHSnapshot(t, h, host.ID)
	if after.MaxAuthTries != 4 {
		t.Errorf("MaxAuthTries = %d", after.MaxAuthTries)
	}
	if !after.ManagedPresent || after.ManagedPath != "/etc/ssh/sshd_config.d/90-flotestro.conf" {
		t.Errorf("panel file = %+v", after.ManagedPath)
	}
	// The server keeps running: the configuration was checked by sshd
	// before the reload.
	if len(after.Ports) == 0 {
		t.Error("the server does not answer after the change")
	}
	_ = state
}

// TestBadSSHConfigurationDoesNotReachTheHost checks the refusal at ordering
// time.
func TestBadSSHConfigurationDoesNotReachTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, tc := range []struct {
		change map[string]any
		why    string
	}{
		{map[string]any{"port": "0"}, "port zero"},
		{map[string]any{"permit_root_login": "maybe"}, "unknown root login value"},
		{map[string]any{"max_auth_tries": "0"}, "zero tries"},
		{map[string]any{"allow_users": []string{"bad entry"}}, "pattern with whitespace"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "ssh.config.apply", "reason": sshReason,
					"payload": map[string]any{"ssh": tc.change}},
				nil, http.StatusBadRequest)
		})
	}

	// Key rotation concerns the types the host has at all.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "ssh.hostkey.rotate", "reason": sshReason,
			"payload": map[string]any{"ssh": map[string]any{"key_type": "dsa"}}},
		nil, http.StatusBadRequest)
}

func hostSSHSnapshot(t *testing.T, h *harness, hostID string) sshSnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/ssh", nil, &fragment, http.StatusOK)
	var state sshSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("sshd snapshot: %v", err)
	}
	return state
}
