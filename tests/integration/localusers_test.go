//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// testKey is a public key; the private material does not exist on the test
// side and is not needed for anything.
const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 test@flotestro"

type accountView struct {
	Name        string   `json:"name"`
	UID         int64    `json:"uid"`
	Source      string   `json:"source"`
	Groups      []string `json:"groups"`
	Locked      *bool    `json:"locked"`
	PasswordSet *bool    `json:"password_set"`
	SSHKeys     []struct {
		Fingerprint string `json:"fingerprint"`
		Type        string `json:"type"`
	} `json:"ssh_keys"`
	ObservedAt string `json:"observed_at"`
}

func accounts(h *harness, hostID, filter string) []accountView {
	h.t.Helper()
	var result struct {
		Accounts []accountView `json:"accounts"`
	}
	path := "/api/v1/hosts/" + hostID + "/local-accounts"
	if filter != "" {
		path += "?source=" + filter
	}
	h.get(path, &result)
	return result.Accounts
}

func account(h *harness, hostID, name string) *accountView {
	h.t.Helper()
	for _, a := range accounts(h, hostID, "") {
		if a.Name == name {
			return &a
		}
	}
	return nil
}

func accountOperation(h *harness, hostID, action string, payload map[string]any) (jobView, []attemptView) {
	h.t.Helper()
	return h.runOperation(hostID, map[string]any{
		"action":  action,
		"payload": map[string]any{"local_user": payload},
	}, 120*time.Second)
}

// TestLocalAccountLifecycle checks the local accounts module from creation
// to revoking access. The module is meant for installations without an
// identity directory, so it must work without any external integration.
func TestLocalAccountLifecycle(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	name := fmt.Sprintf("test%d", time.Now().UnixNano()%100000)

	t.Cleanup(func() {
		// The test account must not outlive the test: an account left
		// behind with a key would be a real way into the host.
		accountOperation(h, host.ID, "localuser.sshkeys.set", map[string]any{
			"name": name, "ssh_keys": []string{},
		})
		accountOperation(h, host.ID, "localuser.lock", map[string]any{"name": name})
	})

	job, _ := accountOperation(h, host.ID, "localuser.create", map[string]any{
		"name": name, "gecos": "Test account", "shell": "/bin/bash",
		"ssh_keys": []string{testKey}, "create_home": true,
	})
	if job.State != "succeeded" {
		t.Fatalf("creating the account ended in state %s", job.State)
	}

	// The state must be visible right after the operation, without waiting
	// for the next inventory report: the agent reads the account after the
	// change.
	created := account(h, host.ID, name)
	if created == nil {
		t.Fatal("the account did not appear in the panel after creation")
	}
	if created.Source != "local" {
		t.Errorf("account source = %q, expected local", created.Source)
	}
	if created.UID < 1000 {
		t.Errorf("the account got UID %d from the system range", created.UID)
	}
	// An account created by the panel has no password, but is not locked:
	// the SSH key gives access. Showing it as locked would be false
	// information about access being cut off.
	if created.Locked == nil || *created.Locked {
		t.Errorf("an SSH key account cannot be locked: locked=%v", created.Locked)
	}
	if created.PasswordSet == nil || *created.PasswordSet {
		t.Errorf("an account created by the panel cannot have a password: password_set=%v", created.PasswordSet)
	}
	if len(created.SSHKeys) != 1 {
		t.Fatalf("the account has %d keys, expected 1", len(created.SSHKeys))
	}
	if created.SSHKeys[0].Type != "ED25519" {
		t.Errorf("key type = %q", created.SSHKeys[0].Type)
	}

	// A repeated creation must be rejected explicitly, not quietly
	// overwrite the existing account.
	repeated, attempts := accountOperation(h, host.ID, "localuser.create", map[string]any{
		"name": name, "ssh_keys": []string{testKey},
	})
	if repeated.State == "succeeded" {
		t.Error("the repeated account creation succeeded")
	}
	if len(attempts) > 0 && attempts[len(attempts)-1].ErrorCode != "account_exists" {
		t.Errorf("error code = %q, expected account_exists", attempts[len(attempts)-1].ErrorCode)
	}

	lock, _ := accountOperation(h, host.ID, "localuser.lock", map[string]any{"name": name})
	if lock.State != "succeeded" {
		t.Fatalf("the lock ended in state %s", lock.State)
	}
	if state := account(h, host.ID, name); state == nil || state.Locked == nil || !*state.Locked {
		t.Errorf("the account was not shown as locked: %+v", state)
	}

	unlock, _ := accountOperation(h, host.ID, "localuser.unlock", map[string]any{"name": name})
	if unlock.State != "succeeded" {
		t.Fatalf("the unlock ended in state %s", unlock.State)
	}
	if state := account(h, host.ID, name); state == nil || state.Locked == nil || *state.Locked {
		t.Errorf("the account stayed locked after the unlock: %+v", state)
	}

	// An empty key list is a deliberate revocation of access.
	revocation, _ := accountOperation(h, host.ID, "localuser.sshkeys.set", map[string]any{
		"name": name, "ssh_keys": []string{},
	})
	if revocation.State != "succeeded" {
		t.Fatalf("revoking the keys ended in state %s", revocation.State)
	}
	state := account(h, host.ID, name)
	if state == nil || len(state.SSHKeys) != 0 {
		t.Errorf("the keys were not revoked: %+v", state)
	}
}

// TestSystemAccountsAreProtected checks that the module gives no way to
// change service accounts or to shadow a directory account.
func TestSystemAccountsAreProtected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, name := range []string{"root", "daemon", "bin"} {
		t.Run(name, func(t *testing.T) {
			job, attempts := accountOperation(h, host.ID, "localuser.lock", map[string]any{"name": name})
			if job.State == "succeeded" {
				t.Fatalf("locking the system account %s succeeded", name)
			}
			if len(attempts) > 0 && attempts[len(attempts)-1].ErrorCode != "system_account" {
				t.Errorf("error code = %q, expected system_account", attempts[len(attempts)-1].ErrorCode)
			}
		})
	}

	// System accounts are outside the default view, but must be reachable
	// with an explicit filter: sometimes one has to confirm that a service
	// account exists.
	defaultView := accounts(h, host.ID, "")
	for _, a := range defaultView {
		if a.Source == "system" {
			t.Errorf("the system account %s got into the default view", a.Name)
		}
	}
	system := accounts(h, host.ID, "system")
	if len(system) == 0 {
		t.Error("the system account filter returned no account")
	}
	for _, a := range system {
		if a.Name == "root" && a.UID != 0 {
			t.Errorf("the root account has UID %d", a.UID)
		}
	}
}

// TestPrivateKeyIsRejected checks that the panel does not accept private
// material even by an operator's mistake. The rejection happens at plan
// validation, so the secret reaches neither the database nor the host.
func TestPrivateKeyIsRejected(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, key := range []string{
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		testKey + "\nssh-rsa AAAAB3NzaC1yc2E stranger@workstation",
		"ssh-dss AAAAB3NzaC1kc3M john@workstation",
	} {
		var problem struct {
			Code string `json:"code"`
		}
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
			"action": "localuser.sshkeys.set",
			"payload": map[string]any{
				"local_user": map[string]any{"name": "irrelevant", "ssh_keys": []string{key}},
			},
		}, &problem, http.StatusBadRequest)
		if problem.Code != "invalid_payload" {
			t.Errorf("key %.30q: code = %q, expected invalid_payload", key, problem.Code)
		}
	}
}
