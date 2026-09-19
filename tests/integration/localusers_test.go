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
	ExpiresAt  string `json:"expires_at"`
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
	// Replacing the keys of an account decides who may log into the host, so the
	// panel asks for a reason as it does for every change of that weight.
	return h.runOperation(hostID, map[string]any{
		"action":  action,
		"reason":  "integration test of the local accounts module",
		"payload": map[string]any{"local_user": payload},
	}, 120*time.Second)
}

// TestLocalAccountLifecycle checks the local accounts module from creation to
// revoking access.
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

	// The state must be visible right after the operation, without waiting for
	// the next inventory report: the agent reads the account after the change.
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
	// An account created by the panel has no password, but is not locked: the SSH
	// key gives access.
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

	// An empty key list takes the last key of an account that has no password, so
	// it cuts the account off entirely - and the host refuses it unless the order
	// says that is the intention.
	refused, attempts := accountOperation(h, host.ID, "localuser.sshkeys.set", map[string]any{
		"name": name, "ssh_keys": []string{},
	})
	if refused.State == "succeeded" {
		t.Fatal("the last key of an account with no password was taken without consent")
	}
	if len(attempts) == 0 || attempts[len(attempts)-1].ErrorCode != "last_key_lockout" {
		t.Fatalf("refusal = %s, want last_key_lockout", lastMessage(attempts))
	}

	// With the consent it is a deliberate revocation of access.
	revocation, _ := accountOperation(h, host.ID, "localuser.sshkeys.set", map[string]any{
		"name": name, "ssh_keys": []string{}, "allow_lockout": true,
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
			// root has a refusal of its own: it is not merely a service account, it is
			// the one the panel never changes, and the operator is to read which of the
			// two rules stopped them.
			want := "system_account"
			if name == "root" {
				want = "protected_account"
			}
			if len(attempts) > 0 && attempts[len(attempts)-1].ErrorCode != want {
				t.Errorf("error code = %q, expected %s", attempts[len(attempts)-1].ErrorCode, want)
			}
		})
	}

	// System accounts are outside the default view, but must be reachable with an
	// explicit filter: sometimes one has to confirm that a service account
	// exists.
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
// material even by an operator's mistake.
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

const accountsReason = "integration test of the local accounts module"

// TestAccountGroupsExpiryAndDeletion checks the operations that change what an
// existing account may do and when it stops: the group list, the expiry date
// and the deletion.
func TestAccountGroupsExpiryAndDeletion(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	name := fmt.Sprintf("test%d", time.Now().UnixNano()%100000)

	t.Cleanup(func() {
		// The deletion at the end of the test takes the account away; the
		// lock is for the case the test stopped before it got there.
		if account(h, host.ID, name) != nil {
			accountOperation(h, host.ID, "localuser.lock", map[string]any{"name": name})
		}
	})

	// An account with no key and no password could not be logged into, and the
	// panel refuses to create one without being told that is the intention.
	created, _ := accountOperation(h, host.ID, "localuser.create", map[string]any{
		"name": name, "gecos": "Groups and expiry test", "shell": "/bin/bash",
		"create_home": true, "inactive": true,
	})
	if created.State != "succeeded" {
		t.Fatalf("creating the account ended in state %s", created.State)
	}

	// The group list is complete: what is on it is granted, the rest is
	// taken away. "users" exists on every Debian host.
	groups, attempts := accountOperation(h, host.ID, "localuser.groups.set", map[string]any{
		"name": name, "groups": []string{"users"},
	})
	if groups.State != "succeeded" {
		t.Fatalf("setting the groups ended in state %s: %s", groups.State, lastMessage(attempts))
	}
	if state := account(h, host.ID, name); state == nil || !containsString(state.Groups, "users") {
		t.Errorf("the account is not in the users group after the operation: %+v", state)
	}

	// An expiry date is access with a date attached; the panel shows the
	// date the host holds, not the one it sent.
	expiry, attempts := accountOperation(h, host.ID, "localuser.expiry.set", map[string]any{
		"name": name, "expires_at": "2031-06-30",
	})
	if expiry.State != "succeeded" {
		t.Fatalf("setting the expiry ended in state %s: %s", expiry.State, lastMessage(attempts))
	}
	if state := account(h, host.ID, name); state == nil || state.ExpiresAt != "2031-06-30" {
		t.Errorf("expires_at = %q after setting it, expected 2031-06-30", expiresOf(state))
	}

	// Clearing the expiry is a deliberate change sent as an empty date.
	cleared, attempts := accountOperation(h, host.ID, "localuser.expiry.set", map[string]any{
		"name": name, "expires_at": "",
	})
	if cleared.State != "succeeded" {
		t.Fatalf("clearing the expiry ended in state %s: %s", cleared.State, lastMessage(attempts))
	}
	if state := account(h, host.ID, name); state == nil || state.ExpiresAt != "" {
		t.Errorf("expires_at = %q after clearing it, expected none", expiresOf(state))
	}

	// A malformed date does not reach the host.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action":  "localuser.expiry.set",
		"payload": map[string]any{"local_user": map[string]any{"name": name, "expires_at": "tomorrow"}},
	}, nil, http.StatusBadRequest)

	// Deletion is destructive: the operator types the account name, gives a
	// reason and two people approve.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "localuser.delete", "reason": accountsReason,
		"payload": map[string]any{"local_user": map[string]any{"name": name, "remove_home": true}},
	}, nil, http.StatusBadRequest)
	// The hostname is not the target of this operation; the account is.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "localuser.delete", "reason": accountsReason,
		"target_confirmation": host.Hostname,
		"payload":             map[string]any{"local_user": map[string]any{"name": name, "remove_home": true}},
	}, nil, http.StatusBadRequest)

	deletion := deleteAccount(t, h, host, name, true)
	if deletion.State != "succeeded" {
		t.Fatalf("the deletion ended in state %s: %s", deletion.State, lastMessage(h.attempts(deletion.ID)))
	}
	if state := account(h, host.ID, name); state != nil {
		t.Errorf("the deleted account is still shown: %+v", state)
	}
}

// TestSystemAccountDeletionIsRefused checks that the host, which sees the
// identifiers, refuses to delete a service account - and says so with the code
// the panel shows.
func TestSystemAccountDeletionIsRefused(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	job := deleteAccount(t, h, host, "daemon", false)
	if job.State == "succeeded" {
		t.Fatal("deleting the system account daemon succeeded")
	}
	if job.ResultErrorCode != "system_account" {
		t.Errorf("error code = %q, expected system_account (%s)", job.ResultErrorCode, lastMessage(h.attempts(job.ID)))
	}
	if state := account(h, host.ID, "daemon"); state != nil && state.Source != "system" {
		t.Errorf("daemon is shown as %s after the refusal", state.Source)
	}
}

// deleteAccount orders a deletion with the typed account name and collects
// the two approvals a destructive operation needs.
func deleteAccount(t *testing.T, h *harness, host hostView, name string, removeHome bool) jobView {
	t.Helper()
	job := h.createOperation(host.ID, map[string]any{
		"action": "localuser.delete", "reason": accountsReason,
		"target_confirmation": name,
		"payload":             map[string]any{"local_user": map[string]any{"name": name, "remove_home": removeHome}},
	})
	if job.RequiredApprovals < 2 {
		t.Errorf("deleting an account requires %d approvals, expected two", job.RequiredApprovals)
	}
	job = h.approve(job.ID, job.PayloadHash)
	if job.CollectedApprovals < job.RequiredApprovals {
		second := h.withToken(h.createPrincipal(uniqueSubject("approver-accounts"),
			[]map[string]string{
				{"role": "approver", "site": host.Site, "environment": host.Environment},
			}))
		second.approve(job.ID, job.PayloadHash)
	}
	return h.awaitTerminal(job.ID, 2*time.Minute)
}

func containsString(list []string, wanted string) bool {
	for _, item := range list {
		if item == wanted {
			return true
		}
	}
	return false
}

func expiresOf(state *accountView) string {
	if state == nil {
		return "<no account>"
	}
	return state.ExpiresAt
}
