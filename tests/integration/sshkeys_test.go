//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

/*
The SSH keys of a local account, edited one key at a time.

Chapter 3 of the roadmap and chapter 14.1 of the security remediation name
the same defect: the panel had one key operation, "write this list", so an
operator who opened the editor on a stale picture replaced what somebody
else had added, and a revocation that went one key too far left an account
nobody could enter. The operations below are the answer - an add that
appends, a removal by fingerprint, a replace bound to the list the operator
saw - and this test holds the whole path, from the panel's order to the
file on the host, to what they promise.
*/

// The keys of this test. They are public material with no private half
// anywhere: nothing here opens a door, and the cleanup deletes the account
// they were put on regardless.
const (
	sshkeysFirst  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 first@flotestro"
	sshkeysSecond = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdequH1cbHejJuOve5gez7fGXR0S6KLEza3hAMskJHR second@flotestro"
	sshkeysThird  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOE/z7iA9QRxCu6U5hZaErGicDDGds23mG+ML13cevit third@flotestro"
)

const sshkeysReason = "integration test of the SSH key operations"

// keyView is one key as the panel reports it: the fingerprint identifies
// it, the source says which file on the host it came from.
type keyView struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Comment     string `json:"comment"`
	Source      string `json:"source"`
}

// accountKeys reads the keys of one account out of the panel's inventory -
// what an operator sees on the account's screen, not what the order said.
func accountKeys(h *harness, hostID, name string) []keyView {
	h.t.Helper()
	var result struct {
		Accounts []struct {
			Name    string    `json:"name"`
			SSHKeys []keyView `json:"ssh_keys"`
		} `json:"accounts"`
	}
	h.get("/api/v1/hosts/"+hostID+"/local-accounts", &result)
	for _, entry := range result.Accounts {
		if entry.Name == name {
			return entry.SSHKeys
		}
	}
	h.t.Fatalf("the account %s is not in the panel's list", name)
	return nil
}

func keyFingerprints(keys []keyView) []string {
	list := make([]string, 0, len(keys))
	for _, key := range keys {
		list = append(list, key.Fingerprint)
	}
	return list
}

func keyByComment(keys []keyView, comment string) *keyView {
	for _, key := range keys {
		if key.Comment == comment {
			return &key
		}
	}
	return nil
}

// keysOperation orders one key operation, with the reason a critical
// change asks for, and waits for the host's answer.
func keysOperation(h *harness, hostID, action, reason string, payload map[string]any) (jobView, []attemptView) {
	h.t.Helper()
	body := map[string]any{
		"action":  action,
		"payload": map[string]any{"local_user": payload},
	}
	if reason != "" {
		body["reason"] = reason
	}
	return h.runOperation(hostID, body, 120*time.Second)
}

// refusalCode is the code the host refused with: the attempt carries it,
// and the job repeats it once the job is done.
func refusalCode(job jobView, attempts []attemptView) string {
	if len(attempts) > 0 && attempts[len(attempts)-1].ErrorCode != "" {
		return attempts[len(attempts)-1].ErrorCode
	}
	return job.ResultErrorCode
}

// TestSSHKeysEditedOneAtATime walks the key operations of one account on a
// real host: an add that leaves the key already there untouched, a removal
// by fingerprint, the refusal to take the last key of an account that has
// no other way in, and the refusal of a replace composed on a list the
// account no longer has.
func TestSSHKeysEditedOneAtATime(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	name := fmt.Sprintf("keys%d", time.Now().UnixNano()%100000)

	created, attempts := accountOperation(h, host.ID, "localuser.create", map[string]any{
		"name": name, "gecos": "SSH key test", "shell": "/bin/bash",
		"ssh_keys": []string{sshkeysFirst}, "create_home": true,
	})
	if created.State != "succeeded" {
		t.Fatalf("creating the account ended in state %s: %s", created.State, lastMessage(attempts))
	}
	t.Cleanup(func() {
		// The account must not outlive the test: one left behind with a key
		// is a real way into the host.
		if account(h, host.ID, name) != nil {
			deleteAccount(t, h, host, name, true)
		}
	})

	first := accountKeys(h, host.ID, name)
	if len(first) != 1 {
		t.Fatalf("the created account has %d keys, expected 1", len(first))
	}
	if first[0].Comment != "first@flotestro" {
		t.Errorf("the comment of the key is %q, expected first@flotestro", first[0].Comment)
	}
	// The key of an account created by the panel goes into the user's own
	// file; the panel's managed file is a choice of the order, not the
	// default.
	if first[0].Source != "authorized_keys" {
		t.Errorf("the key source is %q, expected authorized_keys", first[0].Source)
	}

	// An add appends. The key that was there keeps its fingerprint, its
	// type and its comment: an add that rewrote the line would be the very
	// defect this operation exists to remove.
	added, attempts := keysOperation(h, host.ID, "localuser.sshkeys.add", "", map[string]any{
		"name": name,
		"keys": []map[string]any{{"public_key": sshkeysSecond}},
	})
	if added.State != "succeeded" {
		t.Fatalf("adding a key ended in state %s: %s", added.State, lastMessage(attempts))
	}
	both := accountKeys(h, host.ID, name)
	if len(both) != 2 {
		t.Fatalf("the account has %d keys after the add, expected 2: %v", len(both), keyFingerprints(both))
	}
	kept := keyByComment(both, "first@flotestro")
	if kept == nil {
		t.Fatalf("the key that was there is gone after the add: %v", both)
	}
	if kept.Fingerprint != first[0].Fingerprint || kept.Type != first[0].Type {
		t.Errorf("the key that was there changed: %+v, was %+v", *kept, first[0])
	}
	second := keyByComment(both, "second@flotestro")
	if second == nil {
		t.Fatalf("the added key is not in the account: %v", both)
	}

	// The same add once more changes nothing: a key already there, by
	// fingerprint, is not added twice.
	repeated, attempts := keysOperation(h, host.ID, "localuser.sshkeys.add", "", map[string]any{
		"name": name,
		"keys": []map[string]any{{"public_key": sshkeysSecond}},
	})
	if repeated.State != "succeeded" {
		t.Fatalf("repeating the add ended in state %s: %s", repeated.State, lastMessage(attempts))
	}
	if again := accountKeys(h, host.ID, name); len(again) != 2 {
		t.Errorf("the repeated add left %d keys, expected 2: %v", len(again), keyFingerprints(again))
	}

	// A removal names one fingerprint and takes that key and nothing else.
	removed, attempts := keysOperation(h, host.ID, "localuser.sshkeys.remove", "", map[string]any{
		"name": name, "fingerprints": []string{second.Fingerprint},
	})
	if removed.State != "succeeded" {
		t.Fatalf("removing a key ended in state %s: %s", removed.State, lastMessage(attempts))
	}
	left := accountKeys(h, host.ID, name)
	if len(left) != 1 || left[0].Fingerprint != first[0].Fingerprint {
		t.Fatalf("the removal left %v, expected the first key alone", keyFingerprints(left))
	}

	// The last key of an account with no password login is the last way in.
	// The host refuses to take it away unless the order says the lockout is
	// what the operator means.
	lockout, attempts := keysOperation(h, host.ID, "localuser.sshkeys.remove", "", map[string]any{
		"name": name, "fingerprints": []string{first[0].Fingerprint},
	})
	if lockout.State == "succeeded" {
		t.Fatal("the removal of the last key of a password-less account succeeded")
	}
	if code := refusalCode(lockout, attempts); code != "last_key_lockout" {
		t.Errorf("error code = %q, expected last_key_lockout (%s)", code, lastMessage(attempts))
	}
	if still := accountKeys(h, host.ID, name); len(still) != 1 {
		t.Errorf("the refused removal changed the keys: %v", keyFingerprints(still))
	}

	// A replace is bound to the list the operator saw. The list below names
	// the key that has just been removed, so it is the picture of a moment
	// that has passed: the host refuses it rather than write over what
	// nobody reviewed.
	stale, attempts := keysOperation(h, host.ID, "localuser.sshkeys.replace_all", sshkeysReason, map[string]any{
		"name":                  name,
		"ssh_keys":              []string{sshkeysThird},
		"expected_fingerprints": []string{second.Fingerprint},
	})
	if stale.State == "succeeded" {
		t.Fatal("a replace composed on a stale key list succeeded")
	}
	if code := refusalCode(stale, attempts); code != "stale_plan" {
		t.Errorf("error code = %q, expected stale_plan (%s)", code, lastMessage(attempts))
	}
	if message := lastMessage(attempts); !strings.Contains(message, first[0].Fingerprint) {
		t.Errorf("the refusal does not name the keys the host has now: %s", message)
	}
	if still := accountKeys(h, host.ID, name); len(still) != 1 || still[0].Fingerprint != first[0].Fingerprint {
		t.Errorf("the refused replace changed the keys: %v", keyFingerprints(still))
	}

	// The same replace with the list the account really has goes through.
	replace, attempts := keysOperation(h, host.ID, "localuser.sshkeys.replace_all", sshkeysReason, map[string]any{
		"name":                  name,
		"ssh_keys":              []string{sshkeysThird},
		"expected_fingerprints": []string{first[0].Fingerprint},
	})
	if replace.State != "succeeded" {
		t.Fatalf("the replace ended in state %s: %s", replace.State, lastMessage(attempts))
	}
	after := accountKeys(h, host.ID, name)
	if len(after) != 1 || after[0].Comment != "third@flotestro" {
		t.Errorf("after the replace the account has %v, expected the third key alone", after)
	}
}

// TestKeyRemovalOfAMissingKeyIsRefused checks that a removal of a key the
// account does not carry is a refusal rather than a quiet success: the
// operator may be looking at another host's list, and the key they meant
// is still in place there.
func TestKeyRemovalOfAMissingKeyIsRefused(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	name := fmt.Sprintf("keys%d", time.Now().UnixNano()%100000)

	created, attempts := accountOperation(h, host.ID, "localuser.create", map[string]any{
		"name": name, "shell": "/bin/bash", "ssh_keys": []string{sshkeysFirst}, "create_home": true,
	})
	if created.State != "succeeded" {
		t.Fatalf("creating the account ended in state %s: %s", created.State, lastMessage(attempts))
	}
	t.Cleanup(func() {
		if account(h, host.ID, name) != nil {
			deleteAccount(t, h, host, name, true)
		}
	})

	// A well-formed fingerprint of a key nobody put on this account.
	const absent = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	job, attempts := keysOperation(h, host.ID, "localuser.sshkeys.remove", "", map[string]any{
		"name": name, "fingerprints": []string{absent},
	})
	if job.State == "succeeded" {
		t.Fatal("removing a key the account does not have succeeded")
	}
	if code := refusalCode(job, attempts); code != "key_not_found" {
		t.Errorf("error code = %q, expected key_not_found (%s)", code, lastMessage(attempts))
	}

	// The same removal with ignore_missing is the operator saying the key
	// may be gone already; then there is nothing to do and nothing fails.
	tolerated, attempts := keysOperation(h, host.ID, "localuser.sshkeys.remove", "", map[string]any{
		"name": name, "fingerprints": []string{absent}, "ignore_missing": true,
	})
	if tolerated.State != "succeeded" {
		t.Errorf("a removal that tolerates a missing key ended in state %s: %s",
			tolerated.State, lastMessage(attempts))
	}
	if keys := accountKeys(h, host.ID, name); len(keys) != 1 {
		t.Errorf("the account has %d keys after the tolerated removal, expected 1", len(keys))
	}
}

// TestPrivilegedGroupNeedsItsOwnPermission checks the compound grant of
// chapter 14.1: putting an account into a group that is root by another
// name asks for accounts.privileged_groups on top of the permission of the
// operation itself, in the scope of the host. An operator may change the
// groups of an account; that alone does not let them hand out root.
func TestPrivilegedGroupNeedsItsOwnPermission(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	name := fmt.Sprintf("keys%d", time.Now().UnixNano()%100000)

	created, attempts := accountOperation(h, host.ID, "localuser.create", map[string]any{
		"name": name, "shell": "/bin/bash", "ssh_keys": []string{sshkeysFirst}, "create_home": true,
	})
	if created.State != "succeeded" {
		t.Fatalf("creating the account ended in state %s: %s", created.State, lastMessage(attempts))
	}
	t.Cleanup(func() {
		if account(h, host.ID, name) != nil {
			deleteAccount(t, h, host, name, true)
		}
	})

	// An operator of this host: they order operations, they change the
	// groups of an account, and they have no accounts.privileged_groups.
	operator := h.withToken(h.createPrincipal(uniqueSubject("operator-groups"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	}))

	var refusal struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	operator.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "localuser.groups.set", "reason": sshkeysReason,
		"payload": map[string]any{"local_user": map[string]any{
			"name": name, "groups": []string{"sudo"},
		}},
	}, &refusal, http.StatusForbidden)
	if refusal.Code != "payload_permission_missing" {
		t.Errorf("code = %q, expected payload_permission_missing", refusal.Code)
	}
	if !strings.Contains(refusal.Detail, "accounts.privileged_groups") {
		t.Errorf("the refusal does not name the permission that is missing: %q", refusal.Detail)
	}

	// The same operator creating an account straight into sudo is refused
	// as well. Creating accounts and granting root are two levels of trust,
	// and this identity has neither.
	operator.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "localuser.create", "reason": sshkeysReason,
		"payload": map[string]any{"local_user": map[string]any{
			"name": name + "x", "groups": []string{"sudo"},
			"ssh_keys": []string{sshkeysFirst}, "create_home": true,
		}},
	}, nil, http.StatusForbidden)

	// The refusal is about the group, not about the operation: the same
	// order with a group that is nobody's root passes the door.
	accepted := operator.createOperation(host.ID, map[string]any{
		"action":  "localuser.groups.set",
		"payload": map[string]any{"local_user": map[string]any{"name": name, "groups": []string{"users"}}},
	})
	operator.do(http.MethodPost, "/api/v1/jobs/"+accepted.ID+"/cancel",
		map[string]any{"reason": "end of the integration test"}, nil, http.StatusOK)

	// And the account did not land in sudo along the way.
	if state := account(h, host.ID, name); state == nil || containsString(state.Groups, "sudo") {
		t.Errorf("the account is in sudo after the refusals: %+v", state)
	}
}
