package freeipa

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateSSHPublicKeyRejectsAPrivateKey(t *testing.T) {
	// A private key must never reach the directory or the logs.
	private := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----"
	if err := validateSSHPublicKey(private); err == nil {
		t.Fatal("a private key was accepted")
	}
}

func TestValidateSSHPublicKeyRejectsRubbish(t *testing.T) {
	for _, key := range []string{"", "   ", "abcdef", "ssh-ed25519", "unknown-type AAAA"} {
		if err := validateSSHPublicKey(key); err == nil {
			t.Errorf("an invalid key %q was accepted", key)
		}
	}
}

func TestValidateSSHPublicKeyAcceptsValidKeys(t *testing.T) {
	valid := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@host",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC no-comment",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=",
	}
	for _, key := range valid {
		if err := validateSSHPublicKey(key); err != nil {
			t.Errorf("a valid key %q was rejected: %v", key, err)
		}
	}
}

func TestUserSpecValidate(t *testing.T) {
	valid := UserSpec{UID: "jsmith", LastName: "Smith"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid description was rejected: %v", err)
	}

	cases := map[string]UserSpec{
		"no surname":                   {UID: "jsmith"},
		"a capital letter in the name": {UID: "JSmith", LastName: "Smith"},
		"a name with a space":          {UID: "jane smith", LastName: "Smith"},
		"a name with a path":           {UID: "../root", LastName: "Smith"},
		"a bad group name":             {UID: "jsmith", LastName: "Smith", Groups: []string{"group; rm"}},
		"a private key":                {UID: "jsmith", LastName: "Smith", SSHKeys: []string{"-----BEGIN OPENSSH PRIVATE KEY-----"}},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if err := spec.Validate(); err == nil {
				t.Fatal("an invalid description passed validation")
			}
		})
	}
}

func TestWritingHasAClosedListOfCommands(t *testing.T) {
	// The adapter exposes no commands that delete accounts or change the
	// configuration of the directory itself.
	for _, method := range []string{"user_add", "user_mod", "user_disable",
		"user_enable", "group_add_member", "group_remove_member"} {
		if !allowedMethod(method) {
			t.Errorf("the write command %s should be allowed", method)
		}
	}
	for _, method := range []string{"user_del", "group_del", "config_mod",
		"permission_add", "role_add_member", "hbacsvc_add", "sudocmd_add"} {
		if allowedMethod(method) {
			t.Errorf("the command %s should not be available through the adapter", method)
		}
	}
}

// The directory answers a group change with a list of failures rather than an
// error, and the code used to fold that list into the text of an error - losing
// which accounts it did move - and to leave the cache alone, because the
// invalidation stood after that exit. The panel then read the batch as
// unchanged, ended nobody's session, and an account removed from a group went
// on working with the scope it had (audit of 6c38561, ID-02).
func TestAGroupChangeTheDirectoryTookInPartNamesWhatItMoved(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["group_remove_member"] = func(rpcCall) (any, *rpcError) {
		return map[string]any{
			"result": map[string]any{},
			"failed": map[string]any{
				"member": map[string]any{
					"user": []any{[]any{"carol", "This entry is not a member"}},
				},
			},
		}, nil
	}
	// Something in the cache, so the invalidation is observable.
	client.cache["user_find"] = cacheEntry{expiresAt: time.Now().Add(time.Minute)}

	err := client.RemoveGroupMembers(context.Background(), "developers",
		[]string{"alice", "bob", "carol"})
	var partial *PartialChange
	if !errors.As(err, &partial) {
		t.Fatalf("err = %v, expected a partial change", err)
	}
	if got := strings.Join(partial.Applied, ","); got != "alice,bob" {
		t.Errorf("the accounts that moved came back as %q", got)
	}
	if reason := partial.Refused["carol"]; reason != "This entry is not a member" {
		t.Errorf("the reason the directory gave came back as %q", reason)
	}
	// The error says enough for an operator without the names being parsed
	// out of it again.
	if !strings.Contains(err.Error(), "carol") || !strings.Contains(err.Error(), "developers") {
		t.Errorf("the error does not say what happened: %v", err)
	}
	// And the cache is stale whatever the verdict: accounts moved.
	if len(client.cache) != 0 {
		t.Errorf("the cache survived a change the directory took in part: %v", client.cache)
	}

	// A batch the directory took whole is not a partial change.
	fake.answers["group_add_member"] = func(rpcCall) (any, *rpcError) {
		return map[string]any{"result": map[string]any{}}, nil
	}
	if err := client.AddGroupMembers(context.Background(), "developers", []string{"alice"}); err != nil {
		t.Errorf("a change the directory took whole came back as %v", err)
	}
}

// An outcome nobody confirmed was folded into "nothing happened": a failure
// list in an unexpected shape was skipped entry by entry and the batch returned
// success, an answer that did not parse returned success as well, and a call
// whose answer was lost returned a plain error, so no session of the accounts
// that may have moved was ended.
func TestAMembershipChangeOfUnknownOutcomeSaysSoAndNamesTheAccounts(t *testing.T) {
	asked := []string{"alice", "bob"}
	cases := map[string]func(rpcCall) (any, *rpcError){
		"a failure list that names no account": func(rpcCall) (any, *rpcError) {
			return map[string]any{
				"result": map[string]any{},
				"failed": map[string]any{
					"member": map[string]any{"user": []any{map[string]any{"code": 4202}}},
				},
			}, nil
		},
		"an answer in a shape the adapter does not read": func(rpcCall) (any, *rpcError) {
			return []any{"developers"}, nil
		},
		"an answer that was lost": func(rpcCall) (any, *rpcError) {
			return nil, &rpcError{Code: 4203, Name: "ExecutionError", Message: "the server failed"}
		},
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			fake, client := newFakeDirectory(t)
			fake.answers["group_add_member"] = answer
			client.cache["user_find"] = cacheEntry{expiresAt: time.Now().Add(time.Minute)}

			err := client.AddGroupMembers(context.Background(), "developers", asked)
			var uncertain *UncertainChange
			if !errors.As(err, &uncertain) {
				t.Fatalf("err = %v, expected an uncertain outcome", err)
			}
			if strings.Join(uncertain.Users, ",") != strings.Join(asked, ",") {
				t.Errorf("the accounts of the batch came back as %v", uncertain.Users)
			}
			if !strings.Contains(err.Error(), "not known") || !strings.Contains(err.Error(), "developers") {
				t.Errorf("the error does not say the outcome is unknown: %v", err)
			}
			// The membership may have changed, so the cache cannot stand.
			if len(client.cache) != 0 {
				t.Errorf("the cache survived a change of unknown outcome: %v", client.cache)
			}
		})
	}

	// A command the directory read and turned down is a different thing: the
	// membership stands as it stood, and the error says so plainly.
	fake, client := newFakeDirectory(t)
	fake.answers["group_add_member"] = func(rpcCall) (any, *rpcError) {
		return nil, &rpcError{Code: 4001, Name: "NotFound", Message: "developers: group not found"}
	}
	err := client.AddGroupMembers(context.Background(), "developers", asked)
	var uncertain *UncertainChange
	if errors.As(err, &uncertain) {
		t.Fatalf("a refusal of the whole command became an uncertain outcome: %v", err)
	}
	var refusal *DirectoryError
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, expected the directory's own refusal", err)
	}
}
