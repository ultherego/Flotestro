package freeipa

import "testing"

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
		"permission_add", "role_add_member", "hbacrule_add", "sudorule_add"} {
		if allowedMethod(method) {
			t.Errorf("the command %s should not be available through the adapter", method)
		}
	}
}
