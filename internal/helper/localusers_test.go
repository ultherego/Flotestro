package helper

import (
	"os"
	"path/filepath"
	"testing"
)

// TestShadowSemantics guards the separation of a lock from a missing password.
// An account created by the panel has no password and logs in with an SSH key;
// showing it as locked would be false information about access being cut off.
func TestShadowSemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	content := "" +
		"ordinary:$y$j9T$salt$hash:20000:0:99999:7:::\n" +
		"locked:!$y$j9T$salt$hash:20000:0:99999:7:::\n" +
		"keyonly:*:20000:0:99999:7:::\n" +
		"locked_without_password:!:20000:0:99999:7:::\n" +
		"empty::20000:0:99999:7:::\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	states, err := parseShadow(path)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]shadowState{
		"ordinary":                {locked: false, passwordSet: true},
		"locked":                  {locked: true, passwordSet: true},
		"keyonly":                 {locked: false, passwordSet: false},
		"locked_without_password": {locked: true, passwordSet: false},
		"empty":                   {locked: false, passwordSet: false},
	}
	for name, expected := range cases {
		got, known := states[name]
		if !known {
			t.Errorf("%s: no entry", name)
			continue
		}
		if got != expected {
			t.Errorf("%s: read %+v, expected %+v", name, got, expected)
		}
	}

	if _, err := parseShadow(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("a missing file has to be an error, not an empty map of accounts without passwords")
	}
}

func TestPublicKeyValidation(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 john@workstation"
	if err := validatePublicKey(key); err != nil {
		t.Fatalf("a valid key was rejected: %v", err)
	}

	// A newline character would allow a second key to be appended to
	// authorized_keys.
	for name, value := range map[string]string{
		"a private key":     "-----BEGIN OPENSSH PRIVATE KEY-----",
		"a newline":         key + "\nssh-rsa AAAAB3Nz stranger@workstation",
		"a carriage return": key + "\rssh-rsa AAAAB3Nz stranger@workstation",
		"a retired type":    "ssh-dss AAAAB3NzaC1kc3M john@workstation",
		"without material":  "ssh-ed25519",
		"empty":             "   ",
	} {
		if err := validatePublicKey(value); err == nil {
			t.Errorf("%s: the key should have been rejected", name)
		}
	}
}

func TestLocalAccountName(t *testing.T) {
	for _, name := range []string{"smith", "_service", "john-doe", "machine$"} {
		if !localUserNamePattern.MatchString(name) {
			t.Errorf("the name %q should be allowed", name)
		}
	}
	// The name is inserted into system commands and into the path of the home
	// directory, so the restriction is a security boundary, not cosmetics.
	for _, name := range []string{"Smith", "../root", "john doe", "root;rm", "", "john/doe"} {
		if localUserNamePattern.MatchString(name) {
			t.Errorf("the name %q should not be allowed", name)
		}
	}
}
