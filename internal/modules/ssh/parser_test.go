package ssh

import (
	"strings"
	"testing"
)

// Output copied from a host of the test fleet.
const effectiveOutput = `port 22
addressfamily any
listenaddress [::]:22
listenaddress 0.0.0.0:22
usepam yes
maxauthtries 6
permitrootlogin no
pubkeyauthentication yes
passwordauthentication yes
kbdinteractiveauthentication no
gssapiauthentication no
allowgroups sudo flotestro`

func TestConfigurationIsReadFromServer(t *testing.T) {
	state := ParseEffective(effectiveOutput)

	if len(state.Ports) != 1 || state.Ports[0] != "22" {
		t.Errorf("ports = %v", state.Ports)
	}
	if len(state.ListenAddresses) != 2 {
		t.Errorf("listen addresses = %v", state.ListenAddresses)
	}
	// "prohibit-password" is neither yes nor no - that is why the value is
	// text, not a flag.
	if state.PermitRootLogin != "no" || state.PasswordAuthentication != "yes" {
		t.Errorf("state = %+v", state)
	}
	if state.MaxAuthTries != 6 {
		t.Errorf("maxauthtries = %d", state.MaxAuthTries)
	}
	if len(state.AllowGroups) != 2 || state.AllowGroups[1] != "flotestro" {
		t.Errorf("groups = %v", state.AllowGroups)
	}
}

func TestHostKeyFingerprintWithoutPrivateKey(t *testing.T) {
	key, ok := ParseFingerprint(
		"256 SHA256:qLkjgPdb7MHXjfjzjsoBE8UhRXoe353g82iwnYYNmS4 root@debian-13 (ED25519)",
		"/etc/ssh/ssh_host_ed25519_key.pub")
	if !ok {
		t.Fatal("fingerprint not recognised")
	}
	if key.Type != "ed25519" || key.Bits != 256 {
		t.Errorf("key = %+v", key)
	}
	if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q", key.Fingerprint)
	}
	if _, ok := ParseFingerprint("whatever", "/etc/ssh/x"); ok {
		t.Error("fingerprint recognised in garbage")
	}
}

// Only what the operator asked for is written: printing the whole
// configuration would freeze on the host the defaults of the day of the
// write.
func TestDropInContainsOnlyOrderedSettings(t *testing.T) {
	content, err := ComposeDropIn(Settings{
		PermitRootLogin: "prohibit-password",
		MaxAuthTries:    "3",
		AllowGroups:     []string{"sudo", "flotestro"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "PermitRootLogin prohibit-password") ||
		!strings.Contains(content, "AllowGroups sudo flotestro") {
		t.Errorf("content = %q", content)
	}
	if strings.Contains(content, "PasswordAuthentication") {
		t.Errorf("the file carries a setting nobody asked for: %q", content)
	}
	if !strings.HasPrefix(content, FileHeader) {
		t.Errorf("file without header: %q", content)
	}
	if _, err := ComposeDropIn(Settings{}); err == nil {
		t.Error("accepted a change without any setting")
	}
}

func TestBadConfigurationIsRejected(t *testing.T) {
	cases := []Settings{
		{Port: "0"},
		{Port: "70000"},
		{PermitRootLogin: "maybe"},
		{PasswordAuthentication: "prohibit-password"},
		{MaxAuthTries: "0"},
		{AllowUsers: []string{"bad entry"}},
		{DenyUsers: []string{"a;reboot"}},
	}
	for _, settings := range cases {
		if err := Validate(settings); err == nil {
			t.Errorf("accepted %+v", settings)
		}
	}
	if err := Validate(Settings{PermitRootLogin: "prohibit-password",
		AllowUsers: []string{"ulther", "admin@10.0.0.1", "flot*"}}); err != nil {
		t.Errorf("rejected a valid configuration: %v", err)
	}
}

// A server nobody can log into by any method is not secured - it is
// unavailable.
func TestChangeCuttingOffAllMethodsIsRecognised(t *testing.T) {
	state := ParseEffective(effectiveOutput)

	if CutsOffAllMethods(Settings{PasswordAuthentication: "no"}, state) {
		t.Error("disabling passwords with working keys treated as a lockout")
	}
	if !CutsOffAllMethods(Settings{
		PasswordAuthentication: "no", PubkeyAuthentication: "no"}, state) {
		t.Error("disabling passwords and keys not recognised")
	}
	// A domain-joined host may rely on GSSAPI, so it counts too.
	withDomain := state
	withDomain.GSSAPIAuthentication = "yes"
	if CutsOffAllMethods(Settings{
		PasswordAuthentication: "no", PubkeyAuthentication: "no"}, withDomain) {
		t.Error("GSSAPI skipped as a working method")
	}
}

// In sshd the first value wins, and included files are in alphabetical
// order: an earlier administrator file shadows ours and the change looks
// done although it changes nothing.
func TestDivergenceBetweenOrderAndStateIsNamed(t *testing.T) {
	state := ParseEffective(effectiveOutput)

	divergent := DivergentSettings(Settings{
		PasswordAuthentication: "no", MaxAuthTries: "3"}, state)
	if len(divergent) != 2 {
		t.Fatalf("divergences = %v", divergent)
	}
	if !strings.Contains(divergent[0], "PasswordAuthentication") &&
		!strings.Contains(divergent[1], "PasswordAuthentication") {
		t.Errorf("divergences = %v", divergent)
	}
	if len(DivergentSettings(Settings{PermitRootLogin: "no"}, state)) != 0 {
		t.Error("a matching setting treated as divergent")
	}
}
