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
// configuration would freeze on the host the defaults of the day of the write.
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

// In sshd the first value wins, and included files are in alphabetical order:
// an earlier administrator file shadows ours and the change looks done
// although it changes nothing.
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

// The panel's file is replaced whole, so a directive the order leaves out is
// removed from the host - not kept. The guard may not take the value it has
// now as the value it will have, because that value is the one the directive
// being removed put there (audit of 6c38561, HA-005).
func TestADirectiveTheOrderLeavesOutIsRemovedAndNotKept(t *testing.T) {
	state := ParseEffective(effectiveOutput)
	// A host the panel has already configured: keys only, no passwords, no
	// keyboard-interactive. The effective state reports what that file put there.
	state.Managed, _ = ComposeDropIn(Settings{
		PasswordAuthentication: "no", PubkeyAuthentication: "yes", KbdInteractive: "no",
	})
	state.ManagedPresent = true
	state.PasswordAuthentication, state.PubkeyAuthentication, state.KbdInteractive = "no", "yes", "no"

	// The operator now orders a port and nothing else. Keys were a way in only
	// because the panel's file said so, and that line goes with the rewrite:
	// what the host will apply afterwards is not the panel's to know.
	if !CutsOffAllMethods(Settings{Port: "2222"}, state) {
		t.Error("a change that removes every directive the panel set read as leaving a way in")
	}
	// Said in the order, it is a way in again.
	if CutsOffAllMethods(Settings{Port: "2222", PubkeyAuthentication: "yes"}, state) {
		t.Error("a method the order itself asks for read as cut off")
	}
	// A method the panel never set is the host's own and stays: here GSSAPI,
	// which the panel does not write.
	withDomain := state
	withDomain.GSSAPIAuthentication = "yes"
	if CutsOffAllMethods(Settings{Port: "2222"}, withDomain) {
		t.Error("a method outside the panel's file read as removed by rewriting that file")
	}

	// And the operator is told, in the plan, which lines the order takes away.
	plan := Compute(state, Settings{Port: "2222", PubkeyAuthentication: "yes"}, false)
	if plan.Refusal != "" {
		t.Fatalf("refused: %s", plan.Refusal)
	}
	removed := strings.Join(plan.Changes, "; ")
	for _, directive := range []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no"} {
		if !strings.Contains(removed, directive) {
			t.Errorf("the plan does not say that %q is removed: %s", directive, removed)
		}
	}
	if strings.Contains(removed, "PubkeyAuthentication yes will be removed") {
		t.Errorf("a directive the order keeps named as removed: %s", removed)
	}
}
