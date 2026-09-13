package security

import "testing"

func TestRunningModeAndConfigurationAreTwoFields(t *testing.T) {
	if mode := ParseEnforceMode("1\n"); mode != ModeEnforcing {
		t.Fatalf("mode = %q", mode)
	}
	if mode := ParseEnforceMode("0"); mode != ModePermissive {
		t.Fatalf("mode = %q", mode)
	}
	// A file that does not exist does not mean permissive mode.
	if mode := ParseEnforceMode(""); mode != "" {
		t.Fatalf("an empty read became the mode %q", mode)
	}

	mode, policy := ParseSELinuxConfiguration("# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n")
	if mode != ModeEnforcing || policy != "targeted" {
		t.Fatalf("configuration = %q/%q", mode, policy)
	}
}

// A profile in complain mode does not protect, it only records - counting
// it together with the enforced ones would turn no protection into
// protection.
func TestAppArmorProfilesAreCountedSeparately(t *testing.T) {
	enforcing, complain := ParseAppArmorProfiles(
		"docker-default (enforce)\nlibreoffice (complain)\nwike (unconfined)\nfoo (enforce)\n")
	if enforcing != 2 || complain != 1 {
		t.Fatalf("enforcing = %d, complain = %d", enforcing, complain)
	}

	// A host with only complain-mode profiles is not protected.
	zero, one := 0, 1
	protected := Mandatory{System: SystemAppArmor, ProfilesEnforcing: &zero, ProfilesComplain: &one}
	if protected.Protects() {
		t.Error("complain-mode profiles alone treated as protection")
	}
	if !(Mandatory{System: SystemAppArmor, ProfilesEnforcing: &one}).Protects() {
		t.Error("an enforced profile not treated as protection")
	}
	if !(Mandatory{System: SystemSELinux, Mode: ModeEnforcing}).Protects() {
		t.Error("SELinux in enforcing mode not treated as protection")
	}
	if (Mandatory{System: SystemSELinux, Mode: ModePermissive}).Protects() {
		t.Error("SELinux in permissive mode treated as protection")
	}
}

func TestListenersClassifySocketReach(t *testing.T) {
	output := `udp   UNCONN 0 0    127.0.0.53%lo:53    0.0.0.0:* users:(("systemd-resolve",pid=560,fd=16))
tcp   LISTEN 0 128        0.0.0.0:22    0.0.0.0:* users:(("sshd",pid=1200,fd=3))
tcp   LISTEN 0 128           [::]:22       [::]:* users:(("sshd",pid=1200,fd=4))
udp   UNCONN 0 0        127.0.0.1:323    0.0.0.0:*
raw   UNCONN 0 0          0.0.0.0:1      0.0.0.0:*
`
	sockets := ParseListeners(output)
	if len(sockets) != 4 {
		t.Fatalf("sockets = %d: %+v", len(sockets), sockets)
	}
	if sockets[0].Reach != ReachLoopback {
		t.Errorf("a loopback socket has reach %q", sockets[0].Reach)
	}
	if sockets[1].Port != 22 || sockets[1].Process != "sshd" || sockets[1].PID != 1200 {
		t.Errorf("sshd socket = %+v", sockets[1])
	}
	// Listening on all interfaces is a different situation than listening
	// on one host address - and neither means "visible from the internet".
	if sockets[1].Reach != ReachAllInterfaces || sockets[2].Reach != ReachAllInterfaces {
		t.Errorf("reaches = %q, %q", sockets[1].Reach, sockets[2].Reach)
	}
	if Reach("192.168.56.30") != ReachHostNetwork {
		t.Errorf("a host address classified as %q", Reach("192.168.56.30"))
	}
	if Reach("203.0.113.7") != ReachHostNetwork {
		t.Error("a public address is not by itself a different class than a private one")
	}
	// An IPv6 address contains colons itself: the port is taken after the
	// last one.
	if sockets[2].Address != "::" || sockets[2].Port != 22 {
		t.Errorf("IPv6 socket = %+v", sockets[2])
	}
	snapshot := Snapshot{Listening: sockets}
	if len(snapshot.BeyondLoopback()) != 2 {
		t.Errorf("beyond loopback = %d", len(snapshot.BeyondLoopback()))
	}
	if counts := snapshot.ByReach(); counts[ReachAllInterfaces] != 2 || counts[ReachLoopback] != 2 {
		t.Errorf("split by reach = %v", counts)
	}
}

// Rules written in files and rules loaded into the kernel are two
// questions.
func TestRulesFromFileDoNotCountComments(t *testing.T) {
	content := "# panel rules\n\n-D\n-w /etc/passwd -p wa -k identity\n" +
		"-a always,exit -F arch=b64 -S execve\n"
	if rules := ParseRulesFromFile(content); rules != 2 {
		t.Fatalf("rules from file = %d", rules)
	}
}

// A fact not asked for and a fact not read are two different answers.
func TestSupplementClosesGapsOrLeavesReason(t *testing.T) {
	two := 2
	snapshot := Snapshot{
		MAC:       Mandatory{System: SystemAppArmor, Mode: ModeEnforcing},
		Audit:     Audit{Present: true},
		Listening: []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Reach: ReachAllInterfaces}},
		Missing: map[string]string{
			FactAppArmorProfiles: "the AppArmor profiles live in securityfs",
			FactSocketOwners:     "only root sees the socket owners",
			FactAuditRules:       "only root reads the audit rules",
		},
	}

	supplemented := snapshot.Supplemented(Supplement{
		ProfilesEnforcing: &two,
		SocketOwners: map[string]Owner{
			SocketKey("tcp", "0.0.0.0", 22): {Process: "sshd", PID: 1200},
		},
		Errors: map[string]string{FactAuditRules: "auditctl: permission denied"},
	})

	if supplemented.MAC.ProfilesEnforcing == nil || *supplemented.MAC.ProfilesEnforcing != 2 {
		t.Errorf("profiles = %v", supplemented.MAC.ProfilesEnforcing)
	}
	if !supplemented.OwnersKnown || supplemented.Listening[0].Process != "sshd" {
		t.Errorf("owners = %+v", supplemented.Listening[0])
	}
	// A fact the helper did not read stays missing together with the
	// reason.
	if supplemented.Missing[FactAuditRules] == "" {
		t.Error("a failed rules read vanished from the missing list")
	}
	if _, stillMissing := supplemented.Missing[FactAppArmorProfiles]; stillMissing {
		t.Error("a fact that was read stayed on the missing list")
	}
}

func TestRulesAndAuxiliaryStates(t *testing.T) {
	if rules := ParseRules("No rules\n"); rules != 0 {
		t.Fatalf("rules = %d", rules)
	}
	if rules := ParseRules("-a never,task\n-w /etc/passwd -p wa\n"); rules != 2 {
		t.Fatalf("rules = %d", rules)
	}
	if mode := ParseLockdown("[none] integrity confidentiality\n"); mode != "none" {
		t.Fatalf("lockdown = %q", mode)
	}
	if state := ParseSecureBoot([]byte{6, 0, 0, 0, 1}); state == nil || !*state {
		t.Fatalf("secure boot = %v", state)
	}
	// A variable shorter than the header says nothing; no false is
	// invented.
	if state := ParseSecureBoot([]byte{6, 0, 0, 0}); state != nil {
		t.Fatalf("an incomplete variable became %v", *state)
	}
}

// The panel switches between enforcing and permissive; it does not set
// disabled, because coming back requires relabelling the filesystem and a
// reboot.
func TestPanelDoesNotDisableSELinux(t *testing.T) {
	if err := ValidateMode(ModeEnforcing); err != nil {
		t.Errorf("enforcing rejected: %v", err)
	}
	if err := ValidateMode(ModePermissive); err != nil {
		t.Errorf("permissive rejected: %v", err)
	}
	if err := ValidateMode(ModeDisabled); err == nil {
		t.Error("the panel accepted disabling SELinux")
	}
	if err := ValidateMode("whatever"); err == nil {
		t.Error("an unknown mode passed validation")
	}
}
