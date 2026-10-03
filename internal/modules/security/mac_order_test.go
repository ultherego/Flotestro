package security

import (
	"os"
	"path/filepath"
	"testing"
)

// A leftover /etc/selinux/config used to answer for a host the kernel runs
// AppArmor on: the configuration branch stood before AppArmor was asked about,
// so the host reported "SELinux, disabled". The facts about AppArmor profiles
// are collected only when the system is AppArmor, so they never were - and the
// panel showed a protected host as having no mandatory access control.
//
// The comment at the top of MACState says the configuration file is not to be
// trusted about SELinux. It was trusted enough to hide the other mechanism.
func TestALeftoverSELinuxConfigurationDoesNotHideAppArmor(t *testing.T) {
	dir := t.TempDir()
	configuration := filepath.Join(dir, "selinux-config")
	apparmor := filepath.Join(dir, "apparmor-enabled")
	absent := filepath.Join(dir, "nothing-here")

	if err := os.WriteFile(configuration, []byte("SELINUX=enforcing\nSELINUXTYPE=targeted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apparmor, []byte("Y\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mac := macStateFrom(absent, absent, configuration, apparmor)
	if mac.System != SystemAppArmor {
		t.Fatalf("system = %q, want %q: the kernel runs AppArmor and the configuration of "+
			"the other mechanism answered for it", mac.System, SystemAppArmor)
	}
	if mac.Mode != ModeEnforcing {
		t.Errorf("mode = %q, want %q", mac.Mode, ModeEnforcing)
	}
}

// With SELinux in the kernel, SELinux is the answer whatever else is there:
// the filesystem is the fact, as the comment says.
func TestSELinuxInTheKernelAnswersForTheHost(t *testing.T) {
	dir := t.TempDir()
	selinux := filepath.Join(dir, "selinux")
	if err := os.MkdirAll(selinux, 0o755); err != nil {
		t.Fatal(err)
	}
	enforce := filepath.Join(selinux, "enforce")
	if err := os.WriteFile(enforce, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	apparmor := filepath.Join(dir, "apparmor-enabled")
	if err := os.WriteFile(apparmor, []byte("Y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mac := macStateFrom(selinux, enforce, filepath.Join(dir, "no-config"), apparmor)
	if mac.System != SystemSELinux {
		t.Errorf("system = %q, want %q", mac.System, SystemSELinux)
	}
}

// A configuration with no mechanism behind it is still the case that looks
// like protection, and it still has to be reported as what it is.
func TestAConfigurationWithNoMechanismIsReportedAsDisabled(t *testing.T) {
	dir := t.TempDir()
	configuration := filepath.Join(dir, "selinux-config")
	if err := os.WriteFile(configuration, []byte("SELINUX=enforcing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "nothing-here")
	mac := macStateFrom(absent, absent, configuration, absent)
	if mac.System != SystemSELinux || mac.Mode != ModeDisabled {
		t.Errorf("system = %q, mode = %q; want %q disabled", mac.System, mac.Mode, SystemSELinux)
	}
	if mac.Reason == "" {
		t.Error("nothing said why a configured mechanism is not protecting the host")
	}
}

// Neither mechanism means neither, and the snapshot says so rather than
// naming one of them.
func TestAHostWithNeitherMechanismNamesNeither(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "nothing-here")
	mac := macStateFrom(absent, absent, absent, absent)
	if mac.System != "" {
		t.Errorf("system = %q over a host with neither", mac.System)
	}
	if mac.Reason == "" {
		t.Error("nothing said that the host has neither")
	}
}
