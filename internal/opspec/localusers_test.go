package opspec

import "testing"

func TestLocalAccountValidation(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1 jan@workstation"

	valid := Payload{LocalUser: &LocalUserPayload{
		Name: "smith", Shell: "/bin/bash", Groups: []string{"sudo"}, SSHKeys: []string{key},
	}}
	if err := Validate(ActionLocalUserCreate, valid); err != nil {
		t.Fatalf("a valid payload was rejected: %v", err)
	}

	// An empty list of keys is a deliberate removal of access, not missing
	// data.
	empty := Payload{LocalUser: &LocalUserPayload{Name: "smith", SSHKeys: []string{}}}
	if err := Validate(ActionLocalSSHKeysSet, empty); err != nil {
		t.Fatalf("taking keys away has to be allowed: %v", err)
	}

	cases := map[string]LocalUserPayload{
		"name with a capital letter": {Name: "Smith"},
		"name with a path":           {Name: "../root"},
		"empty name":                 {Name: ""},
		"relative shell":             {Name: "smith", Shell: "bash"},
		"colon in the description":   {Name: "smith", Gecos: "Jane:Smith"},
		"invalid group":              {Name: "smith", Groups: []string{"su do"}},
		"private key":                {Name: "smith", SSHKeys: []string{"-----BEGIN OPENSSH PRIVATE KEY-----"}},
		"key with a newline":         {Name: "smith", SSHKeys: []string{key + "\nssh-rsa AAAA"}},
		"unknown key type":           {Name: "smith", SSHKeys: []string{"ssh-dss AAAAB3Nz jane"}},
		"key without material":       {Name: "smith", SSHKeys: []string{"ssh-ed25519"}},
		"empty key":                  {Name: "smith", SSHKeys: []string{"   "}},
	}
	for name, payload := range cases {
		if err := Validate(ActionLocalUserCreate, payload.copy()); err == nil {
			t.Errorf("%s: the payload should have been rejected", name)
		}
	}

	if err := Validate(ActionLocalUserLock, Payload{}); err == nil {
		t.Error("an operation without a payload has to be rejected")
	}
}

// copy allows using the same structure in a table of cases without sharing
// it.
func (p LocalUserPayload) copy() Payload {
	copied := p
	return Payload{LocalUser: &copied}
}

func TestLocalAccountOperationsHaveSeparatePermissions(t *testing.T) {
	// Locking and unlocking are separated deliberately: in response to an
	// incident, cutting an account off is sometimes allowed where restoring
	// access is not.
	if ActionLocalUserLock.Permission() == ActionLocalUserUnlock.Permission() {
		t.Error("locking and unlocking have to have separate permissions")
	}
	for _, action := range []ActionType{
		ActionLocalUserCreate, ActionLocalUserLock, ActionLocalUserUnlock, ActionLocalSSHKeysSet,
	} {
		if !action.Mutating() {
			t.Errorf("%s changes the state of the host", action)
		}
		// Local accounts work also where there is neither systemd nor a
		// directory.
		if action.RequiredCapability() != "" {
			t.Errorf("%s should not require a host capability", action)
		}
	}
}

// TestPackageRepairValidation guards the boundaries of the repair operation.
// An answer to a configuration question reaches debconf's input, where every
// line is a separate setting: a value with a newline would allow appending
// settings nobody asked for.
func TestPackageRepairValidation(t *testing.T) {
	valid := Payload{PackageRepair: &PackageRepairPayload{
		Answers: []DebconfAnswer{{
			Package: "grub-pc", Question: "grub-pc/install_devices",
			Type: "multiselect", Value: "/dev/sda",
		}},
	}}
	if err := Validate(ActionPackageRepair, valid); err != nil {
		t.Fatalf("a valid answer was rejected: %v", err)
	}

	// A repair without answers is allowed: finishing the configuration is
	// enough when the previous transaction was interrupted.
	if err := Validate(ActionPackageRepair, Payload{PackageRepair: &PackageRepairPayload{}}); err != nil {
		t.Fatalf("a repair without answers was rejected: %v", err)
	}

	cases := map[string]DebconfAnswer{
		"question name without a package": {Package: "grub-pc", Question: "install_devices", Type: "string", Value: "x"},
		"question with a path":            {Package: "grub-pc", Question: "../../etc/passwd", Type: "string", Value: "x"},
		"unknown type":                    {Package: "grub-pc", Question: "grub-pc/x", Type: "shell", Value: "x"},
		"value with a newline":            {Package: "grub-pc", Question: "grub-pc/x", Type: "string", Value: "a\nb c d"},
		"invalid package":                 {Package: "grub pc", Question: "grub-pc/x", Type: "string", Value: "x"},
	}
	for name, answer := range cases {
		payload := Payload{PackageRepair: &PackageRepairPayload{Answers: []DebconfAnswer{answer}}}
		if err := Validate(ActionPackageRepair, payload); err == nil {
			t.Errorf("%s: the payload should have been rejected", name)
		}
	}

	if ActionPackageRepair.Permission() == ActionPackageUpgrade.Permission() {
		t.Error("a repair has to have a permission separate from an upgrade")
	}
	if !ActionPackageRepair.Mutating() {
		t.Error("a repair changes the state of the host")
	}
}
