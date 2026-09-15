package policy

import (
	"errors"
	"testing"
)

func boolPtr(value bool) *bool { return &value }

func TestValidateRulesAcceptsEveryKindOfThisVersion(t *testing.T) {
	rules := []Rule{
		{Kind: KindPackageInstalled, Name: "cron"},
		{Kind: KindPackageAbsent, Name: "telnetd"},
		{Kind: KindUnitState, Unit: "cron.service", Enabled: boolPtr(true), Active: boolPtr(true)},
		{Kind: KindFileContent, Path: "/etc/motd", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{Kind: KindSysctl, Key: "net.ipv4.ip_forward", Value: "0"},
		{Kind: KindSSHKeyPresent, User: "deploy", Fingerprint: "SHA256:Ub7qzE3Gv5WQmC1x2k4T3l0yq9zXvA1b2c3d4e5f6g7"},
	}
	if err := ValidateRules(rules, ModeCampaign); err != nil {
		t.Fatalf("ValidateRules: %v", err)
	}
}

func TestValidateRulesRefusesAnUnknownKindByName(t *testing.T) {
	err := ValidateRules([]Rule{{Kind: KindSysctl, Key: "a", Value: "1"}, {Kind: "timer_present", Unit: "x.timer"}}, ModeReport)
	var unsupported ErrUnsupportedRule
	if !errors.As(err, &unsupported) {
		t.Fatalf("err = %v, want ErrUnsupportedRule", err)
	}
	if unsupported.Index != 1 || unsupported.Kind != "timer_present" {
		t.Fatalf("unsupported = %+v", unsupported)
	}
}

func TestValidateRulesHoldsEveryKindToItsFields(t *testing.T) {
	cases := map[string]Rule{
		"package without a name":     {Kind: KindPackageInstalled},
		"package with a path":        {Kind: KindPackageAbsent, Name: "usr/bin/x"},
		"unit without a suffix":      {Kind: KindUnitState, Unit: "cron", Enabled: boolPtr(true)},
		"unit without a state":       {Kind: KindUnitState, Unit: "cron.service"},
		"file with a relative path":  {Kind: KindFileContent, Path: "etc/motd", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		"file with a short digest":   {Kind: KindFileContent, Path: "/etc/motd", SHA256: "abc"},
		"sysctl without a value":     {Kind: KindSysctl, Key: "net.ipv4.ip_forward"},
		"key without a fingerprint":  {Kind: KindSSHKeyPresent, User: "deploy", Fingerprint: "md5:aa"},
		"key with a one-word public": {Kind: KindSSHKeyPresent, User: "deploy", Fingerprint: "SHA256:Ub7qzE3Gv5WQmC1x2k4T3l0yq9zXvA1b2c3d4e5f6g7", PublicKey: "ssh-ed25519"},
		"no kind":                    {Name: "cron"},
	}
	for name, rule := range cases {
		err := ValidateRules([]Rule{rule}, ModeReport)
		var invalid ErrInvalidRule
		if !errors.As(err, &invalid) {
			t.Errorf("%s: err = %v, want ErrInvalidRule", name, err)
		}
	}
}

func TestValidateRulesRefusesAnEmptyDocumentAndAnUnknownMode(t *testing.T) {
	if err := ValidateRules(nil, ModeReport); !errors.Is(err, ErrNoRules) {
		t.Fatalf("err = %v, want ErrNoRules", err)
	}
	if err := ValidateRules([]Rule{{Kind: KindSysctl, Key: "a", Value: "1"}}, "enforce"); !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("err = %v, want ErrInvalidMode", err)
	}
}

func TestAnApprovalBoundRuleDoesNotRunAutomatically(t *testing.T) {
	rules := []Rule{{Kind: KindPackageAbsent, Name: "telnetd"}}
	if err := ValidateRules(rules, ModeCampaign); err != nil {
		t.Fatalf("campaign mode: %v", err)
	}
	err := ValidateRules(rules, ModeAutomatic)
	var bound ErrApprovalBound
	if !errors.As(err, &bound) || bound.Kind != KindPackageAbsent {
		t.Fatalf("automatic mode: err = %v, want ErrApprovalBound", err)
	}
}

func TestCheckIDBindsTheRuleToItsIndexAndSubject(t *testing.T) {
	id := CheckID(3, Rule{Kind: KindUnitState, Unit: "cron.service", Active: boolPtr(true)})
	if id != "rule:3:unit_state:cron.service" {
		t.Fatalf("id = %q", id)
	}
}

func TestADraftDiffersFromThePublishedDocumentByItsText(t *testing.T) {
	published := Document{Name: "a", Rules: []Rule{{Kind: KindSysctl, Key: "k", Value: "1"}}, RemediationMode: ModeReport, CheckInterval: 900}
	same := Document{Name: "a", Rules: []Rule{{Kind: KindSysctl, Key: "k", Value: "1"}}, RemediationMode: ModeReport, CheckInterval: 900}
	changed := Document{Name: "a", Rules: []Rule{{Kind: KindSysctl, Key: "k", Value: "2"}}, RemediationMode: ModeReport, CheckInterval: 900}
	if !published.Equal(same) {
		t.Fatal("the same text is not equal")
	}
	if published.Equal(changed) {
		t.Fatal("a changed value is equal")
	}
}

func TestSpecValidateBoundsTheInterval(t *testing.T) {
	if err := (Spec{Name: "x", RemediationMode: ModeReport, CheckInterval: 30}).Validate(); err == nil {
		t.Fatal("a half-minute interval passed")
	}
	if err := (Spec{Name: "x", RemediationMode: ModeReport}).Validate(); err != nil {
		t.Fatalf("the default interval: %v", err)
	}
	if err := (Spec{RemediationMode: ModeReport}).Validate(); err == nil {
		t.Fatal("a nameless policy passed")
	}
}

func TestDriftFingerprintIgnoresTheOrderOfHosts(t *testing.T) {
	a := DriftFingerprint("p", 2, []string{"h1\x1fs1", "h2\x1fs2"})
	b := DriftFingerprint("p", 2, []string{"h2\x1fs2", "h1\x1fs1"})
	if a != b {
		t.Fatal("the order of the hosts changed the fingerprint")
	}
	if DriftFingerprint("p", 3, []string{"h1\x1fs1", "h2\x1fs2"}) == a {
		t.Fatal("the version did not change the fingerprint")
	}
	if DriftFingerprint("p", 2, []string{"h1\x1fs1"}) == a {
		t.Fatal("a host less did not change the fingerprint")
	}
}
