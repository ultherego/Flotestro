package agent

import (
	"os"
	"path/filepath"
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

func TestComparingTheStateOfAnAccount(t *testing.T) {
	trueValue, falseValue := true, false

	account := func() *LocalAccount {
		return &LocalAccount{
			Name: "smith", Shell: "/bin/bash", Groups: []string{"sudo", "smith"},
			Locked: &falseValue, PasswordSet: &falseValue,
			SSHKeys: []SSHKeyInfo{{Fingerprint: "SHA256:aaa"}},
		}
	}

	if !sameAccountState(account(), account()) {
		t.Error("an identical state has to be recognized as unchanged")
	}

	// The order of the groups and of the keys depends on the system and is not a
	// change of state.
	other := account()
	other.Groups = []string{"smith", "sudo"}
	if !sameAccountState(account(), other) {
		t.Error("the order of the groups is not a change")
	}

	locked := account()
	locked.Locked = &trueValue
	if sameAccountState(account(), locked) {
		t.Error("a change of the lock has to be detected")
	}

	// An unknown state differs from every known one: a move from "not known" to
	// "locked" is a change in the knowledge of the panel, not the absence of a
	// change.
	unknown := account()
	unknown.Locked = nil
	if sameAccountState(account(), unknown) {
		t.Error("an unknown state must not equal a known one")
	}

	withoutKey := account()
	withoutKey.SSHKeys = nil
	if sameAccountState(account(), withoutKey) {
		t.Error("taking a key away has to be detected")
	}

	if sameAccountState(nil, account()) {
		t.Error("creating an account is a change")
	}
	if !sameAccountState(nil, nil) {
		t.Error("no account before and after is not a change")
	}
}

func TestFillingInThePrivilegedData(t *testing.T) {
	trueValue := true
	accounts := []LocalAccount{{Name: "smith"}, {Name: "jones"}}
	result := &helperv1.LocalAccountsResult{
		Accounts: []*helperv1.LocalAccountDetail{{
			Name:        "smith",
			Locked:      &trueValue,
			PasswordSet: &trueValue,
			SshKeys:     []*helperv1.LocalSSHKey{{Fingerprint: "SHA256:aaa", Type: "ED25519"}},
		}},
	}

	merged := mergePrivilegedAccounts(accounts, result)
	if merged[0].Locked == nil || !*merged[0].Locked {
		t.Error("the lock state was not carried over")
	}
	if len(merged[0].SSHKeys) != 1 || merged[0].SSHKeys[0].Source != "authorized_keys" {
		t.Error("the keys were not carried over with their source")
	}
	// An account the helper said nothing about stays with an unknown state.
	// Writing "unlocked" here would be an invented fact.
	if merged[1].Locked != nil {
		t.Error("missing data has to stay an unknown state")
	}
}

func TestTheUIDRangeFromLoginDefs(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "login.defs")
	content := "# a comment\nUID_MIN\t\t 500\nUID_MAX\t\t 50000\nGID_MIN 1000\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	uidMin, uidMax := parseUIDRange(path)
	if uidMin != 500 || uidMax != 50000 {
		t.Fatalf("read the range %d-%d, expected 500-50000", uidMin, uidMax)
	}

	// A missing file must not shift the classification: the fallback values match
	// the settings of the distributions.
	uidMin, uidMax = parseUIDRange(filepath.Join(directory, "does-not-exist"))
	if uidMin != defaultUIDMin || uidMax != defaultUIDMax {
		t.Fatalf("a missing file gave the range %d-%d", uidMin, uidMax)
	}
}

func TestTheClassificationOfAccounts(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "passwd")
	content := "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"smith:x:1001:1001:John Smith,,,:/home/smith:/bin/bash\n" +
		// "nobody" lies above the range of the accounts of people and is a
		// system account despite its high UID; the lower bound alone would not
		// detect that.
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n" +
		"broken:x:not-a-number:0::/tmp:/bin/sh\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	accounts := parsePasswd(path, 1000, 60000, func(string) []string { return nil })
	sources := map[string]AccountSource{}
	for _, account := range accounts {
		sources[account.Name] = account.Source
	}

	if len(accounts) != 4 {
		t.Fatalf("read %d accounts, expected 4 (the broken line is skipped)", len(accounts))
	}
	for name, expected := range map[string]AccountSource{
		"root": SourceSystem, "daemon": SourceSystem,
		"smith": SourceLocal, "nobody": SourceSystem,
	} {
		if sources[name] != expected {
			t.Errorf("the account %s was classified as %s, expected %s", name, sources[name], expected)
		}
	}

	for _, account := range accounts {
		if account.Name == "smith" && account.Gecos != "John Smith" {
			t.Errorf("the description of the account was read as %q", account.Gecos)
		}
	}
}
