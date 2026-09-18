package freeipa

import "testing"

// The directory writes the rights it grants as letters, per attribute and -
// where it reports them at all - for the entry as a whole. A deployment that
// reports none leaves the move unproven, and unproven is not the same as
// refused.
func TestTheRightsOnAnEntryAreReadAsTheDirectoryWritesThem(t *testing.T) {
	record := map[string]any{
		"attributelevelrights": map[string]any{
			"nsaccountlock": "rscwo",
			"uid":           "rsc",
		},
		"entrylevelrights": []any{"vadn"},
	}
	rights := readRights(record)
	if rights.entry != "vadn" {
		t.Fatalf("the rights on the entry read %q, expected vadn", rights.entry)
	}
	if rights.attribute("nsAccountLock") != "rscwo" {
		t.Errorf("the rights on nsaccountlock read %q; the directory spells the name "+
			"both ways and one spelling must not lose the answer",
			rights.attribute("nsAccountLock"))
	}

	// A directory that says nothing about the entry itself.
	quiet := readRights(map[string]any{
		"attributelevelrights": map[string]any{"nsaccountlock": "rscwo"},
	})
	if quiet.entry != "" {
		t.Errorf("the rights on the entry read %q, expected nothing", quiet.entry)
	}
}

// What blocks a preserve is a proven impediment, never an unknown: a
// directory that does not report entry rights has not refused anything, and
// the operation now asks it first anyway.
func TestOnlyAProvenImpedimentBlocksAPreserve(t *testing.T) {
	cases := []struct {
		name         string
		capabilities DirectoryCapabilities
		blocked      string
	}{
		{"the directory may move the entry",
			DirectoryCapabilities{UserModDN: true}, ""},
		{"the directory does not report the rights",
			DirectoryCapabilities{ReasonCodes: []string{ReasonModDNRightsUnknown}}, ""},
		{"the directory refuses the move",
			DirectoryCapabilities{ReasonCodes: []string{ReasonModDNNotPermitted}},
			ReasonModDNNotPermitted},
		{"there is no container to move into",
			DirectoryCapabilities{ReasonCodes: []string{ReasonPreserveContainerMissing}},
			ReasonPreserveContainerMissing},
		{"the directory did not answer",
			DirectoryCapabilities{ReasonCodes: []string{ReasonDirectoryUnreachable}},
			ReasonDirectoryUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, blocked := tc.capabilities.PreserveBlocked()
			if blocked != (tc.blocked != "") || reason != tc.blocked {
				t.Fatalf("PreserveBlocked = %q, %v, expected %q", reason, blocked, tc.blocked)
			}
		})
	}
}

// The plan names where the entry is, which entry it is and when it last
// changed. Any of the three moving means the plan was made against a state
// the directory no longer holds.
func TestAnEntryIsTheOneThePlanNamedOnlyWhenAllThreeStillAgree(t *testing.T) {
	planned := EntryReference{
		DN:              "uid=alice,cn=users,cn=accounts,dc=ipa,dc=example,dc=test",
		EntryUUID:       "0b1d4c8e-0000-0000-0000-000000000001",
		ModifyTimestamp: "20260917103000Z",
	}
	if reason, moved := planned.Moved(planned); moved {
		t.Fatalf("the same entry read as moved: %s", reason)
	}

	preserved := planned
	preserved.DN = "uid=alice,cn=deleted users,cn=accounts,cn=provisioning,dc=ipa,dc=example,dc=test"
	if _, moved := planned.Moved(preserved); !moved {
		t.Error("an entry already moved into the preserved container read as unchanged")
	}

	reused := planned
	reused.EntryUUID = "0b1d4c8e-0000-0000-0000-000000000002"
	if _, moved := planned.Moved(reused); !moved {
		t.Error("another entry under the same name read as the same entry")
	}

	touched := planned
	touched.ModifyTimestamp = "20260918090000Z"
	if _, moved := planned.Moved(touched); !moved {
		t.Error("an entry changed since the plan read as unchanged")
	}

	// A value the plan recorded and the directory no longer reports is a
	// difference: not being told is not the same as being told it is
	// unchanged.
	silent := planned
	silent.ModifyTimestamp = ""
	if _, moved := planned.Moved(silent); !moved {
		t.Error("a timestamp the directory stopped reporting read as unchanged")
	}

	// A plan made where the directory reports no timestamp binds to what it
	// does report, and that part still has to agree.
	partial := EntryReference{DN: planned.DN}
	if _, moved := partial.Moved(planned); moved {
		t.Error("a plan bound to the DN alone refused an entry whose DN did not move")
	}
	if !partial.Complete() || (EntryReference{}).Complete() {
		t.Error("a reference is complete exactly when it names where the entry is")
	}
}

// The directory returns the identity of an entry under the names it uses:
// the DN beside the attributes, and its own unique identifier rather than
// the one the schema calls entryUUID.
func TestTheIdentityOfAnEntryIsReadUnderTheNamesTheDirectoryUses(t *testing.T) {
	entry := entryFromRecord(map[string]any{
		"dn":              "uid=alice,cn=users,cn=accounts,dc=ipa,dc=example,dc=test",
		"ipauniqueid":     []any{"0b1d4c8e-0000-0000-0000-000000000001"},
		"modifytimestamp": []any{map[string]any{"__datetime__": "20260917103000Z"}},
	})
	if entry.DN == "" || entry.EntryUUID != "0b1d4c8e-0000-0000-0000-000000000001" ||
		entry.ModifyTimestamp != "20260917103000Z" {
		t.Fatalf("the entry read as %+v", entry)
	}

	// A directory that writes the schema name instead answers the same
	// question.
	schema := entryFromRecord(map[string]any{
		"dn":        "uid=bob,cn=users,cn=accounts,dc=ipa,dc=example,dc=test",
		"entryuuid": []any{"0b1d4c8e-0000-0000-0000-000000000002"},
	})
	if schema.EntryUUID != "0b1d4c8e-0000-0000-0000-000000000002" {
		t.Errorf("the entry read as %+v", schema)
	}
}
