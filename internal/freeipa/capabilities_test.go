package freeipa

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// The directory writes the rights it grants as letters, per attribute and -
// where it reports them at all - for the entry as a whole.
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

// What blocks a preserve is a proven impediment, never an unknown: a directory
// that does not report entry rights has not refused anything, and the
// operation now asks it first anyway.
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
// changed.
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
	// difference: not being told is not the same as being told it is unchanged.
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

// The directory returns the identity of an entry under the names it uses: the
// DN beside the attributes, and its own unique identifier rather than the one
// the schema calls entryUUID.
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

// rightsOn answers a read of one account's rights and refuses every other
// name, so a test can tell which entry the preflight asked about.
func rightsOn(uid, entryRights string) func(rpcCall) (any, *rpcError) {
	return func(call rpcCall) (any, *rpcError) {
		if len(call.Args) != 1 || call.Args[0] != uid {
			return nil, &rpcError{Code: 4001, Name: "NotFound",
				Message: strings.Join(call.Args, " ") + ": user not found"}
		}
		record := map[string]any{
			"uid":                  []any{uid},
			"attributelevelrights": map[string]any{"nsaccountlock": "rscwo"},
		}
		if entryRights != "" {
			record["entrylevelrights"] = []any{entryRights}
		}
		return map[string]any{"result": record}, nil
	}
}

// The preflight of an operation asks about the entry that operation will move.
func TestThePreflightReadsTheRightsOnTheEntryTheOperationIsAbout(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["dnszone_find"] = answerList(false)
	fake.answers["user_find"] = answerList(false, map[string]any{"uid": []any{"somebody-else"}})
	fake.answers["user_show"] = rightsOn("jane", "vadn")

	capabilities, err := client.CapabilitiesFor(context.Background(), "jane")
	if err != nil {
		t.Fatalf("the preflight: %v", err)
	}
	if capabilities.Subject != "jane" {
		t.Fatalf("the preflight reports the subject %q", capabilities.Subject)
	}
	if !capabilities.UserModDN || capabilities.Has(ReasonNoEntryToCheck) {
		t.Fatalf("the preflight read %+v", capabilities)
	}
	call, ok := fake.find("user_show")
	if !ok || len(call.Args) != 1 || call.Args[0] != "jane" {
		t.Fatalf("the rights were read on %v", call.Args)
	}
	if rights, _ := call.Options["rights"].(bool); !rights {
		t.Fatalf("the read did not ask for the rights: %v", call.Options)
	}
	// The only search is the one about the container of preserved
	// accounts: with an entry to ask about there is no sample to find.
	if fake.count("user_find") != 1 {
		t.Fatalf("the preflight searched for accounts %d times", fake.count("user_find"))
	}
}

// A directory that reports the rights and does not grant the move refuses the
// preserve here, before anything local is touched, and says what lifts the
// refusal.
func TestADirectoryThatRefusesTheMoveComesWithTheInstructionToProvision(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["dnszone_find"] = answerList(false)
	fake.answers["user_find"] = answerList(false, map[string]any{"uid": []any{"jane"}})
	fake.answers["user_show"] = rightsOn("jane", "vad")

	refused, err := client.CapabilitiesFor(context.Background(), "jane")
	if err != nil {
		t.Fatalf("the preflight: %v", err)
	}
	if refused.UserModDN || !refused.Has(ReasonModDNNotPermitted) {
		t.Fatalf("a directory that refuses the move read %+v", refused)
	}
	reason, blocked := refused.PreserveBlocked()
	if !blocked || reason != ReasonModDNNotPermitted {
		t.Fatalf("PreserveBlocked = %q, %v", reason, blocked)
	}
	for _, part := range []string{"provisioning step", PreservePermission, "repeat"} {
		if !strings.Contains(refused.Instruction, part) {
			t.Errorf("the instruction does not name %q: %s", part, refused.Instruction)
		}
	}

	quiet, client := newFakeDirectory(t)
	quiet.answers["dnszone_find"] = answerList(false)
	quiet.answers["user_find"] = answerList(false, map[string]any{"uid": []any{"jane"}})
	quiet.answers["user_show"] = rightsOn("jane", "")

	unknown, err := client.CapabilitiesFor(context.Background(), "jane")
	if err != nil {
		t.Fatalf("the preflight: %v", err)
	}
	if unknown.Has(ReasonModDNNotPermitted) || !unknown.Has(ReasonModDNRightsUnknown) {
		t.Fatalf("a directory that says nothing read %+v", unknown)
	}
	if _, blocked := unknown.PreserveBlocked(); blocked {
		t.Error("an unknown blocked a preserve; the directory has not refused anything")
	}
	if unknown.Instruction == "" || unknown.Instruction == refused.Instruction {
		t.Errorf("an unknown carries the instruction of a refusal: %s", unknown.Instruction)
	}
}

// The preflight asks two bounded questions - is there a container of preserved
// accounts, is there an account to read the rights on - and a directory that
// holds more than the one record it was asked for marks the answer truncated.
func TestABoundedSearchIsNotATruncatedList(t *testing.T) {
	fake, client := newFakeDirectory(t)
	fake.answers["dnszone_find"] = answerList(false)
	fake.answers["user_find"] = func(call rpcCall) (any, *rpcError) {
		uid := "jane"
		if preserved, _ := call.Options["preserved"].(bool); preserved {
			uid = "olduser"
		}
		return map[string]any{
			"result":    []any{map[string]any{"uid": []any{uid}}},
			"count":     1,
			"truncated": true,
		}, nil
	}
	fake.answers["user_show"] = rightsOn("jane", "vadn")

	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("the preflight: %v", err)
	}
	for _, reason := range []string{ReasonPreserveContainerMissing, ReasonNoEntryToCheck} {
		if capabilities.Has(reason) {
			t.Errorf("a bounded answer was read as %s: %v", reason, capabilities.ReasonCodes)
		}
	}
	if !capabilities.UserModDN {
		t.Fatalf("the rights were not read at all: %+v", capabilities)
	}

	// The rule the bound does not touch: a list the panel shows is refused when
	// the directory cut it short, because a truncated list read as a complete one
	// is the worse mistake.
	if _, err := client.Users(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "paging is required") {
		t.Fatalf("a truncated listing was accepted: %v", err)
	}
}

// The plan says which of the three values it bound to.
func TestThePlanSaysWhichOfTheThreeValuesItBoundTo(t *testing.T) {
	full := EntryReference{
		DN:              "uid=alice,cn=users,cn=accounts,dc=ipa,dc=example,dc=test",
		EntryUUID:       "0b1d4c8e-0000-0000-0000-000000000001",
		ModifyTimestamp: "20260917103000Z",
	}
	if got := full.BoundTo(); !slices.Equal(got, []string{bindingDN, bindingUUID, bindingTimestamp}) {
		t.Fatalf("a full reference bound to %v", got)
	}
	if len(full.Unbound()) != 0 || strings.Contains(full.Binding(), "does not report") {
		t.Fatalf("a full reference reads %q", full.Binding())
	}

	// The laboratory's directory reports no modify timestamp.
	quiet := full
	quiet.ModifyTimestamp = ""
	if got := quiet.BoundTo(); !slices.Equal(got, []string{bindingDN, bindingUUID}) {
		t.Fatalf("the reference bound to %v", got)
	}
	sentence := quiet.Binding()
	if !strings.Contains(sentence, bindingDN) || !strings.Contains(sentence, bindingUUID) ||
		!strings.Contains(sentence, "does not report "+bindingTimestamp) {
		t.Fatalf("the binding reads %q", sentence)
	}
	if (EntryReference{}).Binding() != "the plan names no value of the entry to bind to" {
		t.Fatalf("an empty reference reads %q", (EntryReference{}).Binding())
	}
}
