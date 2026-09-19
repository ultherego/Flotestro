package gateway

import (
	"encoding/json"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Only a different boot identifier proves a restart.
func TestOnlyANewBootIdentifierSettlesARestart(t *testing.T) {
	cases := []struct {
		name             string
		ordered, current string
		returned         bool
	}{
		{name: "another boot", ordered: "boot-1", current: "boot-2", returned: true},
		{name: "the same boot", ordered: "boot-1", current: "boot-1"},
		{name: "the same boot spelled without dashes", ordered: "a1b2-c3d4", current: "A1B2C3D4"},
		{name: "no boot on the order", current: "boot-2"},
		{name: "no boot on the return", ordered: "boot-1"},
		{name: "neither"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verdict := rebootReturn(c.ordered, c.current)
			if verdict.Returned != c.returned {
				t.Fatalf("returned = %v, expected %v", verdict.Returned, c.returned)
			}
			if verdict.Expected == "" || verdict.Observed == "" {
				t.Errorf("the observation says nothing: %+v", verdict)
			}
		})
	}
}

// The observation of a settled restart names the boot the host came back on
// and the boot it was ordered under: an operator reading the attempt sees what
// proved the return rather than the bare word "succeeded".
func TestTheSettledRestartCarriesTheBootIdentifiers(t *testing.T) {
	verdict := rebootReturn("boot-before", "boot-after")
	if !verdict.Returned {
		t.Fatal("a different boot identifier did not settle the restart")
	}
	if verdict.Observed != "boot-after" {
		t.Errorf("observed = %q", verdict.Observed)
	}
	if verdict.Expected != "a boot identifier other than boot-before" {
		t.Errorf("expected = %q", verdict.Expected)
	}
	// A missing identifier is named as unknown rather than left empty: an
	// empty word in the sentence reads as a boot with no name.
	if bare := rebootReturn("", ""); bare.Observed != "unknown" {
		t.Errorf("a missing identifier reads as %q", bare.Observed)
	}
}

// The verification is written as the host reported it, with every field the
// panel shows: an operation that reported none writes none, and that is not
// the same as a change nobody confirmed.
func TestTheVerificationIsStoredAsItCame(t *testing.T) {
	if verificationJSON(nil) != nil {
		t.Fatal("an absent verification was written as a verification")
	}
	encoded := verificationJSON(&agentv1.Verification{
		Verifier: string(opspec.VerifierUnitState), Verified: false,
		Expected: "active", Observed: "failed", Reason: "the unit did not stay active",
	})
	var stored struct {
		Verifier string `json:"verifier"`
		Verified bool   `json:"verified"`
		Expected string `json:"expected"`
		Observed string `json:"observed"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal(encoded, &stored); err != nil {
		t.Fatalf("the verification is not readable: %v", err)
	}
	if stored.Verifier != "unit_state" || stored.Verified {
		t.Errorf("verifier %q, verified %v", stored.Verifier, stored.Verified)
	}
	if stored.Expected != "active" || stored.Observed != "failed" {
		t.Errorf("expected %q, observed %q", stored.Expected, stored.Observed)
	}
	if stored.Reason == "" {
		t.Error("the reason of the mismatch was dropped")
	}
}

// A restart is settled by the panel and never by the agent: the contract
// says so, and the settlement here rests on it.
func TestTheRestartIsSettledByThePanel(t *testing.T) {
	if !opspec.ActionSystemReboot.Verifier().PanelSettled() {
		t.Fatal("the contract no longer leaves the restart to the panel")
	}
	if opspec.ActionUnitRestart.Verifier().PanelSettled() {
		t.Error("a unit restart is verified on the host, not by the panel")
	}
}
