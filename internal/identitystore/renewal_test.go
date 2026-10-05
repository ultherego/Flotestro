package identitystore

import (
	"os"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/pki"
)

// The relay used to write down whatever answered its renewal as the
// authorities of its whole site: no vouch, and not even a look at whether the
// certificate verifies under the trust it already held. Relayctl had the same
// code. Both now ask the one function the agent asks.
func TestARenewalIsJudgedAgainstTheTrustInForce(t *testing.T) {
	fleet, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	held := fleet.Bundle()
	leaf := issueFor(t, fleet)

	if err := AcceptableRenewal(held, leaf, held, nil); err != nil {
		t.Fatalf("a renewal that changes nothing was refused: %v", err)
	}
	// A host with no trust yet is enrolling, and the pinned channel answers
	// for it there.
	if err := AcceptableRenewal(nil, leaf, held, nil); err != nil {
		t.Fatalf("a host without trust was refused its first bundle: %v", err)
	}

	// Somebody else's authority, with a certificate of its own. Both halves
	// have to be refused: the leaf does not verify under the trust held, and
	// nobody in force vouched for the set.
	rogue, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := AcceptableRenewal(held, issueFor(t, rogue), rogue.Bundle(), nil); err == nil {
		t.Fatal("a renewal under a foreign authority was accepted")
	}
	// A leaf that does verify, with a foreign authority appended to the set:
	// this is the one the relay took without asking anything.
	foreign := append(append([]byte(nil), held...), rogue.Bundle()...)
	if err := AcceptableRenewal(held, leaf, foreign, nil); err == nil {
		t.Fatal("a foreign authority appended to the bundle was adopted")
	}
	byItself, err := rogue.Active().SignTrustBundle(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcceptableRenewal(held, leaf, foreign, byItself); err == nil {
		t.Fatal("the authority that wants in vouched for itself and was adopted")
	}

	// The rotation this path exists for: the panel prepares an authority, the
	// set grows, and an authority in force says so.
	if _, err := fleet.Prepare(); err != nil {
		t.Fatal(err)
	}
	rotated := fleet.Bundle()
	vouch, err := fleet.Active().SignTrustBundle(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcceptableRenewal(held, leaf, rotated, vouch); err != nil {
		t.Fatalf("a prepared authority of the fleet was refused: %v", err)
	}
}

// Every path that writes a generation asks that question, so one of them
// cannot be left out again. The enrollment is listed too, and says in its own
// words why the pinned channel is what answers there.
func TestEveryPathThatCommitsAGenerationJudgesTheRenewal(t *testing.T) {
	for path, wanted := range map[string]string{
		"../agent/renewal.go":         "AcceptableRenewal",
		"../relay/renewal.go":         "AcceptableRenewal",
		"../../cmd/relayctl/renew.go": "AcceptableRenewal",
		// The enrollment has no trust to judge against: the request went out
		// over a channel pinned to the bootstrap authority, and that is what
		// stands behind the first bundle.
		"../agent/enroll.go": "the request went out under",
	} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(source), wanted) {
			t.Errorf("%s commits a generation without %q", path, wanted)
		}
	}
}

// issueFor returns a leaf certificate of the given trust, in PEM.
func issueFor(t *testing.T, trust *pki.Trust) []byte {
	t.Helper()
	key, err := New(t.TempDir()).NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := Request(key, "host-1", []string{"host-1.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := trust.Active().SignAgentCSR(csr, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	return issued.PEM
}
