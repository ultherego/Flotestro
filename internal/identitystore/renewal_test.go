package identitystore

import (
	"errors"
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

// The first bundle a host is ever handed is judged the same way, against the
// authority pinned for the request instead of against a trust in force.
//
// The pinned channel does not answer this question. The authority in the pin
// is a CA, and a relay of the fleet holds a leaf of it with serverAuth on it,
// so the far end of that channel need not be the panel - and whoever it is
// can mint an authority of its own and a certificate under it, which is a
// generation consistent with itself. Only the pinned authority's own key can
// produce the vouch.
func TestTheFirstTrustBundleIsVouchedForByThePin(t *testing.T) {
	fleet, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pinned := fleet.Bundle()

	// The pin repeated: the host is asked to believe what it already
	// believes, so there is nothing for an authority to vouch for.
	if err := AcceptableFirstTrust(pinned, pinned, nil); err != nil {
		t.Fatalf("the pinned set itself was refused: %v", err)
	}
	// The panel prepares an authority, so the set it answers with grows, and
	// the authority in force signs for it.
	if _, err := fleet.Prepare(); err != nil {
		t.Fatal(err)
	}
	rotated := fleet.Bundle()
	vouch, err := fleet.Active().SignTrustBundle(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcceptableFirstTrust(pinned, rotated, vouch); err != nil {
		t.Fatalf("an authority the pinned one vouched for was refused: %v", err)
	}
	// The same set with no signature at all - what an older panel answers,
	// and what anybody in the middle answers just as easily.
	if err := AcceptableFirstTrust(pinned, rotated, nil); !errors.Is(err, ErrTrustUnvouched) {
		t.Fatalf("a set nobody vouched for was accepted as the first trust: %v", err)
	}
	// A genuine signature, over another set than the one that travelled.
	vouchForPinned, err := fleet.Active().SignTrustBundle(pinned)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcceptableFirstTrust(pinned, rotated, vouchForPinned); !errors.Is(err, ErrTrustUnvouched) {
		t.Fatalf("a vouch over the pinned set carried another set in: %v", err)
	}

	// Somebody else's authority, vouching for itself.
	rogue, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	byItself, err := rogue.Active().SignTrustBundle(rogue.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	if err := AcceptableFirstTrust(pinned, rogue.Bundle(), byItself); !errors.Is(err, ErrTrustUnvouched) {
		t.Fatalf("the authority that wants in vouched for itself and was accepted: %v", err)
	}
	// An authority appended to the pinned set, vouched for by the newcomer.
	foreign := append(append([]byte(nil), pinned...), rogue.Bundle()...)
	appended, err := rogue.Active().SignTrustBundle(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcceptableFirstTrust(pinned, foreign, appended); !errors.Is(err, ErrTrustUnvouched) {
		t.Fatalf("a foreign authority appended to the pinned set was accepted: %v", err)
	}

	// No pin at all: there is nothing to judge against, and the enrollment
	// path never gets that far, so this is a refusal and not a pass.
	if err := AcceptableFirstTrust(nil, rotated, vouch); !errors.Is(err, ErrTrustUnvouched) {
		t.Fatalf("a bundle was accepted with no pin to judge it against: %v", err)
	}
}

// Every path that writes a generation asks that question, so one of them
// cannot be left out again. The enrollment asks it of the pin, and the
// cryptography of that is held by the tests above and in internal/agent -
// this only keeps a path from losing the call.
func TestEveryPathThatCommitsAGenerationJudgesTheRenewal(t *testing.T) {
	for path, wanted := range map[string]string{
		"../agent/renewal.go":         "AcceptableRenewal",
		"../relay/renewal.go":         "AcceptableRenewal",
		"../../cmd/relayctl/renew.go": "AcceptableRenewal",
		"../agent/enroll.go":          "AcceptableFirstTrust",
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
