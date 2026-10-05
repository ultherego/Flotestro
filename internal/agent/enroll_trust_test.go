package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/identitystore"
	"github.com/ultherego/flotestro/internal/issuer"
	"github.com/ultherego/flotestro/internal/pki"
)

// answerFunc is an enrollment endpoint the test writes itself: the panel, or
// a relay that holds a leaf of the pinned authority and answers in its place.
type answerFunc func(request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error)

func (f answerFunc) Enroll(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	return f(request)
}

// enrollAgainst runs one enrollment against the given endpoint, with the
// given bundle pinned for the request.
func enrollAgainst(t *testing.T, pinned []byte, answer answerFunc) (*identitystore.Store, error) {
	t.Helper()
	store := identitystore.New(t.TempDir())
	enrollment := &Enrollment{
		Store:  store,
		Issuer: answer,
		Request: IdentityRequest{
			// The same token the enrollment tests beside this one use: the
			// scheme is real because TokenPrefix reads it, and the body says
			// what it is rather than looking like a credential.
			Token:     "flt_an-enrollment-token-of-a-test",
			MachineID: "33d45072f9f04beeb492b07e91f61db5", Hostname: "web-01",
		},
		BootstrapPEM: pinned,
		Now:          func() time.Time { return time.Now() },
		Random:       rand.Reader,
	}
	_, err := enrollment.Run(context.Background())
	return store, err
}

// The first enrollment used to write down whatever set of authorities the
// answer carried. The channel is pinned to the bootstrap authority, but that
// authority is a CA and a relay holds a leaf of it with serverAuth on it: the
// far end of the pinned channel need not be the panel. The panel now vouches
// for the set with the authority's own key, and the agent asks for it.
func TestTheFirstTrustBundleIsVouchedForByThePinnedAuthority(t *testing.T) {
	fleet, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	panel := issuer.FromTrust(fleet)
	pinned := fleet.Bundle()

	// The panel's own answer, built by the panel's own code: the set in force
	// and the signature of the authority that signs now.
	answerFromPanel := func(request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
		issued, err := panel.SignHost(context.Background(), request.GetCsrPem(), enrollTestHost)
		if err != nil {
			return nil, err
		}
		bundle, vouch, err := panel.VouchedTrust(context.Background())
		if err != nil {
			return nil, err
		}
		return &agentv1.EnrollResponse{
			HostId: enrollTestHost, CertificatePem: issued.PEM,
			CaBundlePem: bundle, CaBundleSignature: vouch,
		}, nil
	}

	// Adjacency from the legitimate side: a host whose fleet CA is the
	// authority it pinned enrolls as it always did.
	store, err := enrollAgainst(t, pinned, answerFromPanel)
	if err != nil {
		t.Fatalf("an ordinary enrollment was refused: %v", err)
	}
	identity, err := store.Current()
	if err != nil {
		t.Fatalf("the ordinary enrollment wrote no identity: %v", err)
	}
	if string(identity.TrustPEM) != string(pinned) {
		t.Error("the ordinary enrollment wrote a trust bundle other than the panel's")
	}

	// A relay of the fleet, or anything else holding a leaf of the pinned
	// authority, answers with an authority of its own and a certificate that
	// verifies under it. Nothing but the vouch stands in the way: the
	// generation is consistent with itself and the store would take it.
	rogue, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	answerFromRelay := func(request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
		issued, err := rogue.Active().SignAgentCSR(request.GetCsrPem(), enrollTestHost)
		if err != nil {
			return nil, err
		}
		return &agentv1.EnrollResponse{
			HostId: enrollTestHost, CertificatePem: issued.PEM, CaBundlePem: rogue.Bundle(),
		}, nil
	}
	store, err = enrollAgainst(t, pinned, answerFromRelay)
	if err == nil {
		t.Fatal("a foreign authority nobody vouched for was written down as the fleet's")
	}
	if code := ErrorCode(err); code != CodeTrustUnvouched {
		t.Errorf("the refusal is coded %q, not %q", code, CodeTrustUnvouched)
	}
	if _, err := store.Current(); !errors.Is(err, identitystore.ErrIdentityMissing) {
		t.Errorf("a refused enrollment left an identity on disk: %v", err)
	}

	// The same answer with the newcomer vouching for itself: a signature that
	// verifies under the set offered and under nothing the host pinned.
	answerSelfVouched := func(request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
		response, err := answerFromRelay(request)
		if err != nil {
			return nil, err
		}
		response.CaBundleSignature, err = rogue.Active().SignTrustBundle(response.GetCaBundlePem())
		if err != nil {
			return nil, err
		}
		return response, nil
	}
	if _, err := enrollAgainst(t, pinned, answerSelfVouched); err == nil {
		t.Fatal("the authority that wants in vouched for itself and was written down")
	}

	// A genuine vouch, over another set: the signature travels with a bundle
	// it was not made over.
	vouchForPinned, err := fleet.Active().SignTrustBundle(pinned)
	if err != nil {
		t.Fatal(err)
	}
	answerMismatched := func(request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
		response, err := answerFromRelay(request)
		if err != nil {
			return nil, err
		}
		response.CaBundleSignature = vouchForPinned
		return response, nil
	}
	if _, err := enrollAgainst(t, pinned, answerMismatched); err == nil {
		t.Fatal("a vouch over the pinned set carried a foreign set in")
	}

	// The answer that carries no set at all: the host stays on the authority
	// it pinned, so there is nothing unvouched to write - and a certificate
	// from somebody else does not verify under the pin, which is the refusal
	// that was already there.
	answerWithoutBundle := func(request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
		issued, err := rogue.Active().SignAgentCSR(request.GetCsrPem(), enrollTestHost)
		if err != nil {
			return nil, err
		}
		return &agentv1.EnrollResponse{HostId: enrollTestHost, CertificatePem: issued.PEM}, nil
	}
	if _, err := enrollAgainst(t, pinned, answerWithoutBundle); err == nil {
		t.Fatal("a foreign certificate was written under the pinned trust")
	}
	answerOwnWithoutBundle := func(request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
		issued, err := panel.SignHost(context.Background(), request.GetCsrPem(), enrollTestHost)
		if err != nil {
			return nil, err
		}
		return &agentv1.EnrollResponse{HostId: enrollTestHost, CertificatePem: issued.PEM}, nil
	}
	if _, err := enrollAgainst(t, pinned, answerOwnWithoutBundle); err != nil {
		t.Fatalf("an answer with no set, from the pinned authority, was refused: %v", err)
	}

	// Adjacency from the legitimate side again: the panel prepares a second
	// authority, so the set it answers with is no longer the pinned one, and
	// the authority in force says so. This has to keep working.
	if _, err := fleet.Prepare(); err != nil {
		t.Fatal(err)
	}
	store, err = enrollAgainst(t, pinned, answerFromPanel)
	if err != nil {
		t.Fatalf("a rotation prepared by the panel was refused at enrollment: %v", err)
	}
	identity, err = store.Current()
	if err != nil {
		t.Fatalf("the rotated enrollment wrote no identity: %v", err)
	}
	if string(identity.TrustPEM) == string(pinned) {
		t.Error("the prepared authority did not reach the host")
	}
	authorities, err := pki.IssuerIDsOfBundle(identity.TrustPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorities) != 2 {
		t.Errorf("the host wrote %d authorities, not the two the panel holds", len(authorities))
	}
}
