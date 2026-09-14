package agent

import (
	"context"
	"testing"
)

// The certificate check is what tells the operator whether a rename costs
// a re-enrollment. The panel issues the certificate for the identifier, so
// with the identifier in the certificate the answer is no.
func TestCertificateCheckTellsIdentifierFromName(t *testing.T) {
	byID := certificateCheck("3f1c2a7e-0b2d-4c1e-9a1f-0f4d2e6b7a8c", "web01")
	if byID.Passed == nil || !*byID.Passed || byID.GetBlocking() {
		t.Fatalf("a certificate for the identifier: %+v", byID)
	}
	byName := certificateCheck("web01", "web01")
	if byName.Passed == nil || *byName.Passed {
		t.Fatalf("a certificate for the name: %+v", byName)
	}
	unknown := certificateCheck("", "web01")
	if unknown.Passed != nil {
		t.Fatalf("an unloaded certificate is not a known answer: %+v", unknown)
	}
}

// A name that resolves to one of this host's addresses is the host's own
// record; one that resolves elsewhere blocks the rename. The lookup goes
// to the resolver, so the test uses localhost, which every resolver knows.
func TestDNSCheckComparesWithOwnAddresses(t *testing.T) {
	own := map[string]bool{"127.0.0.1": true, "::1": true}
	check := dnsCheck(context.Background(), "localhost", own)
	if check.Passed == nil {
		t.Skipf("the resolver did not answer for localhost: %s", check.GetDetail())
	}
	if !*check.Passed || !check.GetBlocking() {
		t.Fatalf("localhost against its own addresses: %+v", check)
	}
	foreign := dnsCheck(context.Background(), "localhost", map[string]bool{"10.0.0.1": true})
	if foreign.Passed == nil || *foreign.Passed {
		t.Fatalf("localhost against a foreign address: %+v", foreign)
	}
}

func TestPreflightNamesEveryCheck(t *testing.T) {
	checks := hostnamePreflight(context.Background(), "localhost", "web01", "id-1")
	names := map[string]bool{}
	for _, check := range checks {
		names[check.GetName()] = true
	}
	for _, name := range []string{CheckHostnameCurrent, CheckHostnameDNS, CheckHostnameCertificate} {
		if !names[name] {
			t.Errorf("the check %s is missing", name)
		}
	}
}
