package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"testing"
)

func csrWithKey(t *testing.T, key crypto.Signer, dns []string, addresses []net.IP) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "requester"}, DNSNames: dns, IPAddresses: addresses,
	}, key)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// The key in a CSR is the one thing the requester decides, so it is the one
// thing the policy has to check: a small curve or a short modulus would weaken
// the identity of a host for the whole life of the certificate.
func TestSignCSREnforcesTheKeyPolicy(t *testing.T) {
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa3072, _ := rsa.GenerateKey(rand.Reader, 3072)

	for name, key := range map[string]crypto.Signer{"P-384": p384, "RSA-3072": rsa3072} {
		if _, err := ca.SignAgentCSR(csrWithKey(t, key, nil, nil), "host-1"); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	for name, key := range map[string]crypto.Signer{"P-224": p224, "RSA-2048": rsa2048} {
		_, err := ca.SignAgentCSR(csrWithKey(t, key, nil, nil), "host-1")
		if !errors.Is(err, ErrKeyPolicy) {
			t.Errorf("%s: err = %v, expected the key policy refusal", name, err)
		}
	}
}

// A relay is a server towards the agents of its site.
func TestRelayCertificateNeverCarriesAReservedName(t *testing.T) {
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca.Reserved = FixedNames{"panel.example.org", "192.168.56.10"}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	refused := []struct {
		dns []string
		ips []net.IP
	}{
		{dns: []string{"relay.example.org", "Panel.Example.org."}},
		{dns: []string{"localhost"}},
		{ips: []net.IP{net.ParseIP("192.168.56.10")}},
		{ips: []net.IP{net.ParseIP("127.0.0.1")}},
		{ips: []net.IP{net.ParseIP("::1")}},
	}
	for _, request := range refused {
		_, err := ca.SignRelayCSR(csrWithKey(t, key, request.dns, request.ips), "relay-1")
		if !errors.Is(err, ErrRelayNameReserved) {
			t.Errorf("names %v %v: err = %v, expected the reserved name refusal", request.dns, request.ips, err)
		}
	}
	// The names imposed by the panel from the registry go through the same
	// check: a reserved name recorded earlier is not renewed.
	if _, err := ca.SignRelayCSRWithNames(csrWithKey(t, key, nil, nil), "relay-1",
		[]string{"panel.example.org"}); !errors.Is(err, ErrRelayNameReserved) {
		t.Errorf("a reserved name from the registry was renewed: %v", err)
	}
	issued, err := ca.SignRelayCSR(csrWithKey(t, key, []string{"relay.example.org"},
		[]net.IP{net.ParseIP("192.168.56.70")}), "relay-1")
	if err != nil {
		t.Fatalf("an ordinary relay name was refused: %v", err)
	}
	if len(issued.DNSNames) != 1 || len(issued.IPAddresses) != 1 {
		t.Errorf("issued names = %v %v", issued.DNSNames, issued.IPAddresses)
	}
}

// liveNames is a reserved set that changes, the way the installation's
// advertised address does.
type liveNames struct{ names []string }

func (l *liveNames) ReservedNames() []string { return l.names }

// The quietest of the four consequences of a change of address. The CA used to
// hold a copy of the panel's names taken when the process started, so a relay
// registering after the administrator confirmed a new address was issued a
// certificate for it - and then answered in the panel's place to every agent of
// its site, while every screen said the installation was fine.
func TestTheReservedNamesFollowTheAdvertisedAddress(t *testing.T) {
	ca, err := EnsureCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	live := &liveNames{}
	ca.Reserved = live
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Nothing is reserved yet, so the name is a name like any other.
	if _, err := ca.SignRelayCSR(csrWithKey(t, key, []string{"panel.example.test"}, nil),
		"relay-1"); err != nil {
		t.Fatalf("an unreserved name was refused: %v", err)
	}
	// The administrator confirms it as the panel's own address.
	live.names = []string{"panel.example.test"}
	if _, err := ca.SignRelayCSR(csrWithKey(t, key, []string{"panel.example.test"}, nil),
		"relay-1"); !errors.Is(err, ErrRelayNameReserved) {
		t.Errorf("a relay was issued a certificate for the panel's own address: %v", err)
	}
	// And the address the panel moved off stays refused: an agent that has not
	// been reconfigured yet still dials it.
	live.names = []string{"192.0.2.20", "panel.example.test"}
	if _, err := ca.SignRelayCSR(csrWithKey(t, key, []string{"panel.example.test"}, nil),
		"relay-1"); !errors.Is(err, ErrRelayNameReserved) {
		t.Errorf("the address the panel left was handed to a relay: %v", err)
	}
	if _, err := ca.SignRelayCSR(csrWithKey(t, key, nil,
		[]net.IP{net.ParseIP("192.0.2.20")}), "relay-1"); !errors.Is(err, ErrRelayNameReserved) {
		t.Errorf("a relay was issued a certificate for the address in force: %v", err)
	}
}
