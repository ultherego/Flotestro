package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
)

// FuzzSignAgentCSR feeds the CSR decoder what an enrolling host may send.
func FuzzSignAgentCSR(f *testing.F) {
	ca, err := EnsureCA(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	const hostID = "3f2a9c1e-0000-4000-8000-000000000001"

	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add(fuzzCSR(f, elliptic.P256(), "an-entirely-different-host", nil, nil))
	f.Add(fuzzCSR(f, elliptic.P384(), "host", []string{"panel.example.com"}, []net.IP{net.IPv4(10, 0, 0, 5)}))
	// A valid CSR with the last byte of the signature flipped: the shape of
	// a request that was tampered with in flight.
	broken := fuzzCSR(f, elliptic.P256(), "requester", nil, nil)
	block, _ := pem.Decode(broken)
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	f.Add(pem.EncodeToMemory(block))

	f.Fuzz(func(t *testing.T, csrPEM []byte) {
		issued, err := ca.SignAgentCSR(csrPEM, hostID)
		if err != nil {
			return
		}
		certBlock, _ := pem.Decode(issued.PEM)
		if certBlock == nil {
			t.Fatalf("the issued certificate is not PEM: %q", issued.PEM)
		}
		certificate, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			t.Fatalf("the issued certificate does not parse: %v", err)
		}
		if certificate.Subject.CommonName != hostID || issued.CommonName != hostID {
			t.Fatalf("the certificate carries the name %q from the request, not the granted %q",
				certificate.Subject.CommonName, hostID)
		}
		if id, err := HostIDFromCert(certificate); err != nil || id != hostID {
			t.Fatalf("host id = %q, %v; we want %q", id, err, hostID)
		}
		if len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 {
			t.Fatalf("a host certificate took network names from the request: %v %v",
				certificate.DNSNames, certificate.IPAddresses)
		}
	})
}

// fuzzCSR makes a request the way an agent or a relay does, with the names
// a relay would ask for; the host signer must ignore them.
func fuzzCSR(f *testing.F, curve elliptic.Curve, commonName string, dns []string, addresses []net.IP) []byte {
	f.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName}, DNSNames: dns, IPAddresses: addresses,
	}, key)
	if err != nil {
		f.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
