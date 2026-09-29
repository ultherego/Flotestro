package app

import (
	"bytes"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/ultherego/flotestro/internal/pki"
)

// The panel's own certificate used to be issued once, at the start. After a
// handover of signing it was still signed by the authority that had stepped
// down, and the fleet went on accepting it only for as long as nobody took
// that authority out of the trust set - at which point the panel became
// unreachable to every host, with nothing having said so.
func TestThePanelReissuesItsOwnCertificateWhenTheAuthorityChanges(t *testing.T) {
	trust, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	panel, err := newPanelCertificate(trust, []string{"panel.example.test"},
		[]net.IP{net.ParseIP("192.0.2.10")}, log)
	if err != nil {
		t.Fatal(err)
	}
	first := bytes.Clone(panel.get().Certificate[0])

	if !bytes.Equal(panel.get().Certificate[0], first) {
		t.Error("the certificate is issued again while the authority has not changed")
	}
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(panel.get().Certificate[0], first) {
		t.Error("an authority that only waits to take over should not change what the panel presents")
	}

	activated, err := trust.Activate()
	if err != nil {
		t.Fatal(err)
	}
	presented, err := x509.ParseCertificate(panel.get().Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := trust.Active().Certificate.SerialNumber.String(); got != activated.Serial {
		t.Fatalf("the set signs with %s, the handover named %s", got, activated.Serial)
	}
	if err := presented.CheckSignatureFrom(trust.Active().Certificate); err != nil {
		t.Errorf("the panel presents a certificate the authority that signs did not issue: %v", err)
	}
	// The name the fleet reaches the panel under travels to the new certificate.
	if len(presented.DNSNames) != 1 || presented.DNSNames[0] != "panel.example.test" {
		t.Errorf("the advertised names of the panel = %v", presented.DNSNames)
	}
}
