package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/advertise"
	"github.com/ultherego/flotestro/internal/pki"
)

// records is the row the confirmed address lives in, played by a field.
type records struct{ record advertise.Record }

func (r *records) Read(context.Context) (advertise.Record, error) { return r.record, nil }

func (r *records) Write(_ context.Context, names []string, actor string) (advertise.Record, error) {
	r.record = advertise.Record{
		Present: true, Names: names, ConfirmedAt: time.Now().UTC(), ConfirmedBy: actor,
		Superseded: advertise.SupersededAfter(r.record, names),
		Revision:   r.record.Revision + 1,
	}
	return r.record, nil
}

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
	advertised := advertise.NewStore(&records{}, log, advertise.Parse("panel.example.test,192.0.2.10"))
	panel, err := newPanelCertificate(trust, advertised, log)
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
	if !slices.Contains(presented.DNSNames, "panel.example.test") {
		t.Errorf("the advertised names of the panel = %v", presented.DNSNames)
	}
}

// The same defect the CA exchange had, on the other axis. The address the agents
// dial is the installation's choice and an administrator confirms it while the
// panel runs; a certificate issued once at the start carries the loopback the
// panel started with, so the first agent to connect fails the handshake on the
// name it was told to use - and nothing says why.
func TestThePanelReissuesItsOwnCertificateWhenTheAddressIsConfirmed(t *testing.T) {
	trust, err := pki.EnsureTrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	advertised := advertise.NewStore(&records{}, log, advertise.Parse("127.0.0.1"))
	panel, err := newPanelCertificate(trust, advertised, log)
	if err != nil {
		t.Fatal(err)
	}
	first, err := x509.ParseCertificate(panel.get().Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(first.DNSNames, "panel.example.test") {
		t.Fatal("the panel is serving a name nobody confirmed")
	}
	// Until the confirmation the existing local certificate goes on working.
	if !slices.Contains(first.DNSNames, "localhost") {
		t.Errorf("the panel serves under %v, so it is reachable from nowhere", first.DNSNames)
	}

	if _, err := advertised.Confirm(context.Background(),
		advertise.Parse("panel.example.test"), "admin@example.test"); err != nil {
		t.Fatal(err)
	}
	presented, err := x509.ParseCertificate(panel.get().Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(presented.DNSNames, "panel.example.test") {
		t.Errorf("the confirmed name did not reach the certificate: %v", presented.DNSNames)
	}
	if err := presented.CheckSignatureFrom(trust.Active().Certificate); err != nil {
		t.Errorf("the reissued certificate is not signed by the authority that signs: %v", err)
	}
	// A handshake after the reissue does the work once and not per connection.
	again := bytes.Clone(panel.get().Certificate[0])
	if !bytes.Equal(panel.get().Certificate[0], again) {
		t.Error("the certificate is issued again on every handshake")
	}

	// A second change follows too, and takes the previous name out.
	if _, err := advertised.Confirm(context.Background(),
		advertise.Parse("192.0.2.20"), "admin@example.test"); err != nil {
		t.Fatal(err)
	}
	moved, err := x509.ParseCertificate(panel.get().Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(moved.DNSNames, "panel.example.test") {
		t.Errorf("the certificate still names the address the panel left: %v", moved.DNSNames)
	}
	if len(moved.IPAddresses) != 2 {
		t.Errorf("the certificate carries %v, want loopback and the confirmed address",
			moved.IPAddresses)
	}
}
