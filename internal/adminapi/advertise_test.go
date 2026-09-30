package adminapi

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/advertise"
	"github.com/ultherego/flotestro/internal/enrollment"
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

// The instruction a new host is given has to name the address that is in the
// panel's certificate. It used to be composed from a copy of
// FLOTESTRO_ADVERTISE taken when the process started, so a confirmation made
// afterwards reached the certificate and not the file the operator pasted - and
// the host then failed the handshake on a name nobody had told it about.
func TestTheGeneratedAgentConfigurationCarriesTheConfirmedAddress(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	advertised := advertise.NewStore(&records{}, log, advertise.Parse("127.0.0.1"))
	server := &Server{
		advertised: advertised,
		installation: Installation{
			GatewayAddr: ":8443", EnrollmentAddr: ":8444",
		},
	}
	request := httptest.NewRequest("GET", "/api/v1/enrollment/installation", nil)

	// Before the confirmation the panel offers what it has, which reaches only
	// this machine, and the profile says so.
	if !server.advertisedLoopback() {
		t.Fatal("a panel that has confirmed nothing claims to be reachable")
	}

	if _, err := advertised.Confirm(context.Background(),
		advertise.Parse("panel.example.test"), "admin"); err != nil {
		t.Fatal(err)
	}
	connection, err := server.installationConnection(request, "site-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if connection.EnrollmentURL != "https://panel.example.test:8444" {
		t.Errorf("a new host would enrol at %q", connection.EnrollmentURL)
	}
	config := agentConfigText(enrollment.KindAgent, "site-a", "prod", connection)
	if !strings.Contains(config, "panel.example.test:8443") {
		t.Errorf("the generated agent configuration does not name the confirmed address:\n%s", config)
	}
	if server.advertisedLoopback() {
		t.Error("the profile still warns that the panel is reachable only here")
	}

	// A second change follows the same way, without a restart.
	if _, err := advertised.Confirm(context.Background(),
		advertise.Parse("192.0.2.20"), "admin"); err != nil {
		t.Fatal(err)
	}
	connection, err = server.installationConnection(request, "site-a", "")
	if err != nil {
		t.Fatal(err)
	}
	config = agentConfigText(enrollment.KindAgent, "site-a", "prod", connection)
	switch {
	case !strings.Contains(config, "192.0.2.20:8443"):
		t.Errorf("the second confirmation did not reach the instruction:\n%s", config)
	case strings.Contains(config, "panel.example.test"):
		t.Errorf("the instruction still names the address the panel left:\n%s", config)
	}
}

// A panel started without the setting says it advertises nothing rather than
// composing an instruction against a guess.
func TestNoAdvertisedAddressComposesNoInstruction(t *testing.T) {
	server := &Server{installation: Installation{GatewayAddr: ":8443", EnrollmentAddr: ":8444"}}
	request := httptest.NewRequest("GET", "/api/v1/enrollment/installation", nil)
	if _, err := server.installationConnection(request, "site-a", ""); err != errNoAdvertisedAddress {
		t.Errorf("err = %v, want the refusal naming no advertised address", err)
	}
}
