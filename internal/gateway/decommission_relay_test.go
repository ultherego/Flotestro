package gateway

// The decommission handshake of a host behind a relay: the panel's own order
// must not cut off the messages that are its evidence.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/relayproof"
)

func signedMessage(t *testing.T, signer *relayproof.Signer, message *agentv1.AgentMessage) *agentv1.AgentMessage {
	t.Helper()
	if err := signer.SignMessage(message); err != nil {
		t.Fatal(err)
	}
	return message
}

// The order moves the host to retiring before the final task goes out and
// revokes its certificates before the commit. Every relayed message is checked
// against the record, so the two messages of the handshake were refused by the
// panel's own doing: the answer to the final task never arrived, the host was
// retired without the commit ever being sent, and the report that says what
// became of the wipe had no session left to travel on. The panel then had
// nothing but a closed session, which a failed wipe closes too.
func TestTheFinalHandshakeOfARelayedHostSurvivesItsOwnDecommission(t *testing.T) {
	host := newTestHost(t, true)
	ctx := context.Background()
	signer := host.signer(uuid.NewString())

	// The state of the host while the handshake runs: retiring, and from the
	// commit on with every certificate revoked.
	host.records.certificate.LifecycleState = hosts.StateRetiring
	host.records.host.LifecycleState = hosts.StateRetiring

	ready := signedMessage(t, signer, &agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_FinalReady{FinalReady: &agentv1.FinalReady{
			LeasesDropped: true,
		}},
	})
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, ready); err != nil {
		t.Fatalf("the answer to the final task of a retiring host was refused: %v", err)
	}

	host.records.certificate.Revoked = true
	report := signedMessage(t, signer, &agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_FinalWipeReport{FinalWipeReport: &agentv1.FinalWipeReport{
			Accepted: true, RemovedPaths: []string{"/etc/flotestro/agent.key"},
		}},
	})
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, report); err != nil {
		t.Fatalf("the report of the final wipe was refused, so the wipe has no evidence: %v", err)
	}
}

// What a revoked certificate may do is finish the handshake and nothing else:
// no work of any kind, and no new session.
func TestARevokedCertificateCarriesNothingBesidesTheFinalHandshake(t *testing.T) {
	host := newTestHost(t, true)
	ctx := context.Background()
	host.records.certificate.LifecycleState = hosts.StateRetiring
	host.records.host.LifecycleState = hosts.StateRetiring
	host.records.certificate.Revoked = true

	signer := host.signer(uuid.NewString())
	heartbeat := signedMessage(t, signer, &agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}},
	})
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, heartbeat); refusalCode(err) != hosts.RefusalRevokedCertificate {
		t.Fatalf("a heartbeat on a revoked certificate answered %q", refusalCode(err))
	}

	hello := signedHello(t, host.signer(uuid.NewString()))
	if _, err := host.verifier.VerifyMessage(ctx, host.peer, hello); refusalCode(err) != hosts.RefusalRevokedCertificate {
		t.Fatalf("a session opened on a revoked certificate answered %q", refusalCode(err))
	}
}

// The exemption is for the refusals the decommission itself causes. A
// certificate on record for another host does not deliver a wipe report.
func TestAWipeReportOfAnotherHostIsStillRefused(t *testing.T) {
	host := newTestHost(t, true)
	host.records.certificate.HostID = uuid.NewString()

	report := signedMessage(t, host.signer(uuid.NewString()), &agentv1.AgentMessage{
		Payload: &agentv1.AgentMessage_FinalWipeReport{FinalWipeReport: &agentv1.FinalWipeReport{
			Accepted: true,
		}},
	})
	_, err := host.verifier.VerifyMessage(context.Background(), host.peer, report)
	if refusalCode(err) != hosts.RefusalIdentityMismatch {
		t.Fatalf("a wipe report under another host's certificate answered %q", refusalCode(err))
	}
}
