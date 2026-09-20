//go:build integration

package integration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/relayproof"
)

// Chapter 4 of the security document, the inner identity envelope: the relay
// proves itself in the handshake, the host with a signature over every message.

// relayClient is the agent service reached with the relay's identity: what
// a relay speaks to the centre with.
func relayClient(gateway string, identity tls.Certificate) agentv1connect.AgentServiceClient {
	return agentv1connect.NewAgentServiceClient(&http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{identity},
				RootCAs:      testTrustPool(),
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, gateway, connect.WithGRPC())
}

// attestWhole is what an upgraded relay says about the host: the
// identifier, the fingerprint, the serial and the certificate itself.
func attestWhole(headers http.Header, hostID string, leaf *x509.Certificate) {
	headers.Set("Flotestro-Relay-Host", hostID)
	headers.Set("Flotestro-Relay-Host-Fingerprint", hex.EncodeToString(pki.Fingerprint(leaf)))
	headers.Set("Flotestro-Relay-Host-Serial", leaf.SerialNumber.String())
	headers.Set("Flotestro-Relay-Host-Certificate", base64.StdEncoding.EncodeToString(leaf.Raw))
}

// hostSigner is the host's side of the envelope: the key of its identity,
// signing for the relay it goes through.
func hostSigner(t *testing.T, hostID, relayID string, identity tls.Certificate, leaf *x509.Certificate) *relayproof.Signer {
	t.Helper()
	key, ok := identity.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("the test identity carries no signing key")
	}
	return relayproof.NewSigner(key, hostID, leaf.SerialNumber.String(), relayID, uuid.NewString())
}

// relayedStream is a relayed session the test drives message by message.
type relayedStream struct {
	stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.ServerMessage]
	signer *relayproof.Signer
	cancel context.CancelFunc
	// server carries what the centre sends down after the session configuration.
	server chan *agentv1.ServerMessage
}

// awaitAck waits for the panel's acknowledgement of the message of the
// envelope.
func (r *relayedStream) awaitAck(envelope *agentv1.RelayedEnvelope, limit time.Duration) (*agentv1.MessageAck, error) {
	deadline := time.After(limit)
	for {
		select {
		case message, ok := <-r.server:
			if !ok {
				return nil, errors.New("the session ended before the acknowledgement arrived")
			}
			ack := message.GetMessageAck()
			if ack == nil {
				continue
			}
			if ack.GetSessionId() == envelope.GetSessionId() && ack.GetSequence() == envelope.GetSequence() {
				return ack, nil
			}
		case <-deadline:
			return nil, fmt.Errorf("sequence %d of session %s was not acknowledged within %s",
				envelope.GetSequence(), envelope.GetSessionId(), limit)
		}
	}
}

func (r *relayedStream) close() {
	_ = r.stream.CloseRequest()
	_ = r.stream.CloseResponse()
	r.cancel()
}

// send signs and sends a message of the host.
func (r *relayedStream) send(msg *agentv1.AgentMessage) error {
	if err := r.signer.SignMessage(msg); err != nil {
		return err
	}
	return r.stream.Send(msg)
}

// openRelayedStream opens the session of a host through the played relay with
// the given Hello, already signed or altered as the test wants, and waits for
// the session configuration.
func openRelayedStream(ctx context.Context, gateway string, relay testRelay, hostID string,
	leaf *x509.Certificate, signer *relayproof.Signer, hello *agentv1.AgentMessage) (*relayedStream, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	stream := relayClient(gateway, relay.Cert).Connect(streamCtx)
	attestWhole(stream.RequestHeader(), hostID, leaf)
	session := &relayedStream{stream: stream, signer: signer, cancel: cancel}
	if err := stream.Send(hello); err != nil {
		session.close()
		return nil, err
	}
	first, err := stream.Receive()
	if err != nil {
		session.close()
		return nil, err
	}
	if first.GetSessionConfig() == nil {
		session.close()
		return nil, errors.New("the server answered Hello with something other than the session configuration")
	}
	// From here the test reads the downward stream the way a relay does: one
	// reader, everything the centre sends buffered for whoever waits for it.
	session.server = make(chan *agentv1.ServerMessage, 64)
	go func() {
		defer close(session.server)
		for {
			message, err := stream.Receive()
			if err != nil {
				return
			}
			select {
			case session.server <- message:
			case <-streamCtx.Done():
				return
			}
		}
	}()
	return session, nil
}

// signedHello is the first message of a session, signed by the host.
func signedHello(t *testing.T, signer *relayproof.Signer, capabilities *agentv1.Capabilities) *agentv1.AgentMessage {
	t.Helper()
	message := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		AgentVersion: "test", BootId: uuid.NewString(), Capabilities: capabilities,
	}}}
	if err := signer.SignMessage(message); err != nil {
		t.Fatal(err)
	}
	return message
}

// awaitRefusal waits for the gateway to write the refusal on the host: the
// stream is handled asynchronously, and the record follows the message by a
// moment.
func (h *harness) awaitRefusal(hostID, code string, limit time.Duration) bool {
	h.t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if view := h.hostRefusal(hostID); view != nil && view.Code == code {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

// TestARelayedSessionCarriesTheHostsOwnSignature plays a relay that attests
// the host and a host that signs its envelope: the session is end_to_end on
// the host.
func TestARelayedSessionCarriesTheHostsOwnSignature(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)
	relay := h.enrollRelay(t, []string{"envelope-relay.flotestro.test"})
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// The host signs; the session opens end to end.
	signer := hostSigner(t, host.ID, relay.ID, identity, leaf)
	firstHello := signedHello(t, signer, nil)
	session, err := openRelayedStream(ctx, gateway, relay, host.ID, leaf, signer, proto.Clone(firstHello).(*agentv1.AgentMessage))
	if err != nil {
		t.Fatalf("the signed relayed session was refused: %v", err)
	}
	defer session.close()
	if strength := h.relayIdentityOf(host.ID); strength != "end_to_end" {
		t.Fatalf("the host says its session was %q, expected end_to_end", strength)
	}

	// A heartbeat signed and sent: the panel applies it and only then says it has
	// it.
	heartbeat := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}
	if err := session.send(heartbeat); err != nil {
		t.Fatalf("the signed heartbeat was not sent: %v", err)
	}
	ack, err := session.awaitAck(heartbeat.GetEnvelope(), 15*time.Second)
	if err != nil {
		t.Fatalf("the consumed heartbeat was not acknowledged: %v", err)
	}
	if ack.GetHostId() != host.ID {
		t.Fatalf("the acknowledgement names host %q, the session is the one of %s", ack.GetHostId(), host.ID)
	}

	// The same message once more: a relay whose link broke while its spool was
	// draining never saw the acknowledgement and carries the record again.
	refusalBefore := fmt.Sprintf("%+v", h.hostRefusal(host.ID))
	if err := session.stream.Send(heartbeat); err != nil {
		t.Fatalf("the redelivered heartbeat was not sent: %v", err)
	}
	if _, err := session.awaitAck(heartbeat.GetEnvelope(), 15*time.Second); err != nil {
		t.Fatalf("the redelivered heartbeat was not acknowledged; its record would stay in the spool: %v", err)
	}
	if after := fmt.Sprintf("%+v", h.hostRefusal(host.ID)); after != refusalBefore {
		t.Fatalf("a redelivered message changed the refusal on the host from %s to %s", refusalBefore, after)
	}
	later := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}
	if err := session.send(later); err != nil {
		t.Fatalf("the session did not survive the redelivery: %v", err)
	}
	if _, err := session.awaitAck(later.GetEnvelope(), 15*time.Second); err != nil {
		t.Fatalf("the heartbeat after the redelivery was not acknowledged: %v", err)
	}

	// A payload changed after the signature: refused, with the code on
	// the host.
	tampered := signedHello(t, hostSigner(t, host.ID, relay.ID, identity, leaf), nil)
	tampered.GetHello().AgentVersion = "test-altered"
	if altered, err := openRelayedStream(ctx, gateway, relay, host.ID, leaf, nil, tampered); err == nil {
		altered.close()
		t.Fatal("a payload changed after the signature opened a session")
	}
	if !h.awaitRefusal(host.ID, "relay_body_hash_mismatch", 10*time.Second) {
		t.Fatalf("the refusal on the host = %+v, expected relay_body_hash_mismatch", h.hostRefusal(host.ID))
	}

	// The Hello of the first session, carried again as a new session: the
	// sequence of that session was spent.
	if replayed, err := openRelayedStream(ctx, gateway, relay, host.ID, leaf, nil, firstHello); err == nil {
		replayed.close()
		t.Fatal("a replayed Hello opened a session")
	}
	if !h.awaitRefusal(host.ID, "relay_sequence_replayed", 10*time.Second) {
		t.Fatalf("the refusal on the host = %+v, expected relay_sequence_replayed", h.hostRefusal(host.ID))
	}

	// A signature by another key under the host's name: the key is not
	// the certificate's.
	impostor, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := signedHello(t, relayproof.NewSigner(impostor, host.ID, leaf.SerialNumber.String(), relay.ID, uuid.NewString()), nil)
	if opened, err := openRelayedStream(ctx, gateway, relay, host.ID, leaf, nil, forged); err == nil {
		opened.close()
		t.Fatal("a message signed with another key opened a session")
	}
	if !h.awaitRefusal(host.ID, "relay_host_signature_invalid", 10*time.Second) {
		t.Fatalf("the refusal on the host = %+v, expected relay_host_signature_invalid", h.hostRefusal(host.ID))
	}

	// An envelope for another relay than the one that forwarded it.
	elsewhere := signedHello(t, relayproof.NewSigner(identity.PrivateKey.(crypto.Signer), host.ID,
		leaf.SerialNumber.String(), uuid.NewString(), uuid.NewString()), nil)
	if opened, err := openRelayedStream(ctx, gateway, relay, host.ID, leaf, nil, elsewhere); err == nil {
		opened.close()
		t.Fatal("an envelope naming another relay opened a session")
	}
	if !h.awaitRefusal(host.ID, "relay_envelope_invalid", 10*time.Second) {
		t.Fatalf("the refusal on the host = %+v, expected relay_envelope_invalid", h.hostRefusal(host.ID))
	}

	// No envelope at all: the packaged mode lets the session in on the
	// relay's attestation, and the host says so.
	if err := knockAs(ctx, gateway, relay.Cert, attestationOf(host.ID, leaf)); err != nil {
		t.Fatalf("an unsigned relayed session was refused under the packaged mode: %v", err)
	}
	if strength := h.relayIdentityOf(host.ID); strength != "attested" {
		t.Fatalf("the host says its unsigned session was %q, expected attested", strength)
	}
}

// TestARelayedRenewalIsBoundToTheOldKey plays the relay on a renewal: the
// challenge goes through the relay, the proof is signed with the host's key.
func TestARelayedRenewalIsBoundToTheOldKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)
	relay := h.enrollRelay(t, []string{"renewal-relay.flotestro.test"})
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	client := relayClient(gateway, relay.Cert)
	hostKey := identity.PrivateKey.(crypto.Signer)

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := relayCSR(t, newKey, host.ID, nil)
	block, _ := pem.Decode(csrPEM)

	// Without the proof: refused, and the host says what to upgrade.
	bare := connect.NewRequest(&agentv1.RenewCertificateRequest{CsrPem: csrPEM})
	attestWhole(bare.Header(), host.ID, leaf)
	if _, err := client.RenewCertificate(ctx, bare); err == nil {
		t.Fatal("a relayed renewal without the proof was accepted")
	}
	if view := h.hostRefusal(host.ID); view == nil || view.Code != "blocked_upgrade_required" {
		t.Fatalf("the refusal on the host = %+v, expected blocked_upgrade_required", view)
	}

	challenge := func() []byte {
		request := connect.NewRequest(&agentv1.IdentityChallengeRequest{})
		attestWhole(request.Header(), host.ID, leaf)
		response, err := client.RequestIdentityChallenge(ctx, request)
		if err != nil {
			t.Fatalf("the challenge was refused through the relay: %v", err)
		}
		if response.Msg.GetRelayId() != relay.ID {
			t.Fatalf("the challenge names relay %q, the call went through %q", response.Msg.GetRelayId(), relay.ID)
		}
		return response.Msg.GetChallenge()
	}
	renewal := func(key crypto.Signer, challengeBytes []byte) *connect.Request[agentv1.RenewCertificateRequest] {
		message := &agentv1.RenewCertificateRequest{CsrPem: csrPEM, ServerChallenge: challengeBytes}
		proof, err := relayproof.SignRenewalProof(key, block.Bytes, challengeBytes, relay.ID)
		if err != nil {
			t.Fatal(err)
		}
		message.Proof = proof
		signer := relayproof.NewSigner(hostKey, host.ID, leaf.SerialNumber.String(), relay.ID, uuid.NewString())
		envelope, err := signer.SignRequest(relayproof.KindRenewCertificate, message)
		if err != nil {
			t.Fatal(err)
		}
		message.Identity = envelope
		request := connect.NewRequest(message)
		attestWhole(request.Header(), host.ID, leaf)
		return request
	}

	// A proof by another key: the challenge is spent, the renewal refused.
	impostor, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := client.RenewCertificate(ctx, renewal(impostor, challenge())); err == nil {
		t.Fatal("a renewal proof by another key was accepted")
	}
	if view := h.hostRefusal(host.ID); view == nil || view.Code != "relay_host_signature_invalid" {
		t.Fatalf("the refusal on the host = %+v, expected relay_host_signature_invalid", view)
	}

	// The real thing: the old key signs the proof, the certificate comes
	// back for the host of the registry, and the challenge is spent by it.
	spent := challenge()
	response, err := client.RenewCertificate(ctx, renewal(hostKey, spent))
	if err != nil {
		t.Fatalf("the relayed renewal was refused: %v", err)
	}
	_, renewed := tlsPair(t, newKey, response.Msg.GetCertificatePem())
	if id, err := pki.HostIDFromCert(renewed); err != nil || id != host.ID {
		t.Fatalf("the renewed certificate names %q %v, expected host %s", id, err, host.ID)
	}
	if _, err := client.RenewCertificate(ctx, renewal(hostKey, spent)); err == nil {
		t.Fatal("a spent challenge renewed a second time")
	}
	if view := h.hostRefusal(host.ID); view == nil || view.Code != "relay_envelope_invalid" {
		t.Fatalf("the refusal on the host = %+v, expected relay_envelope_invalid", view)
	}
}

// TestASecretFetchedThroughARelayIsSealed drives a whole path: a relayed
// session of a synthetic host receives a task that names a secret, and the
// fetch answers sealed to the host's one-time key, never in the clear.
func TestASecretFetchedThroughARelayIsSealed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gateway := envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)
	relay := h.enrollRelay(t, []string{"secret-relay.flotestro.test"})
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	value := "sealed-through-the-relay-" + fmt.Sprint(time.Now().UnixNano())
	secret := newSecret(t, h, value)

	// The synthetic host announces the adapter the operation needs, so the
	// scheduler dispatches to it.
	signer := hostSigner(t, host.ID, relay.ID, identity, leaf)
	capabilities := &agentv1.Capabilities{Registry: []*agentv1.Capability{
		{Name: "files.managed", Version: 1, Available: true},
		{Name: relayproof.Capability, Version: 1, Available: true, Features: map[string]bool{relayproof.Feature: true}},
	}}
	session, err := openRelayedStream(ctx, gateway, relay, host.ID, leaf, signer, signedHello(t, signer, capabilities))
	if err != nil {
		t.Fatalf("the signed relayed session was refused: %v", err)
	}
	defer session.close()

	// The task arrives on the stream the session already reads: the
	// acknowledgements of the panel come down the same one, and a second reader
	// would take the task off it.
	awaitTask := func(limit time.Duration) *agentv1.TaskEnvelope {
		deadline := time.After(limit)
		for {
			select {
			case message, ok := <-session.server:
				if !ok {
					return nil
				}
				if task := message.GetTask(); task != nil {
					return task
				}
			case <-deadline:
				return nil
			}
		}
	}
	job := h.createOperation(host.ID, map[string]any{
		"action": "file.ensure", "reason": secretReason,
		"payload": map[string]any{"file": map[string]any{
			"path": "/etc/flotestro-relay-secret-test.conf", "mode": "600",
			"content_secret": map[string]any{"name": secret.Name},
		}},
	})
	if job.RequiresApproval {
		h.approve(job.ID, job.PayloadHash)
	}
	t.Cleanup(func() { h.cancelJob(job.ID) })
	task := awaitTask(90 * time.Second)
	if task == nil {
		t.Fatalf("the task did not reach the relayed session; the job is %s", h.job(job.ID).State)
	}

	client := relayClient(gateway, relay.Cert)
	hostKey := identity.PrivateKey.(crypto.Signer)

	// Without the host's proof: refused, whatever the relay attests.
	bare := connect.NewRequest(&agentv1.FetchSecretRequest{TaskId: task.GetTaskId(), SecretName: secret.Name})
	attestWhole(bare.Header(), host.ID, leaf)
	if _, err := client.FetchSecret(ctx, bare); err == nil {
		t.Fatal("a relayed secret fetch without the proof was answered")
	}
	if view := h.hostRefusal(host.ID); view == nil || view.Code != "blocked_upgrade_required" {
		t.Fatalf("the refusal on the host = %+v, expected blocked_upgrade_required", view)
	}

	// With the proof and a one-time key: sealed, and nothing in the clear.
	ephemeral, err := relayproof.NewEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	message := &agentv1.FetchSecretRequest{
		TaskId: task.GetTaskId(), SecretName: secret.Name, EphemeralPublicKey: ephemeral.PublicKey(),
	}
	if message.EphemeralKeySignature, err = relayproof.SignEphemeralKey(hostKey, task.GetTaskId(), secret.Name,
		ephemeral.PublicKey()); err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.ForCall().SignRequest(relayproof.KindFetchSecret, message)
	if err != nil {
		t.Fatal(err)
	}
	message.Identity = envelope
	request := connect.NewRequest(message)
	attestWhole(request.Header(), host.ID, leaf)
	response, err := client.FetchSecret(ctx, request)
	if err != nil {
		t.Fatalf("the relayed secret fetch was refused: %v", err)
	}
	answer := response.Msg
	if len(answer.GetValue()) != 0 || answer.GetSha256() != "" {
		t.Fatal("the relayed answer carries the value or its digest in the clear")
	}
	if answer.GetSealing() != relayproof.Sealing || len(answer.GetSealedValue()) == 0 ||
		len(answer.GetSealedNonce()) == 0 || len(answer.GetServerPublicKey()) == 0 {
		t.Fatalf("the relayed answer is not sealed: %+v", answer)
	}
	if strings.Contains(string(answer.GetSealedValue()), value) {
		t.Fatal("the sealed value contains the plaintext")
	}
	opened, err := ephemeral.Open(answer.GetServerPublicKey(), answer.GetSealedValue(), answer.GetSealedNonce(),
		relayproof.SecretAAD(task.GetTaskId(), secret.Name, answer.GetVersion()))
	if err != nil || string(opened) != value {
		t.Fatalf("the sealed value did not open to the secret: %q %v", opened, err)
	}
}

// TestARenewalThroughTheLabRelayWorks walks the whole path: a host of the lab
// asks the relay on the Ubuntu machine for a challenge and renews with the
// proof, and the panel issues the certificate.
func TestARenewalThroughTheLabRelayWorks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	relay := envOr("FLOTESTRO_TEST_RELAY", defaultRelay)
	address := strings.TrimPrefix(relay, "https://")
	if conn, err := net.DialTimeout("tcp", address, 3*time.Second); err != nil {
		t.Skipf("the lab relay at %s does not answer: %v", address, err)
	} else {
		_ = conn.Close()
	}
	host, identity := h.enrollSyntheticHostWithIdentity(t)
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// The relay names itself in its certificate; the host learns whom it
	// reached from the handshake, as the agent does.
	var relayID string
	client := agentv1connect.NewAgentServiceClient(&http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{identity},
				RootCAs:      testTrustPool(),
				MinVersion:   tls.VersionTLS13,
				VerifyConnection: func(state tls.ConnectionState) error {
					if len(state.PeerCertificates) > 0 {
						relayID, _ = pki.RelayIDFromCert(state.PeerCertificates[0])
					}
					return nil
				},
			},
		},
	}, relay, connect.WithGRPC())

	challenge, err := client.RequestIdentityChallenge(ctx, connect.NewRequest(&agentv1.IdentityChallengeRequest{}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			t.Fatalf("the relay at %s does not forward the renewal challenge; it predates the envelope and needs the upgrade", address)
		}
		t.Fatalf("the challenge was refused through the lab relay: %v", err)
	}
	if relayID == "" || challenge.Msg.GetRelayId() != relayID {
		t.Fatalf("the challenge names relay %q, the handshake reached %q", challenge.Msg.GetRelayId(), relayID)
	}

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := relayCSR(t, newKey, host.ID, nil)
	block, _ := pem.Decode(csrPEM)
	hostKey := identity.PrivateKey.(crypto.Signer)
	message := &agentv1.RenewCertificateRequest{CsrPem: csrPEM, ServerChallenge: challenge.Msg.GetChallenge()}
	if message.Proof, err = relayproof.SignRenewalProof(hostKey, block.Bytes, challenge.Msg.GetChallenge(), relayID); err != nil {
		t.Fatal(err)
	}
	signer := relayproof.NewSigner(hostKey, host.ID, leaf.SerialNumber.String(), relayID, uuid.NewString())
	if message.Identity, err = signer.SignRequest(relayproof.KindRenewCertificate, message); err != nil {
		t.Fatal(err)
	}
	response, err := client.RenewCertificate(ctx, connect.NewRequest(message))
	if err != nil {
		t.Fatalf("the renewal through the lab relay was refused: %v", err)
	}
	_, renewed := tlsPair(t, newKey, response.Msg.GetCertificatePem())
	if id, err := pki.HostIDFromCert(renewed); err != nil || id != host.ID {
		t.Fatalf("the renewed certificate names %q %v, expected host %s", id, err, host.ID)
	}
}
