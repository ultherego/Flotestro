package relayproof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func helloMessage() *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		AgentVersion: "0.54.0", BootId: "boot-1",
		Capabilities: &agentv1.Capabilities{Registry: []*agentv1.Capability{
			{Name: Capability, Available: true, Features: map[string]bool{"v2": true, "v1": false}},
		}},
	}}}
}

// A signed message verifies under the host's public key, the kind is the
// name of the payload field, and the sequence counts up from one across
// the messages of a session.
func TestASignedMessageVerifiesAndCountsUp(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(key, "host-1", "42", "relay-1", "session-1")
	message := helloMessage()
	if err := signer.SignMessage(message); err != nil {
		t.Fatal(err)
	}
	envelope := message.GetEnvelope()
	if envelope.GetSequence() != 1 || envelope.GetMessageKind() != "hello" ||
		envelope.GetHostId() != "host-1" || envelope.GetRelayId() != "relay-1" ||
		envelope.GetCertificateSerial() != "42" || envelope.GetSchemaVersion() != SchemaVersion {
		t.Fatalf("the envelope reads %+v", envelope)
	}
	if err := Verify(&key.PublicKey, envelope); err != nil {
		t.Fatalf("the signature did not verify: %v", err)
	}
	kind, body, err := Payload(message)
	if err != nil || kind != "hello" {
		t.Fatalf("the payload reads %q %v", kind, err)
	}
	if matches, err := DigestMatches(envelope, body); err != nil || !matches {
		t.Fatalf("the digest of the payload does not match: %v %v", matches, err)
	}

	heartbeat := &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{
		Heartbeat: &agentv1.Heartbeat{}}}
	if err := signer.SignMessage(heartbeat); err != nil {
		t.Fatal(err)
	}
	if heartbeat.GetEnvelope().GetSequence() != 2 || heartbeat.GetEnvelope().GetMessageKind() != "heartbeat" {
		t.Fatalf("the second envelope reads %+v", heartbeat.GetEnvelope())
	}
	if string(heartbeat.GetEnvelope().GetNonce()) == string(envelope.GetNonce()) {
		t.Fatal("two envelopes share a nonce")
	}
}

// A payload changed after the signature no longer matches the digest, and
// the digest is the same whatever the order a map was filled in: the
// encoding is deterministic, so the gateway's re-encoding agrees with the
// agent's.
func TestATamperedPayloadDoesNotMatchTheDigest(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(key, "host-1", "42", "relay-1", "session-1")
	message := helloMessage()
	if err := signer.SignMessage(message); err != nil {
		t.Fatal(err)
	}
	// The relay re-encodes: a decoded copy digests the same.
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var carried agentv1.AgentMessage
	if err := proto.Unmarshal(encoded, &carried); err != nil {
		t.Fatal(err)
	}
	_, body, _ := Payload(&carried)
	if matches, _ := DigestMatches(carried.GetEnvelope(), body); !matches {
		t.Fatal("a re-encoded payload does not match its digest")
	}
	// One byte of the payload changed on the way.
	carried.GetHello().AgentVersion = "0.54.1"
	_, body, _ = Payload(&carried)
	if matches, _ := DigestMatches(carried.GetEnvelope(), body); matches {
		t.Fatal("a changed payload still matches the digest")
	}
}

// A signature made with another key, or an envelope with one field
// changed after the signature, does not verify; an envelope of another
// shape is refused before the key is consulted.
func TestATamperedEnvelopeDoesNotVerify(t *testing.T) {
	key := testKey(t)
	other := testKey(t)
	signer := NewSigner(key, "host-1", "42", "relay-1", "session-1")
	envelope, err := signer.Next("heartbeat", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&other.PublicKey, envelope); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("another key verified the envelope: %v", err)
	}
	for name, change := range map[string]func(e *agentv1.RelayedEnvelope){
		"the host":     func(e *agentv1.RelayedEnvelope) { e.HostId = "host-2" },
		"the relay":    func(e *agentv1.RelayedEnvelope) { e.RelayId = "relay-2" },
		"the sequence": func(e *agentv1.RelayedEnvelope) { e.Sequence++ },
		"the kind":     func(e *agentv1.RelayedEnvelope) { e.MessageKind = "task_result" },
		"the digest":   func(e *agentv1.RelayedEnvelope) { e.BodySha256[0] ^= 1 },
		"the serial":   func(e *agentv1.RelayedEnvelope) { e.CertificateSerial = "43" },
		"the session":  func(e *agentv1.RelayedEnvelope) { e.SessionId = "session-2" },
		"the time":     func(e *agentv1.RelayedEnvelope) { e.IssuedAtUnix++ },
		"the nonce":    func(e *agentv1.RelayedEnvelope) { e.Nonce[0] ^= 1 },
	} {
		copied := proto.Clone(envelope).(*agentv1.RelayedEnvelope)
		change(copied)
		if err := Verify(&key.PublicKey, copied); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s changed after the signature still verified: %v", name, err)
		}
	}
	for name, change := range map[string]func(e *agentv1.RelayedEnvelope){
		"another schema":  func(e *agentv1.RelayedEnvelope) { e.SchemaVersion = 1 },
		"a short nonce":   func(e *agentv1.RelayedEnvelope) { e.Nonce = e.Nonce[:8] },
		"a zero sequence": func(e *agentv1.RelayedEnvelope) { e.Sequence = 0 },
		"no host":         func(e *agentv1.RelayedEnvelope) { e.HostId = "" },
		"no signature":    func(e *agentv1.RelayedEnvelope) { e.HostSignature = nil },
		"a short digest":  func(e *agentv1.RelayedEnvelope) { e.BodySha256 = e.BodySha256[:16] },
		"no kind":         func(e *agentv1.RelayedEnvelope) { e.MessageKind = "" },
		"no session":      func(e *agentv1.RelayedEnvelope) { e.SessionId = "" },
		"no serial":       func(e *agentv1.RelayedEnvelope) { e.CertificateSerial = "" },
	} {
		copied := proto.Clone(envelope).(*agentv1.RelayedEnvelope)
		change(copied)
		if err := Verify(&key.PublicKey, copied); !errors.Is(err, ErrShape) {
			t.Errorf("%s was not refused as a shape: %v", name, err)
		}
	}
	if err := Verify(nil, envelope); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("a missing key answered %v", err)
	}
}

// A unary request is signed as a session of its own with sequence 1, over
// the request with its identity field cleared.
func TestAUnaryRequestIsSignedOverItsBody(t *testing.T) {
	key := testKey(t)
	signer := NewSigner(key, "host-1", "42", "relay-1", "call-1")
	request := &agentv1.FetchSecretRequest{TaskId: "task-1", SecretName: "db.password", SecretVersion: 3}
	envelope, err := signer.SignRequest(KindFetchSecret, request)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.GetSequence() != 1 || envelope.GetMessageKind() != KindFetchSecret {
		t.Fatalf("the envelope reads %+v", envelope)
	}
	request.Identity = envelope
	// The gateway clears the identity before it digests the body.
	body := proto.Clone(request).(*agentv1.FetchSecretRequest)
	body.Identity = nil
	if matches, _ := DigestMatches(envelope, body); !matches {
		t.Fatal("the request does not match the digest it carries")
	}
	body.SecretVersion = 4
	if matches, _ := DigestMatches(envelope, body); matches {
		t.Fatal("a changed request still matches the digest")
	}
}

// The renewal proof binds the CSR, the challenge and the relay: a change of
// any of the three, or another key, does not verify.
func TestTheRenewalProofBindsTheCSRTheChallengeAndTheRelay(t *testing.T) {
	key := testKey(t)
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	csr := []byte("a certificate request")
	proof, err := SignRenewalProof(key, csr, challenge, "relay-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRenewalProof(&key.PublicKey, csr, challenge, "relay-1", proof); err != nil {
		t.Fatalf("the proof did not verify: %v", err)
	}
	if err := VerifyRenewalProof(&key.PublicKey, []byte("another request"), challenge, "relay-1", proof); !errors.Is(err, ErrBadSignature) {
		t.Errorf("another CSR verified: %v", err)
	}
	if err := VerifyRenewalProof(&key.PublicKey, csr, challenge, "relay-2", proof); !errors.Is(err, ErrBadSignature) {
		t.Errorf("another relay verified: %v", err)
	}
	other, _ := NewChallenge()
	if err := VerifyRenewalProof(&key.PublicKey, csr, other, "relay-1", proof); !errors.Is(err, ErrBadSignature) {
		t.Errorf("another challenge verified: %v", err)
	}
	if err := VerifyRenewalProof(&key.PublicKey, csr, challenge[:16], "relay-1", proof); !errors.Is(err, ErrShape) {
		t.Errorf("a short challenge was not refused as a shape: %v", err)
	}
	if _, err := SignRenewalProof(key, csr, challenge[:16], "relay-1"); err == nil {
		t.Error("a short challenge was signed")
	}
}

// A value sealed to the host's one-time key opens with that key and the
// panel's public key, under the same associated data - and under nothing
// else.
func TestASealedValueOpensOnlyForItsKeyAndItsLease(t *testing.T) {
	hostKey := testKey(t)
	ephemeral, err := NewEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignEphemeralKey(hostKey, "task-1", "db.password", ephemeral.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEphemeralKey(&hostKey.PublicKey, "task-1", "db.password", ephemeral.PublicKey(), signature); err != nil {
		t.Fatalf("the ephemeral key did not verify: %v", err)
	}
	if err := VerifyEphemeralKey(&hostKey.PublicKey, "task-2", "db.password", ephemeral.PublicKey(), signature); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a key signed for one task verified for another: %v", err)
	}
	if err := VerifyEphemeralKey(&hostKey.PublicKey, "task-1", "db.password", ephemeral.PublicKey()[:16], signature); !errors.Is(err, ErrShape) {
		t.Errorf("a short key was not refused as a shape: %v", err)
	}

	aad := SecretAAD("task-1", "db.password", 3)
	sealed, nonce, serverPublic, err := Seal(ephemeral.PublicKey(), []byte("hunter2"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) == "hunter2" || len(sealed) <= len("hunter2") {
		t.Fatal("the sealed value is not sealed")
	}
	opened, err := ephemeral.Open(serverPublic, sealed, nonce, aad)
	if err != nil || string(opened) != "hunter2" {
		t.Fatalf("the sealed value did not open: %q %v", opened, err)
	}
	if _, err := ephemeral.Open(serverPublic, sealed, nonce, SecretAAD("task-1", "db.password", 4)); !errors.Is(err, ErrSealing) {
		t.Errorf("the value opened under another lease: %v", err)
	}
	other, _ := NewEphemeralKey()
	if _, err := other.Open(serverPublic, sealed, nonce, aad); !errors.Is(err, ErrSealing) {
		t.Errorf("the value opened with another key: %v", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[0] ^= 1
	if _, err := ephemeral.Open(serverPublic, tampered, nonce, aad); !errors.Is(err, ErrSealing) {
		t.Errorf("a tampered cipher text opened: %v", err)
	}
	if _, _, _, err := Seal([]byte("short"), []byte("x"), aad); !errors.Is(err, ErrSealing) {
		t.Errorf("a key that is not one was sealed to: %v", err)
	}
}
