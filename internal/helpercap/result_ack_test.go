package helpercap

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

func ackSignerAndRing(t *testing.T) (*Signer, *Keyring) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{key: private, public: public, keyID: KeyID(public)}, NewKeyring(public)
}

func settled() *agentv1.TaskResultAck {
	return &agentv1.TaskResultAck{
		TaskId: "attempt-1", IdempotencyKey: "key-1", Status: agentv1.TaskResultAck_STATUS_SETTLED,
	}
}

func TestASignedResultAckIsAccepted(t *testing.T) {
	signer, ring := ackSignerAndRing(t)
	ack := settled()
	signer.SignResultAck("host-1", ack)
	if err := VerifyResultAck(ring, "host-1", ack); err != nil {
		t.Fatalf("a genuine acknowledgement was refused: %v", err)
	}
}

// What a relay can do to an acknowledgement, each of it refused.
func TestAResultAckAltered_Moved_OrInvented_IsRefused(t *testing.T) {
	signer, ring := ackSignerAndRing(t)
	_, strangerRing := ackSignerAndRing(t)

	for name, tamper := range map[string]func(*agentv1.TaskResultAck){
		"another status":      func(a *agentv1.TaskResultAck) { a.Status = agentv1.TaskResultAck_STATUS_DUPLICATE },
		"another attempt":     func(a *agentv1.TaskResultAck) { a.TaskId = "attempt-2" },
		"another key":         func(a *agentv1.TaskResultAck) { a.IdempotencyKey = "key-2" },
		"another reason":      func(a *agentv1.TaskResultAck) { a.ReasonCode = "job_already_settled" },
		"the signature wiped": func(a *agentv1.TaskResultAck) { a.Signature = nil },
		"a signature cut":     func(a *agentv1.TaskResultAck) { a.Signature = a.Signature[:10] },
		"a key nobody trusts": func(a *agentv1.TaskResultAck) { a.KeyId = "0000000000000000" },
		"the key id removed":  func(a *agentv1.TaskResultAck) { a.KeyId = "" },
	} {
		ack := settled()
		signer.SignResultAck("host-1", ack)
		tamper(ack)
		if err := VerifyResultAck(ring, "host-1", ack); err == nil {
			t.Errorf("%s: the acknowledgement was accepted", name)
		}
	}

	ack := settled()
	signer.SignResultAck("host-1", ack)
	if err := VerifyResultAck(ring, "host-2", ack); !errors.Is(err, ErrResultAckInvalid) {
		t.Errorf("an acknowledgement moved to another host: %v", err)
	}
	if err := VerifyResultAck(strangerRing, "host-1", ack); !errors.Is(err, ErrResultAckKey) {
		t.Errorf("an acknowledgement checked by a host that does not trust the key: %v", err)
	}

	// Written by somebody with no key at all: the whole of what a relay has.
	invented := settled()
	invented.KeyId, invented.Signature = signer.KeyID(), make([]byte, ed25519.SignatureSize)
	if err := VerifyResultAck(ring, "host-1", invented); !errors.Is(err, ErrResultAckInvalid) {
		t.Errorf("an invented acknowledgement: %v", err)
	}
	if err := VerifyResultAck(ring, "host-1", settled()); !errors.Is(err, ErrResultAckUnsigned) {
		t.Errorf("an unsigned acknowledgement: %v", err)
	}
}
