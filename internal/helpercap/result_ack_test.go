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

// legacyResultAckSigningBytes is the function an agent from before the digest runs
// over an acknowledgement: it knows the host, the attempt, the key, the status and
// the reason, and no digest. It is written out here, and not called, so that the
// test stays true to that agent if the real function ever grows.
func legacyResultAckSigningBytes(hostID string, ack *agentv1.TaskResultAck) []byte {
	out := []byte("flotestro/result-ack/v1\x00")
	out = appendBytes(out, []byte(hostID))
	out = appendBytes(out, []byte(ack.GetTaskId()))
	out = appendBytes(out, []byte(ack.GetIdempotencyKey()))
	out = appendUint(out, uint64(ack.GetStatus()))
	out = appendBytes(out, []byte(ack.GetReasonCode()))
	return out
}

// An agent from before the digest verifies the acknowledgement of a panel that
// sends one: the signature it checks is over the bytes it always was. This is the
// order "panels first" depends on - the first form of the digest was folded into
// that signature and no older agent would have released a result again.
func TestAnAgentFromBeforeTheDigestStillVerifiesAnAcknowledgementThatHasOne(t *testing.T) {
	signer, _ := ackSignerAndRing(t)
	ack := settled()
	ack.ResultDigest = ResultDigest(&agentv1.TaskResult{TaskId: "attempt-1", Message: "done"})
	signer.SignResultAck("host-1", ack)

	if !ed25519.Verify(signer.PublicKey(), legacyResultAckSigningBytes("host-1", ack), ack.GetSignature()) {
		t.Fatal("an agent that does not know the digest cannot verify the acknowledgement")
	}
}

// With the digest, the new check: the digest has a signature of its own, and
// neither the digest nor the signature can be added, taken off or swapped alone.
func TestTheDigestOfAResultIsSignedWithTheAcknowledgement(t *testing.T) {
	signer, ring := ackSignerAndRing(t)
	digest := ResultDigest(&agentv1.TaskResult{TaskId: "attempt-1", Message: "done"})
	if len(digest) != 32 {
		t.Fatalf("the digest of a result is %d bytes", len(digest))
	}
	signed := func() *agentv1.TaskResultAck {
		ack := settled()
		ack.ResultDigest = digest
		signer.SignResultAck("host-1", ack)
		return ack
	}

	if err := VerifyResultAck(ring, "host-1", signed()); err != nil {
		t.Fatalf("an acknowledgement with its digest was refused: %v", err)
	}

	for name, tamper := range map[string]func(*agentv1.TaskResultAck){
		"another digest": func(a *agentv1.TaskResultAck) {
			a.ResultDigest = ResultDigest(&agentv1.TaskResult{TaskId: "attempt-1", Message: "other"})
		},
		"the digest taken off, its signature left": func(a *agentv1.TaskResultAck) { a.ResultDigest = nil },
		"the signature of the digest wiped":        func(a *agentv1.TaskResultAck) { a.DigestSignature = nil },
		"the signature of the digest cut":          func(a *agentv1.TaskResultAck) { a.DigestSignature = a.DigestSignature[:10] },
		"the signature of the acknowledgement used": func(a *agentv1.TaskResultAck) {
			a.DigestSignature = a.Signature
		},
	} {
		ack := signed()
		tamper(ack)
		if err := VerifyResultAck(ring, "host-1", ack); !errors.Is(err, ErrResultAckInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A digest written into an acknowledgement that never had one.
	added := settled()
	signer.SignResultAck("host-1", added)
	added.ResultDigest = digest
	if err := VerifyResultAck(ring, "host-1", added); !errors.Is(err, ErrResultAckInvalid) {
		t.Errorf("a digest written into an acknowledgement that had none: %v", err)
	}

	// Moved to another host, the digest goes with the rest.
	if err := VerifyResultAck(ring, "host-2", signed()); !errors.Is(err, ErrResultAckInvalid) {
		t.Errorf("an acknowledgement with a digest moved to another host: %v", err)
	}

	// A panel from before the field signs as it always did, and that still verifies.
	old := settled()
	signer.SignResultAck("host-1", old)
	if err := VerifyResultAck(ring, "host-1", old); err != nil {
		t.Errorf("an acknowledgement without a digest was refused: %v", err)
	}
}

func TestTheDigestOfAResultFollowsItsContent(t *testing.T) {
	a := &agentv1.TaskResult{TaskId: "t", Message: "one", Stdout: []byte("x")}
	b := &agentv1.TaskResult{TaskId: "t", Message: "one", Stdout: []byte("x")}
	if string(ResultDigest(a)) != string(ResultDigest(b)) {
		t.Error("two equal results have two digests")
	}
	b.Stdout = []byte("y")
	if string(ResultDigest(a)) == string(ResultDigest(b)) {
		t.Error("two different results have one digest")
	}
	if ResultDigest(nil) != nil {
		t.Error("nothing has a digest")
	}
}
