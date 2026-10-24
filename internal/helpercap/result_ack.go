package helpercap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// resultAckPrefix keeps a signature of an acknowledgement from being read as
// anything else this key signs.
const resultAckPrefix = "flotestro/result-ack/v1\x00"

// ResultAckSigningBytes is the deterministic form of an acknowledgement of a
// task result for one host. The host is part of it because the message that
// carries the acknowledgement is not: a relay could otherwise move a genuine
// one to another host that holds an answer under the same identifiers.
func ResultAckSigningBytes(hostID string, ack *agentv1.TaskResultAck) []byte {
	out := []byte(resultAckPrefix)
	out = appendBytes(out, []byte(hostID))
	out = appendBytes(out, []byte(ack.GetTaskId()))
	out = appendBytes(out, []byte(ack.GetIdempotencyKey()))
	out = appendUint(out, uint64(ack.GetStatus()))
	out = appendBytes(out, []byte(ack.GetReasonCode()))
	return out
}

// resultAckDigestPrefix keeps the signature of a digest from being read as the
// signature of the acknowledgement it travels with.
const resultAckDigestPrefix = "flotestro/result-ack-digest/v1\x00"

// ResultAckDigestSigningBytes is what the signature of the digest covers: the
// acknowledgement as it was always signed and the digest of the result with it.
// It is a signature of its own because an agent from before the digest verifies
// the first one over the bytes it knows, and an acknowledgement it cannot verify
// frees nothing - the order "panels first" would have stopped every older agent
// from ever releasing a result.
func ResultAckDigestSigningBytes(hostID string, ack *agentv1.TaskResultAck) []byte {
	out := append([]byte(resultAckDigestPrefix), ResultAckSigningBytes(hostID, ack)...)
	return appendBytes(out, ack.GetResultDigest())
}

// ResultDigest is the SHA-256 of the deterministic encoding of a task result:
// the same bytes on every computation of the same result, on the agent that
// sent it and on the panel that took it. Nil when the result cannot be encoded.
func ResultDigest(result *agentv1.TaskResult) []byte {
	if result == nil {
		return nil
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(encoded)
	return sum[:]
}

// SignResultAck signs the acknowledgement for the host in place: the signature
// every agent verifies, and, when the acknowledgement names the content of the
// result, the signature of the digest for the agents that know it.
func (s *Signer) SignResultAck(hostID string, ack *agentv1.TaskResultAck) {
	ack.KeyId = s.keyID
	ack.Signature = ed25519.Sign(s.key, ResultAckSigningBytes(hostID, ack))
	ack.DigestSignature = nil
	if len(ack.GetResultDigest()) > 0 {
		ack.DigestSignature = ed25519.Sign(s.key, ResultAckDigestSigningBytes(hostID, ack))
	}
}

// Errors of a result acknowledgement the host will not act on.
var (
	ErrResultAckUnsigned = errors.New("the acknowledgement carries no signature")
	ErrResultAckKey      = errors.New("the acknowledgement is signed with a key this host does not trust")
	ErrResultAckInvalid  = errors.New("the signature of the acknowledgement does not match it")
)

// VerifyResultAck checks the acknowledgement against the keys the host trusts.
func VerifyResultAck(ring *Keyring, hostID string, ack *agentv1.TaskResultAck) error {
	if len(ack.GetSignature()) == 0 {
		return ErrResultAckUnsigned
	}
	public, ok := ring.Lookup(ack.GetKeyId())
	if !ok {
		return ErrResultAckKey
	}
	if len(ack.GetSignature()) != ed25519.SignatureSize ||
		!ed25519.Verify(public, ResultAckSigningBytes(hostID, ack), ack.GetSignature()) {
		return ErrResultAckInvalid
	}
	// The content it names is signed too, or it is not named: a digest nobody
	// signed, and a signature of a digest that is not there, are both somebody's
	// work on the way.
	digest, signature := ack.GetResultDigest(), ack.GetDigestSignature()
	if len(digest) == 0 && len(signature) == 0 {
		return nil
	}
	if len(digest) == 0 || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(public, ResultAckDigestSigningBytes(hostID, ack), signature) {
		return ErrResultAckInvalid
	}
	return nil
}
