// Package relayproof is the host's own proof on a path that goes through a
// relay: the inner identity envelope, the renewal proof bound to the old key,
// and the sealing of a secret to a one-time key of the host.
package relayproof

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// SchemaVersion is the layout of the envelope this release signs and verifies.
// It is the "v2" of relay.
const SchemaVersion uint32 = 2

// The capability an agent announces in Hello when it signs the envelope, and
// its feature.
const (
	Capability = "relay.identity"
	Feature    = "v2"
)

// NonceSize is the length of the nonce of an envelope.
const NonceSize = 16

// ChallengeSize is the length of the renewal challenge the panel issues.
const ChallengeSize = 32

// ChallengeTTL is how long a renewal challenge is good for.
const ChallengeTTL = 120 * time.Second

// UnaryWindow is how far the issued_at of an envelope on a renewal or a secret
// fetch may lie from the panel's clock.
const UnaryWindow = 5 * time.Minute

// The kinds of the unary requests. A stream message takes its kind from
// the name of the payload field, so those need no constants.
const (
	KindRenewCertificate = "renew_certificate"
	KindFetchSecret      = "fetch_secret"
)

// Sealing names the scheme a relayed secret is sealed with.
const Sealing = "x25519-hkdf-sha256-aes256gcm"

// The domain prefixes keep the signatures of this package apart from every
// other use of the host key - a certificate request, a capability - and from
// each other.
const (
	envelopePrefix  = "flotestro-relay-envelope/2\n"
	ephemeralPrefix = "flotestro-secret-seal-key/1\n"
	sealingInfo     = "flotestro-secret-seal/1"
)

// The errors of a verification. The gateway maps them to its typed refusal
// codes; the agent reads them when it opens a sealed value.
var (
	// ErrUnsupportedKey is a key the fleet does not sign with.
	ErrUnsupportedKey = errors.New("the host key is not an ECDSA key")
	// ErrBadSignature is a signature that does not verify under the key of
	// the certificate the envelope names.
	ErrBadSignature = errors.New("the host signature does not verify")
	// ErrBodyDigest is a payload other than the one the envelope signs.
	ErrBodyDigest = errors.New("the payload does not match the digest the host signed")
	// ErrShape is an envelope that is not one this release reads: another schema,
	// an empty identifier, a nonce or a digest of the wrong length, a sequence of
	// zero.
	ErrShape = errors.New("the envelope is not of the expected shape")
	// ErrSealing is a sealed value this release cannot open: an unknown scheme, a
	// key of the wrong length, or a cipher text that does not authenticate.
	ErrSealing = errors.New("the sealed value cannot be opened")
)

// Payload names the kind of a message of the agent and returns the payload the
// envelope hashes.
func Payload(msg *agentv1.AgentMessage) (kind string, body proto.Message, err error) {
	if msg == nil {
		return "", nil, errors.New("no message")
	}
	reflection := msg.ProtoReflect()
	oneof := reflection.Descriptor().Oneofs().ByName("payload")
	if oneof == nil {
		return "", nil, errors.New("the message has no payload")
	}
	field := reflection.WhichOneof(oneof)
	if field == nil {
		return "", nil, errors.New("the message carries no payload")
	}
	if field.Kind() != protoreflect.MessageKind {
		return "", nil, fmt.Errorf("the payload %s is not a message", field.Name())
	}
	return string(field.Name()), reflection.Get(field).Message().Interface(), nil
}

// BodyDigest is the SHA-256 of a message in its deterministic protobuf
// encoding.
func BodyDigest(body proto.Message) ([]byte, error) {
	if body == nil {
		return nil, errors.New("no payload to digest")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	return sum[:], nil
}

// DigestMatches says whether the payload is the one the envelope signs,
// in constant time.
func DigestMatches(envelope *agentv1.RelayedEnvelope, body proto.Message) (bool, error) {
	digest, err := BodyDigest(body)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(digest, envelope.GetBodySha256()) == 1, nil
}

// SigningBytes is the deterministic byte form of fields 1-10 of an envelope,
// the thing the host signs and the gateway verifies.
func SigningBytes(e *agentv1.RelayedEnvelope) []byte {
	var out []byte
	out = append(out, envelopePrefix...)
	out = appendUint(out, uint64(e.GetSchemaVersion()))
	out = appendBytes(out, []byte(e.GetRelayId()))
	out = appendBytes(out, []byte(e.GetHostId()))
	out = appendBytes(out, []byte(e.GetCertificateSerial()))
	out = appendBytes(out, []byte(e.GetSessionId()))
	out = appendUint(out, e.GetSequence())
	out = appendUint(out, uint64(e.GetIssuedAtUnix()))
	out = appendBytes(out, e.GetNonce())
	out = appendBytes(out, []byte(e.GetMessageKind()))
	out = appendBytes(out, e.GetBodySha256())
	return out
}

func appendUint(out []byte, value uint64) []byte {
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], value)
	return append(out, word[:]...)
}

func appendBytes(out, value []byte) []byte {
	out = appendUint(out, uint64(len(value)))
	return append(out, value...)
}

// CheckShape refuses an envelope this release does not read before any key is
// looked up: another schema, an empty identifier, a nonce or a digest of the
// wrong length, a sequence of zero.
func CheckShape(e *agentv1.RelayedEnvelope) error {
	switch {
	case e == nil:
		return fmt.Errorf("%w: no envelope", ErrShape)
	case e.GetSchemaVersion() != SchemaVersion:
		return fmt.Errorf("%w: schema %d, this release reads %d", ErrShape, e.GetSchemaVersion(), SchemaVersion)
	case e.GetHostId() == "" || e.GetCertificateSerial() == "" || e.GetSessionId() == "":
		return fmt.Errorf("%w: the host, the certificate serial and the session have to be named", ErrShape)
	case e.GetSequence() == 0:
		return fmt.Errorf("%w: the sequence starts at 1", ErrShape)
	case len(e.GetNonce()) != NonceSize:
		return fmt.Errorf("%w: the nonce has %d bytes, expected %d", ErrShape, len(e.GetNonce()), NonceSize)
	case len(e.GetBodySha256()) != sha256.Size:
		return fmt.Errorf("%w: the body digest has %d bytes, expected %d", ErrShape, len(e.GetBodySha256()), sha256.Size)
	case e.GetMessageKind() == "":
		return fmt.Errorf("%w: the kind of the message is missing", ErrShape)
	case len(e.GetHostSignature()) == 0:
		return fmt.Errorf("%w: the envelope is not signed", ErrShape)
	}
	return nil
}

// Verify checks the signature of an envelope under the public key of the
// certificate it names.
func Verify(public crypto.PublicKey, e *agentv1.RelayedEnvelope) error {
	if err := CheckShape(e); err != nil {
		return err
	}
	return verifyDigest(public, digestOf(SigningBytes(e)), e.GetHostSignature())
}

// digestOf is the SHA-256 the key signs.
func digestOf(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// signDigest signs with the host key. The identities of the fleet are ECDSA
// P-256, and the signature is the ASN.
func signDigest(key crypto.Signer, digest []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("no host key")
	}
	if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
		return nil, ErrUnsupportedKey
	}
	return key.Sign(rand.Reader, digest, crypto.SHA256)
}

func verifyDigest(public crypto.PublicKey, digest, signature []byte) error {
	key, ok := public.(*ecdsa.PublicKey)
	if !ok {
		return ErrUnsupportedKey
	}
	if !ecdsa.VerifyASN1(key, digest, signature) {
		return ErrBadSignature
	}
	return nil
}

// Signer signs the envelopes of one session of a host.
type Signer struct {
	key      crypto.Signer
	hostID   string
	serial   string
	relayID  string
	session  string
	sequence atomic.Uint64
	// now and random are swapped by the tests; the product signs with the
	// wall clock and the system's randomness.
	now    func() time.Time
	random io.Reader
}

// NewSigner prepares the signer of a session.
func NewSigner(key crypto.Signer, hostID, certificateSerial, relayID, sessionID string) *Signer {
	return &Signer{
		key: key, hostID: hostID, serial: certificateSerial, relayID: relayID, session: sessionID,
		now: time.Now, random: rand.Reader,
	}
}

// SessionID is the session the signer numbers.
func (s *Signer) SessionID() string { return s.session }

// Key is the host key the signer signs with, for the proofs beside the
// envelope: the renewal proof and the one-time key of a secret fetch.
func (s *Signer) Key() crypto.Signer { return s.key }

// ForCall derives the signer of one unary request from the signer of the
// session: the same key, host, certificate and relay, a session of its own, so
// the request's envelope does not take a number from the stream.
func (s *Signer) ForCall() *Signer {
	return &Signer{
		key: s.key, hostID: s.hostID, serial: s.serial, relayID: s.relayID,
		session: uuid.NewString(), now: s.now, random: s.random,
	}
}

// RelayID is the relay the signer names, empty for a direct connection.
func (s *Signer) RelayID() string { return s.relayID }

// Sequence is the number of the last envelope signed, zero before the
// first.
func (s *Signer) Sequence() uint64 { return s.sequence.Load() }

// Next signs the next envelope of the session for a payload of the given
// kind and digest.
func (s *Signer) Next(kind string, bodyDigest []byte) (*agentv1.RelayedEnvelope, error) {
	return s.envelope(kind, bodyDigest, s.sequence.Add(1))
}

// envelope signs one envelope with an explicit sequence.
func (s *Signer) envelope(kind string, bodyDigest []byte, sequence uint64) (*agentv1.RelayedEnvelope, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return nil, fmt.Errorf("drawing the nonce: %w", err)
	}
	envelope := &agentv1.RelayedEnvelope{
		SchemaVersion:     SchemaVersion,
		RelayId:           s.relayID,
		HostId:            s.hostID,
		CertificateSerial: s.serial,
		SessionId:         s.session,
		Sequence:          sequence,
		IssuedAtUnix:      s.now().Unix(),
		Nonce:             nonce,
		MessageKind:       kind,
		BodySha256:        bodyDigest,
	}
	signature, err := signDigest(s.key, digestOf(SigningBytes(envelope)))
	if err != nil {
		return nil, err
	}
	envelope.HostSignature = signature
	return envelope, nil
}

// SignMessage attaches the next envelope of the session to a message of the
// stream.
func (s *Signer) SignMessage(msg *agentv1.AgentMessage) error {
	kind, body, err := Payload(msg)
	if err != nil {
		return err
	}
	digest, err := BodyDigest(body)
	if err != nil {
		return err
	}
	envelope, err := s.Next(kind, digest)
	if err != nil {
		return err
	}
	msg.Envelope = envelope
	return nil
}

// SignRequest signs the single envelope of a unary request: the body is the
// request itself, with its identity field cleared by the caller, and the
// sequence is 1.
func (s *Signer) SignRequest(kind string, body proto.Message) (*agentv1.RelayedEnvelope, error) {
	digest, err := BodyDigest(body)
	if err != nil {
		return nil, err
	}
	return s.envelope(kind, digest, 1)
}

// RenewalProofDigest is what the old host key signs when a host renews through
// a relay: SHA256(csr_der || challenge || relay_id).
func RenewalProofDigest(csrDER, challenge []byte, relayID string) []byte {
	data := make([]byte, 0, len(csrDER)+len(challenge)+len(relayID))
	data = append(data, csrDER...)
	data = append(data, challenge...)
	data = append(data, relayID...)
	return digestOf(data)
}

// SignRenewalProof binds a renewal to the key the host holds now.
func SignRenewalProof(key crypto.Signer, csrDER, challenge []byte, relayID string) ([]byte, error) {
	if len(challenge) != ChallengeSize {
		return nil, fmt.Errorf("the challenge has %d bytes, expected %d", len(challenge), ChallengeSize)
	}
	return signDigest(key, RenewalProofDigest(csrDER, challenge, relayID))
}

// VerifyRenewalProof checks the proof under the key of the certificate the
// host renews from.
func VerifyRenewalProof(public crypto.PublicKey, csrDER, challenge []byte, relayID string, proof []byte) error {
	if len(challenge) != ChallengeSize {
		return fmt.Errorf("%w: the challenge has %d bytes, expected %d", ErrShape, len(challenge), ChallengeSize)
	}
	if len(proof) == 0 {
		return fmt.Errorf("%w: the proof is missing", ErrShape)
	}
	return verifyDigest(public, RenewalProofDigest(csrDER, challenge, relayID), proof)
}

// NewChallenge draws a renewal challenge.
func NewChallenge() ([]byte, error) {
	challenge := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		return nil, err
	}
	return challenge, nil
}

// ChallengeDigest is what the panel keeps of a challenge: the challenge
// itself is worth nothing to anyone who reads the database.
func ChallengeDigest(challenge []byte) []byte { return digestOf(challenge) }

// EphemeralKey is the one-time X25519 key a host fetches a sealed secret
// with. It lives for one fetch and is never written anywhere.
type EphemeralKey struct {
	private *ecdh.PrivateKey
}

// NewEphemeralKey draws a fresh key.
func NewEphemeralKey() (*EphemeralKey, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &EphemeralKey{private: private}, nil
}

// PublicKey is the 32-byte public key the panel seals to.
func (k *EphemeralKey) PublicKey() []byte { return k.private.PublicKey().Bytes() }

// Open unseals a value the panel sealed to this key.
func (k *EphemeralKey) Open(serverPublic, sealed, nonce, aad []byte) ([]byte, error) {
	return Open(k.private, serverPublic, sealed, nonce, aad)
}

// EphemeralKeySigningBytes is what the host key signs over a one-time key: the
// task, the secret and the key itself, so a key signed for one fetch buys
// nothing for another.
func EphemeralKeySigningBytes(taskID, secretName string, public []byte) []byte {
	var out []byte
	out = append(out, ephemeralPrefix...)
	out = appendBytes(out, []byte(taskID))
	out = appendBytes(out, []byte(secretName))
	out = appendBytes(out, public)
	return out
}

// SignEphemeralKey binds a one-time key to the host identity.
func SignEphemeralKey(key crypto.Signer, taskID, secretName string, public []byte) ([]byte, error) {
	return signDigest(key, digestOf(EphemeralKeySigningBytes(taskID, secretName, public)))
}

// VerifyEphemeralKey checks that the one-time key was signed by the host
// for this task and this secret.
func VerifyEphemeralKey(hostPublic crypto.PublicKey, taskID, secretName string, ephemeral, signature []byte) error {
	if len(ephemeral) != 32 {
		return fmt.Errorf("%w: the ephemeral key has %d bytes, expected 32", ErrShape, len(ephemeral))
	}
	if len(signature) == 0 {
		return fmt.Errorf("%w: the ephemeral key is not signed", ErrShape)
	}
	return verifyDigest(hostPublic, digestOf(EphemeralKeySigningBytes(taskID, secretName, ephemeral)), signature)
}

// SecretAAD is the associated data of a sealed value: the task, the name and
// the version, so a sealed value carried from one lease to another does not
// open.
func SecretAAD(taskID, secretName string, version uint32) []byte {
	return []byte(taskID + "|" + secretName + "|" + strconv.FormatUint(uint64(version), 10))
}

// Seal encrypts a value to the host's one-time key with a one-time key of the
// panel's own: X25519 for the shared secret, HKDF-SHA256 for the cipher key,
// AES-256-GCM for the value.
func Seal(hostPublic, plaintext, aad []byte) (sealed, nonce, serverPublic []byte, err error) {
	peer, err := ecdh.X25519().NewPublicKey(hostPublic)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrSealing, err)
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	shared, err := private.ECDH(peer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrSealing, err)
	}
	serverPublic = private.PublicKey().Bytes()
	aead, err := sealingCipher(shared, hostPublic, serverPublic)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}
	sealed = aead.Seal(nil, nonce, plaintext, aad)
	return sealed, nonce, serverPublic, nil
}

// Open decrypts a value sealed by Seal.
func Open(private *ecdh.PrivateKey, serverPublic, sealed, nonce, aad []byte) ([]byte, error) {
	if private == nil {
		return nil, fmt.Errorf("%w: no ephemeral key", ErrSealing)
	}
	peer, err := ecdh.X25519().NewPublicKey(serverPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealing, err)
	}
	shared, err := private.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealing, err)
	}
	aead, err := sealingCipher(shared, private.PublicKey().Bytes(), serverPublic)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: the nonce has %d bytes, expected %d", ErrSealing, len(nonce), aead.NonceSize())
	}
	plaintext, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: the cipher text does not authenticate", ErrSealing)
	}
	return plaintext, nil
}

// sealingCipher derives the AES-256-GCM key from the shared secret.
func sealingCipher(shared, hostPublic, serverPublic []byte) (cipher.AEAD, error) {
	salt := make([]byte, 0, len(hostPublic)+len(serverPublic))
	salt = append(salt, hostPublic...)
	salt = append(salt, serverPublic...)
	key, err := hkdf.Key(sha256.New, shared, salt, sealingInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
