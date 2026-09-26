// Package helpercap is the signed capability the control plane issues for
// every mutating operation the root helper carries out.
package helpercap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// SchemaVersion is the layout of the capability this release signs and
// verifies. The helper refuses any other rather than guessing.
const SchemaVersion uint32 = 1

// Mode is how the helper treats a request without a valid capability.
type Mode string

const (
	// ModeObserve records what a capability would have decided and enforces
	// nothing: a request without one is carried out, and one that fails
	// verification is carried out too, with the failure on the log.
	ModeObserve Mode = "observe"
	// ModePrefer verifies every capability it is handed and refuses a failed one;
	// a request without a capability is still carried out and reported as a
	// legacy request.
	ModePrefer Mode = "prefer"
	// ModeEnforce refuses a mutating request without a valid capability.
	ModeEnforce Mode = "enforce"
)

// ParseMode reads a mode from configuration.
func ParseMode(value string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "observe", "audit":
		return ModeObserve, nil
	case "prefer", "":
		return ModePrefer, nil
	case "enforce":
		return ModeEnforce, nil
	}
	return "", errors.New("the capability mode has to be observe, prefer or enforce")
}

// The stable error codes of a refusal.
const (
	// ErrorCapabilityRequired: the mode is enforce and the request carried
	// no capability.
	ErrorCapabilityRequired = "capability_required"
	// ErrorCapabilityVersion: a capability layout this helper does not know.
	ErrorCapabilityVersion = "capability_version"
	// ErrorWrongHost: the capability names another host than the one the
	// helper's root-owned identity names.
	ErrorWrongHost = "capability_wrong_host"
	// ErrorWrongAction: the capability authorizes another operation than
	// the request asks for.
	ErrorWrongAction = "capability_wrong_action"
	// ErrorCapabilityExpired: outside the validity window, on either side.
	ErrorCapabilityExpired = "capability_expired"
	// ErrorTTLTooLong: the window is longer than the class of the operation
	// allows, so it is not a window the panel would have issued.
	ErrorTTLTooLong = "capability_ttl_too_long"
	// ErrorPayloadMismatch: the payload handed over is not the one the capability
	// binds.
	ErrorPayloadMismatch = "payload_hash_mismatch"
	// ErrorPayloadBinding: the digest matches but the request carries other
	// values than the bound payload names - another unit, another user, another
	// path.
	ErrorPayloadBinding = "payload_binding_mismatch"
	// ErrorPayloadUnchecked: the helper holds no rule for comparing a request of
	// this kind with the payload the capability binds, so it refuses rather than
	// carry out a change nothing compared.
	ErrorPayloadUnchecked = "payload_binding_unchecked"
	// ErrorTrustPin: the first bundle a host is handed is signed by a key the
	// operator did not write down on that host beforehand.
	ErrorTrustPin = "trust_pin_mismatch"
	// ErrorUnknownKey: the keyring holds no key of that identifier.
	ErrorUnknownKey = "capability_unknown_key"
	// ErrorBadSignature: the signature does not verify under the named key.
	ErrorBadSignature = "capability_bad_signature"
	// ErrorInvalidNonce: the nonce is not 32 bytes.
	ErrorInvalidNonce = "capability_invalid_nonce"
	// ErrorCapabilityReplay: the nonce was consumed before, by an earlier
	// task or by an earlier life of the helper.
	ErrorCapabilityReplay = "capability_replay"
	// ErrorCapabilityInFlight: this very request is being carried out under
	// this nonce right now. Asking again does not start it a second time.
	ErrorCapabilityInFlight = "capability_in_flight"
	// ErrorCapabilityPerformed: this very request already ran under this nonce
	// and its answer was too large to keep, so the helper can neither repeat
	// the answer nor repeat the effect.
	ErrorCapabilityPerformed = "capability_already_performed"
)

// Error is a refusal with its stable code.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func refusal(code, message string) error { return &Error{Code: code, Message: message} }

// CodeOf returns the stable code of a refusal, or "" for another error.
func CodeOf(err error) string {
	var refused *Error
	if errors.As(err, &refused) {
		return refused.Code
	}
	return ""
}

// The classes of validity windows.
const (
	ClassDefault            = "default"
	ClassPackages           = "packages"
	ClassStorageDestructive = "storage_destructive"
)

// ClockSkew is how far the helper's clock may sit behind the panel's
// before a fresh capability looks like one from the future.
const ClockSkew = 30 * time.Second

// MaxTTL is the longest window of each class. The panel issues exactly these;
// the helper refuses a longer one as a window the panel would not have signed.
var MaxTTL = map[string]time.Duration{
	ClassDefault:            5 * time.Minute,
	ClassPackages:           10 * time.Minute,
	ClassStorageDestructive: 2 * time.Minute,
}

// ClassOf names the window class of an action type.
func ClassOf(action string) string {
	typed := opspec.ActionType(action)
	switch {
	case typed.LockClass() == opspec.LockPackages:
		return ClassPackages
	case typed.LockClass() == opspec.LockStorage && typed.Risk() == opspec.RiskDestructive:
		return ClassStorageDestructive
	}
	return ClassDefault
}

// TTLOf is the window the panel issues for an action type.
func TTLOf(action string) time.Duration {
	return MaxTTL[ClassOf(action)]
}

// KeyID names a public key: the first sixteen hex characters of the SHA-256 of
// the raw key.
func KeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:8])
}

// KeyFingerprint is the whole SHA-256 of a public key, as a pin names it. The
// key identifier is eight bytes of the same digest, which is enough to look a
// key up and not enough to decide, once, which panel owns a host for good.
func KeyFingerprint(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:])
}

// Bootstrap says what the helper does with the first bundle it is handed, when
// its keyring is empty and it has no identity yet.
type Bootstrap string

const (
	// BootstrapTOFU takes that first bundle on trust. It is how an installation
	// made before the pin existed enrolls, and it means whoever reaches the
	// helper's socket first decides which panel owns the host.
	BootstrapTOFU Bootstrap = "tofu"
	// BootstrapPinned takes it only when its signing key is one the operator
	// wrote down on the host beforehand. A host with no pin enrolls with
	// nobody.
	BootstrapPinned Bootstrap = "pinned"
)

// ParseBootstrap reads the bootstrap policy from configuration.
func ParseBootstrap(value string) (Bootstrap, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tofu", "":
		return BootstrapTOFU, nil
	case "pinned":
		return BootstrapPinned, nil
	}
	return "", errors.New("the bootstrap policy has to be tofu or pinned")
}

// signingPrefix separates capability signatures from every other use of the
// same key, so bytes signed as a capability cannot be presented as something
// else and the other way round.
const signingPrefix = "flotestro-helper-capability/1\n"

// SigningBytes is the deterministic byte form of a capability, the thing the
// panel signs and the helper verifies.
func SigningBytes(capability *helperv1.HelperCapability) []byte {
	var out []byte
	out = append(out, signingPrefix...)
	out = appendUint(out, uint64(capability.GetSchemaVersion()))
	out = appendBytes(out, []byte(capability.GetKeyId()))
	out = appendBytes(out, []byte(capability.GetCapabilityId()))
	out = appendBytes(out, []byte(capability.GetHostId()))
	out = appendBytes(out, []byte(capability.GetTaskId()))
	out = appendBytes(out, []byte(capability.GetActionType()))
	out = appendBytes(out, capability.GetPayloadSha256())
	out = appendUint(out, uint64(capability.GetNotBeforeUnix()))
	out = appendUint(out, uint64(capability.GetExpiresUnix()))
	out = appendBytes(out, capability.GetNonce())
	out = appendUint(out, capability.GetPolicyRevision())
	out = appendUint(out, uint64(len(capability.GetGrants())))
	for _, grant := range capability.GetGrants() {
		out = appendBytes(out, []byte(grant))
	}
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

// Sign signs a capability with a private key.
func Sign(key ed25519.PrivateKey, capability *helperv1.HelperCapability) []byte {
	return ed25519.Sign(key, SigningBytes(capability))
}

// VerifySignature checks a capability's signature under a public key.
func VerifySignature(public ed25519.PublicKey, capability *helperv1.HelperCapability, signature []byte) bool {
	if len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(public, SigningBytes(capability), signature)
}
