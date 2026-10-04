package helpercap

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// A write whose content comes from the secret store used to be checked against
// nothing at all: the request said "fill this file from the secret
// db-password", and the helper wrote the bytes the request carried. The place
// such a file goes is often worth more than the secret - authorized_keys, a
// rule under sudoers.d, a systemd unit - so a consent to write one secret into
// one path authorized writing anything into it.
//
// The digest cannot live in the capability. A reference with version 0 means
// "whatever is current when the task is delivered", so when the panel signs the
// consent it does not yet know the content. The receipt is the only shape that
// closes: it is made when the value is released, by the side that released it.

// receiptPrefix separates receipt signatures from every other use of the same
// key, so bytes signed as a receipt cannot be presented as a capability or the
// other way round.
const receiptPrefix = "flotestro-secret-receipt/1\n"

// ReceiptTTL is how long a receipt stands. It covers the way from the release
// of the value to the write of the file, which is one task; a receipt older
// than that belongs to another task's release.
const ReceiptTTL = 30 * time.Minute

// ReceiptSigningBytes is the deterministic byte form of a receipt: what the
// panel signs and the helper verifies.
func ReceiptSigningBytes(receipt *helperv1.SecretReceipt) []byte {
	var out []byte
	out = append(out, receiptPrefix...)
	out = appendBytes(out, []byte(receipt.GetHostId()))
	out = appendBytes(out, []byte(receipt.GetTaskId()))
	out = appendBytes(out, []byte(receipt.GetSecretName()))
	out = appendUint(out, uint64(receipt.GetSecretVersion()))
	out = appendBytes(out, []byte(receipt.GetSha256()))
	out = appendUint(out, uint64(receipt.GetIssuedUnix()))
	out = appendBytes(out, []byte(receipt.GetSignedByKeyId()))
	return out
}

// SignReceipt signs a receipt with a private key.
func SignReceipt(key ed25519.PrivateKey, receipt *helperv1.SecretReceipt) []byte {
	return ed25519.Sign(key, ReceiptSigningBytes(receipt))
}

// VerifyReceiptSignature checks a receipt's signature under a public key.
func VerifyReceiptSignature(public ed25519.PublicKey, receipt *helperv1.SecretReceipt, signature []byte) bool {
	if len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(public, ReceiptSigningBytes(receipt), signature)
}

// Release is what the panel releasing a secret knows about it.
type Release struct {
	HostID     string
	TaskID     string
	SecretName string
	// Version is the one actually released, never the 0 of "the current one":
	// the receipt says which that turned out to be.
	Version uint32
	// SHA256 is the digest of the bytes released, hex, as the rest of the
	// protocol spells one.
	SHA256 string
	Now    time.Time
}

// IssueReceipt signs the release of a secret's bytes.
func (s *Signer) IssueReceipt(release Release) (*helperv1.SecretReceipt, error) {
	if release.HostID == "" || release.TaskID == "" || release.SecretName == "" {
		return nil, errors.New("a receipt needs a host, a task and a secret")
	}
	if release.SHA256 == "" {
		return nil, errors.New("a receipt binds the digest of the bytes released")
	}
	now := release.Now
	if now.IsZero() {
		now = time.Now()
	}
	receipt := &helperv1.SecretReceipt{
		HostId:        release.HostID,
		TaskId:        release.TaskID,
		SecretName:    release.SecretName,
		SecretVersion: release.Version,
		Sha256:        release.SHA256,
		IssuedUnix:    now.Unix(),
		SignedByKeyId: s.keyID,
	}
	receipt.Signature = SignReceipt(s.key, receipt)
	return receipt, nil
}

// VerifyReceipt checks a receipt against the keyring and the clock. What it is
// a receipt *for* - this host, this task, this secret, these bytes - is checked
// where the rest of the binding is, against the capability and the payload the
// panel signed.
func (v *Verifier) VerifyReceipt(receipt *helperv1.SecretReceipt) error {
	if receipt == nil {
		return refusal(ErrorPayloadBinding,
			"the request fills the file from a secret and carries no receipt for its bytes")
	}
	ring, err := v.keyring()
	if err != nil {
		return fmt.Errorf("reading the keyring: %w", err)
	}
	public, known := ring.Lookup(receipt.GetSignedByKeyId())
	if !known {
		return refusal(ErrorUnknownKey,
			fmt.Sprintf("the receipt is signed by the key %q, which this host does not trust",
				receipt.GetSignedByKeyId()))
	}
	if !VerifyReceiptSignature(public, receipt, receipt.GetSignature()) {
		return refusal(ErrorBadSignature, "the signature of the receipt does not verify")
	}
	// The clock, after the signature: an unsigned receipt's timestamp is worth
	// nothing, so there is no point reading it first.
	issued := time.Unix(receipt.GetIssuedUnix(), 0)
	now := v.now()
	if issued.After(now.Add(ClockSkew)) {
		return refusal(ErrorCapabilityExpired,
			fmt.Sprintf("the receipt was issued at %s, which is ahead of this host's clock", issued.UTC().Format(time.RFC3339)))
	}
	if now.After(issued.Add(ReceiptTTL)) {
		return refusal(ErrorCapabilityExpired,
			fmt.Sprintf("the receipt was issued at %s and receipts stand for %s",
				issued.UTC().Format(time.RFC3339), ReceiptTTL))
	}
	return nil
}
