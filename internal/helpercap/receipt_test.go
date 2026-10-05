package helpercap

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// fileFromSecret is a whole request to write a file whose content comes from
// the store: the consent the panel signed, and the receipt it signed when it
// released the bytes.
func (f *fixture) fileFromSecret(t *testing.T, released []byte,
	spoil func(*helperv1.SecretReceipt)) *helperv1.HelperRequest {
	t.Helper()
	payload := opspec.Payload{File: &opspec.FilePayload{
		Path:          "/etc/app.conf",
		Mode:          "0600",
		ContentSecret: &opspec.SecretRef{Name: "app.conf"},
	}}
	canonical, err := CanonicalPayload(opspec.ActionFileEnsure, opspec.ActionVersion, payload)
	if err != nil {
		t.Fatal(err)
	}
	capability, signature, err := f.signer.Issue(Mint{
		HostID: "host-1", TaskID: "task-1",
		ActionType:    string(opspec.ActionFileEnsure),
		PayloadSHA256: PayloadDigest(canonical),
		Now:           f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := f.signer.IssueReceipt(Release{
		HostID: "host-1", TaskID: "task-1", SecretName: "app.conf",
		Version: 4, SHA256: contentDigest(released), Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if spoil != nil {
		spoil(receipt)
	}
	return &helperv1.HelperRequest{
		TaskId:              "task-1",
		Capability:          capability,
		CapabilitySignature: signature,
		CanonicalPayload:    canonical,
		SecretReceipts:      []*helperv1.SecretReceipt{receipt},
		Action: &helperv1.HelperRequest_File{File: &helperv1.FileRequest{
			Operation:  helperv1.FileRequest_OPERATION_ENSURE,
			Path:       "/etc/app.conf",
			Mode:       "0600",
			Content:    released,
			FromSecret: true,
		}},
	}
}

func TestAWriteFromASecretIsAcceptedWithTheReceiptOfItsRelease(t *testing.T) {
	f := newFixture(t)
	if err := verify(f.verifier, f.fileFromSecret(t, []byte("a-secret-value"), nil)); err != nil {
		t.Fatalf("a write from a secret with its receipt was refused: %v", err)
	}
}

// The case the whole mechanism exists for. The consent is honoured, the receipt
// is the panel's own, and the bytes are the agent's: a rule under sudoers.d
// instead of the secret the panel released.
func TestBytesTheReceiptDoesNotVouchForAreRefused(t *testing.T) {
	f := newFixture(t)
	request := f.fileFromSecret(t, []byte("a-secret-value"), nil)
	request.GetFile().Content = []byte("flotestro-agent ALL=(ALL) NOPASSWD: ALL\n")
	expectCode(t, verify(f.verifier, request), ErrorPayloadBinding)
}

func TestAWriteFromASecretWithNoReceiptIsRefused(t *testing.T) {
	f := newFixture(t)
	request := f.fileFromSecret(t, []byte("a-secret-value"), nil)
	request.SecretReceipts = nil
	expectCode(t, verify(f.verifier, request), ErrorPayloadBinding)
}

// A receipt signed by a key this host does not trust is a receipt the agent
// could have made itself.
func TestAReceiptSignedByAStrangerIsRefused(t *testing.T) {
	f := newFixture(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stranger := NewSignerFromKey(private)
	released := []byte("a-secret-value")
	request := f.fileFromSecret(t, released, nil)
	forged, err := stranger.IssueReceipt(Release{
		HostID: "host-1", TaskID: "task-1", SecretName: "app.conf",
		Version: 4, SHA256: contentDigest([]byte("something else")), Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	request.SecretReceipts = []*helperv1.SecretReceipt{forged}
	expectCode(t, verify(f.verifier, request), ErrorUnknownKey)
}

// A signature over other fields than the ones presented.
func TestAReceiptWhoseFieldsWereChangedIsRefused(t *testing.T) {
	f := newFixture(t)
	released := []byte("a-secret-value")
	request := f.fileFromSecret(t, released, func(receipt *helperv1.SecretReceipt) {
		receipt.Sha256 = contentDigest([]byte("whatever the agent wants"))
	})
	expectCode(t, verify(f.verifier, request), ErrorBadSignature)
}

// A receipt of another host or another task is a receipt from elsewhere, and a
// valid signature does not make it this write's.
func TestAReceiptOfAnotherHostOrTaskIsRefused(t *testing.T) {
	for name, release := range map[string]Release{
		"another host": {HostID: "host-2", TaskID: "task-1"},
		"another task": {HostID: "host-1", TaskID: "task-9"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			released := []byte("a-secret-value")
			request := f.fileFromSecret(t, released, nil)
			elsewhere, err := f.signer.IssueReceipt(Release{
				HostID: release.HostID, TaskID: release.TaskID, SecretName: "app.conf",
				Version: 4, SHA256: contentDigest(released), Now: f.now,
			})
			if err != nil {
				t.Fatal(err)
			}
			request.SecretReceipts = []*helperv1.SecretReceipt{elsewhere}
			expectCode(t, verify(f.verifier, request), ErrorPayloadBinding)
		})
	}
}

// A receipt stands for the length of one task. An old one, kept from an
// earlier release of the same secret, is not a receipt for this write.
func TestAReceiptPastItsWindowIsRefused(t *testing.T) {
	f := newFixture(t)
	released := []byte("a-secret-value")
	request := f.fileFromSecret(t, released, nil)
	stale, err := f.signer.IssueReceipt(Release{
		HostID: "host-1", TaskID: "task-1", SecretName: "app.conf",
		Version: 4, SHA256: contentDigest(released),
		Now: f.now.Add(-ReceiptTTL - time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	request.SecretReceipts = []*helperv1.SecretReceipt{stale}
	expectCode(t, verify(f.verifier, request), ErrorCapabilityExpired)
}

// The bytes signed as a receipt must not verify as a capability, or a key used
// for one would vouch for the other.
func TestReceiptAndCapabilityBytesDoNotCross(t *testing.T) {
	f := newFixture(t)
	receipt, err := f.signer.IssueReceipt(Release{
		HostID: "host-1", TaskID: "task-1", SecretName: "app.conf",
		Version: 1, SHA256: contentDigest([]byte("x")), Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	capability, _, err := f.signer.Issue(Mint{
		HostID: "host-1", TaskID: "task-1",
		ActionType: string(opspec.ActionUnitRestart), PayloadSHA256: PayloadDigest(f.canonical), Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if VerifySignature(f.signer.PublicKey(), capability, receipt.GetSignature()) {
		t.Error("a receipt's signature verifies as a capability's")
	}
	if VerifyReceiptSignature(f.signer.PublicKey(), receipt, SigningBytes(capability)) {
		t.Error("a capability's bytes verify as a receipt's signature")
	}
}
