package helpercap

import (
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// TR-03 / HP-02 / PKG-02. The receipt of a secret's release was checked for one
// consumer, the file write. Every other place that spends a secret handed the
// helper the bytes of the request and the binding said only that *a* secret
// travelled: the repository password of a backup decides what the copy is
// encrypted with, its environment carries the credentials of the object store,
// a certificate's key is the identity of a service, and the password of a
// package repository is what the host authenticates to a source of packages
// with.
func (f *fixture) backupSpendingSecrets(t *testing.T, password []byte,
	receipts []*helperv1.SecretReceipt) *helperv1.HelperRequest {
	t.Helper()
	payload := opspec.Payload{Backup: &opspec.BackupPayload{
		ID: "nightly", Tool: "restic", Repository: "/srv/backups",
		PasswordSecret: &opspec.SecretRef{Name: "backup.password"},
	}}
	canonical, err := CanonicalPayload(opspec.ActionBackupRun, opspec.ActionVersion, payload)
	if err != nil {
		t.Fatal(err)
	}
	capability, signature, err := f.signer.Issue(Mint{
		HostID: "host-1", TaskID: "task-1",
		ActionType:    string(opspec.ActionBackupRun),
		PayloadSHA256: PayloadDigest(canonical),
		Now:           f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &helperv1.HelperRequest{
		TaskId:              "task-1",
		Capability:          capability,
		CapabilitySignature: signature,
		CanonicalPayload:    canonical,
		SecretReceipts:      receipts,
		Action: &helperv1.HelperRequest_Backup{Backup: &helperv1.BackupRequest{
			Operation:  helperv1.BackupRequest_OPERATION_RUN,
			Id:         "nightly",
			Tool:       "restic",
			Repository: "/srv/backups",
			Password:   password,
		}},
	}
}

func (f *fixture) backupReceipt(t *testing.T, released []byte) *helperv1.SecretReceipt {
	t.Helper()
	receipt, err := f.signer.IssueReceipt(Release{
		HostID: "host-1", TaskID: "task-1", SecretName: "backup.password",
		Version: 3, SHA256: contentDigest(released), Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestABackupPasswordIsBoundToTheBytesThePanelReleased(t *testing.T) {
	f := newFixture(t)
	released := []byte("the repository password")
	receipt := f.backupReceipt(t, released)

	if err := verify(f.verifier, f.backupSpendingSecrets(t, released,
		[]*helperv1.SecretReceipt{receipt})); err != nil {
		t.Fatalf("a backup with the released password was refused: %v", err)
	}

	// The case this exists for: the consent is honoured, the receipt is the
	// panel's, and the password is the agent's own - so the copy would be
	// encrypted with something nobody can open it with.
	substituted := f.backupSpendingSecrets(t, []byte("a password the agent chose"),
		[]*helperv1.SecretReceipt{receipt})
	expectCode(t, verify(f.verifier, substituted), ErrorPayloadBinding)

	// And no receipt at all is refused rather than trusted.
	expectCode(t, verify(f.verifier, f.backupSpendingSecrets(t, released, nil)), ErrorPayloadBinding)
}

// Two receipts for one secret is not a question this has an answer to.
func TestTwoReceiptsForOneSecretAreRefused(t *testing.T) {
	f := newFixture(t)
	released := []byte("the repository password")
	receipt := f.backupReceipt(t, released)
	request := f.backupSpendingSecrets(t, released,
		[]*helperv1.SecretReceipt{receipt, f.backupReceipt(t, []byte("another"))})
	expectCode(t, verify(f.verifier, request), ErrorPayloadBinding)
}

// A receipt of another task does not become this task's by being attached to
// it, however correctly it is signed.
func TestAReceiptOfAnotherTaskDoesNotTravel(t *testing.T) {
	f := newFixture(t)
	released := []byte("the repository password")
	elsewhere, err := f.signer.IssueReceipt(Release{
		HostID: "host-1", TaskID: "task-9", SecretName: "backup.password",
		Version: 3, SHA256: contentDigest(released), Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := f.backupSpendingSecrets(t, released, []*helperv1.SecretReceipt{elsewhere})
	expectCode(t, verify(f.verifier, request), ErrorPayloadBinding)
}
