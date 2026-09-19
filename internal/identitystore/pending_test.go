package identitystore

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// zeroes is a source of randomness a test can predict: every attempt
// identifier it gives is the same.
type zeroes struct{}

func (zeroes) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0x5a
	}
	return len(p), nil
}

var testClock = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

func TestAPendingAttemptIsRecordedBeforeTheNetwork(t *testing.T) {
	store := New(t.TempDir())
	pending, err := store.PreparePending(zeroes{}, testClock, "machine-1", nil, nil, "flt_ab12")
	if err != nil {
		t.Fatalf("preparing the attempt: %v", err)
	}
	if pending.ClientRequestID == "" || !strings.Contains(pending.ClientRequestID, "-") {
		t.Fatalf("the attempt identifier = %q", pending.ClientRequestID)
	}
	if !pending.CreatedAt.Equal(testClock) {
		t.Fatalf("created_at = %s, want the injected clock", pending.CreatedAt)
	}

	// The record carries the private key, so nobody but the owner may read
	// it - and that from the moment it exists.
	info, err := os.Stat(store.PendingPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pending permissions = %04o", info.Mode().Perm())
	}
	if _, err := os.Stat(store.PendingPath() + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("the temporary file of the record stayed behind")
	}

	// The token itself has no place in the record, only its opening.
	content, err := os.ReadFile(store.PendingPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte(`"token_prefix": "flt_ab12"`)) {
		t.Fatalf("the record has no token prefix: %s", content)
	}
	for _, field := range []string{"client_request_id", "key_pem", "csr_pem", "created_at"} {
		if !bytes.Contains(content, []byte(`"`+field+`"`)) {
			t.Fatalf("the record has no %s: %s", field, content)
		}
	}

	// The same attempt comes back to the byte: that is what a replay is.
	loaded, err := store.LoadPending()
	if err != nil {
		t.Fatalf("loading the attempt: %v", err)
	}
	if loaded.ClientRequestID != pending.ClientRequestID {
		t.Fatalf("identifier after loading = %q, want %q", loaded.ClientRequestID, pending.ClientRequestID)
	}
	if !bytes.Equal(loaded.CSRPEM, pending.CSRPEM) {
		t.Fatal("the loaded request differs from the recorded one")
	}
	key, err := loaded.Key()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(loaded.CSRPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !keysMatch(csr.PublicKey, key.Public()) {
		t.Fatal("the request was not signed with the recorded key")
	}
	if csr.Subject.CommonName != "machine-1" {
		t.Fatalf("subject = %q", csr.Subject.CommonName)
	}
}

func TestAStaleAttemptIsRecognisedByTheClock(t *testing.T) {
	store := New(t.TempDir())
	pending, err := store.PreparePending(zeroes{}, testClock, "machine-1", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Stale(testClock.Add(23 * time.Hour)) {
		t.Fatal("an attempt from 23 hours ago is still worth repeating")
	}
	if !pending.Stale(testClock.Add(PendingMaxAge + time.Minute)) {
		t.Fatal("an attempt older than a day has no token to be repeated with")
	}
	if got := pending.Age(testClock.Add(90 * time.Minute)); got != 90*time.Minute {
		t.Fatalf("age = %s", got)
	}
}

func TestRemovingTheAttemptIsFinal(t *testing.T) {
	store := New(t.TempDir())
	if _, err := store.LoadPending(); !errors.Is(err, ErrPendingMissing) {
		t.Fatalf("an empty store reports %v, want pending_missing", err)
	}
	if _, err := store.PreparePending(zeroes{}, testClock, "machine-1", nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.RemovePending(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPending(); !errors.Is(err, ErrPendingMissing) {
		t.Fatalf("after removal the store reports %v, want pending_missing", err)
	}
	// Removing twice is not an error: the attempt is over either way.
	if err := store.RemovePending(); err != nil {
		t.Fatalf("a repeated removal: %v", err)
	}
}

func TestADamagedRecordIsReportedAsInvalid(t *testing.T) {
	store := New(t.TempDir())
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	// Half a file after a crash, or a record written by hand: neither is an
	// attempt that can be repeated, and neither may pass as "no attempt".
	if err := os.WriteFile(store.PendingPath(), []byte(`{"client_request_id": "x"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPending(); !errors.Is(err, ErrPendingInvalid) {
		t.Fatalf("a truncated record: %v, want pending_invalid", err)
	}
	if err := os.WriteFile(store.PendingPath(),
		[]byte(`{"client_request_id": "not-a-uuid", "key_pem": "", "csr_pem": ""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPending(); !errors.Is(err, ErrPendingInvalid) {
		t.Fatalf("a record without a key: %v, want pending_invalid", err)
	}
}

func TestAnAttemptNeedsAKeyThatCanBeWritten(t *testing.T) {
	// A hardware key gives out no material: recording an attempt with it would
	// leave a record that cannot be repeated.
	source := &nonExportableSource{keys: map[string]crypto.Signer{}}
	store := NewWithSource(t.TempDir(), source)
	if _, err := store.PreparePending(zeroes{}, testClock, "machine-1", nil, nil, ""); !errors.Is(err, ErrKeyNotExportable) {
		t.Fatalf("a hardware key: %v, want key_not_exportable", err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir(), PendingName)); !os.IsNotExist(err) {
		t.Fatal("a record without a key was written")
	}
}
