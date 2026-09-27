package helpercap

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The helper verified its first bundle with a key carried inside that bundle,
// so any signer at all verified against itself: whoever reached the helper's
// socket before the panel did owned the host from then on. A pin written by
// root beforehand is what decides instead.
func TestTheFirstBundleIsHeldToThePinnedPanel(t *testing.T) {
	panel := newSigner(t)
	stranger := newSigner(t)
	now := time.Now()

	pinned := func(t *testing.T, fingerprints ...string) TrustStore {
		t.Helper()
		dir := t.TempDir()
		store := TrustStore{Dir: filepath.Join(dir, "trust.d"),
			HostIDPath: filepath.Join(dir, "host-id"),
			PinPath:    filepath.Join(dir, "panel-trust.pin")}
		if len(fingerprints) > 0 {
			if err := store.WritePins(fingerprints); err != nil {
				t.Fatalf("writing the pin: %v", err)
			}
		}
		return store
	}

	// The panel the operator named enrolls the host.
	store := pinned(t, panel.Fingerprints()[0])
	if _, err := store.Apply(panel.TrustBundle("host-1", now)); err != nil {
		t.Fatalf("the pinned panel was refused: %v", err)
	}

	// Anybody else does not, however well formed their bundle is.
	store = pinned(t, panel.Fingerprints()[0])
	if _, err := store.Apply(stranger.TrustBundle("host-1", now)); CodeOf(err) != ErrorTrustPin {
		t.Fatalf("a bundle of another panel got %v, expected %s", err, ErrorTrustPin)
	}

	// A host that names nobody enrolls with nobody, and a field nobody filled
	// in counts as that: the safe answer is the one no operator has to choose.
	store = pinned(t)
	if _, err := store.Apply(stranger.TrustBundle("host-1", now)); CodeOf(err) != ErrorTrustPin {
		t.Fatalf("a host with no pin and nothing said got %v, expected %s", err, ErrorTrustPin)
	}
	store = pinned(t)
	store.Bootstrap = BootstrapPinned
	if _, err := store.Apply(panel.TrustBundle("host-1", now)); CodeOf(err) != ErrorTrustPin {
		t.Fatalf("a host on pinned with no pin got %v, expected %s", err, ErrorTrustPin)
	}

	// Taking the first panel that asks is still possible, and it is now a thing
	// somebody wrote down rather than the way a host behaves by default.
	store = pinned(t)
	store.Bootstrap = BootstrapTOFU
	if _, err := store.Apply(stranger.TrustBundle("host-1", now)); err != nil {
		t.Fatalf("a host told to take the first bundle refused it: %v", err)
	}
}

// A rotation signs the bundle with the previous key, so both fingerprints the
// panel prints belong in the file.
func TestThePinCoversBothKeysOfARotation(t *testing.T) {
	panel := newSigner(t)
	panel.previous = newSigner(t)
	dir := t.TempDir()
	store := TrustStore{Dir: filepath.Join(dir, "trust.d"),
		HostIDPath: filepath.Join(dir, "host-id"),
		PinPath:    filepath.Join(dir, "panel-trust.pin")}
	fingerprints := panel.Fingerprints()
	if len(fingerprints) != 2 {
		t.Fatalf("a rotating panel prints %d fingerprints, expected 2", len(fingerprints))
	}
	if err := store.WritePins(fingerprints); err != nil {
		t.Fatalf("writing the pin: %v", err)
	}
	if _, err := store.Apply(panel.TrustBundle("host-1", time.Now())); err != nil {
		t.Fatalf("a bundle signed by the previous key was refused: %v", err)
	}
}

// The file belongs to the operator, and what it says is read back as written.
func TestThePinFileIsReadAsWritten(t *testing.T) {
	dir := t.TempDir()
	store := TrustStore{PinPath: filepath.Join(dir, "panel-trust.pin")}
	if pins, err := store.Pins(); err != nil || len(pins) != 0 {
		t.Fatalf("a missing file gave %v (%v), expected no pin and no error", pins, err)
	}
	signer := newSigner(t)
	if err := store.WritePins([]string{"sha256:" + signer.Fingerprints()[0]}); err != nil {
		t.Fatalf("writing the pin: %v", err)
	}
	pins, err := store.Pins()
	if err != nil || len(pins) != 1 || pins[0] != signer.Fingerprints()[0] {
		t.Fatalf("the pin came back as %v (%v)", pins, err)
	}
	if err := store.WritePins([]string{"not-a-fingerprint"}); err == nil {
		t.Error("a line that is not a fingerprint was written")
	}
	if err := store.WritePins(nil); err != nil {
		t.Fatalf("clearing the pin: %v", err)
	}
	if _, err := os.Stat(store.PinPath); !os.IsNotExist(err) {
		t.Error("clearing the pin left the file behind")
	}
}
