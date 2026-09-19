package gateway

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/hosts"
)

// A relay attests the certificate of the host with its fingerprint and serial.
func TestTheRelayAttestationIsReadWhole(t *testing.T) {
	fingerprint := strings.Repeat("ab", 32)
	headers := http.Header{}
	headers.Set(relayHostFingerprintHeader, fingerprint)
	headers.Set(relayHostSerialHeader, "42")
	attestation, err := readRelayAttestation(headers)
	if err != nil || attestation == nil {
		t.Fatalf("a whole attestation was not read: %v %v", attestation, err)
	}
	if hex.EncodeToString(attestation.Fingerprint) != fingerprint || attestation.Serial != "42" {
		t.Fatalf("read %x %q", attestation.Fingerprint, attestation.Serial)
	}

	if attestation, err := readRelayAttestation(http.Header{}); err != nil || attestation != nil {
		t.Fatalf("a relay that said nothing was read as %v %v", attestation, err)
	}
	for name, header := range map[string]http.Header{
		"a serial without a fingerprint":  {relayHostSerialHeader: {"42"}},
		"a fingerprint that is not hex":   {relayHostFingerprintHeader: {"not-hex"}},
		"a fingerprint of the wrong size": {relayHostFingerprintHeader: {"abcd"}},
	} {
		if _, err := readRelayAttestation(header); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The record carries the validity of a certificate the gateway never sees -
// one presented to a relay - and the refusal reads it the way the handshake
// reads the certificate itself.
func TestTheValidityOfAnAttestedCertificateComesFromTheRecord(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	live := hosts.CertificateStatus{Known: true, HostID: testHostID, LifecycleState: hosts.StateActive,
		Serial: "7", NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour)}
	if code, _ := certificateStatusRefusal(live, testHostID, now); code != "" {
		t.Fatalf("a live certificate on record was refused: %s", code)
	}
	expired := live
	expired.NotAfter = now.Add(-time.Minute)
	if code, detail := certificateStatusRefusal(expired, testHostID, now); code != hosts.RefusalCertificateExpired ||
		!strings.Contains(detail, "serial 7") {
		t.Fatalf("an expired certificate on record answered %q %q", code, detail)
	}
	future := live
	future.NotBefore = now.Add(time.Hour)
	if code, _ := certificateStatusRefusal(future, testHostID, now); code != hosts.RefusalCertificateNotYetValid {
		t.Fatalf("a certificate from the future on record answered %q", code)
	}
	// Revocation outranks the validity: a revoked certificate is refused
	// as revoked whatever its dates say.
	revoked := expired
	revoked.Revoked = true
	if code, _ := certificateStatusRefusal(revoked, testHostID, now); code != hosts.RefusalRevokedCertificate {
		t.Fatalf("a revoked and expired certificate answered %q", code)
	}
}

// The mode is read strictly: the three words, or the default for nothing,
// and anything else is a misconfiguration rather than a silent default.
func TestTheRelayIdentityModeIsReadStrictly(t *testing.T) {
	for value, want := range map[string]RelayIdentityMode{
		"": RelayIdentityPrefer, "observe": RelayIdentityObserve, "prefer": RelayIdentityPrefer,
		"enforce": RelayIdentityEnforce, " Enforce ": RelayIdentityEnforce,
	} {
		got, err := ParseRelayIdentityMode(value)
		if err != nil || got != want {
			t.Errorf("%q: %q %v, expected %q", value, got, err, want)
		}
	}
	if _, err := ParseRelayIdentityMode("strict"); err == nil {
		t.Error("an unknown mode was accepted")
	}
}
