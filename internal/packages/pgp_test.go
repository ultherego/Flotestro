package packages

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// keyPacket assembles a minimal public key packet in version 4: the version,
// the timestamp, the algorithm and the key material. Nothing more is needed to
// compute the fingerprint, and a packet of our own allows checking the
// reckoning without pasting somebody else's key into the test.
func keyPacket() []byte {
	content := []byte{4, 0x66, 0x00, 0x00, 0x00, 1}
	content = append(content, make([]byte, 20)...)
	return content
}

func frame(data []byte) string {
	header := []byte{0xc0 | 6, byte(len(data))}
	full := append(header, data...)
	encoded := base64.StdEncoding.EncodeToString(full)
	return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" +
		encoded + "\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n"
}

func TestTheKeyFingerprintComputesSHA1OverThePrefix(t *testing.T) {
	packet := keyPacket()
	fingerprint, err := KeyFingerprint(frame(packet))
	if err != nil {
		t.Fatalf("KeyFingerprint: %v", err)
	}

	sum := sha1.New()
	sum.Write([]byte{0x99, byte(len(packet) >> 8), byte(len(packet))})
	sum.Write(packet)
	expected := strings.ToUpper(hex.EncodeToString(sum.Sum(nil)))
	if fingerprint != expected {
		t.Fatalf("fingerprint = %s, expected %s", fingerprint, expected)
	}
	if len(fingerprint) != 40 {
		t.Fatalf("the fingerprint of a v4 key has %d characters", len(fingerprint))
	}
}

func TestTheKeyFingerprintRejectsWhatIsNotAKey(t *testing.T) {
	bad := map[string]string{
		"empty":                  "",
		"without a frame":        "this is not a key",
		"an empty frame":         "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----",
		"broken base64":          "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n-----END PGP PUBLIC KEY BLOCK-----",
		"a certificate":          "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"a packet without a key": frame([]byte{}),
	}
	for name, material := range bad {
		if _, err := KeyFingerprint(material); err == nil {
			t.Errorf("%s: the material was accepted as a key", name)
		}
	}

	// A version we do not know is not guessed at: a wrong fingerprint is worse
	// than none, because a person would call it a match with the one of the
	// supplier.
	unknownVersion := append([]byte{9}, make([]byte, 10)...)
	if _, err := KeyFingerprint(frame(unknownVersion)); err == nil {
		t.Error("a key of an unknown version got a fingerprint")
	}
}
