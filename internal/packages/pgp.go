package packages

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// The key of a repository is public material, so the panel may send it in an
// order - unlike a password, which goes through the secret store. Public does
// not mean arbitrary, though: it is that key that settles whose packages the
// host will install. That is why, before it lands on disk, we check that it
// really is an OpenPGP key and compute its fingerprint - so that a person has
// something to compare with the fingerprint given by the supplier.
//
// We compute it ourselves, without an OpenPGP library: what is needed is one
// packet from an ASCII frame and one digest, not a whole trust model.

// KeyFingerprint checks the key material and returns the fingerprint of the
// primary key.
func KeyFingerprint(material string) (string, error) {
	data, err := unwrapFrame(material)
	if err != nil {
		return "", err
	}
	packet, err := firstPublicKey(data)
	if err != nil {
		return "", err
	}
	return keyPacketFingerprint(packet)
}

// unwrapFrame removes the ASCII frame and decodes the content.
//
// A key given in binary is a key as well: we recognise it by the missing frame
// header and pass it on without decoding.
func unwrapFrame(material string) ([]byte, error) {
	trimmed := strings.TrimSpace(material)
	if trimmed == "" {
		return nil, fmt.Errorf("the key material is empty")
	}
	if !strings.HasPrefix(trimmed, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		return nil, fmt.Errorf("the material is not an OpenPGP public key in an ASCII frame")
	}
	lines := strings.Split(trimmed, "\n")
	var content strings.Builder
	inContent := false
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "-----END"):
			inContent = false
		case !inContent && line == "":
			// An empty line ends the headers of the frame and starts the
			// content.
			inContent = true
		case inContent:
			// The CRC24 checksum starts with an equals sign and does not
			// belong to the content.
			if strings.HasPrefix(line, "=") {
				continue
			}
			content.WriteString(line)
		}
	}
	if content.Len() == 0 {
		return nil, fmt.Errorf("the frame of the key carries no content")
	}
	data, err := base64.StdEncoding.DecodeString(content.String())
	if err != nil {
		return nil, fmt.Errorf("the content of the key is not valid base64: %w", err)
	}
	return data, nil
}

// firstPublicKey finds the packet of the primary key (tag 6).
func firstPublicKey(data []byte) ([]byte, error) {
	i := 0
	for i < len(data) {
		header := data[i]
		if header&0x80 == 0 {
			return nil, fmt.Errorf("the key material has an invalid packet structure")
		}
		var tag int
		var length int
		if header&0x40 != 0 {
			// The new format: the tag in six bits, the length one or several
			// bytes.
			tag = int(header & 0x3f)
			i++
			if i >= len(data) {
				return nil, fmt.Errorf("the packet of the key is cut short")
			}
			first := int(data[i])
			switch {
			case first < 192:
				length = first
				i++
			case first < 224:
				if i+1 >= len(data) {
					return nil, fmt.Errorf("the packet of the key is cut short")
				}
				length = (first-192)<<8 + int(data[i+1]) + 192
				i += 2
			case first == 255:
				if i+4 >= len(data) {
					return nil, fmt.Errorf("the packet of the key is cut short")
				}
				length = int(data[i+1])<<24 | int(data[i+2])<<16 |
					int(data[i+3])<<8 | int(data[i+4])
				i += 5
			default:
				// A partial length occurs in streamed data rather than in a
				// key.
				return nil, fmt.Errorf("the key material has an unsupported packet length")
			}
		} else {
			tag = int(header&0x3c) >> 2
			lengthType := int(header & 0x03)
			i++
			switch lengthType {
			case 0:
				if i >= len(data) {
					return nil, fmt.Errorf("the packet of the key is cut short")
				}
				length = int(data[i])
				i++
			case 1:
				if i+1 >= len(data) {
					return nil, fmt.Errorf("the packet of the key is cut short")
				}
				length = int(data[i])<<8 | int(data[i+1])
				i += 2
			case 2:
				if i+3 >= len(data) {
					return nil, fmt.Errorf("the packet of the key is cut short")
				}
				length = int(data[i])<<24 | int(data[i+1])<<16 |
					int(data[i+2])<<8 | int(data[i+3])
				i += 4
			default:
				return nil, fmt.Errorf("the key material has an unsupported packet length")
			}
		}
		if length < 0 || i+length > len(data) {
			return nil, fmt.Errorf("the packet of the key is cut short")
		}
		if tag == 6 {
			return data[i : i+length], nil
		}
		i += length
	}
	return nil, fmt.Errorf("the material carries no public key packet")
}

// keyPacketFingerprint computes the fingerprint of the primary key.
//
// Version 4 computes SHA-1 over the prefix 0x99 and a two-byte length; version
// 6 - SHA-256 over the prefix 0x9b and a four-byte length. A version we do not
// know is not guessed at: a wrong fingerprint is worse than no fingerprint,
// because a person would compare it with the one of the supplier and call it a
// match.
func keyPacketFingerprint(packet []byte) (string, error) {
	if len(packet) == 0 {
		return "", fmt.Errorf("the packet of the key is empty")
	}
	switch packet[0] {
	case 4:
		sum := sha1.New()
		sum.Write([]byte{0x99, byte(len(packet) >> 8), byte(len(packet))})
		sum.Write(packet)
		return strings.ToUpper(hex.EncodeToString(sum.Sum(nil))), nil
	case 6:
		sum := sha256.New()
		length := len(packet)
		sum.Write([]byte{0x9b, byte(length >> 24), byte(length >> 16),
			byte(length >> 8), byte(length)})
		sum.Write(packet)
		return strings.ToUpper(hex.EncodeToString(sum.Sum(nil))), nil
	}
	return "", fmt.Errorf("a key of version %d is not supported", packet[0])
}
