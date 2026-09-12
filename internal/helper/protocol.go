// Package helper holds the protocol and the server of the root helper. The
// helper listens only on a unix socket, is activated by systemd on demand and
// never talks to the control plane.
package helper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// ProtocolVersion changes with every incompatible change of the contract. The
// helper rejects a version it does not know instead of guessing the meaning of
// the fields.
const ProtocolVersion = 1

// maxFrameBytes limits a single message. The helper runs as root, so it must
// not let the peer allocate an arbitrary amount of memory.
const maxFrameBytes = 1 << 20

// ErrFrameTooLarge means a frame exceeding the limit.
var ErrFrameTooLarge = errors.New("the frame exceeds the allowed size")

// Stable helper error codes. They are part of the contract and do not depend
// on the language.
const (
	ErrorUnsupportedVersion = "unsupported_version"
	ErrorUnknownAction      = "unknown_action"
	ErrorExpired            = "expired"
	ErrorProtectedUnit      = "protected_unit"
	ErrorInvalidUnit        = "invalid_unit"
	ErrorLocked             = "locked"
	ErrorExecFailed         = "exec_failed"
	ErrorTimeout            = "timeout"
	// ErrorUnsupported means an operation this host does not support. A clear
	// refusal is better than pretending the operation ran.
	ErrorUnsupported = "unsupported"
	ErrorMalformed   = "malformed_request"
	// ErrorPreconditionFailed means an order placed against a host state other
	// than the one the host has now. This is neither a flaw of the order nor a
	// failure of the execution: it is a change that happened in between.
	ErrorPreconditionFailed = "precondition_failed"
	// Refusals of container engine cleanup. Different reasons, because the
	// conclusions differ: an object in use is not removed until the service is
	// stopped, and a built-in network is never removed.
	ErrorDockerInUse         = "docker_object_in_use"
	ErrorDockerPredefined    = "docker_network_predefined"
	ErrorDockerObjectMissing = "docker_object_missing"
)

// WriteMessage writes a message preceded by a 4-byte length.
func WriteMessage(w io.Writer, message proto.Message) error {
	payload, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	if len(payload) > maxFrameBytes {
		return ErrFrameTooLarge
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// ReadMessage reads a message preceded by a 4-byte length.
func ReadMessage(r io.Reader, message proto.Message) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxFrameBytes {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return proto.Unmarshal(payload, message)
}
