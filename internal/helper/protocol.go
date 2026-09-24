// Package helper holds the protocol and the server of the root helper.
package helper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// ProtocolVersion changes with every incompatible change of the contract.
const ProtocolVersion = 1

// maxFrameBytes limits a single message. The helper runs as root, so it must
// not let the peer allocate an arbitrary amount of memory.
const maxFrameBytes = 4 << 20

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
	// ErrorRepositoryAbsent means a backup repository that is not there yet.
	ErrorRepositoryAbsent = "repository_absent"
	// ErrorPreconditionFailed means an order placed against a host state other
	// than the one the host has now.
	ErrorPreconditionFailed = "precondition_failed"
	// ErrorInhibitorsUnknown: the host could not be asked whether anything is
	// holding a restart or a shutdown back, so it was not ordered on an
	// unread answer.
	ErrorInhibitorsUnknown = "inhibitors_unknown"
	// Refusals of container engine cleanup.
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
