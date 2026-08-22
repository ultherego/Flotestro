// Package helper zawiera protokol i serwer helpera roota. Helper nasluchuje
// wylacznie na gniezdzie unixowym, jest aktywowany przez systemd na zadanie
// i nigdy nie rozmawia z control plane.
package helper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// ProtocolVersion zmienia sie przy kazdej niezgodnej zmianie kontraktu.
// Helper odrzuca wersje, ktorej nie zna, zamiast zgadywac znaczenie pol.
const ProtocolVersion = 1

// maxFrameBytes ogranicza pojedyncza wiadomosc. Helper dziala jako root, wiec
// nie moze pozwolic rozmowcy zaalokowac dowolnej ilosci pamieci.
const maxFrameBytes = 1 << 20

// ErrFrameTooLarge oznacza ramke przekraczajaca limit.
var ErrFrameTooLarge = errors.New("ramka przekracza dozwolony rozmiar")

// Stabilne kody bledow helpera. Sa czescia kontraktu i nie zaleza od jezyka.
const (
	ErrorUnsupportedVersion = "unsupported_version"
	ErrorUnknownAction      = "unknown_action"
	ErrorExpired            = "expired"
	ErrorProtectedUnit      = "protected_unit"
	ErrorInvalidUnit        = "invalid_unit"
	ErrorLocked             = "locked"
	ErrorExecFailed         = "exec_failed"
	ErrorTimeout            = "timeout"
	ErrorMalformed          = "malformed_request"
)

// WriteMessage zapisuje wiadomosc poprzedzona 4-bajtowa dlugoscia.
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

// ReadMessage czyta wiadomosc poprzedzona 4-bajtowa dlugoscia.
func ReadMessage(r io.Reader, message proto.Message) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxFrameBytes {
		return fmt.Errorf("%w: %d bajtow", ErrFrameTooLarge, length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return proto.Unmarshal(payload, message)
}
