package helpercap

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/ultherego/flotestro/internal/jcs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// payloadScheme is the line that opens the canonical payload: the scheme of
// the payload hash the agent already verifies (opspec.
const payloadScheme = "flotestro-payload-hash/2"

// CanonicalPayload renders the bytes the capability binds: the preimage of the
// version 2 payload hash - the scheme line, the action type, the action
// version and the canonical JSON of the payload.
func CanonicalPayload(action opspec.ActionType, version int, payload opspec.Payload) ([]byte, error) {
	encoded, err := jcs.Canonical(withoutEmptySubPayloads(payload))
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "%s\n%s\n%d\n%s", payloadScheme, action, version, encoded), nil
}

// withoutEmptySubPayloads drops the sub-payloads that carry no content, the
// way the payload hash does: a payload with an empty sub-payload and one
// without it describe the same operation, and the bytes under the digest have
func withoutEmptySubPayloads(payload opspec.Payload) opspec.Payload {
	value := reflect.ValueOf(&payload).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() != reflect.Pointer || field.IsNil() {
			continue
		}
		zero := reflect.New(field.Type().Elem())
		if reflect.DeepEqual(field.Interface(), zero.Interface()) {
			field.Set(reflect.Zero(field.Type()))
		}
	}
	return payload
}

// BoundPayload is what the helper reads out of the canonical payload.
type BoundPayload struct {
	Action  opspec.ActionType
	Version int
	Payload opspec.Payload
}

// DecodeCanonicalPayload reads the canonical payload back.
func DecodeCanonicalPayload(canonical []byte) (*BoundPayload, error) {
	parts := bytes.SplitN(canonical, []byte("\n"), 4)
	if len(parts) != 4 {
		return nil, errors.New("the canonical payload has fewer than four parts")
	}
	if string(parts[0]) != payloadScheme {
		return nil, fmt.Errorf("the canonical payload uses the scheme %q, not %s", parts[0], payloadScheme)
	}
	version, err := strconv.Atoi(string(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("the action version of the canonical payload: %w", err)
	}
	var payload opspec.Payload
	if err := json.Unmarshal(parts[3], &payload); err != nil {
		return nil, fmt.Errorf("the canonical payload: %w", err)
	}
	return &BoundPayload{Action: opspec.ActionType(parts[1]), Version: version, Payload: payload}, nil
}

// PayloadDigest is the digest a capability carries for a canonical payload.
func PayloadDigest(canonical []byte) []byte {
	sum := sha256.Sum256(canonical)
	return sum[:]
}
