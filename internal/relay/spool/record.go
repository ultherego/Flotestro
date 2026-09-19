// Package spool is the durable queue of a relay: the messages of the agents of
// a site that the centre has not yet confirmed it consumed.
package spool

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// The streams of the spool and their priorities, from the security document:
// identity and control first, job results and acknowledgements next, then
// inventory, metrics and interactive logs.
const (
	StreamControl   = "control"
	StreamJobResult = "job_result"
	StreamInventory = "inventory"
	StreamMetric    = "metric"
	StreamLog       = "log"
)

// The priorities of the streams. The number is what the send order and
// the quota read; the name is what the log and the panel show.
const (
	PriorityControl   uint8 = 0
	PriorityJobResult uint8 = 1
	PriorityInventory uint8 = 2
	PriorityMetric    uint8 = 3
	PriorityLog       uint8 = 4
)

// PriorityOf returns the priority of a stream.
func PriorityOf(stream string) uint8 {
	switch stream {
	case StreamControl:
		return PriorityControl
	case StreamJobResult:
		return PriorityJobResult
	case StreamInventory:
		return PriorityInventory
	case StreamMetric:
		return PriorityMetric
	}
	return PriorityLog
}

// Durable says whether a stream is written ahead of the live forward: a
// message of a durable stream goes to the disk before the socket, so a restart
// of the relay between the send and the panel's commit loses nothing.
func Durable(stream string) bool {
	return PriorityOf(stream) <= PriorityInventory
}

// Classify names the stream of a message of an agent.
func Classify(message *agentv1.AgentMessage) string {
	switch message.GetPayload().(type) {
	case *agentv1.AgentMessage_TaskResult, *agentv1.AgentMessage_TaskProgress:
		return StreamJobResult
	case *agentv1.AgentMessage_Inventory:
		return StreamInventory
	case *agentv1.AgentMessage_MetricsSample:
		return StreamMetric
	case *agentv1.AgentMessage_TaskLogLines:
		return StreamLog
	}
	// Hello, heartbeat, final ready, cancel ack: the control of the session.
	return StreamControl
}

// Record is one spooled message, as the security document lays it out.
type Record struct {
	ID        uuid.UUID
	Site      string
	HostID    string
	SessionID string
	Stream    string
	Priority  uint8
	// Sequence is the sequence of the envelope, zero for a message of an agent
	// from before the envelope.
	Sequence  uint64
	CreatedAt time.Time
	ExpiresAt *time.Time
	// Envelope is the host's signed envelope as it came, untouched: the
	// resend after a restart carries the same signature.
	Envelope []byte
	// Payload is the message without its envelope, in its protobuf
	// encoding; PayloadHash is its SHA-256.
	Payload     []byte
	PayloadHash [32]byte
}

// Full says whether the record carries a full inventory report. Only a
// full report supersedes the earlier inventory records of the host.
func (r *Record) Full() bool {
	if r.Stream != StreamInventory {
		return false
	}
	message, err := r.Message()
	if err != nil {
		return false
	}
	return message.GetInventory().GetFull()
}

// Message rebuilds the message of the agent with its envelope.
func (r *Record) Message() (*agentv1.AgentMessage, error) {
	message := &agentv1.AgentMessage{}
	if err := proto.Unmarshal(r.Payload, message); err != nil {
		return nil, err
	}
	// The record speaks its own identifier: that is what the panel acknowledges
	// it under, and what a redelivery has to carry again.
	message.RelayMessageId = r.ID.String()
	if len(r.Envelope) > 0 {
		envelope := &agentv1.RelayedEnvelope{}
		if err := proto.Unmarshal(r.Envelope, envelope); err != nil {
			return nil, err
		}
		message.Envelope = envelope
	}
	return message, nil
}

// Size is the room the record takes in a segment, header included.
func (r *Record) Size() int {
	return headerSize + r.bodySize()
}

// FromMessage builds the record of a message of an agent.
func FromMessage(site, hostID string, message *agentv1.AgentMessage, now time.Time) (*Record, error) {
	if message == nil {
		return nil, errors.New("no message")
	}
	stream := Classify(message)
	record := &Record{
		ID: uuid.New(), Site: site, HostID: hostID, Stream: stream,
		Priority: PriorityOf(stream), CreatedAt: now.UTC(),
	}
	if envelope := message.GetEnvelope(); envelope != nil {
		encoded, err := proto.Marshal(envelope)
		if err != nil {
			return nil, err
		}
		record.Envelope = encoded
		record.SessionID = envelope.GetSessionId()
		record.Sequence = envelope.GetSequence()
	}
	bare := proto.Clone(message).(*agentv1.AgentMessage)
	bare.Envelope = nil
	// The identifier belongs to the record, not to the payload: keeping it out
	// leaves the hash of what the host sent the same across every delivery.
	bare.RelayMessageId = ""
	payload, err := proto.Marshal(bare)
	if err != nil {
		return nil, err
	}
	record.Payload = payload
	record.PayloadHash = sha256.Sum256(payload)
	if expires := lifetimeOf(stream); expires > 0 {
		at := record.CreatedAt.Add(expires)
		record.ExpiresAt = &at
	}
	return record, nil
}

// lifetimeOf says how long a message of the stream is worth carrying.
func lifetimeOf(stream string) time.Duration {
	switch stream {
	case StreamMetric:
		return 6 * time.Hour
	case StreamLog:
		return time.Hour
	}
	return 30 * 24 * time.Hour
}

// The layout of a record on disk: a fixed header and a body.
const (
	headerSize    = 13
	kindRecord    = 1
	kindTombstone = 2
	bodyVersion   = 1
)

var magic = [4]byte{'F', 'S', 'P', '1'}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// errTorn is a record the reader cannot take: the segment ends inside it
// or its checksum does not match.
var errTorn = errors.New("torn record")

// frame writes a header and a body to a buffer.
func frame(kind byte, body []byte) []byte {
	out := make([]byte, headerSize+len(body))
	copy(out, magic[:])
	out[4] = kind
	binary.LittleEndian.PutUint32(out[5:9], uint32(len(body)))
	binary.LittleEndian.PutUint32(out[9:13], crc32.Checksum(body, castagnoli))
	copy(out[headerSize:], body)
	return out
}

// readFrame reads one frame from the reader. io.
func readFrame(reader io.Reader) (kind byte, body []byte, err error) {
	header := make([]byte, headerSize)
	n, err := io.ReadFull(reader, header)
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return 0, nil, io.EOF
		}
		return 0, nil, errTorn
	}
	if !bytes.Equal(header[:4], magic[:]) {
		return 0, nil, errTorn
	}
	kind = header[4]
	length := binary.LittleEndian.Uint32(header[5:9])
	if length > maxRecordBytes {
		return 0, nil, errTorn
	}
	body = make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return 0, nil, errTorn
	}
	if crc32.Checksum(body, castagnoli) != binary.LittleEndian.Uint32(header[9:13]) {
		return 0, nil, errTorn
	}
	return kind, body, nil
}

// maxRecordBytes bounds one record: an inventory report is at most a few
// megabytes, and a length beyond this is a corrupt header rather than a
// message.
const maxRecordBytes = 64 << 20

func (r *Record) bodySize() int {
	return 1 + 16 + 1 + 8 + 8 + 8 +
		2 + len(r.Site) + 2 + len(r.HostID) + 2 + len(r.SessionID) + 1 + len(r.Stream) +
		32 + 4 + len(r.Envelope) + 4 + len(r.Payload)
}

// encode writes the body of a record.
func (r *Record) encode() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, r.bodySize()))
	buf.WriteByte(bodyVersion)
	buf.Write(r.ID[:])
	buf.WriteByte(r.Priority)
	var scratch [8]byte
	put64 := func(value uint64) {
		binary.LittleEndian.PutUint64(scratch[:], value)
		buf.Write(scratch[:])
	}
	put64(r.Sequence)
	put64(uint64(r.CreatedAt.UnixNano()))
	if r.ExpiresAt != nil {
		put64(uint64(r.ExpiresAt.UnixNano()))
	} else {
		put64(0)
	}
	put16 := func(value string) {
		binary.LittleEndian.PutUint16(scratch[:2], uint16(len(value)))
		buf.Write(scratch[:2])
		buf.WriteString(value)
	}
	put16(r.Site)
	put16(r.HostID)
	put16(r.SessionID)
	buf.WriteByte(byte(len(r.Stream)))
	buf.WriteString(r.Stream)
	buf.Write(r.PayloadHash[:])
	put32 := func(value []byte) {
		binary.LittleEndian.PutUint32(scratch[:4], uint32(len(value)))
		buf.Write(scratch[:4])
		buf.Write(value)
	}
	put32(r.Envelope)
	put32(r.Payload)
	return buf.Bytes()
}

// decode reads the body of a record.
func decode(body []byte) (*Record, error) {
	reader := bytes.NewReader(body)
	version, err := reader.ReadByte()
	if err != nil || version != bodyVersion {
		return nil, fmt.Errorf("record version %d is not %d", version, bodyVersion)
	}
	record := &Record{}
	if _, err := io.ReadFull(reader, record.ID[:]); err != nil {
		return nil, err
	}
	if record.Priority, err = reader.ReadByte(); err != nil {
		return nil, err
	}
	var scratch [8]byte
	get64 := func() (uint64, error) {
		if _, err := io.ReadFull(reader, scratch[:]); err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(scratch[:]), nil
	}
	if record.Sequence, err = get64(); err != nil {
		return nil, err
	}
	created, err := get64()
	if err != nil {
		return nil, err
	}
	record.CreatedAt = time.Unix(0, int64(created)).UTC()
	expires, err := get64()
	if err != nil {
		return nil, err
	}
	if expires != 0 {
		at := time.Unix(0, int64(expires)).UTC()
		record.ExpiresAt = &at
	}
	get16 := func() (string, error) {
		if _, err := io.ReadFull(reader, scratch[:2]); err != nil {
			return "", err
		}
		value := make([]byte, binary.LittleEndian.Uint16(scratch[:2]))
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", err
		}
		return string(value), nil
	}
	if record.Site, err = get16(); err != nil {
		return nil, err
	}
	if record.HostID, err = get16(); err != nil {
		return nil, err
	}
	if record.SessionID, err = get16(); err != nil {
		return nil, err
	}
	length, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	stream := make([]byte, length)
	if _, err := io.ReadFull(reader, stream); err != nil {
		return nil, err
	}
	record.Stream = string(stream)
	if _, err := io.ReadFull(reader, record.PayloadHash[:]); err != nil {
		return nil, err
	}
	get32 := func() ([]byte, error) {
		if _, err := io.ReadFull(reader, scratch[:4]); err != nil {
			return nil, err
		}
		value := make([]byte, binary.LittleEndian.Uint32(scratch[:4]))
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, err
		}
		return value, nil
	}
	if record.Envelope, err = get32(); err != nil {
		return nil, err
	}
	if record.Payload, err = get32(); err != nil {
		return nil, err
	}
	if sha256.Sum256(record.Payload) != record.PayloadHash {
		return nil, errors.New("the payload does not match its hash")
	}
	return record, nil
}
