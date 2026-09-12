// Package relay implements the relay of a site: it terminates the connections
// of the agents, keeps one connection to the centre and buffers the results
// while the link is down.
package relay

import (
	"errors"
	"sync"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"google.golang.org/protobuf/proto"
)

// ErrBufferFull means the buffer is exhausted. The relay says so outright
// instead of silently losing results: a lost result of a job looks to the
// panel like a job that is still running.
var ErrBufferFull = errors.New("the buffer of the relay is full")

// Buffer keeps the messages of the agents for the duration of a break in the
// connectivity with the centre.
//
// The document requires a bounded buffer: a relay in a cut-off site must not
// grow until the disk is exhausted, because that takes from the site what
// works locally as well. The limit is counted in bytes, because it is bytes
// that correspond to the occupied resource rather than the number of
// messages.
type Buffer struct {
	mu       sync.Mutex
	items    []*bufferedMessage
	bytes    int
	maxBytes int
	dropped  int
}

type bufferedMessage struct {
	hostID  string
	payload []byte
	size    int
}

func NewBuffer(maxBytes int) *Buffer {
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	return &Buffer{maxBytes: maxBytes}
}

// Add sets a message of an agent aside. Once the limit is exceeded new
// messages are dropped rather than deleting the older ones: an older result
// usually concerns a job that has already finished and is closer to delivery
// than a newer one.
func (b *Buffer) Add(hostID string, message *agentv1.AgentMessage) error {
	payload, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.bytes+len(payload) > b.maxBytes {
		b.dropped++
		return ErrBufferFull
	}
	b.items = append(b.items, &bufferedMessage{hostID: hostID, payload: payload, size: len(payload)})
	b.bytes += len(payload)
	return nil
}

// Take takes the oldest message without removing it from the buffer. A
// message disappears only after a confirmed send: a loss at the edge of the
// network must not mean a lost result.
func (b *Buffer) Take() (hostID string, message *agentv1.AgentMessage, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) == 0 {
		return "", nil, false
	}
	item := b.items[0]
	decoded := &agentv1.AgentMessage{}
	if err := proto.Unmarshal(item.payload, decoded); err != nil {
		// A damaged message cannot be delivered; we remove it so that it does
		// not block the whole queue.
		b.removeFirstLocked()
		return "", nil, false
	}
	return item.hostID, decoded, true
}

// Commit removes a confirmed message.
func (b *Buffer) Commit() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removeFirstLocked()
}

func (b *Buffer) removeFirstLocked() {
	if len(b.items) == 0 {
		return
	}
	b.bytes -= b.items[0].size
	b.items = b.items[1:]
}

// Stats describes the fill of the buffer for the metrics and for the
// decisions of the operator.
type Stats struct {
	Messages int
	Bytes    int
	MaxBytes int
	Dropped  int
}

func (b *Buffer) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{Messages: len(b.items), Bytes: b.bytes, MaxBytes: b.maxBytes, Dropped: b.dropped}
}

// TakeFor returns the oldest message of a given host without removing it from
// the buffer. The buffer is shared by the site, but it is sent back in the
// session of a specific host: the centre binds a stream to one identity.
func (b *Buffer) TakeFor(hostID string) (*agentv1.AgentMessage, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, item := range b.items {
		if item.hostID != hostID {
			continue
		}
		decoded := &agentv1.AgentMessage{}
		if err := proto.Unmarshal(item.payload, decoded); err != nil {
			b.removeLocked(item)
			return nil, false
		}
		return decoded, true
	}
	return nil, false
}

// CommitFor removes the oldest message of a given host.
func (b *Buffer) CommitFor(hostID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, item := range b.items {
		if item.hostID == hostID {
			b.removeLocked(item)
			return
		}
	}
}

func (b *Buffer) removeLocked(target *bufferedMessage) {
	for index, item := range b.items {
		if item != target {
			continue
		}
		b.bytes -= item.size
		b.items = append(b.items[:index], b.items[index+1:]...)
		return
	}
}
