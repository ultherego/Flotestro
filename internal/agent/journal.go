package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// IdempotencyJournal remembers the results of performed tasks. The network
// works at-least-once, so the same task can arrive several times - the handler
// has to return the previous result then instead of performing the mutation
// again.
//
// The key is the idempotency_key and not the task_id. Ordering the same
// operation again creates a new attempt with a new task_id, so keying by
// task_id would allow the mutation to be performed a second time.
type IdempotencyJournal struct {
	dir string
	mu  sync.Mutex
	ttl time.Duration
}

func NewIdempotencyJournal(dir string, ttl time.Duration) (*IdempotencyJournal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("the journal directory: %w", err)
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	journal := &IdempotencyJournal{dir: dir, ttl: ttl}
	journal.Prune()
	return journal, nil
}

// Lookup returns the stored result of a task or nil when the task has not been
// seen yet.
func (j *IdempotencyJournal) Lookup(idempotencyKey string) *agentv1.TaskResult {
	if idempotencyKey == "" {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	data, err := os.ReadFile(j.path(idempotencyKey))
	if err != nil {
		return nil
	}
	var result agentv1.TaskResult
	if err := proto.Unmarshal(data, &result); err != nil {
		return nil
	}
	return &result
}

// Store writes the result of a task. The write is atomic so that an interrupted
// agent does not leave a truncated entry that would look like a valid result.
//
// The result replaces the in-flight marker of the same key: from now on the
// journal knows how the operation ended, so the question the marker asked is
// answered. The marker goes only after the result is in place - a crash
// between the two must leave the marker rather than nothing.
func (j *IdempotencyJournal) Store(idempotencyKey string, result *agentv1.TaskResult) error {
	if idempotencyKey == "" {
		return fmt.Errorf("an empty idempotency key")
	}
	data, err := proto.Marshal(result)
	if err != nil {
		return err
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if err := j.writeAtomically(j.path(idempotencyKey), data); err != nil {
		return err
	}
	if err := os.Remove(j.inFlightPath(idempotencyKey)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("the in-flight marker was not removed: %w", err)
	}
	return nil
}

// MarkInFlight records that the host is about to carry a mutation out. The
// marker lives next to the result, under its own name, and is written with
// the same discipline: a truncated marker must not look like a valid one.
//
// The marker is what tells a restart in the middle of an operation from a
// task that never started. Without it the agent that came back would compute
// the plan again and either carry the change out a second time or refuse it
// as changed - and neither answer says that the host has been touched.
func (j *IdempotencyJournal) MarkInFlight(marker InFlight) error {
	if marker.IdempotencyKey == "" {
		return fmt.Errorf("an empty idempotency key")
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	return j.writeAtomically(j.inFlightPath(marker.IdempotencyKey), data)
}

// InFlight returns the marker of a key that has no result yet. A key with a
// result has no marker: Store removes it.
func (j *IdempotencyJournal) InFlight(idempotencyKey string) (InFlight, bool) {
	if idempotencyKey == "" {
		return InFlight{}, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.readInFlight(j.inFlightPath(idempotencyKey))
}

// InFlightMarkers lists every marker the journal holds. The agent reads the
// list once, when it starts: every entry is an operation the previous process
// did not live to see the end of.
func (j *IdempotencyJournal) InFlightMarkers() []InFlight {
	j.mu.Lock()
	defer j.mu.Unlock()

	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return nil
	}
	var markers []InFlight
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), inFlightSuffix) {
			continue
		}
		if marker, ok := j.readInFlight(filepath.Join(j.dir, entry.Name())); ok {
			markers = append(markers, marker)
		}
	}
	return markers
}

// readInFlight decodes one marker. A marker that cannot be read is treated
// as absent: the file is either a leftover the atomic write protects
// against or of a shape this agent does not know, and neither is evidence
// of a change in progress.
func (j *IdempotencyJournal) readInFlight(path string) (InFlight, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return InFlight{}, false
	}
	var marker InFlight
	if err := json.Unmarshal(data, &marker); err != nil || marker.IdempotencyKey == "" {
		return InFlight{}, false
	}
	return marker, true
}

// writeAtomically puts the content in place through a temporary file and a
// rename. The caller holds the lock.
func (j *IdempotencyJournal) writeAtomically(path string, data []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// Prune removes the entries older than the TTL. The journal must not grow
// without end.
func (j *IdempotencyJournal) Prune() {
	j.mu.Lock()
	defer j.mu.Unlock()

	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return
	}
	deadline := time.Now().Add(-j.ttl)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(deadline) {
			_ = os.Remove(filepath.Join(j.dir, entry.Name()))
		}
	}
}

// path turns the key into a file name through a digest. The key comes from the
// network and can contain any characters, so it does not go into a path
// directly.
func (j *IdempotencyJournal) path(idempotencyKey string) string {
	sum := sha256.Sum256([]byte(idempotencyKey))
	return filepath.Join(j.dir, hex.EncodeToString(sum[:]))
}

// inFlightSuffix tells a marker from a result in the same directory. The
// result keeps the bare digest, as it always has, so a journal written by an
// older agent is read unchanged.
const inFlightSuffix = ".inflight"

func (j *IdempotencyJournal) inFlightPath(idempotencyKey string) string {
	return j.path(idempotencyKey) + inFlightSuffix
}
