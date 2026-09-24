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

// IdempotencyJournal remembers the results of performed tasks.
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

// Store writes the result of a task.
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

// MarkInFlight records that the host is about to carry a mutation out.
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

// InFlightMarkers lists every marker the journal holds.
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

// readInFlight decodes one marker.
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
// rename, flushing both the file and the directory. The caller holds the lock.
// A rename that is only in the page cache is no record at all: the event this
// journal exists for - a host that stops in the middle of a change - is
// exactly the event that would lose it.
func (j *IdempotencyJournal) writeAtomically(path string, data []byte) error {
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncPath(filepath.Dir(path))
}

// syncPath flushes a directory entry, so a rename survives a power cut.
func syncPath(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
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
		// A marker of a task nobody resolved is the record that the outcome is
		// unknown. Aging it out turns "the host may have carried this out" into
		// "it never ran", and the task is then carried out a second time. It
		// leaves when the result replaces it or reconciliation resolves it.
		if strings.HasSuffix(entry.Name(), inFlightSuffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(deadline) {
			_ = os.Remove(filepath.Join(j.dir, entry.Name()))
		}
	}
}

// path turns the key into a file name through a digest.
func (j *IdempotencyJournal) path(idempotencyKey string) string {
	sum := sha256.Sum256([]byte(idempotencyKey))
	return filepath.Join(j.dir, hex.EncodeToString(sum[:]))
}

// inFlightSuffix tells a marker from a result in the same directory.
const inFlightSuffix = ".inflight"

func (j *IdempotencyJournal) inFlightPath(idempotencyKey string) string {
	return j.path(idempotencyKey) + inFlightSuffix
}
