package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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

	temporary := j.path(idempotencyKey) + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, j.path(idempotencyKey))
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
