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

// IdempotencyJournal pamieta wyniki wykonanych zadan. Siec dziala w trybie
// at-least-once, wiec to samo zadanie moze dotrzec kilka razy - handler musi
// wtedy zwrocic poprzedni wynik, a nie wykonac mutacje ponownie.
//
// Kluczem jest idempotency_key, a nie task_id. Ponowne zlecenie tej samej
// operacji tworzy nowa probe z nowym task_id, wiec kluczowanie po task_id
// pozwolilo by wykonac mutacje drugi raz.
type IdempotencyJournal struct {
	dir string
	mu  sync.Mutex
	ttl time.Duration
}

func NewIdempotencyJournal(dir string, ttl time.Duration) (*IdempotencyJournal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("katalog dziennika: %w", err)
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	journal := &IdempotencyJournal{dir: dir, ttl: ttl}
	journal.Prune()
	return journal, nil
}

// Lookup zwraca zapisany wynik zadania albo nil, gdy zadania jeszcze nie bylo.
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

// Store zapisuje wynik zadania. Zapis jest atomowy, zeby przerwany agent nie
// zostawil obcietego wpisu, ktory wygladalby jak poprawny wynik.
func (j *IdempotencyJournal) Store(idempotencyKey string, result *agentv1.TaskResult) error {
	if idempotencyKey == "" {
		return fmt.Errorf("pusty klucz idempotencji")
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

// Prune usuwa wpisy starsze niz TTL. Dziennik nie moze rosnac bez konca.
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

// path zamienia klucz na nazwe pliku przez skrot. Klucz pochodzi z sieci
// i moze zawierac dowolne znaki, wiec nie trafia do sciezki wprost.
func (j *IdempotencyJournal) path(idempotencyKey string) string {
	sum := sha256.Sum256([]byte(idempotencyKey))
	return filepath.Join(j.dir, hex.EncodeToString(sum[:]))
}
