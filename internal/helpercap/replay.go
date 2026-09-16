package helpercap

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultReplayDir is where a packaged helper remembers consumed nonces.
const DefaultReplayDir = "/var/lib/flotestro-helper/replay"

// ReplayStore remembers every nonce the helper consumed, as a file per
// nonce in a root-owned directory. No database and no service: the file
// system is what survives a restart of the helper, and O_EXCL is what
// makes two consumptions of one nonce impossible - the second create
// fails in the kernel, whichever process asks.
//
// One task may ask the helper more than once under one capability: a
// network change is applied and then confirmed, a package upgrade
// refreshes the metadata and then upgrades. The nonce is consumed by the
// first request; a later request of the same task is honoured for as long
// as this process lives, because the record names the task and the life
// of the helper that made it. After a restart the same nonce is a replay,
// which is what the document's third helper test demands.
type ReplayStore struct {
	dir   string
	dirfd int
	// life names this process; a record made by another life is a replay.
	life string
	mu   sync.Mutex
	// sweptAt is when expired records were last removed.
	sweptAt time.Time
	now     func() time.Time
}

// OpenReplayStore opens the directory, creating it with mode 0700 when it
// is missing. The directory descriptor is kept open, so every record is
// created relative to it and never through a path somebody else could
// redirect.
func OpenReplayStore(dir string) (*ReplayStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	dirfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("the replay directory %s: %w", dir, err)
	}
	life := make([]byte, 8)
	if _, err := rand.Read(life); err != nil {
		unix.Close(dirfd)
		return nil, err
	}
	store := &ReplayStore{dir: dir, dirfd: dirfd, life: hex.EncodeToString(life), now: time.Now}
	store.Sweep()
	return store, nil
}

// Close releases the directory.
func (s *ReplayStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirfd < 0 {
		return nil
	}
	err := unix.Close(s.dirfd)
	s.dirfd = -1
	return err
}

// Consume records the nonce. The second consumption of a nonce by another
// task, or by another life of the helper, is a replay.
func (s *ReplayStore) Consume(nonce []byte, expires int64, taskID string) error {
	if len(nonce) != NonceSize {
		return refusal(ErrorInvalidNonce, fmt.Sprintf("the nonce has %d bytes, not %d", len(nonce), NonceSize))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirfd < 0 {
		return errors.New("the replay store is closed")
	}
	s.sweepLocked()

	sum := sha256.Sum256(nonce)
	name := hex.EncodeToString(sum[:])
	fd, err := unix.Openat(s.dirfd, name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if errors.Is(err, unix.EEXIST) {
		if s.sameTaskInThisLife(name, taskID) {
			return nil
		}
		return refusal(ErrorCapabilityReplay, "the nonce of the capability was consumed before")
	}
	if err != nil {
		return fmt.Errorf("recording the nonce: %w", err)
	}
	defer unix.Close(fd)
	record := strconv.FormatInt(expires, 10) + "\n" + taskID + "\n" + s.life + "\n"
	if err := writeAndFsync(fd, record); err != nil {
		return err
	}
	// The directory entry has to be durable as well: a record whose entry
	// vanished with a power cut would let the nonce be consumed again.
	if err := unix.Fsync(s.dirfd); err != nil {
		return fmt.Errorf("syncing the replay directory: %w", err)
	}
	return nil
}

// sameTaskInThisLife says whether the existing record belongs to the same
// task and was made by this process.
func (s *ReplayStore) sameTaskInThisLife(name, taskID string) bool {
	if taskID == "" {
		return false
	}
	fd, err := unix.Openat(s.dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	buffer := make([]byte, 512)
	n, err := unix.Read(fd, buffer)
	if err != nil {
		return false
	}
	lines := strings.Split(string(buffer[:n]), "\n")
	return len(lines) >= 3 && lines[1] == taskID && lines[2] == s.life
}

func writeAndFsync(fd int, content string) error {
	data := []byte(content)
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err != nil {
			return fmt.Errorf("writing the nonce record: %w", err)
		}
		data = data[n:]
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("syncing the nonce record: %w", err)
	}
	return nil
}

// Sweep removes the records of capabilities that expired long enough ago
// that no clock skew could bring them back. A record is kept ClockSkew
// past its expiry, because the verifier accepts a capability that far past
// its window on a host whose clock runs ahead.
func (s *ReplayStore) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweptAt = time.Time{}
	s.sweepLocked()
}

// sweepInterval bounds how often a consumption pays for a directory scan.
const sweepInterval = time.Minute

func (s *ReplayStore) sweepLocked() {
	now := s.now()
	if now.Sub(s.sweptAt) < sweepInterval {
		return
	}
	s.sweptAt = now
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || len(entry.Name()) != 64 {
			continue
		}
		expires, ok := s.expiryOf(entry.Name())
		if !ok {
			continue
		}
		if now.Unix() > expires+int64(ClockSkew.Seconds()) {
			_ = unix.Unlinkat(s.dirfd, entry.Name(), 0)
		}
	}
}

func (s *ReplayStore) expiryOf(name string) (int64, bool) {
	fd, err := unix.Openat(s.dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, false
	}
	defer unix.Close(fd)
	buffer := make([]byte, 64)
	n, err := unix.Read(fd, buffer)
	if err != nil || n == 0 {
		return 0, false
	}
	first, _, _ := strings.Cut(string(buffer[:n]), "\n")
	expires, err := strconv.ParseInt(strings.TrimSpace(first), 10, 64)
	if err != nil {
		return 0, false
	}
	return expires, true
}
