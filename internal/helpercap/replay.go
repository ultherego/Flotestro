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

// ReplayStore remembers every nonce the helper consumed, as a file per nonce
// in a root-owned directory.
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

// OpenReplayStore opens the directory, creating it with mode 0700 when it is
// missing.
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

// One capability covers a whole task, and a task calls the helper more than
// once: a network change and its confirmation, a file write and its registry,
// a sysctl order and the rollback of it. So a nonce is not one effect, and the
// store keeps two kinds of record under it.
//
// The owner record, prefixed ownerPrefix, says which task and which life of the
// helper the nonce belongs to. A nonce that turns up under another task or
// another life is a replay, which is what it always was.
//
// The effect record, prefixed effectPrefix and named after the nonce together
// with the digest of the request, says what happened to one particular request.
// This is what was missing: the store held one bit per nonce and answered a
// repeat with "yes, carry on", so the same signed effect ran as many times as
// it was asked for. Now a repeat of a request that already ran is answered with
// the answer that was kept, and never by doing it again.
const (
	ownerPrefix  = "n-"
	effectPrefix = "e-"
)

// keptResultLimit bounds what the store keeps so that a nonce cannot be used
// to fill the helper's disk. An answer larger than this is recorded as done
// without its body: the helper then refuses the repeat rather than perform it,
// and the agent reports an outcome it does not know, which is true.
const keptResultLimit = 256 << 10

// Reservation is what the store says about the request under this nonce.
type Reservation struct {
	// Fresh says this call reserved the effect: it has not run yet and the
	// caller is the one to run it.
	Fresh bool
	// Kept is the answer of the effect that already ran, when the store kept
	// it. Only set when Fresh is false.
	Kept []byte
	// complete records the answer of the effect the caller is about to carry
	// out. The verifier fills it in; the store itself has no opinion.
	complete func(result []byte) error
}

// Reserve claims the right to carry out one request under a nonce, or answers
// with what happened the last time that very request was made under it.
func (s *ReplayStore) Reserve(nonce []byte, expires int64, taskID, digest string) (Reservation, error) {
	if len(nonce) != NonceSize {
		return Reservation{}, refusal(ErrorInvalidNonce,
			fmt.Sprintf("the nonce has %d bytes, not %d", len(nonce), NonceSize))
	}
	if digest == "" {
		return Reservation{}, errors.New("a reservation names the digest of the request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirfd < 0 {
		return Reservation{}, errors.New("the replay store is closed")
	}
	s.sweepLocked()

	if err := s.claimOwnerLocked(nonce, expires, taskID); err != nil {
		return Reservation{}, err
	}
	return s.claimEffectLocked(nonce, expires, taskID, digest)
}

// claimOwnerLocked binds the nonce to one task and one life of the helper.
func (s *ReplayStore) claimOwnerLocked(nonce []byte, expires int64, taskID string) error {
	name := ownerName(nonce)
	fd, err := unix.Openat(s.dirfd, name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if errors.Is(err, unix.EEXIST) {
		lines := s.readRecordLocked(name)
		if len(lines) >= 3 && lines[1] == taskID && lines[2] == s.life && taskID != "" {
			return nil
		}
		return refusal(ErrorCapabilityReplay, "the nonce of the capability was consumed before")
	}
	if err != nil {
		return fmt.Errorf("recording the nonce: %w", err)
	}
	defer unix.Close(fd)
	if err := writeAndFsync(fd, strconv.FormatInt(expires, 10)+"\n"+taskID+"\n"+s.life+"\n"); err != nil {
		return err
	}
	// The directory entry has to be durable as well: a record whose entry
	// vanished with a power cut would let the nonce be consumed again.
	if err := unix.Fsync(s.dirfd); err != nil {
		return fmt.Errorf("syncing the replay directory: %w", err)
	}
	return nil
}

// claimEffectLocked reserves this request, or reports what became of it.
func (s *ReplayStore) claimEffectLocked(nonce []byte, expires int64,
	taskID, digest string) (Reservation, error) {
	name := effectName(nonce, digest)
	fd, err := unix.Openat(s.dirfd, name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if errors.Is(err, unix.EEXIST) {
		lines := s.readRecordLocked(name)
		if len(lines) < 4 {
			return Reservation{}, refusal(ErrorCapabilityReplay,
				"the record of this request under the nonce cannot be read")
		}
		switch lines[3] {
		case stateCompleted:
			if len(lines) >= 5 && lines[4] != "" {
				kept, err := hex.DecodeString(lines[4])
				if err != nil {
					return Reservation{}, refusal(ErrorCapabilityPerformed,
						"this request already ran under this nonce and the answer kept for it does not read")
				}
				return Reservation{Kept: kept}, nil
			}
			return Reservation{}, refusal(ErrorCapabilityPerformed,
				"this request already ran under this nonce and its answer was too large to keep")
		default:
			return Reservation{}, refusal(ErrorCapabilityInFlight,
				"this request is being carried out under this nonce already")
		}
	}
	if err != nil {
		return Reservation{}, fmt.Errorf("reserving the request: %w", err)
	}
	defer unix.Close(fd)
	record := strconv.FormatInt(expires, 10) + "\n" + taskID + "\n" + s.life + "\n" + stateReserved + "\n\n"
	if err := writeAndFsync(fd, record); err != nil {
		return Reservation{}, err
	}
	if err := unix.Fsync(s.dirfd); err != nil {
		return Reservation{}, fmt.Errorf("syncing the replay directory: %w", err)
	}
	return Reservation{Fresh: true}, nil
}

// The states an effect record stands in.
const (
	stateReserved  = "reserved"
	stateCompleted = "completed"
)

// Complete records that the request ran and keeps its answer, so that a repeat
// is answered rather than performed. An answer that does not fit is recorded as
// done without a body.
func (s *ReplayStore) Complete(nonce []byte, expires int64, taskID, digest string, result []byte) error {
	if len(nonce) != NonceSize || digest == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirfd < 0 {
		return errors.New("the replay store is closed")
	}
	body := ""
	if len(result) > 0 && len(result) <= keptResultLimit {
		body = hex.EncodeToString(result)
	}
	name := effectName(nonce, digest)
	fd, err := unix.Openat(s.dirfd, name,
		unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("completing the request record: %w", err)
	}
	defer unix.Close(fd)
	record := strconv.FormatInt(expires, 10) + "\n" + taskID + "\n" + s.life + "\n" +
		stateCompleted + "\n" + body + "\n"
	return writeAndFsync(fd, record)
}

func ownerName(nonce []byte) string {
	sum := sha256.Sum256(nonce)
	return ownerPrefix + hex.EncodeToString(sum[:])
}

func effectName(nonce []byte, digest string) string {
	sum := sha256.Sum256(append(append([]byte(nil), nonce...), []byte(digest)...))
	return effectPrefix + hex.EncodeToString(sum[:])
}

// readRecordLocked reads a record whole; a kept answer makes it larger than one
// buffer, so it is read to the end.
func (s *ReplayStore) readRecordLocked(name string) []string {
	fd, err := unix.Openat(s.dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(fd)
	var content []byte
	buffer := make([]byte, 32<<10)
	for len(content) <= keptResultLimit*2+1024 {
		n, err := unix.Read(fd, buffer)
		if n > 0 {
			content = append(content, buffer[:n]...)
		}
		if err != nil || n == 0 {
			break
		}
	}
	return strings.Split(string(content), "\n")
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

// Sweep removes the records of capabilities that expired long enough ago that
// no clock skew could bring them back.
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
		if entry.IsDir() || len(entry.Name()) != len(ownerPrefix)+64 {
			continue
		}
		if !strings.HasPrefix(entry.Name(), ownerPrefix) && !strings.HasPrefix(entry.Name(), effectPrefix) {
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
