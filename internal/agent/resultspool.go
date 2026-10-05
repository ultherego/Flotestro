package agent

// The agent's own spool of task results: the answers the panel has not yet
// said it holds.
//
// A task whose result cannot be sent has still been carried out on the host.
// The panel does not redeliver a task it believes is leased and running, so an
// answer dropped at a broken session leaves the two sides waiting for each
// other. The answer is written down before it is sent and offered again at the
// next session that works, the same way the resource samples are.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

const (
	// ResultSpoolSize is how many unacknowledged results the agent keeps. The
	// panel serializes the work of one host behind its resource locks and the
	// agent's own budget, so a host produces a handful of answers between two
	// sessions; this many is far past any burst and still a directory a person
	// can read.
	ResultSpoolSize = 64
	// ResultSpoolBytes bounds the spool on disk. A result carries the clamped
	// output of its operation, and a file read carries the file, so the count
	// alone does not bound the bytes - and the state directory is not to grow
	// without limit while a host is cut off.
	ResultSpoolBytes = 32 << 20
	// ResultSpoolTTL is how long an undelivered answer is worth offering. It is
	// the retention of the idempotency journal: past it the agent no longer
	// remembers the operation the answer belongs to, so there is nothing left
	// for the answer to settle, and a host that has been cut off for a day has
	// a bigger problem than one job.
	ResultSpoolTTL = 24 * time.Hour

	// resultSpoolDirName is the directory of the spool inside the agent's state
	// directory.
	resultSpoolDirName = "result-spool"
	// resultSpoolSuffix marks a spooled result. A file without it - a
	// half-written temporary file - is not one.
	resultSpoolSuffix = ".result"
	// resultSpoolHeader is the header of a spooled result: four bytes that say
	// what the file is and four that say whether it survived.
	resultSpoolHeader = 8
)

var resultSpoolMagic = [4]byte{'F', 'R', 'S', '1'}

// ResultSpool is the bounded, file-backed queue of the results the panel has
// not acknowledged.
type ResultSpool struct {
	dir     string
	limit   int
	maxSize int64
	ttl     time.Duration
	log     *slog.Logger

	// spooled says a result was written down. The spool belongs to the process
	// and the session that is live listens on it, so an answer written by a task
	// of a session that is already gone wakes the one that can send it.
	spooled chan struct{}

	mu sync.Mutex
	// sequence orders the results within the spool; the attempt identifier is
	// what a result is found by.
	sequence uint64
	// entries are the results held, oldest first.
	entries []spooledResult
	// bytes is what the held results occupy.
	bytes int64
}

// spooledResult is one result on disk.
type spooledResult struct {
	file      string
	sequence  uint64
	taskID    string
	spooledAt time.Time
	size      int64
}

// The spool of one process. A task started in one session finishes in a
// goroutine that holds that session's spool object, and the next session used
// to build its own: the directory was read once, at the open, so the file the
// old goroutine wrote was invisible to the new session until the agent
// restarted - and the time-to-live could remove it first. The panel meanwhile
// held the job leased over a host where the change had already been made,
// which is the one case this spool exists for.
//
// Two live objects over one directory also counted their own sequence numbers
// and kept their own limits, so the directory could grow to twice the limit.
var (
	processSpoolOnce sync.Once
	processSpool     *ResultSpool
	processSpoolErr  error
	processSpoolDir  string
)

// ProcessResultSpool returns the spool of this agent process, opening it the
// first time it is asked for. Every session shares it, which is what makes a
// result written after a reconnect visible to the session that follows.
func ProcessResultSpool(stateDir string, limit int, maxSize int64, ttl time.Duration,
	log *slog.Logger) (*ResultSpool, error) {
	processSpoolOnce.Do(func() {
		processSpool, processSpoolErr = OpenResultSpool(stateDir, limit, maxSize, ttl, log)
		processSpoolDir = stateDir
	})
	if processSpoolErr != nil {
		return nil, processSpoolErr
	}
	// One process serves one state directory. A second one would be a different
	// agent in the same process, which is not a thing this product builds, and
	// saying so is better than handing back a spool over another directory.
	if stateDir != processSpoolDir {
		return nil, fmt.Errorf("the result spool of this process is under %s and this session asks for %s",
			processSpoolDir, stateDir)
	}
	return processSpool, nil
}

// resetProcessResultSpool forgets the spool of this process. Only a test calls
// it: a process has one agent and one state directory, and the whole point of
// the singleton is that nothing opens a second one.
func resetProcessResultSpool() {
	processSpoolOnce = sync.Once{}
	processSpool, processSpoolErr, processSpoolDir = nil, nil, ""
}

// OpenResultSpool opens - and if need be creates - the spool under the agent's
// state directory.
func OpenResultSpool(stateDir string, limit int, maxSize int64, ttl time.Duration,
	log *slog.Logger) (*ResultSpool, error) {
	if stateDir == "" {
		return nil, errors.New("a result spool needs the agent's state directory")
	}
	if limit <= 0 {
		limit = ResultSpoolSize
	}
	if maxSize <= 0 {
		maxSize = ResultSpoolBytes
	}
	if ttl <= 0 {
		ttl = ResultSpoolTTL
	}
	dir := filepath.Join(stateDir, resultSpoolDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("the directory of the result spool: %w", err)
	}
	spool := &ResultSpool{dir: dir, limit: limit, maxSize: maxSize, ttl: ttl, log: log,
		spooled: make(chan struct{}, 1)}
	if err := spool.load(); err != nil {
		return nil, err
	}
	return spool, nil
}

// load reads what the directory holds.
func (s *ResultSpool) load() error {
	listing, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("reading the result spool: %w", err)
	}
	for _, item := range listing {
		if item.IsDir() || !strings.HasSuffix(item.Name(), resultSpoolSuffix) {
			continue
		}
		sequence, taskID, ok := parseResultName(item.Name())
		if !ok {
			s.discard(item.Name(), "the name does not belong to the spool")
			continue
		}
		info, err := item.Info()
		if err != nil {
			s.discard(item.Name(), err.Error())
			continue
		}
		result, err := s.read(item.Name())
		if err != nil {
			s.discard(item.Name(), err.Error())
			continue
		}
		if result.GetTaskId() != taskID {
			s.discard(item.Name(), "the result does not name the attempt its file name gives it")
			continue
		}
		s.entries = append(s.entries, spooledResult{
			file: item.Name(), sequence: sequence, taskID: taskID,
			// The moment the file was written is what the answer's age is counted
			// from, and it is the one clock that survives a restart of the agent.
			spooledAt: info.ModTime(), size: info.Size(),
		})
		s.bytes += info.Size()
		if sequence > s.sequence {
			s.sequence = sequence
		}
	}
	sort.Slice(s.entries, func(i, j int) bool {
		return s.entries[i].sequence < s.entries[j].sequence
	})
	s.evict()
	return nil
}

// Enqueue writes the result to the spool, where it waits for the panel's
// answer. A result already held is written again: the second copy is the same
// answer to the same attempt.
func (s *ResultSpool) Enqueue(result *agentv1.TaskResult) error {
	taskID := result.GetTaskId()
	if !spoolableTaskID(taskID) {
		return fmt.Errorf("the attempt %q cannot name a file of the spool", taskID)
	}
	body, err := proto.Marshal(result)
	if err != nil {
		return err
	}
	if int64(len(body))+resultSpoolHeader > s.maxSize {
		return fmt.Errorf("the result of the attempt %s is %d bytes and the whole spool holds %d",
			taskID, len(body), s.maxSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.forget(taskID)
	s.sequence++
	name := resultSpoolName(s.sequence, taskID)
	if err := s.write(name, body); err != nil {
		return fmt.Errorf("writing the result of the attempt %s to the spool: %w", taskID, err)
	}
	size := int64(len(body) + resultSpoolHeader)
	s.entries = append(s.entries, spooledResult{
		file: name, sequence: s.sequence, taskID: taskID,
		spooledAt: time.Now(), size: size,
	})
	s.bytes += size
	s.evict()
	s.wake()
	return nil
}

// Spooled is the signal that an answer was written down, for the session that
// is live to offer it.
func (s *ResultSpool) Spooled() <-chan struct{} { return s.spooled }

// wake rings the signal without waiting for anybody to be listening. The
// caller holds the lock.
func (s *ResultSpool) wake() {
	if s.spooled == nil {
		return
	}
	select {
	case s.spooled <- struct{}{}:
	default:
	}
}

// Pending returns the results the panel has not acknowledged, oldest first:
// what the agent offers again on the next session that works. The answers too
// old to be worth offering are given up here, and the journal says which.
func (s *ResultSpool) Pending(now time.Time) []*agentv1.TaskResult {
	s.expire(now)

	s.mu.Lock()
	held := append([]spooledResult(nil), s.entries...)
	s.mu.Unlock()

	pending := make([]*agentv1.TaskResult, 0, len(held))
	for _, entry := range held {
		result, err := s.read(entry.file)
		if err != nil {
			// The file was readable when it was written and is not now.
			if s.log != nil {
				s.log.Warn("a spooled result could not be read back and was given up",
					"task_id", entry.taskID, "file", entry.file, "err", err)
			}
			s.Forget(entry.taskID)
			continue
		}
		pending = append(pending, result)
	}
	return pending
}

// Acknowledge drops the result the panel answered, whatever the answer says:
// a settlement, a duplicate and a refusal all mean the panel will not take
// this answer again.
func (s *ResultSpool) Acknowledge(ack *agentv1.TaskResultAck) {
	if ack == nil || ack.GetTaskId() == "" {
		return
	}
	s.Forget(ack.GetTaskId())
}

// Forget removes one result from the spool by the attempt it answers.
func (s *ResultSpool) Forget(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forget(taskID)
}

// Len is how many results wait for an acknowledgement.
func (s *ResultSpool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Bytes is what the held results occupy on disk.
func (s *ResultSpool) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// expire gives up the answers older than the spool keeps them for. A host
// cut off this long no longer remembers the operation in its idempotency
// journal either, so the answer has nothing left to settle.
func (s *ResultSpool) expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.entries[:0]
	for _, entry := range s.entries {
		if now.Sub(entry.spooledAt) < s.ttl {
			kept = append(kept, entry)
			continue
		}
		if s.log != nil {
			s.log.Error("the result of a finished task was never taken by the panel and is given up",
				"task_id", entry.taskID, "spooled_at", entry.spooledAt.UTC().Format(time.RFC3339),
				"age", now.Sub(entry.spooledAt).Round(time.Second).String(),
				"kept_for", s.ttl.String(),
				"consequence", "the change was made on this host and the panel never recorded it")
		}
		s.bytes -= entry.size
		s.remove(entry.file)
	}
	s.entries = kept
}

// forget removes one result. The caller holds the lock.
func (s *ResultSpool) forget(taskID string) {
	for i, entry := range s.entries {
		if entry.taskID != taskID {
			continue
		}
		s.remove(entry.file)
		s.bytes -= entry.size
		s.entries = append(s.entries[:i], s.entries[i+1:]...)
		return
	}
}

// evict drops the oldest results until the spool is within its bounds. The
// caller holds the lock.
func (s *ResultSpool) evict() {
	for len(s.entries) > s.limit || (s.bytes > s.maxSize && len(s.entries) > 1) {
		oldest := s.entries[0]
		if s.log != nil {
			s.log.Error("the oldest undelivered result left the spool because it is full",
				"task_id", oldest.taskID, "held", len(s.entries), "limit", s.limit,
				"bytes", s.bytes, "max_bytes", s.maxSize,
				"consequence", "the change was made on this host and the panel never recorded it")
		}
		s.remove(oldest.file)
		s.bytes -= oldest.size
		s.entries = s.entries[1:]
	}
}

// write puts one result on disk under a temporary name and moves it into
// place, so a spool file is either whole or not there.
func (s *ResultSpool) write(name string, body []byte) error {
	frame := make([]byte, resultSpoolHeader+len(body))
	copy(frame[:4], resultSpoolMagic[:])
	binary.LittleEndian.PutUint32(frame[4:8], crc32.Checksum(body, castagnoliSpool))
	copy(frame[resultSpoolHeader:], body)

	temporary := filepath.Join(s.dir, name+".writing")
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(frame); err != nil {
		file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, filepath.Join(s.dir, name)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return s.syncDir()
}

// read decodes one spooled result.
func (s *ResultSpool) read(name string) (*agentv1.TaskResult, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) < resultSpoolHeader || int64(len(raw)) > s.maxSize {
		return nil, errors.New("the file is not the size of a spooled result")
	}
	if string(raw[:4]) != string(resultSpoolMagic[:]) {
		return nil, errors.New("the file does not begin as a spooled result")
	}
	body := raw[resultSpoolHeader:]
	if crc32.Checksum(body, castagnoliSpool) != binary.LittleEndian.Uint32(raw[4:8]) {
		return nil, errors.New("the checksum of the spooled result does not match")
	}
	result := &agentv1.TaskResult{}
	if err := proto.Unmarshal(body, result); err != nil {
		return nil, err
	}
	return result, nil
}

// syncDir makes the creations and the deletions of the directory survive a
// power cut, which is the case the spool exists for.
func (s *ResultSpool) syncDir() error {
	handle, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

// remove deletes one spool file.
func (s *ResultSpool) remove(name string) {
	if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !os.IsNotExist(err) && s.log != nil {
		s.log.Debug("a spooled result was not deleted", "file", name, "err", err)
	}
}

// discard removes a file the spool cannot use and says why once.
func (s *ResultSpool) discard(name, reason string) {
	if s.log != nil {
		s.log.Warn("a file of the result spool was discarded", "file", name, "reason", reason)
	}
	_ = os.Remove(filepath.Join(s.dir, name))
}

// resultSpoolName is the file name of one result: the order it was spooled in,
// zero-padded so the directory sorts into that order, and the attempt it
// answers.
func resultSpoolName(sequence uint64, taskID string) string {
	return fmt.Sprintf("%019d-%s%s", sequence, taskID, resultSpoolSuffix)
}

// parseResultName reads the sequence and the attempt back out of the name.
func parseResultName(name string) (sequence uint64, taskID string, ok bool) {
	trimmed, found := strings.CutSuffix(name, resultSpoolSuffix)
	if !found {
		return 0, "", false
	}
	left, right, found := strings.Cut(trimmed, "-")
	if !found {
		return 0, "", false
	}
	sequence, err := strconv.ParseUint(left, 10, 64)
	if err != nil || sequence == 0 || !spoolableTaskID(right) {
		return 0, "", false
	}
	return sequence, right, true
}

// spoolableTaskID says whether an attempt identifier may name a file. The
// panel hands out identifiers of one shape; anything else is refused here
// rather than written somewhere in the file system.
func spoolableTaskID(taskID string) bool {
	if taskID == "" || len(taskID) > 64 {
		return false
	}
	for _, letter := range taskID {
		switch {
		case letter >= '0' && letter <= '9',
			letter >= 'a' && letter <= 'z',
			letter >= 'A' && letter <= 'Z',
			letter == '-', letter == '_':
		default:
			return false
		}
	}
	return true
}
