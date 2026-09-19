package agent

// The agent's own spool of resource samples: the readings the panel has not
// yet said it holds.

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

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

const (
	// MetricsSpoolSize is how many unacknowledged samples the agent keeps: four
	// hours at one a minute.
	MetricsSpoolSize = 240
	// metricsSpoolDirName is the directory of the spool inside the agent's
	// state directory.
	metricsSpoolDirName = "metrics-spool"
	// metricsSpoolSuffix marks a spooled sample. A file without it - the
	// counter, a half-written temporary file - is not one.
	metricsSpoolSuffix = ".sample"
	// metricsSpoolCounter holds the last sequence handed out, so a restart of the
	// agent within one boot carries on counting instead of handing out numbers
	// the panel already holds and would answer as duplicates.
	metricsSpoolCounter = "sequence"
	// metricsSpoolMagic and metricsSpoolHeader are the header of a spooled
	// sample: four bytes that say what the file is and four that say whether it
	// survived.
	metricsSpoolHeader = 8
	// maxSpooledSample bounds what is read back from one file. A sample is
	// a few hundred bytes; anything of this size is a corrupt length.
	maxSpooledSample = 1 << 20
)

var metricsSpoolMagic = [4]byte{'F', 'M', 'S', '1'}

// castagnoliSpool is the checksum of a spooled sample, the same polynomial
// the relay's spool uses.
var castagnoliSpool = crc32.MakeTable(crc32.Castagnoli)

// MetricsSpool is the bounded, file-backed queue of the samples the panel has
// not acknowledged.
type MetricsSpool struct {
	dir    string
	limit  int
	bootID string
	log    *slog.Logger

	mu sync.Mutex
	// epoch orders the boots in the spool.
	epoch uint64
	// sequence is the last number handed out for this boot.
	sequence uint64
	// entries are the samples held, oldest first.
	entries []spooledSample
}

// spooledSample is one sample on disk.
type spooledSample struct {
	file     string
	epoch    uint64
	bootID   string
	sequence uint64
}

// OpenMetricsSpool opens - and if need be creates - the spool under the
// agent's state directory for the boot the host is on.
func OpenMetricsSpool(stateDir, bootID string, limit int, log *slog.Logger) (*MetricsSpool, error) {
	if bootID == "" {
		return nil, errors.New("a metrics spool needs the boot the samples are counted within")
	}
	if limit <= 0 {
		limit = MetricsSpoolSize
	}
	dir := filepath.Join(stateDir, metricsSpoolDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("the directory of the metrics spool: %w", err)
	}
	spool := &MetricsSpool{dir: dir, limit: limit, bootID: bootID, log: log}
	if err := spool.load(); err != nil {
		return nil, err
	}
	return spool, nil
}

// load reads what the directory holds.
func (s *MetricsSpool) load() error {
	listing, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("reading the metrics spool: %w", err)
	}
	var highestEpoch uint64
	epochOfBoot := map[string]uint64{}
	for _, item := range listing {
		if item.IsDir() || !strings.HasSuffix(item.Name(), metricsSpoolSuffix) {
			continue
		}
		epoch, sequence, ok := parseSpoolName(item.Name())
		if !ok {
			s.discard(item.Name(), "the name does not belong to the spool")
			continue
		}
		sample, err := s.read(item.Name())
		if err != nil {
			s.discard(item.Name(), err.Error())
			continue
		}
		if sample.GetSequence() != sequence || sample.GetBootId() == "" {
			s.discard(item.Name(), "the sample does not carry the identity its name gives it")
			continue
		}
		if epoch > highestEpoch {
			highestEpoch = epoch
		}
		if known, seen := epochOfBoot[sample.GetBootId()]; !seen || epoch < known {
			epochOfBoot[sample.GetBootId()] = epoch
		}
		s.entries = append(s.entries, spooledSample{
			file: item.Name(), epoch: epoch, bootID: sample.GetBootId(), sequence: sequence,
		})
	}
	sort.Slice(s.entries, func(i, j int) bool {
		if s.entries[i].epoch != s.entries[j].epoch {
			return s.entries[i].epoch < s.entries[j].epoch
		}
		return s.entries[i].sequence < s.entries[j].sequence
	})

	if epoch, seen := epochOfBoot[s.bootID]; seen {
		s.epoch = epoch
	} else {
		s.epoch = highestEpoch + 1
	}
	// The next number is past everything this boot has already used: what the
	// counter recorded, and what is still on disk.
	s.sequence = s.readCounter()
	for _, entry := range s.entries {
		if entry.bootID == s.bootID && entry.sequence > s.sequence {
			s.sequence = entry.sequence
		}
	}
	s.evict()
	return nil
}

// Enqueue gives the sample its identity, writes it to the spool and returns it
// ready to send.
func (s *MetricsSpool) Enqueue(sample *agentv1.MetricsSample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
	sample.BootId = s.bootID
	sample.Sequence = s.sequence

	name := spoolName(s.epoch, s.sequence)
	if err := s.write(name, sample); err != nil {
		return fmt.Errorf("writing the sample %d to the spool: %w", s.sequence, err)
	}
	if err := s.writeCounter(s.sequence); err != nil {
		return fmt.Errorf("recording the sequence of the samples: %w", err)
	}
	s.entries = append(s.entries, spooledSample{
		file: name, epoch: s.epoch, bootID: s.bootID, sequence: s.sequence,
	})
	s.evict()
	return nil
}

// Pending returns the samples the panel has not acknowledged, oldest first:
// what the agent sends on reconnect before the reading it is about to take.
func (s *MetricsSpool) Pending() []*agentv1.MetricsSample {
	s.mu.Lock()
	held := append([]spooledSample(nil), s.entries...)
	s.mu.Unlock()

	pending := make([]*agentv1.MetricsSample, 0, len(held))
	for _, entry := range held {
		sample, err := s.read(entry.file)
		if err != nil {
			// The file was readable when it was written and is not now.
			if s.log != nil {
				s.log.Warn("a spooled sample could not be read back and was dropped",
					"file", entry.file, "err", err)
			}
			s.Forget(entry.bootID, entry.sequence)
			continue
		}
		pending = append(pending, sample)
	}
	return pending
}

// Acknowledge drops the sample the panel named.
func (s *MetricsSpool) Acknowledge(ack *agentv1.MetricsAck) {
	if ack == nil || ack.GetBootId() == "" || ack.GetSequence() == 0 {
		return
	}
	s.Forget(ack.GetBootId(), ack.GetSequence())
}

// Forget removes one sample from the spool by its identity.
func (s *MetricsSpool) Forget(bootID string, sequence uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, entry := range s.entries {
		if entry.bootID != bootID || entry.sequence != sequence {
			continue
		}
		s.remove(entry.file)
		s.entries = append(s.entries[:i], s.entries[i+1:]...)
		return
	}
}

// Len is how many samples wait for an acknowledgement.
func (s *MetricsSpool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// evict drops the oldest samples until the spool is within its bound. The
// caller holds the lock.
func (s *MetricsSpool) evict() {
	for len(s.entries) > s.limit {
		oldest := s.entries[0]
		s.remove(oldest.file)
		s.entries = s.entries[1:]
		if s.log != nil {
			s.log.Debug("the oldest sample left the spool because it is full",
				"boot_id", oldest.bootID, "sequence", oldest.sequence, "limit", s.limit)
		}
	}
}

// write puts one sample on disk under a temporary name and moves it into
// place, so a spool file is either whole or not there.
func (s *MetricsSpool) write(name string, sample *agentv1.MetricsSample) error {
	body, err := proto.Marshal(sample)
	if err != nil {
		return err
	}
	frame := make([]byte, metricsSpoolHeader+len(body))
	copy(frame[:4], metricsSpoolMagic[:])
	binary.LittleEndian.PutUint32(frame[4:8], crc32.Checksum(body, castagnoliSpool))
	copy(frame[metricsSpoolHeader:], body)

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

// read decodes one spooled sample.
func (s *MetricsSpool) read(name string) (*agentv1.MetricsSample, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return nil, err
	}
	if len(raw) < metricsSpoolHeader || len(raw) > maxSpooledSample {
		return nil, errors.New("the file is not the size of a spooled sample")
	}
	if string(raw[:4]) != string(metricsSpoolMagic[:]) {
		return nil, errors.New("the file does not begin as a spooled sample")
	}
	body := raw[metricsSpoolHeader:]
	if crc32.Checksum(body, castagnoliSpool) != binary.LittleEndian.Uint32(raw[4:8]) {
		return nil, errors.New("the checksum of the spooled sample does not match")
	}
	sample := &agentv1.MetricsSample{}
	if err := proto.Unmarshal(body, sample); err != nil {
		return nil, err
	}
	return sample, nil
}

// readCounter reads the last sequence recorded for this boot; zero when
// the counter names another boot or is not there.
func (s *MetricsSpool) readCounter() uint64 {
	raw, err := os.ReadFile(filepath.Join(s.dir, metricsSpoolCounter))
	if err != nil {
		return 0
	}
	boot, value, found := strings.Cut(strings.TrimSpace(string(raw)), " ")
	if !found || boot != s.bootID {
		return 0
	}
	sequence, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return sequence
}

// writeCounter records the last sequence handed out for this boot.
func (s *MetricsSpool) writeCounter(sequence uint64) error {
	temporary := filepath.Join(s.dir, metricsSpoolCounter+".writing")
	line := s.bootID + " " + strconv.FormatUint(sequence, 10) + "\n"
	if err := os.WriteFile(temporary, []byte(line), 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(s.dir, metricsSpoolCounter)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return s.syncDir()
}

// syncDir makes the creations and the deletions of the directory survive a
// power cut, which is the case the spool exists for.
func (s *MetricsSpool) syncDir() error {
	handle, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

// remove deletes one spool file.
func (s *MetricsSpool) remove(name string) {
	if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !os.IsNotExist(err) && s.log != nil {
		s.log.Debug("a spooled sample was not deleted", "file", name, "err", err)
	}
}

// discard removes a file the spool cannot use and says why once.
func (s *MetricsSpool) discard(name, reason string) {
	if s.log != nil {
		s.log.Warn("a file of the metrics spool was discarded", "file", name, "reason", reason)
	}
	_ = os.Remove(filepath.Join(s.dir, name))
}

// spoolName is the file name of one sample: the epoch of its boot and its
// sequence, both zero-padded so that the directory sorts into the order the
// samples were taken.
func spoolName(epoch, sequence uint64) string {
	return fmt.Sprintf("%010d-%019d%s", epoch, sequence, metricsSpoolSuffix)
}

// parseSpoolName reads the epoch and the sequence back out of the name.
func parseSpoolName(name string) (epoch, sequence uint64, ok bool) {
	trimmed, found := strings.CutSuffix(name, metricsSpoolSuffix)
	if !found {
		return 0, 0, false
	}
	left, right, found := strings.Cut(trimmed, "-")
	if !found {
		return 0, 0, false
	}
	epoch, err := strconv.ParseUint(left, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	sequence, err = strconv.ParseUint(right, 10, 64)
	if err != nil || sequence == 0 {
		return 0, 0, false
	}
	return epoch, sequence, true
}
