package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// The typed refusals of the spool. Every one of them is counted; the
// relay names the code in its log and the panel sees the count in the
// heartbeat.
var (
	// ErrExhausted is the spool refusing a message of a light class: the
	// room outside the reserve is spent, or the disk is at its floor. The
	// stream of interactive logs ends with it, as the document asks.
	ErrExhausted = errors.New("resource_exhausted: the spool of the relay has no room for this class")
	// ErrCritical is the spool refusing a message of a durable class: the
	// whole quota is spent or the disk is at its floor. It is the alarm
	// relay_spool_critical of the document, and a new session is refused
	// before an existing record is lost.
	ErrCritical = errors.New("relay_spool_critical: the spool of the relay is full")
	// ErrClosed is a spool after Close.
	ErrClosed = errors.New("the spool is closed")
)

// Options bound the spool. They are the spool: keys of relay.yaml.
type Options struct {
	// Site names the site of the relay on every record.
	Site string
	// MaxBytes is the room the segments may take together.
	MaxBytes int64
	// CriticalReserveBytes is the part of MaxBytes only control and job
	// results may enter. Inventory, metrics and logs are refused once the
	// spool has grown to MaxBytes - CriticalReserveBytes.
	CriticalReserveBytes int64
	// MinFreeBytes is the floor of free space on the filesystem of the
	// spool: nothing is appended below it, whatever the class, because a
	// filesystem the relay filled takes from the site what works locally.
	MinFreeBytes int64
	// AckTimeout is how long a sent record waits for the panel's
	// acknowledgement before it is sent again.
	AckTimeout time.Duration
	// MaxInflightPerHost bounds the records of one host sent and not yet
	// acknowledged.
	MaxInflightPerHost int
	// SegmentBytes is the size at which the active segment rolls over.
	SegmentBytes int64
	// FlushInterval is the batch of the light classes: an appended record
	// of priority above job_result reaches the disk within it.
	FlushInterval time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// The defaults of the spool.
const (
	DefaultMaxBytes             int64 = 1 << 30
	DefaultCriticalReserveBytes int64 = 128 << 20
	DefaultMinFreeBytes         int64 = 256 << 20
	DefaultAckTimeout                 = 30 * time.Second
	DefaultMaxInflightPerHost         = 64
	DefaultSegmentBytes         int64 = 16 << 20
	DefaultFlushInterval              = 100 * time.Millisecond
)

func (o *Options) fill() {
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.CriticalReserveBytes <= 0 {
		o.CriticalReserveBytes = DefaultCriticalReserveBytes
	}
	if o.CriticalReserveBytes > o.MaxBytes {
		o.CriticalReserveBytes = o.MaxBytes
	}
	if o.MinFreeBytes < 0 {
		o.MinFreeBytes = 0
	}
	if o.AckTimeout <= 0 {
		o.AckTimeout = DefaultAckTimeout
	}
	if o.MaxInflightPerHost <= 0 {
		o.MaxInflightPerHost = DefaultMaxInflightPerHost
	}
	if o.SegmentBytes <= 0 {
		o.SegmentBytes = DefaultSegmentBytes
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = DefaultFlushInterval
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// entry is what the index keeps of a record: enough to order, to find by
// the acknowledgement and to account, without the payload.
type entry struct {
	id        uuid.UUID
	hostID    string
	sessionID string
	stream    string
	priority  uint8
	sequence  uint64
	createdAt time.Time
	expiresAt *time.Time
	full      bool
	size      int
	segment   uint64
	offset    int64
	// sentAt is when the record was last sent up; zero for one waiting.
	sentAt time.Time
}

// Stats describes the spool for the heartbeat, the state file and the
// tests.
type Stats struct {
	// BytesUsed is what the waiting records take: the fill the quota is
	// spent against and the panel charts against BytesLimit.
	BytesUsed  int64
	BytesLimit int64
	// DiskBytes is what the segment files take, dead records and
	// tombstones included; compaction keeps it near BytesUsed.
	DiskBytes int64
	Items     int
	Inflight  int
	// DroppedTotal counts the messages the spool refused or evicted since
	// the start of the process: a non-zero value means the site lost
	// something, and the panel alarms on its growth.
	DroppedTotal int64
	// ExpiredTotal counts the records cut for their age.
	ExpiredTotal int64
	// Critical says the spool is in its reserve: new sessions are refused.
	Critical bool
	Segments int
}

// Spool is the durable queue of a relay.
type Spool struct {
	dir     string
	options Options

	mu       sync.Mutex
	index    map[uuid.UUID]*entry
	byHost   map[string][]*entry
	segments map[uint64]*segmentState
	active   *segment
	nextID   uint64
	// live is what the waiting records take together: the fill of the
	// spool as the quota reads it. The files take more - a deleted record
	// stays in its segment until the segment dies or is compacted.
	live     int64
	dropped  int64
	expired  int64
	dirty    bool
	closed   bool
	flusher  chan struct{}
	flushErr error
}

// segmentState accounts one segment file: its size on disk and the live
// records in it, so that a segment nobody needs is removed.
type segmentState struct {
	id   uint64
	size int64
	live int
}

// Open opens or creates the spool under the directory. The directory is
// the relay's own and readable by nobody else: the spool carries the
// hosts' messages, signed but not sealed.
func Open(dir string, options Options) (*Spool, error) {
	options.fill()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("the spool directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("the spool directory: %w", err)
	}
	s := &Spool{
		dir: dir, options: options,
		index:    map[uuid.UUID]*entry{},
		byHost:   map[string][]*entry{},
		segments: map[uint64]*segmentState{},
		flusher:  make(chan struct{}),
	}
	if err := s.rebuild(); err != nil {
		return nil, err
	}
	go s.flushLoop()
	return s, nil
}

// Dir returns the directory of the spool.
func (s *Spool) Dir() string { return s.dir }

// Close flushes and closes the active segment.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.flusher)
	if s.active != nil {
		err := s.active.close()
		s.active = nil
		return err
	}
	return nil
}

// flushLoop syncs the active segment on the batch interval while any
// light record waits for its fsync.
func (s *Spool) flushLoop() {
	ticker := time.NewTicker(s.options.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.flusher:
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.dirty && s.active != nil {
				s.flushErr = s.active.sync()
				s.dirty = false
			}
			s.mu.Unlock()
		}
	}
}

// Append writes a message to the spool by the policy of its class and
// returns the record it became. A message the class cannot keep is
// counted as dropped and refused with the typed error.
//
// Control and job results may spend the whole quota and are synced
// before the call returns. Inventory coalesces: a full report replaces
// the older inventory records of the host that have not been sent.
// Metrics evict the oldest waiting sample when there is no room. Logs are
// refused with ErrExhausted.
func (s *Spool) Append(record *Record) error {
	if record == nil {
		return errors.New("no record")
	}
	if record.Site == "" {
		record.Site = s.options.Site
	}
	if record.ID == uuid.Nil {
		record.ID = uuid.New()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if record.Stream == StreamInventory && record.Full() {
		s.coalesceInventoryLocked(record.HostID)
	}
	size := int64(record.Size())
	if err := s.roomLocked(record.Priority, size); err != nil {
		if record.Stream == StreamMetric && s.evictOldestMetricLocked(size) {
			err = s.roomLocked(record.Priority, size)
		}
		if err != nil {
			s.dropped++
			return err
		}
	}
	if err := s.writeLocked(record); err != nil {
		return err
	}
	if Durable(record.Stream) {
		// Every durable class reaches the disk before the caller goes on:
		// what the relay took is what it holds, whatever happens next.
		// Control, job results and inventory alike - a class written
		// ahead of the live forward is a class the relay answers for, and
		// a batch of a tenth of a second is exactly the window a power
		// failure takes a report away in.
		if err := s.active.sync(); err != nil {
			s.flushErr = err
			return err
		}
		s.flushErr = nil
		s.dirty = false
	} else {
		s.dirty = true
	}
	return nil
}

// FlushError returns the last failure of the batched sync of the light
// classes, nil once a sync succeeded again.
//
// The batch is the one place where a record is on its way to the disk
// rather than on it, and a disk that stopped taking writes shows up here
// first. The relay reads it into its readiness: a spool that cannot
// reach the disk is not a spool the site should be handing results to.
func (s *Spool) FlushError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushErr
}

// roomLocked says whether a record of the priority fits: within the
// quota of its class and above the floor of free space.
func (s *Spool) roomLocked(priority uint8, size int64) error {
	limit := s.options.MaxBytes
	refusal := ErrCritical
	if priority > PriorityJobResult {
		limit -= s.options.CriticalReserveBytes
		refusal = ErrExhausted
	}
	if s.live+size > limit {
		return refusal
	}
	if free, ok := freeBytes(s.dir); ok && free-uint64(size) < uint64(s.options.MinFreeBytes) {
		return refusal
	}
	return nil
}

// diskLocked is what the segments take on disk together.
func (s *Spool) diskLocked() int64 {
	var used int64
	for _, segment := range s.segments {
		used += segment.size
	}
	return used
}

// coalesceInventoryLocked removes the inventory records of the host that
// have not been sent: a full report about to be written says everything
// they said. One in flight is left alone - the panel may be committing
// it - and is acknowledged or resent on its own.
func (s *Spool) coalesceInventoryLocked(hostID string) {
	for _, item := range append([]*entry(nil), s.byHost[hostID]...) {
		if item.stream == StreamInventory && item.sentAt.IsZero() {
			_ = s.deleteLocked(item)
		}
	}
}

// evictOldestMetricLocked removes waiting metric samples, oldest first
// and of any host, until the given size fits or none is left. Each
// eviction is a drop and is counted.
func (s *Spool) evictOldestMetricLocked(size int64) bool {
	var candidates []*entry
	for _, item := range s.index {
		if item.stream == StreamMetric && item.sentAt.IsZero() {
			candidates = append(candidates, item)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].createdAt.Before(candidates[j].createdAt)
	})
	evicted := false
	for _, item := range candidates {
		if s.roomLocked(PriorityMetric, size) == nil {
			break
		}
		if err := s.deleteLocked(item); err != nil {
			break
		}
		s.dropped++
		evicted = true
	}
	return evicted
}

// writeLocked appends the record to the active segment, rolling it over
// when it is full, and indexes it.
func (s *Spool) writeLocked(record *Record) error {
	if s.active == nil || s.active.size >= s.options.SegmentBytes {
		if err := s.rollLocked(); err != nil {
			return err
		}
	}
	framed := frame(kindRecord, record.encode())
	offset, err := s.active.append(framed)
	if err != nil {
		return err
	}
	state := s.segments[s.active.id]
	state.size = s.active.size
	state.live++
	item := &entry{
		id: record.ID, hostID: record.HostID, sessionID: record.SessionID,
		stream: record.Stream, priority: record.Priority, sequence: record.Sequence,
		createdAt: record.CreatedAt, expiresAt: record.ExpiresAt, full: record.Full(),
		size: len(framed), segment: s.active.id, offset: offset,
	}
	s.index[record.ID] = item
	s.byHost[record.HostID] = append(s.byHost[record.HostID], item)
	s.live += int64(len(framed))
	return nil
}

// rollLocked closes the active segment and opens the next one.
func (s *Spool) rollLocked() error {
	if s.active != nil {
		if err := s.active.close(); err != nil {
			return err
		}
	}
	s.nextID++
	segment, err := createSegment(s.dir, s.nextID)
	if err != nil {
		return err
	}
	s.active = segment
	s.segments[segment.id] = &segmentState{id: segment.id}
	return nil
}

// deleteLocked forgets a record: a tombstone in the active segment, the
// index entry gone, and the segment file removed once nothing in it is
// alive and it is not the one being written.
func (s *Spool) deleteLocked(item *entry) error {
	if _, known := s.index[item.id]; !known {
		return nil
	}
	if s.active == nil || s.active.size >= s.options.SegmentBytes {
		if err := s.rollLocked(); err != nil {
			return err
		}
	}
	if _, err := s.active.append(frame(kindTombstone, item.id[:])); err != nil {
		return err
	}
	s.segments[s.active.id].size = s.active.size
	s.dirty = true
	delete(s.index, item.id)
	s.live -= int64(item.size)
	list := s.byHost[item.hostID]
	for i, candidate := range list {
		if candidate == item {
			s.byHost[item.hostID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(s.byHost[item.hostID]) == 0 {
		delete(s.byHost, item.hostID)
	}
	if state := s.segments[item.segment]; state != nil {
		state.live--
		if state.live <= 0 && (s.active == nil || state.id != s.active.id) {
			// A dead segment goes at once: its tombstones are in a later
			// one, and a rebuild that never sees the file has nothing to
			// forget.
			if err := os.Remove(segmentPath(s.dir, state.id)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			delete(s.segments, state.id)
		}
	}
	return s.compactLocked()
}

// compactLocked rewrites the living records of the older segments into a
// fresh one once the dead bytes outgrow their allowance, and removes the
// old files. The segments are append-only, so a deleted record keeps its
// bytes until its segment dies; under a long outage with samples evicted
// and results acknowledged one by one, the files would otherwise grow
// well past the quota the live records respect.
func (s *Spool) compactLocked() error {
	allowance := s.options.SegmentBytes
	if quarter := s.options.MaxBytes / 4; quarter > allowance {
		allowance = quarter
	}
	if s.diskLocked()-s.live <= allowance || len(s.segments) < 2 {
		return nil
	}
	if err := s.rollLocked(); err != nil {
		return err
	}
	ids := make([]uint64, 0, len(s.segments))
	for id := range s.segments {
		if id != s.active.id {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		for _, item := range s.index {
			if item.segment != id {
				continue
			}
			record, err := s.readLocked(item)
			if err != nil {
				return err
			}
			offset, err := s.active.append(frame(kindRecord, record.encode()))
			if err != nil {
				return err
			}
			item.segment, item.offset = s.active.id, offset
			s.segments[s.active.id].live++
			s.segments[s.active.id].size = s.active.size
		}
		if err := s.active.sync(); err != nil {
			return err
		}
		if err := os.Remove(segmentPath(s.dir, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		delete(s.segments, id)
	}
	return nil
}

// Next returns the records of the host due to be sent, by priority and
// then by sequence, and marks them sent. Due is a record never sent or
// one whose acknowledgement did not arrive within the timeout. The count
// is bounded by the in-flight limit of the host. Expired records are cut
// on the way.
func (s *Spool) Next(hostID string, limit int) ([]*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	now := s.options.Now()
	s.expireLocked(hostID, now)
	list := s.byHost[hostID]
	inflight := 0
	for _, item := range list {
		if !item.sentAt.IsZero() && now.Sub(item.sentAt) < s.options.AckTimeout {
			inflight++
		}
	}
	room := s.options.MaxInflightPerHost - inflight
	if limit > 0 && limit < room {
		room = limit
	}
	if room <= 0 {
		return nil, nil
	}
	due := make([]*entry, 0, len(list))
	for _, item := range list {
		if item.sentAt.IsZero() || now.Sub(item.sentAt) >= s.options.AckTimeout {
			due = append(due, item)
		}
	}
	sort.SliceStable(due, func(i, j int) bool {
		if due[i].priority != due[j].priority {
			return due[i].priority < due[j].priority
		}
		if due[i].sequence != due[j].sequence {
			return due[i].sequence < due[j].sequence
		}
		return due[i].createdAt.Before(due[j].createdAt)
	})
	if len(due) > room {
		due = due[:room]
	}
	records := make([]*Record, 0, len(due))
	for _, item := range due {
		record, err := s.readLocked(item)
		if err != nil {
			// A record the disk no longer gives back cannot be delivered;
			// it is dropped and counted rather than left to block the host.
			s.dropped++
			_ = s.deleteLocked(item)
			continue
		}
		item.sentAt = now
		records = append(records, record)
	}
	return records, nil
}

// MarkSent notes that a record went up outside Next - written ahead of a
// live forward - so that the tick does not send it again before the
// acknowledgement timeout.
func (s *Spool) MarkSent(id uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if item, known := s.index[id]; known {
		item.sentAt = s.options.Now()
	}
}

// Hosts lists the hosts with records waiting.
func (s *Spool) Hosts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	hosts := make([]string, 0, len(s.byHost))
	for hostID := range s.byHost {
		hosts = append(hosts, hostID)
	}
	sort.Strings(hosts)
	return hosts
}

// Unsend marks the records of a host as waiting again: the stream they
// were sent on broke, and the next session sends them anew.
func (s *Spool) Unsend(hostID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.byHost[hostID] {
		item.sentAt = time.Time{}
	}
}

// Ack deletes the record the panel acknowledged, found by the host, the
// session and the sequence of its envelope. It returns whether a record
// was found: an acknowledgement of a record already deleted, or of a
// message the relay forwarded live without spooling it, finds none and
// that is no error.
func (s *Spool) Ack(hostID, sessionID string, sequence uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	for _, item := range s.byHost[hostID] {
		if item.sessionID == sessionID && item.sequence == sequence && item.sequence != 0 {
			return true, s.deleteLocked(item)
		}
	}
	return false, nil
}

// Delete removes a record by its identifier: the confirmation of a
// message without an envelope, which has no acknowledgement to wait for.
func (s *Spool) Delete(id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	item, known := s.index[id]
	if !known {
		return nil
	}
	return s.deleteLocked(item)
}

// expireLocked cuts the records of the host past their expiry.
func (s *Spool) expireLocked(hostID string, now time.Time) {
	for _, item := range append([]*entry(nil), s.byHost[hostID]...) {
		if item.expiresAt != nil && now.After(*item.expiresAt) {
			if err := s.deleteLocked(item); err == nil {
				s.expired++
			}
		}
	}
}

// Stats describes the spool.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := Stats{
		BytesUsed: s.live, BytesLimit: s.options.MaxBytes, DiskBytes: s.diskLocked(),
		Items: len(s.index), DroppedTotal: s.dropped, ExpiredTotal: s.expired,
		Segments: len(s.segments),
	}
	now := s.options.Now()
	for _, item := range s.index {
		if !item.sentAt.IsZero() && now.Sub(item.sentAt) < s.options.AckTimeout {
			stats.Inflight++
		}
	}
	stats.Critical = stats.BytesUsed > s.options.MaxBytes-s.options.CriticalReserveBytes
	if free, ok := freeBytes(s.dir); ok && free < uint64(s.options.MinFreeBytes) {
		stats.Critical = true
	}
	return stats
}

// Critical says whether the spool is in its reserve or the disk at its
// floor: the relay refuses new sessions then, before an existing record
// is lost.
func (s *Spool) Critical() bool { return s.Stats().Critical }

// readLocked reads a record back from its segment.
func (s *Spool) readLocked(item *entry) (*Record, error) {
	file, err := os.Open(segmentPath(s.dir, item.segment))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := file.Seek(item.offset, 0); err != nil {
		return nil, err
	}
	kind, body, err := readFrame(file)
	if err != nil {
		return nil, err
	}
	if kind != kindRecord {
		return nil, errors.New("the offset names a tombstone")
	}
	record, err := decode(body)
	if err != nil {
		return nil, err
	}
	if record.ID != item.id {
		return nil, errors.New("the offset names another record")
	}
	return record, nil
}

// rebuild reads every segment and builds the index. A torn tail is
// truncated; a segment nothing lives in is removed; the newest segment
// is reopened for appending.
func (s *Spool) rebuild() error {
	ids, err := listSegments(s.dir)
	if err != nil {
		return err
	}
	tombstones := map[uuid.UUID]bool{}
	// The tombstones of every segment are collected first: a record in
	// an older segment may be deleted by a tombstone in a newer one.
	for _, id := range ids {
		err := walkSegment(segmentPath(s.dir, id), func(kind byte, body []byte, offset int64, size int) error {
			if kind == kindTombstone && len(body) == 16 {
				var target uuid.UUID
				copy(target[:], body)
				tombstones[target] = true
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	for _, id := range ids {
		state := &segmentState{id: id}
		err := walkSegment(segmentPath(s.dir, id), func(kind byte, body []byte, offset int64, size int) error {
			if kind != kindRecord {
				return nil
			}
			record, err := decode(body)
			if err != nil {
				// A record that frames correctly but does not decode is one
				// this release cannot read; it is skipped and counted, not
				// a reason to refuse the whole spool.
				s.dropped++
				return nil
			}
			if tombstones[record.ID] {
				return nil
			}
			item := &entry{
				id: record.ID, hostID: record.HostID, sessionID: record.SessionID,
				stream: record.Stream, priority: record.Priority, sequence: record.Sequence,
				createdAt: record.CreatedAt, expiresAt: record.ExpiresAt, full: record.Full(),
				size: size, segment: id, offset: offset,
			}
			s.index[record.ID] = item
			s.byHost[record.HostID] = append(s.byHost[record.HostID], item)
			s.live += int64(size)
			state.live++
			return nil
		})
		if err != nil {
			return err
		}
		info, err := os.Stat(segmentPath(s.dir, id))
		if err != nil {
			return err
		}
		state.size = info.Size()
		s.segments[id] = state
		if id > s.nextID {
			s.nextID = id
		}
	}
	// Segments without a living record are removed, except the newest,
	// which is reopened: the tombstones it holds may name records of
	// older segments that still exist.
	for _, id := range ids {
		state := s.segments[id]
		if state.live == 0 && id != s.nextID {
			if err := os.Remove(segmentPath(s.dir, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			delete(s.segments, id)
		}
	}
	if s.nextID > 0 {
		segment, err := openSegment(s.dir, s.nextID)
		if err != nil {
			return err
		}
		s.active = segment
		s.segments[segment.id].size = segment.size
	}
	return nil
}

// freeBytes reads the free space of the filesystem the directory is on.
func freeBytes(dir string) (uint64, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, false
	}
	return stat.Bavail * uint64(stat.Bsize), true
}

// segmentPath names the file of a segment.
func segmentPath(dir string, id uint64) string {
	return filepath.Join(dir, fmt.Sprintf("segment-%016d.log", id))
}
