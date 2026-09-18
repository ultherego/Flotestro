package spool

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// segment is the active file of the spool, open for appending.
type segment struct {
	id   uint64
	file *os.File
	size int64
}

// createSegment creates a new segment file. The directory is synced so
// that the file survives a power failure together with its first record.
func createSegment(dir string, id uint64) (*segment, error) {
	file, err := os.OpenFile(segmentPath(dir, id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating a segment: %w", err)
	}
	if err := syncDir(dir); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &segment{id: id, file: file}, nil
}

// openSegment reopens an existing segment for appending. The file is
// walked first: a torn tail is cut off, so the append starts at a frame
// boundary.
func openSegment(dir string, id uint64) (*segment, error) {
	path := segmentPath(dir, id)
	if err := walkSegment(path, func(byte, []byte, int64, int) error { return nil }); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening a segment: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &segment{id: id, file: file, size: info.Size()}, nil
}

// append writes a framed record and returns its offset.
func (s *segment) append(framed []byte) (int64, error) {
	offset := s.size
	written := 0
	for written < len(framed) {
		n, err := s.file.Write(framed[written:])
		if err != nil {
			// A short write leaves a torn frame at the tail; the size is
			// left where the frame began, so the next append overwrites
			// nothing but the walk at the next start cuts it off.
			return 0, fmt.Errorf("writing a record: %w", err)
		}
		written += n
	}
	s.size += int64(len(framed))
	return offset, nil
}

// sync flushes the file to the disk.
func (s *segment) sync() error {
	return s.file.Sync()
}

// close syncs and closes the file.
func (s *segment) close() error {
	syncErr := s.file.Sync()
	closeErr := s.file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// syncDir flushes the directory entries to the disk.
func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

// listSegments returns the identifiers of the segments in the directory
// in ascending order. Files with other names are not the spool's and are
// left alone.
func listSegments(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ids []uint64
	for _, item := range entries {
		name := item.Name()
		if item.IsDir() || !strings.HasPrefix(name, "segment-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, "segment-"), ".log"), 10, 64)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// walkSegment reads the frames of a segment in order and calls the
// function with each. A frame the reader cannot take - the file ends
// inside it, or its checksum does not match - is where the segment is
// cut: the file is truncated at the offset the frame began, the frames
// before it are kept, and the walk ends without an error. That is the
// crash the document names: the last record torn, the earlier ones whole.
func walkSegment(path string, visit func(kind byte, body []byte, offset int64, size int) error) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("opening a segment: %w", err)
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 1<<20)
	var offset int64
	for {
		kind, body, err := readFrame(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, errTorn) {
			if err := file.Truncate(offset); err != nil {
				return fmt.Errorf("cutting the torn tail of %s: %w", filepath.Base(path), err)
			}
			return file.Sync()
		}
		if err != nil {
			return err
		}
		size := headerSize + len(body)
		if err := visit(kind, body, offset, size); err != nil {
			return err
		}
		offset += int64(size)
	}
}
