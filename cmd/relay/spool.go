package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/relay"
	"github.com/ultherego/flotestro/internal/relay/spool"
	"github.com/ultherego/flotestro/internal/relayconfig"
)

// This file wires the spool section of relay. yaml into the relay and says at
// the start what the spool holds.

// spoolSettings turns the configuration into what the relay needs: the
// directory of the segment files and the bounds of the spool.
func spoolSettings(cfg relayconfig.Config) (string, spool.Options) {
	maxBytes, reserve, minFree, ackTimeout, maxInflight := cfg.SpoolLimits()
	return cfg.SpoolPath(), spool.Options{
		// The site is named on every record: a spool carried to another
		// machine still says whose messages it holds.
		Site:                 cfg.Relay.Site,
		MaxBytes:             maxBytes,
		CriticalReserveBytes: reserve,
		MinFreeBytes:         minFree,
		AckTimeout:           ackTimeout,
		MaxInflightPerHost:   maxInflight,
	}
}

// prepareSpoolDir creates the directory of the spool private to the account
// the relay runs under, and narrows one that a previous release or an operator
// left wider.
func prepareSpoolDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("the spool directory %s is not an absolute path", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("the spool directory %s: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("the spool directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("the spool path %s is not a directory", dir)
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("the mode of the spool directory %s: %w", dir, err)
		}
	}
	return nil
}

// spoolBacklog describes what the spool holds for the log at the start: the
// records waiting, the room they take and how long the oldest of them has been
// waiting.
type spoolBacklog struct {
	Records int
	Bytes   int64
	// DiskBytes is what the segment files take, the dead records in them
	// included.
	DiskBytes int64
	// OldestWrite is the last write into the oldest segment still on disk, zero
	// when the spool is empty.
	OldestWrite time.Time
}

// readSpoolBacklog reads the fill from the relay and the age from the
// directory.
func readSpoolBacklog(proxy *relay.Relay, dir string) spoolBacklog {
	_, buffer, _ := proxy.Stats()
	backlog := spoolBacklog{
		Records: buffer.Messages, Bytes: int64(buffer.Bytes), DiskBytes: int64(buffer.DiskBytes),
	}
	if backlog.Records > 0 {
		backlog.OldestWrite = oldestSegmentWrite(dir)
	}
	return backlog
}

// oldestSegmentWrite returns the modification time of the oldest segment file
// in the directory.
func oldestSegmentWrite(dir string) time.Time {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "segment-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return time.Time{}
	}
	sort.Strings(names)
	info, err := os.Stat(filepath.Join(dir, names[0]))
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// logSpoolBacklog says at the start what waits in the spool.
func logSpoolBacklog(log *slog.Logger, dir string, options spool.Options, backlog spoolBacklog) {
	fields := []any{
		"path", dir,
		"records", backlog.Records,
		"bytes", backlog.Bytes,
		"disk_bytes", backlog.DiskBytes,
		"max_bytes", options.MaxBytes,
		"critical_reserve_bytes", options.CriticalReserveBytes,
		"ack_timeout", options.AckTimeout.String(),
	}
	if backlog.Records == 0 {
		log.Info("the spool of the relay is empty", fields...)
		return
	}
	if !backlog.OldestWrite.IsZero() {
		fields = append(fields,
			"oldest", backlog.OldestWrite.UTC().Format(time.RFC3339),
			"waiting_for", time.Since(backlog.OldestWrite).Truncate(time.Second).String())
	}
	log.Warn("the spool of the relay holds messages from before the start; they go out with the sessions of their hosts",
		fields...)
}
