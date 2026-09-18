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

// This file wires the spool section of relay.yaml into the relay and says
// at the start what the spool holds.
//
// The spool is the durable buffer of chapter 13: the messages of the
// agents the centre has not yet confirmed it consumed survive a restart
// of the relay and the machine, and they leave the spool on the panel's
// acknowledgement alone. That makes its directory and its limits part of
// the configuration of the site rather than a constant in the code, and
// it makes the fill at the start something the operator has to see: a
// relay that comes up with a day of results waiting is a site whose
// results did not arrive, and nothing else says so before the panel does.

// spoolSettings turns the configuration into what the relay needs: the
// directory of the segment files and the bounds of the spool. The
// defaults live in relayconfig, so a file that says nothing gets the same
// values as one that writes them out.
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

// prepareSpoolDir creates the directory of the spool private to the
// account the relay runs under, and narrows one that a previous release
// or an operator left wider.
//
// Private rather than readable: the records hold the results of the
// agents of the whole site - inventories, outputs of operations - and
// they wait on disk for as long as the link is down. The owner is the
// service account (the packaged unit runs the relay as
// flotestro-relay, not as root, and the service has to be able to write
// its own spool); the mode is what keeps everybody else out.
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

// spoolBacklog describes what the spool holds for the log at the start:
// the records waiting, the room they take and how long the oldest of them
// has been waiting.
type spoolBacklog struct {
	Records int
	Bytes   int64
	// DiskBytes is what the segment files take, the dead records in them
	// included.
	DiskBytes int64
	// OldestWrite is the last write into the oldest segment still on
	// disk, zero when the spool is empty. A record in that segment was
	// written then or earlier, so the age of the backlog is at least
	// this: the timestamp of a single record is not kept outside its
	// frame, and reading every segment at the start to find one would
	// cost more than the number is worth.
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

// oldestSegmentWrite returns the modification time of the oldest segment
// file in the directory. The segments are numbered in the order they were
// created, so the lowest number is the oldest; a directory without one
// gives the zero time.
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

// logSpoolBacklog says at the start what waits in the spool. An empty
// spool is said once as well: an operator reading the log after an
// incident has to be able to tell "nothing was waiting" from "nobody
// looked".
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
