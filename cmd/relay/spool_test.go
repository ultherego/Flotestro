package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/relayconfig"
)

// relayConfig is the smallest configuration that passes the checks, with
// the spool section the test wants on top of it.
func relayConfig(t *testing.T, spool relayconfig.Spool, buffer *int64) relayconfig.Config {
	t.Helper()
	cfg := relayconfig.Config{
		SchemaVersion: relayconfig.SchemaVersionSupported,
		Relay: relayconfig.Relay{
			Name: "relay-1", Site: "lab", Listen: "0.0.0.0:8453",
			AdvertisedNames: []string{"relay.flotestro.test"},
			StateDir:        "/var/lib/flotestro-relay",
			BufferMaxBytes:  buffer,
		},
		Upstream: relayconfig.Upstream{
			EnrollmentURL: "https://centre.flotestro.test",
			GatewayURLs:   []string{"https://centre.flotestro.test"},
		},
		Spool: spool,
	}
	if err := cfg.Check(); err != nil {
		t.Fatalf("the test configuration does not pass its own checks: %v", err)
	}
	return cfg
}

// A file that says nothing about the spool gets the directory under the
// state directory and the defaults of relayconfig; the site of the relay
// is carried into the options, because it is named on every record.
func TestTheSpoolSettingsFollowTheConfiguration(t *testing.T) {
	cfg := relayConfig(t, relayconfig.Spool{}, nil)
	dir, options := spoolSettings(cfg)
	if want := filepath.Join(cfg.Relay.StateDir, relayconfig.SpoolDirName); dir != want {
		t.Fatalf("the spool sits in %q, expected %q", dir, want)
	}
	if options.Site != "lab" {
		t.Fatalf("the records would be written for site %q", options.Site)
	}
	if options.MaxBytes != relayconfig.DefaultSpoolMaxBytes ||
		options.CriticalReserveBytes != relayconfig.DefaultSpoolCriticalReserve ||
		options.MinFreeBytes != relayconfig.DefaultSpoolMinFree ||
		options.AckTimeout != relayconfig.DefaultSpoolAckTimeout ||
		options.MaxInflightPerHost != relayconfig.DefaultSpoolMaxInflight {
		t.Fatalf("the defaults of the spool were not taken: %+v", options)
	}

	// Every limit of the file reaches the spool as it was written.
	maxBytes := int64(64 << 20)
	reserve := int64(8 << 20)
	free := int64(4 << 20)
	timeout := 90 * time.Second
	inflight := 7
	cfg = relayConfig(t, relayconfig.Spool{
		Path: "/srv/spool", MaxBytes: &maxBytes, CriticalReserveBytes: &reserve,
		MinFreeBytes: &free, AckTimeout: &timeout, MaxInflightPerHost: &inflight,
	}, nil)
	dir, options = spoolSettings(cfg)
	if dir != "/srv/spool" {
		t.Fatalf("the spool sits in %q, expected the path of the file", dir)
	}
	if options.MaxBytes != maxBytes || options.CriticalReserveBytes != reserve ||
		options.MinFreeBytes != free || options.AckTimeout != timeout ||
		options.MaxInflightPerHost != inflight {
		t.Fatalf("the limits of the file were not taken: %+v", options)
	}
}

// A file from before the spool names buffer_max_bytes alone: the spool
// takes that limit, so an upgrade keeps the room the operator gave the
// site instead of silently granting a gigabyte.
func TestTheSpoolKeepsTheRoomOfAnOlderConfiguration(t *testing.T) {
	buffer := int64(32 << 20)
	_, options := spoolSettings(relayConfig(t, relayconfig.Spool{}, &buffer))
	if options.MaxBytes != buffer {
		t.Fatalf("the spool may take %d bytes, the file gave the site %d", options.MaxBytes, buffer)
	}
	if options.CriticalReserveBytes > options.MaxBytes/2 {
		t.Fatalf("the reserve of %d bytes leaves no room in a spool of %d",
			options.CriticalReserveBytes, options.MaxBytes)
	}
}

// The directory is created private, and one left wider by a previous
// release or by a hand is narrowed: the records hold the results and the
// inventories of a whole site.
func TestTheSpoolDirectoryIsCreatedPrivate(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state", "spool")
	if err := prepareSpoolDir(dir); err != nil {
		t.Fatalf("the spool directory was not created: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("the spool directory is %s, expected 0700", info.Mode().Perm())
	}

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareSpoolDir(dir); err != nil {
		t.Fatalf("an existing spool directory was refused: %v", err)
	}
	info, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("a directory left readable stayed %s", info.Mode().Perm())
	}

	// A relative path is a configuration mistake rather than a directory
	// to create somewhere under the working directory of the service.
	if err := prepareSpoolDir("spool"); err == nil {
		t.Fatal("a relative spool path was accepted")
	}
	// A path that is a file is named as such rather than left to fail at
	// the first record.
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareSpoolDir(file); err == nil {
		t.Fatal("a file was accepted as the spool directory")
	}
}

// The age of the backlog comes from the oldest segment still on disk. An
// empty directory, or one without segments, gives no time at all rather
// than the zero of the epoch dressed up as a date.
func TestTheOldestSegmentDatesTheBacklog(t *testing.T) {
	dir := t.TempDir()
	if when := oldestSegmentWrite(dir); !when.IsZero() {
		t.Fatalf("an empty spool is dated %s", when)
	}
	if when := oldestSegmentWrite(filepath.Join(dir, "gone")); !when.IsZero() {
		t.Fatalf("a spool that is not there is dated %s", when)
	}

	older := filepath.Join(dir, "segment-0000000000000007.log")
	newer := filepath.Join(dir, "segment-0000000000000042.log")
	for _, name := range []string{older, newer, filepath.Join(dir, "notes.txt")} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(older, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	when := oldestSegmentWrite(dir)
	if !when.Truncate(time.Second).Equal(stamp) {
		t.Fatalf("the backlog is dated %s, the oldest segment was written at %s", when, stamp)
	}
}
