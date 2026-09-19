package helper

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ultherego/flotestro/internal/modules/firewall"
)

// bootRestoreRoot is a host filesystem with nft on it and a boot the kernel
// names. What each test adds to it is what that host is about.
func bootRestoreRoot(files map[string]string) fstest.MapFS {
	root := fstest.MapFS{
		"usr/sbin/nft":                   &fstest.MapFile{Data: []byte("binary")},
		"proc/sys/kernel/random/boot_id": &fstest.MapFile{Data: []byte("f0b9\n")},
	}
	for name, content := range files {
		root[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return root
}

// writePanelRegistry writes a registry with one panel rule in it.
func writePanelRegistry(t *testing.T, dir string) {
	t.Helper()
	registry := firewall.Registry{Rules: []firewall.RuleSpec{{
		ID: "test", Chain: firewall.ChainInput, Action: "drop",
		Protocol: "tcp", Ports: []string{"25"}}}}
	if err := firewall.SaveRegistry(dir, registry); err != nil {
		t.Fatalf("writing the registry: %v", err)
	}
}

// Every refusal of the restore is recorded, and none of them runs a command
// on the host. The record is what the panel reads afterwards.
func TestTheBootRestoreRecordsWhyItTouchedNothing(t *testing.T) {
	const panelTableInBootFile = `flush ruleset
table inet flotestro {
	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 25 drop comment "flotestro:test"
	}
}
`
	nftHost := firewall.ParseNftUnit("LoadState=loaded\nUnitFileState=enabled\n" +
		"ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf }\n")

	for _, tc := range []struct {
		why      string
		registry bool
		files    map[string]string
		unit     firewall.NftUnit
		reason   string
	}{
		{why: "a host the panel never gave a rule", unit: nftHost},
		{why: "firewalld holds the rules", registry: true,
			files:  map[string]string{"usr/bin/firewall-cmd": "binary"},
			unit:   nftHost,
			reason: firewall.BootRestoreNotApplicable},
		{why: "ufw holds the rules", registry: true,
			files:  map[string]string{"etc/ufw/ufw.conf": "ENABLED=yes\n"},
			unit:   nftHost,
			reason: firewall.BootRestoreNotApplicable},
		{why: "the host's own unit loads the panel table", registry: true,
			files:  map[string]string{"etc/nftables.conf": panelTableInBootFile},
			unit:   nftHost,
			reason: firewall.BootRestoreNotNeeded},
	} {
		t.Run(tc.why, func(t *testing.T) {
			dir := t.TempDir()
			if tc.registry {
				writePanelRegistry(t, dir)
			}
			server := &Server{}
			record, err := server.restoreTable(context.Background(), bootRestoreInputs{
				dir: dir, root: bootRestoreRoot(tc.files), unit: tc.unit})
			if err != nil {
				t.Fatalf("the restore ended with an error: %v", err)
			}
			if record.Reason != tc.reason || record.Detail == "" {
				t.Fatalf("record = %+v", record)
			}
			if record.Boot != "f0b9" {
				t.Errorf("the record does not name the boot it belongs to: %+v", record)
			}
			// The panel reads the record, not the process that wrote it.
			written, err := firewall.LoadBootRestoreRecord(dir)
			if err != nil || written.Reason != tc.reason || written.Boot != record.Boot {
				t.Fatalf("written = %+v, err = %v", written, err)
			}
		})
	}
}

// A restore that cannot do its work ends the unit as failed and says why:
// a unit that finished cleanly would mean the table is there.
func TestABootRestoreThatCannotRebuildFails(t *testing.T) {
	dir := t.TempDir()
	writePanelRegistry(t, dir)
	root := bootRestoreRoot(nil)
	delete(root, "usr/sbin/nft")

	server := &Server{}
	record, err := server.restoreTable(context.Background(), bootRestoreInputs{
		dir: dir, root: root, unit: firewall.ParseNftUnit("LoadState=not-found\n")})
	if err == nil {
		t.Fatal("a host without nft rebuilt the panel's table")
	}
	if record.Reason != firewall.DriftBootRestoreFailed || !strings.Contains(record.Detail, "nft") {
		t.Fatalf("record = %+v", record)
	}
	written, err := firewall.LoadBootRestoreRecord(dir)
	if err != nil || written.Reason != firewall.DriftBootRestoreFailed {
		t.Fatalf("the failure was not recorded: %+v, %v", written, err)
	}
}

// What the helper records and what the panel is told are two sides of one
// answer: a run of this boot with nothing against it puts the rules back.
func TestTheRecordOfARestoreIsWhatThePanelReads(t *testing.T) {
	dir := t.TempDir()
	server := &Server{}
	record, err := server.restoreTable(context.Background(), bootRestoreInputs{
		dir: dir, root: bootRestoreRoot(nil),
		unit: firewall.ParseNftUnit("LoadState=not-found\n")})
	if err != nil {
		t.Fatalf("the restore ended with an error: %v", err)
	}

	state := firewall.BootRestoreState(
		firewall.ParseBootRestoreUnit("LoadState=loaded\nUnitFileState=enabled\n"+
			"ActiveState=active\nResult=success\n"),
		record, "f0b9", 0)
	if !state.Ran || !state.InForce() {
		t.Fatalf("state = %+v", state)
	}
}
