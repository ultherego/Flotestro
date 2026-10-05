package helper

import (
	"context"
	"errors"
	"slices"
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

// Zone listings copied from a host of the test fleet. The running one carries
// the markers firewall-cmd puts on a zone that is on an interface and the
// interface it is on; the permanent configuration has no notion of either, so
// its listing prints the zone name alone. The two are the host's two answers.
const zonesListing = `public (default, active)
  target: default
  interfaces: enp0s3
  services: cockpit dhcpv6-client ssh
  ports: 8443/tcp
  rich rules:
`

const permanentZonesListing = `public (default)
  target: default
  services: cockpit dhcpv6-client ssh
  ports: 8443/tcp
  rich rules:
`

// zoneListings attributes each answer to the command that produced it. The
// permanent one is the command the executor's own write carries, which is what
// makes the pair a statement about one configuration and not two.
func zoneListings(runtime, permanent string) (zoneListing, zoneListing) {
	running := zoneListing{command: firewall.ZoneListArguments(false), output: runtime}
	kept := zoneListing{command: firewall.ZoneListArguments(true), output: permanent}
	return running, kept
}

// zoneState is one reading of a firewalld host as readFirewall takes it: both
// listings recorded, then the fingerprint sealed over the whole answer.
func zoneState(runtime, permanent string) firewall.Snapshot {
	snapshot := firewall.Snapshot{Hash: "ruleset-digest", Writable: true}
	running, kept := zoneListings(runtime, permanent)
	recordZones(&snapshot, "public\n", running, kept)
	firewall.SealFingerprint(&snapshot)
	return snapshot
}

// runtimeOnlyFingerprint is the fingerprint as it was before the permanent
// configuration was read and before anything but the modelled fields counted:
// the ruleset and the running zones. The tests below use it to show that what
// they exercise is invisible to it.
func runtimeOnlyFingerprint(runtime, permanent string) string {
	snapshot := firewall.Snapshot{Hash: "ruleset-digest", Writable: true}
	running, kept := zoneListings(runtime, permanent)
	recordZones(&snapshot, "public\n", running, kept)
	snapshot.PermanentZones, snapshot.PermanentZonesReason = nil, ""
	snapshot.ZonesDigest, snapshot.PermanentZonesDigest = "", ""
	firewall.SealFingerprint(&snapshot)
	return snapshot.Hash
}

// The read and the write have to be proved to concern one configuration. The
// absence of that proof is the whole defect: the guard asked the running zones
// whether the entry was there, and the executor wrote the permanent ones.
func TestTheZoneGuardReadsTheConfigurationTheExecutorWrites(t *testing.T) {
	// The exact arguments the executor runs, written out and not derived.
	steps, err := firewall.PortArguments("public", "8080", "tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	write := []string{"/usr/bin/firewall-cmd", "--permanent", "--zone=public", "--add-port=8080/tcp"}
	reload := []string{"/usr/bin/firewall-cmd", "--reload"}
	if len(steps) != 2 || !slices.Equal(steps[0], write) || !slices.Equal(steps[1], reload) {
		t.Fatalf("the executor runs %v", steps)
	}

	// The host filters with 8080/tcp now and does not keep it, so the two
	// configurations disagree about the very entry the write above is about.
	running, kept := zoneListings(
		strings.Replace(zonesListing, "8443/tcp", "8443/tcp 8080/tcp", 1), permanentZonesListing)
	if kept.command[1] != steps[0][1] {
		t.Fatalf("the guard reads %v and the executor writes %v: not one configuration",
			kept.command, steps[0])
	}
	if slices.Contains(running.command, firewall.PermanentFlag) {
		t.Errorf("the reading of what the host filters with now carries %s: %v",
			firewall.PermanentFlag, running.command)
	}
	state := firewall.Snapshot{Writable: true}
	recordZones(&state, "public\n", running, kept)

	// The answer that decides whether the change has work to do, and what the
	// way back is, comes from the listing the write targets.
	present, known := zoneHasPort(state, "public", "8080", "tcp")
	if !known || present {
		t.Fatalf("the guard says present=%v known=%v about a port only the running "+
			"configuration carries; the write above goes into the other one", present, known)
	}
	if carried, _ := zoneHasPort(state, "public", "8443", "tcp"); !carried {
		t.Error("an entry both configurations carry did not read as carried")
	}
}

// (a) A --permanent change made by somebody else between the plan and the
// apply does not move the running configuration, so the precondition held
// while the configuration the change writes had already moved.
func TestAPermanentOnlyChangeMovesTheFingerprint(t *testing.T) {
	const kept = permanentZonesListing
	// Somebody writes --permanent --add-port=9090/tcp and does not reload.
	moved := strings.Replace(kept, "8443/tcp", "8443/tcp 9090/tcp", 1)

	// The running configuration is the same in both readings, which is why the
	// fingerprint taken from it alone could not see this.
	if runtimeOnlyFingerprint(zonesListing, kept) != runtimeOnlyFingerprint(zonesListing, moved) {
		t.Fatal("the running configuration moved too, so this proves nothing about the permanent one")
	}
	if zoneState(zonesListing, kept).Hash == zoneState(zonesListing, moved).Hash {
		t.Fatal("a change to the configuration a zone change writes leaves the fingerprint still")
	}
	// And two readings of one unchanged host are one fingerprint: a precondition
	// that moved by itself would refuse every apply instead of the wrong ones.
	if zoneState(zonesListing, kept).Hash != zoneState(zonesListing, kept).Hash {
		t.Error("two readings of the same host have different fingerprints")
	}

	// A field the panel does not model is covered too, through the digest the
	// reader computes: a rich rule written with --permanent and not reloaded
	// moves the fingerprint, although the zones the panel models are the same.
	// firewalld prints a rich rule under its field, one per line; the field is
	// the last of the listing, so the rule belongs to it.
	rich := kept + "\trule family=\"ipv4\" source address=\"10.0.0.0/8\" drop\n"
	withRule := zoneState(zonesListing, rich)
	plain := zoneState(zonesListing, kept)
	if withRule.PermanentZonesDigest == plain.PermanentZonesDigest {
		t.Error("the digest of the kept configuration does not cover a rich rule")
	}
	if withRule.Hash == plain.Hash {
		t.Fatal("a rich rule written and not reloaded leaves the fingerprint still")
	}
	if runtimeOnlyFingerprint(zonesListing, rich) != runtimeOnlyFingerprint(zonesListing, kept) {
		t.Error("the reading this fingerprint came from is not the same on both sides")
	}
	// The difference is named rather than only counted, because nobody can
	// settle a difference the message does not name.
	refusal := firewall.ZoneReloadRefusal(withRule.Drift)
	if !strings.Contains(refusal, "rich rules") {
		t.Errorf("the refusal does not name the field: %s", refusal)
	}
}

// (c) The way back is built from the state found, and the state found has to be
// the one the inverse is written into. Read from the running configuration, the
// inverse restored a permanent state the host never had.
func TestTheWayBackIsBuiltFromTheConfigurationTheChangeWrites(t *testing.T) {
	// The host keeps 8443/tcp and is not filtering with it: a --permanent write
	// nobody reloaded. An order to close it has work to do, and the way back is
	// to put the entry back.
	state := zoneState(strings.Replace(zonesListing, "  ports: 8443/tcp\n", "", 1),
		permanentZonesListing)
	present, known := zoneHasPort(state, "public", "8443", "tcp")
	if !known || !present {
		t.Fatalf("an entry the host keeps reads as present=%v known=%v", present, known)
	}
	// The two commands changeZone composes out of that one answer: the steps
	// from the order, the way back from the state found.
	steps, err := firewall.PortArguments("public", "8443", "tcp", false)
	if err != nil {
		t.Fatal(err)
	}
	undo, err := firewall.PortArguments("public", "8443", "tcp", present)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(steps[0], "--remove-port=8443/tcp") {
		t.Errorf("the change does not remove the entry: %v", steps[0])
	}
	if !slices.Contains(undo[0], "--add-port=8443/tcp") {
		t.Errorf("the way back does not put the entry back: %v", undo[0])
	}

	// The other direction: the host filters with 9090/tcp and does not keep it.
	// Read from the running configuration, "close 9090" looked like a change to
	// make, and the inverse armed for it - --permanent --add-port=9090/tcp -
	// would have written an entry the permanent configuration never had.
	other := zoneState(strings.Replace(zonesListing, "8443/tcp", "8443/tcp 9090/tcp", 1),
		permanentZonesListing)
	present, known = zoneHasPort(other, "public", "9090", "tcp")
	if !known || present {
		t.Fatalf("an entry the host does not keep reads as present=%v known=%v", present, known)
	}
	undo, err = firewall.PortArguments("public", "9090", "tcp", present)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(undo[0], "--add-port=9090/tcp") {
		t.Errorf("the way back would write an entry the host never kept: %v", undo[0])
	}
}

// (b) Our own reload makes the whole permanent configuration the running one,
// so a pending difference of somebody else's travels with our change. A
// reading that cannot compare the two is the same answer, not a quiet yes.
func TestAReloadThatWouldCarrySomebodyElsesChangeIsRefused(t *testing.T) {
	pending := zoneState(strings.Replace(zonesListing, "  ports: 8443/tcp\n", "", 1),
		permanentZonesListing)
	refusal := firewall.ZoneReloadRefusal(pending.Drift)
	if refusal == "" {
		t.Fatal("a change kept and not in force would have been carried by our reload unannounced")
	}
	if !strings.Contains(refusal, "8443/tcp") || !strings.Contains(refusal, "public") {
		t.Errorf("the refusal does not name what it is about: %s", refusal)
	}

	// An order with nothing to write runs no command and reloads nothing, so it
	// is answered rather than refused - and the answer says that the host is
	// nevertheless not filtering the way the order describes.
	message := zoneNoChangeMessage(pending, "port")
	if !strings.Contains(message, "8443/tcp") {
		t.Errorf("an answer of no work to do hides the difference: %s", message)
	}
	plain := zoneNoChangeMessage(zoneState(zonesListing, permanentZonesListing), "port")
	if strings.Contains(plain, "difference") {
		t.Errorf("an ordinary host is told about a difference it does not have: %s", plain)
	}

	// From the good side: the two configurations of an ordinary host say the
	// same thing, and the change goes in.
	if refusal := firewall.ZoneReloadRefusal(zoneState(zonesListing, permanentZonesListing).Drift); refusal != "" {
		t.Errorf("a host whose two configurations agree was refused: %s", refusal)
	}
	// And a host that is not firewalld at all has nothing to compare and is
	// refused nothing.
	nftables := firewall.Snapshot{Hash: "ruleset-digest", Writable: true}
	firewall.SealFingerprint(&nftables)
	if refusal := firewall.ZoneReloadRefusal(nftables.Drift); refusal != "" {
		t.Errorf("a host without firewalld was refused: %s", refusal)
	}
	if nftables.Hash == "" {
		t.Error("a host without zones has no fingerprint, which reads as no precondition")
	}
}

// A permanent listing nobody read is a third state: not an empty permanent
// configuration, and not the same state as a running listing nobody read.
func TestAnUnreadPermanentListingIsItsOwnState(t *testing.T) {
	state := firewall.Snapshot{Hash: "ruleset-digest", Writable: true}
	running, kept := zoneListings(zonesListing, "")
	kept.err = errors.New("exit status 252")
	recordZones(&state, "public\n", running, kept)
	firewall.SealFingerprint(&state)

	if !strings.Contains(state.PermanentZonesReason, "firewall-cmd --permanent --list-all-zones") ||
		!strings.Contains(state.PermanentZonesReason, "exit status 252") {
		t.Fatalf("the reason does not name the command that failed: %q", state.PermanentZonesReason)
	}
	if state.ZonesReason != "" || len(state.Zones) != 1 {
		t.Errorf("the reading that answered was taken away with the one that did not: %+v", state)
	}
	// Every question about the configuration the change writes is unanswered -
	// the entries the running listing happens to name included.
	for _, port := range []string{"8443", "25"} {
		if _, known := zoneHasPort(state, "public", port, "tcp"); known {
			t.Errorf("the port %s was answered from a listing nobody read", port)
		}
	}
	if _, known := zoneHasService(state, "public", "ssh"); known {
		t.Error("a service question was answered from a listing nobody read")
	}
	// An empty permanent configuration is an answer, and a different one.
	if state.Hash == zoneState(zonesListing, "").Hash {
		t.Error("an unread permanent listing has the fingerprint of an empty one")
	}
	// Nothing can be said about the reload either.
	if firewall.ZoneReloadRefusal(state.Drift) == "" {
		t.Error("a host whose configurations cannot be compared was allowed to reload")
	}
	// And the plan refuses by naming which of the two was not read.
	refusal := zonesUnknownRefusal(state)
	if !strings.Contains(refusal, "keeps for its next start") || strings.Contains(refusal, "filters with now") {
		t.Errorf("the refusal does not name the unread configuration alone: %s", refusal)
	}
	if zonesUnknownRefusal(zoneState(zonesListing, permanentZonesListing)) != "" {
		t.Error("a host that answered both questions was refused")
	}
}

// A firewalld host whose nftables underneath answered leaves no
// UnavailableReason, so a failed "firewall-cmd --list-all-zones" used to leave
// Zones empty and every zone question answered: the port is not open, the way
// back is "close it", and the rollback restores a state nobody read. The
// listing is a question the host did not answer (audit of 6c38561, HOP-F02).
func TestAFailedZoneListingIsNotAnEmptyFirewall(t *testing.T) {
	// The nftables underneath answered: this is the snapshot the reader has
	// before firewall-cmd is asked anything.
	answered := firewall.Snapshot{Writable: true}
	runtimeListing, permanentListing := zoneListings(zonesListing, permanentZonesListing)
	recordZones(&answered, "public\n", runtimeListing, permanentListing)
	if answered.Adapter != firewall.AdapterFirewalld || len(answered.Zones) != 1 {
		t.Fatalf("a listing that answered was not taken: %+v", answered)
	}
	if present, known := zoneHasPort(answered, "public", "8443", "tcp"); !known || !present {
		t.Errorf("a port the listing names: present=%v known=%v", present, known)
	}
	if present, known := zoneHasPort(answered, "public", "25", "tcp"); !known || present {
		t.Errorf("a port the listing does not name: present=%v known=%v", present, known)
	}
	// A zone absent from a list that was read carries nothing, and that is an
	// answer.
	if present, known := zoneHasPort(answered, "dmz", "8443", "tcp"); !known || present {
		t.Errorf("a zone absent from a read listing: present=%v known=%v", present, known)
	}

	unanswered := firewall.Snapshot{Writable: true}
	runtimeListing, permanentListing = zoneListings("", "")
	runtimeListing.err = errors.New("exit status 252")
	permanentListing.err = errors.New("exit status 252")
	recordZones(&unanswered, "", runtimeListing, permanentListing)
	if unanswered.ZonesReason == "" || unanswered.PermanentZonesReason == "" {
		t.Fatal("a listing that failed left no reason, so an empty list reads as an answer")
	}
	if unanswered.Adapter != firewall.AdapterFirewalld {
		t.Errorf("adapter = %q; a host carrying firewall-cmd is a firewalld host "+
			"whether the listing answered or not", unanswered.Adapter)
	}
	if _, known := zoneHasPort(unanswered, "public", "8443", "tcp"); known {
		t.Error("a port question was answered from a listing nobody read")
	}
	if _, known := zoneHasService(unanswered, "public", "ssh"); known {
		t.Error("a service question was answered from a listing nobody read")
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
