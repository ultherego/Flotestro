//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/modules/firewall"
)

// Where the laboratory leaves what it read off the firewalld hosts, and what it
// planted while it was there. The directory is the gate's own run directory, so
// the captures are artefacts of the run that judged them; gate/firewall-zones.sh
// writes it.
const firewallCapturesEnv = "FLOTESTRO_TEST_FIREWALL_CAPTURES"

// How old a capture may be and still be evidence about this run. A gate run
// takes a couple of hours at most; anything older is a directory left behind by
// an earlier one, and reading it would attest a host nobody asked today.
const firewallCapturesFresh = 12 * time.Hour

// firewallCapture is one host the laboratory read, with the names of the files
// holding each reading.
type firewallCapture struct {
	guest string
	// zone is what firewall-cmd --get-default-zone said, which ParseZones is
	// given; empty for a guest that carries no firewalld.
	zone      string
	firewalld bool
}

// The property no unit test can decide: on an untouched host the two firewalld
// configurations agree, by the definition a zone change is guarded with. One
// routine field differing on a distribution refuses every zone change on that
// whole family, and the only way to learn it is to ask each family.
//
// 05.10: a zone change was guarded with a fingerprint of the running nftables
// while the executor writes the permanent configuration and reloads, so a
// --permanent change made by somebody else between plan and apply did not move
// the fingerprint and our reload carried it into force. The guard that replaced
// it compares the two configurations, which only works where they agree when
// nobody has touched them - measured here, per family, and not argued.
func TestTheTwoFirewalldConfigurationsAgreePerFamily(t *testing.T) {
	directory := os.Getenv(firewallCapturesEnv)
	if directory == "" {
		absent(t, "%s is not set; nothing read the firewalld hosts of this laboratory, "+
			"so whether their two configurations agree is unmeasured - run gate/firewall-zones.sh",
			firewallCapturesEnv)
	}
	if _, err := os.Stat(directory); err != nil {
		absent(t, "%s names %s and there is nothing there: %v", firewallCapturesEnv, directory, err)
	}

	port, captures := readFirewallManifest(t, directory)
	measured := 0
	for _, capture := range captures {
		if !capture.firewalld {
			t.Logf("%s carries no firewalld, so this family is unmeasured by this laboratory", capture.guest)
			continue
		}
		measured++
		t.Run(capture.guest, func(t *testing.T) {
			checkFirewallCapture(t, directory, capture, port)
		})
	}
	// A check that inspected no host must not pass. The laboratory having no
	// firewalld guest is not the absence of the problem, it is the absence of
	// the answer, and this stage exists because that difference was once read
	// the wrong way round.
	if measured == 0 {
		t.Fatalf("the captures in %s name %d guest(s) and not one of them carries firewalld, "+
			"so the property this check is about was measured nowhere", directory, len(captures))
	}
}

// checkFirewallCapture renders the verdict for one host out of its four
// readings: the untouched pair, the pair with a port planted in the kept
// configuration, and the pair after the planting was undone.
func checkFirewallCapture(t *testing.T, directory string, capture firewallCapture, port string) {
	read := func(part string) string {
		return firewallCaptureFile(t, directory, capture.guest+"."+part+".txt")
	}
	running, kept := read("runtime"), read("permanent")

	// 1. The per-family property.
	clean, err := firewall.CompareZoneCaptures(running, kept, capture.zone)
	if err != nil {
		t.Fatalf("the untouched pair of %s cannot be compared, so this host answered nothing: %v",
			capture.guest, err)
	}
	t.Logf("%s: %d zones, default %s, filters with %s, keeps %s",
		capture.guest, len(clean.RuntimeZones), capture.zone, clean.RuntimeDigest, clean.PermanentDigest)
	if !clean.Agree() {
		t.Errorf("the two firewalld configurations of %s disagree although nobody touched it: %s\n"+
			"every zone change on this family is refused until the field is settled in "+
			"zoneListingNormalisation; the panel would say: %s",
			capture.guest, clean.Disagreement(), clean.Refusal)
	}
	if clean.Refusal != "" {
		t.Errorf("a zone change on the untouched %s is refused: %s", capture.guest, clean.Refusal)
	}

	// 2. The change made to the kept configuration behind the panel's back.
	planted, err := firewall.CompareZoneCaptures(running, read("permanent-planted"), capture.zone)
	if err != nil {
		t.Fatalf("the planted pair of %s cannot be compared: %v", capture.guest, err)
	}
	if planted.PermanentDigest == clean.PermanentDigest {
		t.Errorf("%s: a --permanent %s planted in %s left the fingerprint of the kept "+
			"configuration still, so a plan made before it would still apply after it",
			capture.guest, port, capture.zone)
	}
	if !planted.Names(port) {
		t.Errorf("%s: the planted %s is not named in any difference, so the operator would be "+
			"refused without being told what for: %s", capture.guest, port, planted.Disagreement())
	}
	if planted.Refusal == "" {
		t.Errorf("%s: a zone change would be taken while the kept configuration carries %s",
			capture.guest, port)
	}

	// 3. And the host was left as it was found. The running reading is here
	// too: a --permanent change must not move it, and if it did then something
	// reloaded the host, which is a change left behind rather than undone.
	restored, err := firewall.CompareZoneCaptures(read("runtime-restored"), read("permanent-restored"), capture.zone)
	if err != nil {
		t.Fatalf("the pair of %s read after the cleanup cannot be compared: %v", capture.guest, err)
	}
	if !restored.Agree() {
		t.Errorf("%s does not agree with itself after the cleanup: %s", capture.guest, restored.Disagreement())
	}
	if restored.PermanentDigest != clean.PermanentDigest {
		t.Errorf("%s keeps a different configuration than before this check: %s became %s",
			capture.guest, clean.PermanentDigest, restored.PermanentDigest)
	}
	if restored.RuntimeDigest != clean.RuntimeDigest {
		t.Errorf("%s filters differently than before this check: %s became %s - a --permanent "+
			"change alone cannot do that, so the host was reloaded and left changed",
			capture.guest, clean.RuntimeDigest, restored.RuntimeDigest)
	}
	// And the files on disk, which the two listings cannot answer for. The
	// first run of this check left /etc/firewalld/zones/FedoraServer.xml.old
	// on the host carrying the port it had just removed: both listings read
	// clean, the host did not, and a trace nobody notices is the fault this
	// laboratory charges itself for.
	if before, after := read("zonefiles"), read("zonefiles-restored"); before != after {
		t.Errorf("%s does not keep the files it kept before this check:\nbefore:\n%s\nafter:\n%s",
			capture.guest, before, after)
	}
}

// readFirewallManifest reads what the laboratory says it did: the port it
// planted and every guest it visited, firewalld or not.
func readFirewallManifest(t *testing.T, directory string) (string, []firewallCapture) {
	t.Helper()
	name := filepath.Join(directory, "captures.tsv")
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("the captures do not say what was read: %v", err)
	}
	port := ""
	var captures []firewallCapture
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Split(line, "\t")
		switch {
		case fields[0] == "port" && len(fields) == 2:
			port = fields[1]
		case fields[0] == "captured_at" && len(fields) == 2:
			at, err := time.Parse(time.RFC3339, fields[1])
			if err != nil {
				t.Fatalf("the captures are dated %q, which is no timestamp: %v", fields[1], err)
			}
			if age := time.Since(at); age > firewallCapturesFresh {
				t.Fatalf("the captures in %s were taken %s ago, so they are an earlier run's "+
					"evidence and say nothing about this one", directory, age.Round(time.Minute))
			}
		case fields[0] == "guest" && len(fields) == 4:
			captures = append(captures, firewallCapture{
				guest: fields[1], firewalld: fields[2] == "firewalld", zone: fields[3],
			})
		}
	}
	if port == "" {
		t.Fatalf("%s does not say which port was planted, so nothing can assert it was named", name)
	}
	if len(captures) == 0 {
		t.Fatalf("%s names no guest at all", name)
	}
	return port, captures
}

// firewallCaptureFile reads one capture and refuses an empty one here rather
// than letting it travel as an answer: a file that is not there, or is there
// and empty, is a reading that did not happen.
func firewallCaptureFile(t *testing.T, directory, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatalf("a reading this check is about is missing: %v", err)
	}
	if strings.TrimSpace(string(content)) == "" {
		t.Fatalf("%s is empty, so firewall-cmd answered nothing and the host said nothing", name)
	}
	return string(content)
}
