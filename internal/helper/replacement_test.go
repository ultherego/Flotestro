package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
)

func TestAgentReplacementRecognizesTheAgentPackage(t *testing.T) {
	cases := []struct {
		name     string
		packages []string
		expected bool
		spec     string
	}{
		{"apt with a version", []string{"flotestro-agent=0.6.0"}, true, "flotestro-agent=0.6.0"},
		{"dnf with a version", []string{"flotestro-agent-0.6.0"}, true, "flotestro-agent-0.6.0"},
		{"without a version", []string{"flotestro-agent"}, true, "flotestro-agent"},
		{"a foreign package", []string{"curl=8.0"}, false, ""},
		{"a similar name", []string{"flotestro-agent-tools=1.0"}, false, ""},
		{"the agent in company", []string{"flotestro-agent=0.6.0", "curl"}, false, ""},
		{"empty", nil, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := agentReplacement(tc.packages)
			if ok != tc.expected {
				t.Fatalf("agentReplacement(%v) = %v, expected %v",
					tc.packages, ok, tc.expected)
			}
			if ok && spec != tc.spec {
				t.Fatalf("spec = %q, expected %q", spec, tc.spec)
			}
		})
	}
}

// The artefact of the version the host can go back to is kept locally before
// the replacement runs.
func TestTheArtefactToGoBackToIsKeptOutOfThePackageCache(t *testing.T) {
	state := t.TempDir()
	cache := t.TempDir()
	withUpgradeDirs(t, state, map[string][]string{"apt": {cache}})

	// The package cache of the host holds the file of the version that runs.
	cached := filepath.Join(cache, "flotestro-agent_0.54.0-1_amd64.deb")
	if err := os.WriteFile(cached, []byte("the previous release"), 0o644); err != nil {
		t.Fatal(err)
	}

	kept, err := keepRollbackArtefact(context.Background(), "apt",
		"flotestro-agent=0.55.0", "0.54.0")
	if err != nil {
		t.Fatalf("the artefact to go back to was not kept: %v", err)
	}
	if !strings.HasPrefix(kept, filepath.Join(state, "rollback")) {
		t.Fatalf("the artefact was kept at %q, expected it under the helper's state directory", kept)
	}
	content, err := os.ReadFile(kept)
	if err != nil || string(content) != "the previous release" {
		t.Fatalf("the kept artefact reads %q (%v), expected the file from the cache", content, err)
	}
	// The original stays where it was: the cache is the host's, not ours to
	// empty on the way past.
	if _, err := os.Stat(cached); err != nil {
		t.Errorf("the file was taken out of the package cache rather than copied: %v", err)
	}
}

// A version that is neither in the cache nor obtainable refuses the upgrade
// rather than letting it run without the return it promised.
func TestAnArtefactToGoBackToThatCannotBeObtainedRefusesTheUpgrade(t *testing.T) {
	withUpgradeDirs(t, t.TempDir(), map[string][]string{"apt": {t.TempDir()}})

	if _, err := keepRollbackArtefact(context.Background(), "unknown-manager",
		"flotestro-agent=0.55.0", "0.54.0"); err == nil {
		t.Fatal("a manager that cannot fetch an artefact still reported a prepared return")
	}
}

// The digest is what settles whether the file on disk is the file the release
// published.
func TestAnArtefactIsAcceptedOnlyOnTheOrderedDigest(t *testing.T) {
	dir := t.TempDir()
	artefact := filepath.Join(dir, "flotestro-agent_0.55.0-1_amd64.deb")
	if err := os.WriteFile(artefact, []byte("the release"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("the release"))
	correct := hex.EncodeToString(sum[:])

	if err := verifyDigest(artefact, correct); err != nil {
		t.Fatalf("the artefact of the release was refused: %v", err)
	}
	if err := verifyDigest(artefact, strings.Repeat("9f", 32)); !errors.Is(err, errDigestMismatch) {
		t.Fatalf("a wrong digest gave %v, expected a digest mismatch", err)
	}
	// The check is case-insensitive on the notation of the digest alone; the
	// content is compared byte for byte.
	if err := verifyDigest(artefact, strings.ToUpper(correct)); err != nil {
		t.Errorf("the same digest in capitals was refused: %v", err)
	}
}

// Only a package file of the agent counts as an artefact. A directory full
// of other things is a directory the order did not obtain its artefact into.
func TestOnlyThePackageFilesOfTheAgentCountAsArtefacts(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"flotestro-agent_0.55.0-1_amd64.deb",
		"flotestro-agent-0.55.0-1.el9.x86_64.rpm",
		"flotestro-agent-tools_1.0_all.deb",
		"curl_8.0_amd64.deb",
		"flotestro-agent_0.55.0.deb.tmp",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	found, err := artefactsIn(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 3 {
		t.Fatalf("the artefacts found were %v, expected the three package files of the agent", found)
	}
	// The name of the package alone does not make it that version.
	if !nameCarriesVersion("flotestro-agent_0.55.0-1_amd64.deb", "0.55.0") ||
		nameCarriesVersion("flotestro-agent_0.55.0-1_amd64.deb", "0.54.0") {
		t.Error("the version is not read out of the name of the artefact")
	}
	// An epoch is written differently by every manager and is not compared.
	if !nameCarriesVersion("flotestro-agent-0.55.0-1.el9.x86_64.rpm", "1:0.55.0") {
		t.Error("an epoch in the ordered version hid the artefact of that version")
	}
}

// The rollback version is named in whatever notation the order used, so the
// two never disagree about how a version is written for this manager.
func TestTheRollbackVersionIsNamedInTheNotationOfTheOrder(t *testing.T) {
	cases := []struct {
		spec, version, expected string
		ok                      bool
	}{
		{"flotestro-agent=0.55.0", "0.54.0", "flotestro-agent=0.54.0", true},
		{"flotestro-agent-0.55.0", "0.54.0", "flotestro-agent-0.54.0", true},
		{"flotestro-agent", "0.54.0", "", false},
		{"flotestro-agent=0.55.0", "", "", false},
	}
	for _, tc := range cases {
		spec, ok := specForVersion(tc.spec, tc.version)
		if ok != tc.ok || spec != tc.expected {
			t.Errorf("specForVersion(%q, %q) = %q, %v, expected %q, %v",
				tc.spec, tc.version, spec, ok, tc.expected, tc.ok)
		}
	}
}

// The unit that outlives the helper reads the order only when it is the order
// for the package it was started with.
func TestAReplacementOrderIsReadOnlyForItsOwnPackage(t *testing.T) {
	withUpgradeDirs(t, t.TempDir(), nil)
	order := replacementOrder{
		Spec:           "flotestro-agent=0.55.0",
		ArtefactPath:   "/var/lib/flotestro-helper/agent-upgrade/download/agent.deb",
		ArtefactSHA256: strings.Repeat("ab", 32),
		OrderedAt:      time.Now().UTC(),
	}
	if err := writeReplacementOrder(order); err != nil {
		t.Fatal(err)
	}
	if read, ok := readReplacementOrder("flotestro-agent=0.55.0"); !ok ||
		read.ArtefactPath != order.ArtefactPath {
		t.Fatalf("the order of its own package read as %+v, %v", read, ok)
	}
	if _, ok := readReplacementOrder("flotestro-agent=0.56.0"); ok {
		t.Fatal("the order of another version was taken as the order of this one")
	}
}

// withUpgradeDirs points the replacement's state directory and the package
// caches it looks into at directories of the test.
func withUpgradeDirs(t *testing.T, state string, caches map[string][]string) {
	t.Helper()
	previousDir, previousCaches := agentUpgradeDir, managerCacheDirs
	agentUpgradeDir = state
	if caches != nil {
		managerCacheDirs = caches
	}
	t.Cleanup(func() {
		agentUpgradeDir, managerCacheDirs = previousDir, previousCaches
	})
}

// The copy the host kept answers before the repository: going back must not
// depend on the old version still being published. The manager here can fetch
func TestTheKeptArtefactAnswersBeforeTheRepository(t *testing.T) {
	state := t.TempDir()
	withUpgradeDirs(t, state, nil)
	kept := writeKeptArtefact(t, "flotestro-agent_0.54.0-1_amd64.deb", "the previous release")

	path, source, err := obtainArtefact(context.Background(), "no-such-manager",
		"flotestro-agent=0.54.0", digestOfContent("the previous release"))
	if err != nil {
		t.Fatalf("the kept artefact did not answer the order: %v", err)
	}
	if path != kept {
		t.Fatalf("the order was answered with %q, expected the kept artefact %q", path, kept)
	}
	if source != artefactSourceKept {
		t.Errorf("the artefact came from %q, expected %q", source, artefactSourceKept)
	}
	// The version decides: the artefact of another release is not an answer to
	// this order, and this manager cannot ask the repository.
	if _, _, err := obtainArtefact(context.Background(), "no-such-manager",
		"flotestro-agent=0.55.0", digestOfContent("the previous release")); err == nil {
		t.Error("the artefact of another version was taken for the ordered one")
	}
}

// A kept copy that does not hash to the digest of the order is a refusal of
// its own. Downloading the version again here would turn an artefact nobody
func TestAKeptArtefactThatDoesNotVerifyIsRefusedRatherThanFetchedAgain(t *testing.T) {
	withUpgradeDirs(t, t.TempDir(), nil)
	writeKeptArtefact(t, "flotestro-agent_0.54.0-1_amd64.deb", "a file nobody published")

	_, _, err := obtainArtefact(context.Background(), "apt",
		"flotestro-agent=0.54.0", digestOfContent("the previous release"))
	if !errors.Is(err, errKeptArtefactInvalid) {
		t.Fatalf("the kept artefact gave %v, expected the refusal of a kept artefact", err)
	}
	if code := artefactRefusalCode(err); code != ErrorKeptArtefactInvalid {
		t.Errorf("the refusal is %q, expected %q", code, ErrorKeptArtefactInvalid)
	}
	// The refusal says where the file the host would not install is.
	if !strings.Contains(err.Error(), filepath.Join(rollbackDir(), "flotestro-agent_0.54.0-1_amd64.deb")) {
		t.Errorf("the refusal %q does not name the kept artefact", err)
	}
}

// What an older replacement kept is neither installed now nor promised to
// anybody as a way back.
func TestPruningLeavesOnlyTheArtefactsTheOrderNeeds(t *testing.T) {
	withUpgradeDirs(t, t.TempDir(), nil)
	installed := writeKeptArtefact(t, "flotestro-agent_0.54.0-1_amd64.deb", "the version being installed")
	promised := writeKeptArtefact(t, "flotestro-agent_0.55.0-1_amd64.deb", "the way back")
	stale := writeKeptArtefact(t, "flotestro-agent_0.52.0-1_amd64.deb", "an older replacement")

	removed := pruneKeptArtefacts(installed, promised)
	if len(removed) != 1 || removed[0] != filepath.Base(stale) {
		t.Fatalf("pruning removed %v, expected only %s", removed, filepath.Base(stale))
	}
	for _, path := range []string{installed, promised} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("pruning removed %s, which this order needs: %v", path, err)
		}
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the artefact of an older replacement stayed")
	}
}

// The kept artefact goes when the host holds the version the order installed,
// and only then: a host that did not come back in that version is exactly the
func TestTheKeptArtefactIsReleasedOnlyOnceTheHostHoldsTheOrderedVersion(t *testing.T) {
	withUpgradeDirs(t, t.TempDir(), nil)
	order := replacementOrder{Spec: "flotestro-agent=0.55.0"}
	cases := []struct {
		installed string
		settled   bool
	}{
		{"0.55.0", true},
		{"0.55.0-1", true},
		{"1:0.55.0-2.el9", true},
		{"0.54.0", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := keptArtefactsSettled(order, tc.installed); got != tc.settled {
			t.Errorf("with %q installed the replacement counted as settled = %v, expected %v",
				tc.installed, got, tc.settled)
		}
	}

	kept := writeKeptArtefact(t, "flotestro-agent_0.54.0-1_amd64.deb", "the way back")
	if err := writeReplacementOrder(order); err != nil {
		t.Fatal(err)
	}
	released, err := releaseKeptArtefacts()
	if err != nil {
		t.Fatalf("what the replacement kept was not released: %v", err)
	}
	if len(released) != 1 || released[0] != filepath.Base(kept) {
		t.Fatalf("the release reports %v, expected %s", released, filepath.Base(kept))
	}
	if _, err := os.Stat(kept); err == nil {
		t.Error("the artefact kept for a return is still on the host after the release")
	}
	if _, ok := readReplacementOrder(order.Spec); ok {
		t.Error("the order of the settled replacement is still on the host")
	}
}

// One key is written as a fingerprint by one manager and as a long key ID by
// another; a short identity names a family of keys rather than one key.
func TestOneKeyIsRecognizedWhateverTheManagerCallsIt(t *testing.T) {
	fingerprint := "3B4FE6ACC0B21F32B4B6C1F4A2C794A986419D8A"
	cases := []struct {
		established, expected string
		same                  bool
	}{
		{fingerprint, fingerprint, true},
		{fingerprint, "A2C794A986419D8A", true},
		{"a2c794a986419d8a", fingerprint, true},
		{fingerprint, "0000000000000000", false},
		{fingerprint, "86419D8A", false},
		{"", fingerprint, false},
		{fingerprint, "", false},
	}
	for _, tc := range cases {
		if got := signerMatches(tc.established, tc.expected); got != tc.same {
			t.Errorf("signerMatches(%q, %q) = %v, expected %v",
				tc.established, tc.expected, got, tc.same)
		}
	}
}

// The identity is read out of what the tool of the manager itself printed,
// and only from a line that says the signature was accepted.
func TestTheSignerIsReadOutOfWhatTheManagerAccepted(t *testing.T) {
	accepted := "/tmp/flotestro-agent.rpm:\n" +
		"    Header V4 RSA/SHA256 Signature, key ID a2c794a986419d8a: OK\n" +
		"    Header SHA256 digest: OK\n"
	identity, ok := rpmSigner(accepted)
	if !ok || identity != "A2C794A986419D8A" {
		t.Fatalf("rpm named the signer %q (%v), expected A2C794A986419D8A", identity, ok)
	}
	missing := "/tmp/flotestro-agent.rpm:\n" +
		"    Header V4 RSA/SHA256 Signature, key ID a2c794a986419d8a: NOKEY\n"
	if _, ok := rpmSigner(missing); ok {
		t.Error("a key the host does not hold was taken for an accepted signature")
	}
	status := "[GNUPG:] NEWSIG\n" +
		"[GNUPG:] GOODSIG A2C794A986419D8A Flotestro Release\n" +
		"[GNUPG:] VALIDSIG 3B4FE6ACC0B21F32B4B6C1F4A2C794A986419D8A 2026-09-18\n"
	identity, ok = gpgValidSigner(status)
	if !ok || identity != "3B4FE6ACC0B21F32B4B6C1F4A2C794A986419D8A" {
		t.Fatalf("gpg named the signer %q (%v), expected the fingerprint of VALIDSIG", identity, ok)
	}
	if _, ok := gpgValidSigner("[GNUPG:] BADSIG A2C794A986419D8A Flotestro Release\n"); ok {
		t.Error("a bad signature named a signer")
	}
}

// An order that names a key and a host that cannot say who signed the file is
// a refusal, never an install. An order that names no key installs as before.
func TestAnEstablishedSignerIsRequiredOnlyWhenTheOrderNamesOne(t *testing.T) {
	withUpgradeDirs(t, t.TempDir(), nil)
	artefact := writeKeptArtefact(t, "flotestro-agent_0.54.0-1_amd64.deb", "the release")

	identity, _, err := artefactSigner(context.Background(), "apt", artefact)
	if !errors.Is(err, errSignerUnavailable) {
		t.Fatalf("a Debian package file established the signer %q (%v)", identity, err)
	}
	if refusal := judgeSigner("", identity, err); refusal != nil {
		t.Fatalf("an order naming no key was refused as %q: %s",
			refusal.GetErrorCode(), refusal.GetMessage())
	}
	refusal := judgeSigner("A2C794A986419D8A", identity, err)
	if refusal == nil || refusal.GetErrorCode() != ErrorSignerUnknown {
		t.Fatalf("an order naming a key the host cannot establish gave %v, expected %q",
			refusal, ErrorSignerUnknown)
	}
	wrong := judgeSigner("A2C794A986419D8A", "0000000000000000", nil)
	if wrong == nil || wrong.GetErrorCode() != ErrorSignerMismatch {
		t.Fatalf("an artefact of another signer gave %v, expected %q", wrong, ErrorSignerMismatch)
	}
	if right := judgeSigner("A2C794A986419D8A", "A2C794A986419D8A", nil); right != nil {
		t.Errorf("the key the order names was refused as %q", right.GetErrorCode())
	}
}

// The detached signature travels with the artefact: a kept copy without it
// could never prove who built it.
func TestTheDetachedSignatureIsKeptBesideTheArtefact(t *testing.T) {
	state := t.TempDir()
	cache := t.TempDir()
	withUpgradeDirs(t, state, map[string][]string{packages.PacmanName: {cache}})

	cached := filepath.Join(cache, "flotestro-agent-0.54.0-1-x86_64.pkg.tar.zst")
	if err := os.WriteFile(cached, []byte("the previous release"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached+signatureSuffix, []byte("the signature"), 0o644); err != nil {
		t.Fatal(err)
	}

	kept, err := keepRollbackArtefact(context.Background(), packages.PacmanName,
		"flotestro-agent=0.55.0", "0.54.0")
	if err != nil {
		t.Fatalf("the artefact to go back to was not kept: %v", err)
	}
	if _, err := os.Stat(kept + signatureSuffix); err != nil {
		t.Fatalf("the signature was not kept beside the artefact: %v", err)
	}
}

// writeKeptArtefact puts a package file among the ones the host kept for a
// return.
func writeKeptArtefact(t *testing.T, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(rollbackDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(rollbackDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// digestOfContent is the digest an order would carry for this content.
func digestOfContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}
