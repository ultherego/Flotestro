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
// the replacement runs. The document's rule is that a return must not depend
// on the repository still carrying the old release, so the copy is what
// proves the return exists at all.
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

// The digest is what settles whether the file on disk is the file the
// release published. A file that hashes to anything else is refused with the
// code the panel acts on, and nothing is installed from it.
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

// The unit that outlives the helper reads the order only when it is the
// order for the package it was started with. A leftover of an abandoned run
// must not decide what a new one installs.
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
