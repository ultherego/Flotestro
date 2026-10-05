package release

import (
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The secret scan's allowlist takes findings out of the scan, so a careless
// entry is worse than the finding it silences: it is a hole with a comment
// above it saying the hole is fine.
//
// Nine fixtures were allowlisted on 05.10, and the one that mattered was the
// PEM block. MHcCAQEEIA is the opening of every P-256 EC key there is, so
// allowlisting that literal would have hidden the real thing; the entry is
// written as a block whose body is one short line instead, and the bound is
// what makes it safe. That was checked by planting a key-shaped block by hand
// and watching the scan still report it - which is a command, so it is a test.

// allowlistEntries reads the regexes of the scan's allowlist. The file is TOML
// and the entries are its literal strings; parsed by shape rather than with a
// parser, and the test refuses to pass when it finds none.
func allowlistEntries(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", ".github", "gitleaks.toml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	literal := regexp.MustCompile(`(?s)'''(.*?)'''`)
	var entries []string
	for _, found := range literal.FindAllStringSubmatch(string(content), -1) {
		if text := strings.TrimSpace(found[1]); text != "" {
			entries = append(entries, text)
		}
	}
	if len(entries) == 0 {
		t.Fatalf("no allowlist entry was read out of %s, so this test checked nothing", path)
	}
	return entries
}

// No entry may match a credential. The secrets below are generated here rather
// than written down, so the test cannot pass by the entry having memorised the
// example.
func TestNoAllowlistEntryMatchesARealSecret(t *testing.T) {
	entries := allowlistEntries(t)

	random := rand.New(rand.NewSource(20261005))
	base64Body := func(length int) string {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		body := make([]byte, length)
		for i := range body {
			body[i] = alphabet[random.Intn(len(alphabet))]
		}
		return string(body)
	}

	secrets := map[string]string{
		// A key as a Go string literal, which is the shape the fixtures take.
		"an EC key in a string literal": `key := "-----BEGIN EC PRIVATE KEY-----\n` +
			base64Body(240) + `\n-----END EC PRIVATE KEY-----"`,
		// And one written across real lines, which is the shape a key file takes.
		"a key across real lines": "-----BEGIN PRIVATE KEY-----\n" +
			base64Body(64) + "\n" + base64Body(64) + "\n" + base64Body(64) +
			"\n-----END PRIVATE KEY-----\n",
		// An EC key whose body opens exactly as the allowlisted fixture does:
		// the one case where a literal entry would have been a hole.
		"a key opening like the fixture": `key := "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA` +
			base64Body(220) + `\n-----END EC PRIVATE KEY-----"`,
		"a github token":    "token := \"ghp_" + base64Body(36) + "\"",
		"an aws access key": "AWS_ACCESS_KEY_ID=AKIA" + strings.ToUpper(base64Body(16)),
		"a slack token":     "xoxb-" + base64Body(24),
		"a bearer token":    `Authorization: Bearer ` + base64Body(120),
	}

	for name, secret := range secrets {
		for _, entry := range entries {
			pattern, err := regexp.Compile(entry)
			if err != nil {
				t.Errorf("the allowlist entry %q is not a regular expression: %v", entry, err)
				continue
			}
			if pattern.MatchString(secret) {
				t.Errorf("the allowlist entry %q would take %s out of the scan", entry, name)
			}
		}
	}
}

// And the fixtures the entries exist for are still allowed, so the scan does
// not go red on the tree it was measured against. Adjacency from the other
// side: an entry that allows nothing is an entry somebody will delete the next
// time the scan is red for an unrelated reason.
func TestEveryAllowlistEntryStillAllowsTheFixtureItWasWrittenFor(t *testing.T) {
	entries := allowlistEntries(t)
	fixtures := []string{
		`"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA\n-----END EC PRIVATE KEY-----\n"`,
		`"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"`,
		`"-----BEGIN PRIVATE KEY-----\nactive\n-----END PRIVATE KEY-----\n"`,
		`"-----BEGIN PRIVATE KEY-----\nprevious\n-----END PRIVATE KEY-----\n"`,
		`"-----BEGIN EC PRIVATE KEY-----\nnot really\n-----END EC PRIVATE KEY-----\n"`,
		`KeyID: "cf4a324d-ea01-5141-a3a4-032fdc10e703"`,
		`KeyID: "hs-0123456789abcdef"`,
		`keyID: "keycloak-rs256-1"`,
		`ManagedKeysFileName = "60-flotestro.keys"`,
		`"password": "Zx9-temporary"`,
		`MUSTNOTLEAVE`,
		`b3BlbnNzaC1rZXk=`,
	}
	for _, fixture := range fixtures {
		allowed := false
		for _, entry := range entries {
			if pattern, err := regexp.Compile(entry); err == nil && pattern.MatchString(fixture) {
				allowed = true
				break
			}
		}
		if !allowed {
			t.Errorf("no allowlist entry allows %q, so the scan reports the tree it was measured on", fixture)
		}
	}
	// Each entry has to be the reason some fixture is allowed; one that is the
	// reason for nothing is stale, and a stale entry is a hole nobody reads.
	for _, entry := range entries {
		pattern, err := regexp.Compile(entry)
		if err != nil {
			continue
		}
		used := false
		for _, fixture := range fixtures {
			if pattern.MatchString(fixture) {
				used = true
				break
			}
		}
		if !used {
			t.Errorf("the allowlist entry %q allows none of the fixtures this test knows; "+
				"either it is stale or a fixture is missing here", entry)
		}
	}
}
