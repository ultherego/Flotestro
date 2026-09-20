package packages

import (
	"strings"
	"testing"
)

const inlineSource = `Types: deb
URIs: https://packages.example.org/flotestro/deb
Suites: stable
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 mQINBGXexampleAQ//placeholder
 =abcd
 -----END PGP PUBLIC KEY BLOCK-----
`

// A source that carries its key instead of naming a keyring is trusted by apt
// exactly the same way. Reading it as no key at all was what made such a
// repository report apt_index_key_untrusted.
func TestAnInlineKeyIsReadOutOfTheSource(t *testing.T) {
	blocks := ParseAPTInlineKeys(inlineSource)
	if len(blocks) != 1 {
		t.Fatalf("read %d keys out of the source, want 1", len(blocks))
	}
	block := blocks[0]
	if !strings.HasPrefix(block, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n") {
		t.Errorf("the block does not start with the armour header: %q", block)
	}
	if !strings.HasSuffix(block, "-----END PGP PUBLIC KEY BLOCK-----\n") {
		t.Errorf("the block does not end with the armour footer: %q", block)
	}
	// The dot line is an empty line, and the leading space of every
	// continuation line belongs to the file, not to the key.
	if !strings.Contains(block, "-----\n\nmQINBGXexample") {
		t.Errorf("the dot line did not become an empty line: %q", block)
	}
	if strings.Contains(block, "\n ") {
		t.Errorf("a continuation space survived into the key: %q", block)
	}
}

// The field stops where the paragraph's next field begins.
func TestAnInlineKeyStopsAtTheNextField(t *testing.T) {
	content := inlineSource + "Architectures: amd64\nEnabled: yes\n"
	blocks := ParseAPTInlineKeys(content)
	if len(blocks) != 1 {
		t.Fatalf("read %d keys, want 1", len(blocks))
	}
	for _, unwanted := range []string{"Architectures", "Enabled"} {
		if strings.Contains(blocks[0], unwanted) {
			t.Errorf("the key swallowed the %s field: %q", unwanted, blocks[0])
		}
	}
}

// A source that names a keyring carries no key material, and a Signed-By that
// names a path is not an inline key.
func TestANamedKeyringIsNotAnInlineKey(t *testing.T) {
	content := "Types: deb\nURIs: https://example.org\nSigned-By: /usr/share/keyrings/example.gpg\n"
	if blocks := ParseAPTInlineKeys(content); len(blocks) != 0 {
		t.Fatalf("read %d keys out of a source that names a keyring", len(blocks))
	}
	paths := ParseAPTSignedBy(content)
	if len(paths) != 1 || paths[0] != "/usr/share/keyrings/example.gpg" {
		t.Fatalf("the named keyring was read as %v", paths)
	}
}

// Reading the paths must not pick the armour apart into path-like fragments.
func TestAnInlineKeyNamesNoKeyring(t *testing.T) {
	if paths := ParseAPTSignedBy(inlineSource); len(paths) != 0 {
		t.Fatalf("an inline key was read as the keyrings %v", paths)
	}
}

// Two sources, each with its own key, are two anchors.
func TestEverySourceContributesItsOwnKey(t *testing.T) {
	blocks := ParseAPTInlineKeys(inlineSource + "\n" + inlineSource)
	if len(blocks) != 2 {
		t.Fatalf("read %d keys out of two sources, want 2", len(blocks))
	}
}
