package cryptostate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One format and no other. A reader that accepted both raw bytes and
// hexadecimal would have to guess which it was looking at, and a guess about
// key material is how an installation ends up with a key nobody can reproduce.
func TestOnlyOneShapeOfKeyIsAccepted(t *testing.T) {
	const good = "3f1a9c0e5b7d2648a0c3e5f7091b2d4e6a8c0e2f4a6b8d0f1234567890abcdef"
	for _, test := range []struct {
		name    string
		content string
		code    string
	}{
		{"the key as openssl rand -hex writes it", good + "\n", ""},
		{"the same without the line break", good, ""},
		{"upper case is hexadecimal too", strings.ToUpper(good), ""},
		{"empty", "", CodeKEKFileMalformed},
		{"only a line break", "\n", CodeKEKFileMalformed},
		{"half a key", good[:32], CodeKEKFileMalformed},
		{"a key and a half", good + good, CodeKEKFileMalformed},
		{"raw bytes rather than hexadecimal", strings.Repeat("\x01", 32), CodeKEKFileMalformed},
		{"hexadecimal with a space in it", good[:63] + " ", CodeKEKFileMalformed},
		{"a second line", good + "\nand a note\n", CodeKEKFileMalformed},
		{"zeros", strings.Repeat("0", 64), CodeKEKFileMalformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			kek, err := ParseKEK(test.content, "/run/secrets/flotestro-kek")
			if test.code == "" {
				if err != nil {
					t.Fatalf("the key was refused: %v", err)
				}
				if !strings.HasPrefix(kek.ID(), "kek-") || len(kek.ID()) != 20 {
					t.Errorf("the identifier of the key is %q", kek.ID())
				}
				return
			}
			if err == nil {
				t.Fatal("the content was accepted as a key")
			}
			var fatal *FatalError
			if !errors.As(err, &fatal) || fatal.Code != test.code {
				t.Errorf("the refusal is %v, expected %s", err, test.code)
			}
		})
	}
}

// The identifier travels in the database and in the log. It is derived with
// the key rather than from it, so that holding the identifier tells nobody
// anything about the key, and two different keys never share a name.
func TestTheIdentifierNamesTheKeyWithoutGivingItAway(t *testing.T) {
	const one = "3f1a9c0e5b7d2648a0c3e5f7091b2d4e6a8c0e2f4a6b8d0f1234567890abcdef"
	const two = "3f1a9c0e5b7d2648a0c3e5f7091b2d4e6a8c0e2f4a6b8d0f1234567890abcdee"
	first, err := ParseKEK(one, "kek")
	if err != nil {
		t.Fatal(err)
	}
	same, err := ParseKEK(one+"\n", "kek")
	if err != nil {
		t.Fatal(err)
	}
	other, err := ParseKEK(two, "kek")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != same.ID() {
		t.Error("the same key came back under two names")
	}
	if first.ID() == other.ID() {
		t.Error("two keys share a name")
	}
	if strings.Contains(first.ID(), one[:16]) {
		t.Error("the identifier carries the key itself")
	}
	if !first.Is(same.ID()) || first.Is(other.ID()) {
		t.Error("the key does not recognise its own name")
	}
}

// Whoever can rewrite the file decides what the installation's records are
// sealed with, so the file is judged before it is read - and on the descriptor
// that was opened, not on the path, which somebody could swap in between.
func TestAKeyFileAnybodyElseCouldRewriteIsRefused(t *testing.T) {
	const good = "3f1a9c0e5b7d2648a0c3e5f7091b2d4e6a8c0e2f4a6b8d0f1234567890abcdef"
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent")
	if _, err := ReadKEKFile(missing); !refusedWith(err, CodeKEKFileMissing) {
		t.Errorf("a missing file answered %v", err)
	}

	path := filepath.Join(dir, "flotestro-kek")
	write := func(t *testing.T, mode os.FileMode) {
		t.Helper()
		// The previous case may have left the file unwritable by its own owner,
		// which only root would get past.
		_ = os.Chmod(path, 0o600)
		if err := os.WriteFile(path, []byte(good+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// The mode is set after the write: a umask would take the bits off again
		// and leave the case untested.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}

	write(t, 0o400)
	kek, err := ReadKEKFile(path)
	if err != nil {
		t.Fatalf("a key file of this account, readable by nobody else, was refused: %v", err)
	}
	if kek.ID() == "" {
		t.Error("the key came back without a name")
	}

	for _, mode := range []os.FileMode{0o440, 0o404, 0o600 | 0o060, 0o444} {
		write(t, mode)
		if _, err := ReadKEKFile(path); !refusedWith(err, CodeKEKFileUnsafe) {
			t.Errorf("a key file with mode %04o answered %v", mode, err)
		}
	}

	// A link is not the file that was checked.
	write(t, 0o400)
	link := filepath.Join(dir, "linked-kek")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("this filesystem takes no symbolic links: %v", err)
	}
	if _, err := ReadKEKFile(link); !refusedWith(err, CodeKEKFileUnsafe) {
		t.Errorf("a key behind a symbolic link answered %v", err)
	}

	// Neither is a directory.
	if _, err := ReadKEKFile(dir); !refusedWith(err, CodeKEKFileUnsafe) {
		t.Errorf("a directory answered %v", err)
	}
}

func refusedWith(err error, code string) bool {
	var fatal *FatalError
	return errors.As(err, &fatal) && fatal.Code == code
}
