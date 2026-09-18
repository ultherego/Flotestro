package accounts

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Line is one line of an authorized_keys file. A line that grants access
// carries the fingerprint of its key; a comment, an empty line or a line
// the parser does not understand carries none and is kept as it is. The
// editor never rewrites a line it did not add: the options in front of a
// key (command=, from=, no-pty) are part of the text and travel with it.
type Line struct {
	Text        string `json:"text"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Type        string `json:"type,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// KeyInput is a key the operator pasted: the public key in the form the
// file takes, options included, and an optional comment appended when
// the key carries none of its own.
type KeyInput struct {
	PublicKey string `json:"public_key"`
	Comment   string `json:"comment,omitempty"`
}

// Change describes an edit by the fingerprints it touched. Before and
// After are the keys of the file on each side of the edit; Added and
// Removed are the difference, so an idempotent repeat shows empty ones.
type Change struct {
	Before  []string `json:"before"`
	After   []string `json:"after"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// NoOp says whether the edit leaves the file as it found it.
func (c Change) NoOp() bool {
	return len(c.Added) == 0 && len(c.Removed) == 0
}

// KeyNotFoundError names the fingerprints a removal asked for that the
// file does not carry. A removal of what is not there is refused rather
// than counted as done: the operator may be looking at another host's
// list, and the key they meant is still in place.
type KeyNotFoundError struct {
	Fingerprints []string
}

func (e *KeyNotFoundError) Error() string {
	return "the account has no key with the fingerprint " + strings.Join(e.Fingerprints, ", ")
}

// ErrInvalidKey marks material that is not a public key sshd would read.
var ErrInvalidKey = errors.New("not a public key")

// MaxKeyLineBytes bounds one line. A public key is under a kilobyte; a
// line beyond this is not one.
const MaxKeyLineBytes = 16384

// ParseKeyFile splits the content of a key file into lines. The trailing
// newline is not a line; a file with a final line without a newline gets
// one on the way back out.
func ParseKeyFile(content []byte) []Line {
	text := strings.TrimSuffix(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	if text == "" {
		return nil
	}
	var lines []Line
	for _, raw := range strings.Split(text, "\n") {
		lines = append(lines, describeLine(raw))
	}
	return lines
}

// describeLine reads one line the way sshd would: a key gets its
// fingerprint, anything else stays text.
func describeLine(raw string) Line {
	line := Line{Text: raw}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return line
	}
	key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return line
	}
	line.Fingerprint = ssh.FingerprintSHA256(key)
	line.Type = KeyTypeName(key.Type())
	line.Comment = comment
	return line
}

// ParseKey turns pasted material into a line of the file. The text is
// kept as pasted, trimmed of surrounding whitespace, so options in front
// of the key survive; a comment given apart is appended only when the key
// has none, because the comment in the file is the one people grep for.
func ParseKey(input KeyInput) (Line, error) {
	text := strings.TrimSpace(input.PublicKey)
	if text == "" {
		return Line{}, fmt.Errorf("%w: empty", ErrInvalidKey)
	}
	if strings.ContainsAny(text, "\n\r") {
		// A newline would append a line nobody reviewed.
		return Line{}, fmt.Errorf("%w: the key contains a newline", ErrInvalidKey)
	}
	if len(text) > MaxKeyLineBytes {
		return Line{}, fmt.Errorf("%w: the line is longer than %d bytes", ErrInvalidKey, MaxKeyLineBytes)
	}
	if strings.Contains(text, "PRIVATE KEY") {
		return Line{}, fmt.Errorf("%w: a private key was given; only a public key goes to the host", ErrInvalidKey)
	}
	key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		return Line{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if extra := strings.TrimSpace(input.Comment); extra != "" && comment == "" {
		if strings.ContainsAny(extra, "\n\r") {
			return Line{}, fmt.Errorf("%w: the comment contains a newline", ErrInvalidKey)
		}
		text += " " + extra
		comment = extra
	}
	return Line{
		Text:        text,
		Fingerprint: ssh.FingerprintSHA256(key),
		Type:        KeyTypeName(key.Type()),
		Comment:     comment,
	}, nil
}

// Fingerprints lists the keys of the lines, each once, in file order.
func Fingerprints(lines []Line) []string {
	seen := map[string]bool{}
	fingerprints := []string{}
	for _, line := range lines {
		if line.Fingerprint == "" || seen[line.Fingerprint] {
			continue
		}
		seen[line.Fingerprint] = true
		fingerprints = append(fingerprints, line.Fingerprint)
	}
	return fingerprints
}

// Render writes the lines back as a file. Nothing is reordered and
// nothing is reformatted; the file ends with a newline when it has any
// line at all.
func Render(lines []Line) string {
	if len(lines) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, line := range lines {
		builder.WriteString(line.Text)
		builder.WriteByte('\n')
	}
	return builder.String()
}

// AddKeys appends the keys the file does not carry yet. A key already
// there - by fingerprint, whatever its comment or options - is left as it
// is and not added twice; the same key twice in one order counts once.
func AddKeys(lines []Line, keys []KeyInput) ([]Line, Change, error) {
	before := Fingerprints(lines)
	present := map[string]bool{}
	for _, fingerprint := range before {
		present[fingerprint] = true
	}
	result := append([]Line(nil), lines...)
	change := Change{Before: before}
	for _, input := range keys {
		line, err := ParseKey(input)
		if err != nil {
			return nil, Change{}, err
		}
		if present[line.Fingerprint] {
			continue
		}
		present[line.Fingerprint] = true
		result = append(result, line)
		change.Added = append(change.Added, line.Fingerprint)
	}
	change.After = Fingerprints(result)
	return result, change, nil
}

// RemoveKeys drops the lines that carry the named fingerprints and
// nothing else. A fingerprint the file does not carry is a refusal unless
// the order says it may be missing; then it is simply not there.
func RemoveKeys(lines []Line, fingerprints []string, ignoreMissing bool) ([]Line, Change, error) {
	before := Fingerprints(lines)
	wanted := map[string]bool{}
	for _, fingerprint := range fingerprints {
		wanted[strings.TrimSpace(fingerprint)] = true
	}
	present := map[string]bool{}
	for _, fingerprint := range before {
		present[fingerprint] = true
	}
	var missing []string
	for _, fingerprint := range fingerprints {
		if !present[strings.TrimSpace(fingerprint)] {
			missing = append(missing, fingerprint)
		}
	}
	if len(missing) > 0 && !ignoreMissing {
		return nil, Change{}, &KeyNotFoundError{Fingerprints: missing}
	}
	change := Change{Before: before}
	var result []Line
	removed := map[string]bool{}
	for _, line := range lines {
		if line.Fingerprint != "" && wanted[line.Fingerprint] {
			if !removed[line.Fingerprint] {
				removed[line.Fingerprint] = true
				change.Removed = append(change.Removed, line.Fingerprint)
			}
			continue
		}
		result = append(result, line)
	}
	change.After = Fingerprints(result)
	return result, change, nil
}

// ReplaceKeys writes the file anew with the given keys and nothing else:
// the old semantics of the key operation, kept for the operator who
// really wants the file to be exactly this list. Lines that are not keys
// go with the rest - the caller has seen the full list of fingerprints
// and approved it, and a comment left behind would suggest the file was
// edited rather than replaced.
func ReplaceKeys(lines []Line, keys []KeyInput) ([]Line, Change, error) {
	before := Fingerprints(lines)
	var result []Line
	present := map[string]bool{}
	for _, input := range keys {
		line, err := ParseKey(input)
		if err != nil {
			return nil, Change{}, err
		}
		if present[line.Fingerprint] {
			continue
		}
		present[line.Fingerprint] = true
		result = append(result, line)
	}
	after := Fingerprints(result)
	change := Change{Before: before, After: after}
	for _, fingerprint := range after {
		if !contains(before, fingerprint) {
			change.Added = append(change.Added, fingerprint)
		}
	}
	for _, fingerprint := range before {
		if !present[fingerprint] {
			change.Removed = append(change.Removed, fingerprint)
		}
	}
	return result, change, nil
}

// SameFingerprints says whether two lists name the same keys, whatever
// their order. The comparison is what makes a replace stale: the list the
// operator saw against the list the host has now.
func SameFingerprints(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	for i := range a {
		a[i] = strings.TrimSpace(a[i])
	}
	for i := range b {
		b[i] = strings.TrimSpace(b[i])
	}
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// KeyTypeName names the key type the way ssh-keygen -l does, which is the
// way the panel has shown it since the read went through the tool.
func KeyTypeName(algorithm string) string {
	switch algorithm {
	case ssh.KeyAlgoED25519:
		return "ED25519"
	case ssh.KeyAlgoRSA:
		return "RSA"
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return "ECDSA"
	case ssh.KeyAlgoSKED25519:
		return "ED25519-SK"
	case ssh.KeyAlgoSKECDSA256:
		return "ECDSA-SK"
	case ssh.KeyAlgoDSA:
		return "DSA"
	}
	return algorithm
}

func contains(list []string, wanted string) bool {
	for _, item := range list {
		if item == wanted {
			return true
		}
	}
	return false
}
