package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// The contract for secrets.
//
// A non-secret setting may live in the environment; a secret may not. In a
// container the value of an environment variable sits in the inspection
// output of the engine, in the shell history of whoever started it and in
// the environment of every child process, so the installation mounts a
// secret as a file and names the file instead: for every variable NAME the
// panel also accepts NAME_FILE and reads the value from that file once, at
// start.
//
// Nothing in this file ever puts a value into an error, a log line or a
// String method, and no type here keeps a secret in a field. A refusal
// names the variable, the path and what was wrong with it - never the
// value, because a refusal is the one message an operator copies into a
// ticket.

// maxSecretFileSize is the largest file this contract reads. A secret is a
// password, a key or a token; a file of megabytes is a mount that points at
// the wrong thing, and reading it whole would only turn a mistake into
// memory pressure.
const maxSecretFileSize = 64 << 10

// ErrSecretMissing marks the one refusal a caller is allowed to ignore: the
// secret is not configured in either form. An optional secret may stay
// absent, but a configured one that cannot be read is never treated as
// absent - that is how a signature quietly stops being checked.
var ErrSecretMissing = errors.New("the secret is not configured")

// SecretReason says which of the refusals happened. The text of a message
// is for people; this is what a caller may branch on.
type SecretReason string

const (
	// SecretReasonMissing: neither NAME nor NAME_FILE is set.
	SecretReasonMissing SecretReason = "missing"
	// SecretReasonConflict: NAME and NAME_FILE are both set.
	SecretReasonConflict SecretReason = "conflict"
	// SecretReasonEmpty: the variable or the file holds nothing.
	SecretReasonEmpty SecretReason = "empty"
	// SecretReasonNotRegular: the path is a symlink, a directory, a named
	// pipe, a socket or a device.
	SecretReasonNotRegular SecretReason = "not_a_regular_file"
	// SecretReasonTooLarge: the file is over the size a secret may take.
	SecretReasonTooLarge SecretReason = "too_large"
	// SecretReasonExposed: the group or others may read or write the file.
	SecretReasonExposed SecretReason = "readable_by_others"
	// SecretReasonForeignOwner: the file belongs to somebody who is neither
	// root nor the account the service runs as.
	SecretReasonForeignOwner SecretReason = "foreign_owner"
	// SecretReasonUnreadable: the file does not exist or the open failed.
	SecretReasonUnreadable SecretReason = "unreadable"
)

// SecretError is the refusal of this contract. It carries the name of the
// variable, the path it named and the reason, and it never carries the
// value: neither Error nor any other method of it can leak a secret into a
// log.
type SecretError struct {
	// Name is the secret, for example FLOTESTRO_WEBHOOK_SECRET. It is empty
	// when a file was checked on its own, through CheckSecretFile.
	Name string
	// Path is the file the refusal is about; empty when the refusal is
	// about the variable itself.
	Path string
	// Reason says which refusal this is.
	Reason SecretReason
	// Detail is the fact that decided it: the mode, the size, the owner or
	// the kind of the file. Never the value.
	Detail string
	cause  error
}

// Error renders the refusal for the operator who has to fix it.
func (e *SecretError) Error() string {
	subject := "the secret file " + e.Path
	if e.Name != "" && e.Path != "" {
		subject = fmt.Sprintf("%s_FILE names %s, and that file", e.Name, e.Path)
	}
	switch e.Reason {
	case SecretReasonConflict:
		return fmt.Sprintf("%s and %s_FILE are both set; a secret comes either from the environment "+
			"or from a file, never from both", e.Name, e.Name)
	case SecretReasonMissing:
		return fmt.Sprintf("%s is not configured; set %s_FILE to the file the value is mounted as", e.Name, e.Name)
	case SecretReasonEmpty:
		if e.Path == "" {
			return fmt.Sprintf("%s is set but empty", e.Name)
		}
		return subject + " is empty"
	case SecretReasonNotRegular:
		return fmt.Sprintf("%s is %s; a secret is mounted as a regular file", subject, e.Detail)
	case SecretReasonTooLarge:
		return fmt.Sprintf("%s is %s, over the %d KiB a secret may take", subject, e.Detail, maxSecretFileSize>>10)
	case SecretReasonExposed:
		return fmt.Sprintf("%s is readable by the group or by others (mode %s); chmod 600 it", subject, e.Detail)
	case SecretReasonForeignOwner:
		return fmt.Sprintf("%s belongs to uid %s rather than to root or to the service user", subject, e.Detail)
	case SecretReasonUnreadable:
		return fmt.Sprintf("%s cannot be read: %v", subject, e.cause)
	default:
		return fmt.Sprintf("%s was refused (%s)", subject, e.Reason)
	}
}

// Unwrap exposes the missing marker and the underlying file error, so a
// caller can ask errors.Is about ErrSecretMissing or about os.ErrNotExist.
func (e *SecretError) Unwrap() error { return e.cause }

// SecretValue reads the secret NAME. The value comes either from the
// variable itself or from the file NAME_FILE names, never from both, and
// the file is read once - the caller keeps the value, this package keeps
// nothing.
//
// A secret that is not configured at all comes back wrapping
// ErrSecretMissing, which is what tells an optional secret apart from a
// broken mount.
func SecretValue(name string) (string, error) {
	value, valueSet := os.LookupEnv(name)
	path, fileSet := os.LookupEnv(name + "_FILE")

	// Both forms at once is a refusal rather than a precedence rule: the
	// two mean different things to whoever set them, and starting with one
	// of them silently is how an installation signs with a secret nobody
	// believes is in use any more.
	if valueSet && fileSet {
		return "", &SecretError{Name: name, Reason: SecretReasonConflict}
	}
	if valueSet {
		if value == "" {
			return "", &SecretError{Name: name, Reason: SecretReasonEmpty}
		}
		return value, nil
	}
	// A NAME_FILE set to nothing is the same statement as not setting it:
	// the installation named no file.
	if !fileSet || path == "" {
		return "", &SecretError{Name: name, Reason: SecretReasonMissing, cause: ErrSecretMissing}
	}
	result, err := readSecretFile(path)
	if err != nil {
		return "", withSecretName(name, err)
	}
	return result, nil
}

// OptionalSecretValue reads a secret a deployment may leave out.
//
// A secret that is not configured comes back empty and without an error,
// and for an optional one an empty variable says exactly that: an
// environment file listing every variable the product knows, each with
// nothing after the equals sign, is how a package ships its configuration,
// and a panel that refuses to start over one of those lines would be
// refusing its own defaults. An empty variable is a statement for a
// required secret - SecretValue keeps refusing it - and no statement at
// all for an optional one.
//
// A configured secret that cannot be read is still a refusal, whichever
// kind it is: falling back to "no secret" on an unreadable mount turns a
// mounting mistake into a panel that quietly stops signing.
func OptionalSecretValue(name string) (string, error) {
	value, err := SecretValue(name)
	var refusal *SecretError
	if errors.As(err, &refusal) && refusal.Reason == SecretReasonEmpty && refusal.Path == "" {
		return "", nil
	}
	if errors.Is(err, ErrSecretMissing) {
		return "", nil
	}
	return value, err
}

// SecretConfigured says whether the installation set the secret at all, in
// either form. It answers the settings screen, which shows that a secret is
// in place without ever showing one, and it answers a caller that only
// enables a feature when its secret exists.
func SecretConfigured(name string) bool {
	if value, ok := os.LookupEnv(name); ok && value != "" {
		return true
	}
	path, ok := os.LookupEnv(name + "_FILE")
	return ok && path != ""
}

// CheckSecretFile runs the protections of this contract over a secret that
// stays a file - the keytab of the directory connector, for instance, whose
// path the panel hands to a library rather than reading the bytes. A keytab
// anyone on the machine can read hands out the identity of the connector
// just as surely as a leaked password.
func CheckSecretFile(path string) error {
	file, err := openSecretFile(path)
	if err != nil {
		return err
	}
	return file.Close()
}

// readSecretFile reads a checked file and applies the newline rule.
func readSecretFile(path string) (string, error) {
	file, err := openSecretFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// One byte over the limit on purpose: a file that grew between the
	// check and the read is refused rather than silently handed over
	// truncated, which would be a secret nobody can explain afterwards.
	raw, err := io.ReadAll(io.LimitReader(file, maxSecretFileSize+1))
	if err != nil {
		return "", &SecretError{Path: path, Reason: SecretReasonUnreadable, cause: err}
	}
	if len(raw) > maxSecretFileSize {
		return "", &SecretError{
			Path:   path,
			Reason: SecretReasonTooLarge,
			Detail: fmt.Sprintf("over %d bytes", maxSecretFileSize),
		}
	}
	value := trimSecretNewline(string(raw))
	if value == "" {
		return "", &SecretError{Path: path, Reason: SecretReasonEmpty}
	}
	return value, nil
}

// openSecretFile opens the path and makes sure what it opened is a secret
// and not something else that was put in its place: the checks run on the
// descriptor, so the file that was inspected is the file that is read.
func openSecretFile(path string) (*os.File, error) {
	// The Lstat comes first for two reasons: the refusal has to name the
	// symlink rather than whatever it points at, and a named pipe would
	// otherwise hold the open until somebody writes to it.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, &SecretError{Path: path, Reason: SecretReasonUnreadable, cause: err}
	}
	if kind := irregularKind(info.Mode()); kind != "" {
		return nil, &SecretError{Path: path, Reason: SecretReasonNotRegular, Detail: kind}
	}
	// O_NOFOLLOW and O_NONBLOCK close the window between the Lstat and the
	// open: if the path became a link or a pipe in the meantime, the open
	// fails or returns at once instead of following it or blocking.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &SecretError{Path: path, Reason: SecretReasonUnreadable, cause: err}
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, &SecretError{Path: path, Reason: SecretReasonUnreadable, cause: err}
	}
	if kind := irregularKind(opened.Mode()); kind != "" {
		file.Close()
		return nil, &SecretError{Path: path, Reason: SecretReasonNotRegular, Detail: kind}
	}
	// A secret the group or others may touch is a secret of the whole
	// machine: reading it is the leak, writing it is worse, so both are
	// refused rather than reported.
	perm := opened.Mode().Perm()
	if perm&0o077 != 0 {
		file.Close()
		return nil, &SecretError{
			Path:   path,
			Reason: SecretReasonExposed,
			Detail: fmt.Sprintf("%04o", perm),
		}
	}
	if stat, ok := opened.Sys().(*syscall.Stat_t); ok {
		// A file somebody else owns is a file somebody else can rewrite
		// whatever its mode says now, because the owner sets the mode.
		if owner := int(stat.Uid); owner != 0 && owner != os.Geteuid() {
			file.Close()
			return nil, &SecretError{
				Path:   path,
				Reason: SecretReasonForeignOwner,
				Detail: strconv.Itoa(owner),
			}
		}
	}
	if size := opened.Size(); size > maxSecretFileSize {
		file.Close()
		return nil, &SecretError{
			Path:   path,
			Reason: SecretReasonTooLarge,
			Detail: fmt.Sprintf("%d bytes", size),
		}
	}
	return file, nil
}

// irregularKind names what the path is when it is not a regular file, and
// returns an empty string for a regular one.
func irregularKind(mode os.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "a symlink"
	case mode.IsDir():
		return "a directory"
	case mode&os.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&os.ModeSocket != 0:
		return "a socket"
	case mode&os.ModeDevice != 0:
		return "a device"
	case !mode.IsRegular():
		return "of an unsupported kind"
	}
	return ""
}

// trimSecretNewline removes the single newline an editor or a here-document
// leaves at the end of a secret file, and nothing else. TrimSpace would hand
// the caller a different value than the one the operator mounted: a password
// may legitimately begin or end with a space, and a generated key may end
// with several newlines that belong to it.
func trimSecretNewline(value string) string {
	if !strings.HasSuffix(value, "\n") {
		return value
	}
	value = strings.TrimSuffix(value, "\n")
	// A file written on Windows ends the line with CR LF, and the CR
	// belongs to the line ending. A lone CR without a newline after it is
	// left alone, because then it is a byte of the value.
	return strings.TrimSuffix(value, "\r")
}

// withSecretName puts the name of the variable on a refusal that was raised
// about a bare path, so the operator reads which setting sent the panel to
// that file.
func withSecretName(name string, err error) error {
	var refusal *SecretError
	if errors.As(err, &refusal) {
		named := *refusal
		named.Name = name
		return &named
	}
	return err
}
