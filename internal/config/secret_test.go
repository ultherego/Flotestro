package config

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// writeSecretFile puts a value into a file of the temporary directory with
// the mode a mounted secret has.
func writeSecretFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("the secret file could not be written: %v", err)
	}
	// The umask of the environment running the tests must not decide what
	// the check sees, so the mode is set explicitly.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("the mode of the secret file could not be set: %v", err)
	}
	return path
}

// refusal asserts that the error is a refusal of this contract with the
// expected reason, and returns it.
func refusal(t *testing.T, err error, reason SecretReason) *SecretError {
	t.Helper()
	if err == nil {
		t.Fatalf("the secret was accepted although %s was expected", reason)
	}
	var refused *SecretError
	if !errors.As(err, &refused) {
		t.Fatalf("the refusal is not a *SecretError: %v", err)
	}
	if refused.Reason != reason {
		t.Fatalf("the reason is %q rather than %q: %v", refused.Reason, reason, err)
	}
	return refused
}

func TestSecretValueFromEnvironment(t *testing.T) {
	// A password may begin and end with a space, and the environment form
	// hands over exactly what was set.
	t.Setenv("FLOTESTRO_TEST_SECRET", "  with spaces  ")
	value, err := SecretValue("FLOTESTRO_TEST_SECRET")
	if err != nil {
		t.Fatalf("the secret was refused: %v", err)
	}
	if value != "  with spaces  " {
		t.Fatalf("the value is %q rather than the one that was set", value)
	}
}

func TestSecretValueRefusesBothForms(t *testing.T) {
	path := writeSecretFile(t, "secret", "from-the-file\n")
	t.Setenv("FLOTESTRO_TEST_SECRET", "from-the-environment")
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", path)

	_, err := SecretValue("FLOTESTRO_TEST_SECRET")
	refused := refusal(t, err, SecretReasonConflict)
	if !strings.Contains(refused.Error(), "FLOTESTRO_TEST_SECRET and FLOTESTRO_TEST_SECRET_FILE") {
		t.Fatalf("the refusal does not name both forms: %v", err)
	}
	if strings.Contains(refused.Error(), "from-the-environment") || strings.Contains(refused.Error(), "from-the-file") {
		t.Fatalf("the refusal carries a value: %v", err)
	}
	if errors.Is(err, ErrSecretMissing) {
		t.Fatal("a conflict must not read as a missing secret")
	}
}

func TestSecretValueRefusesEmptyVariable(t *testing.T) {
	t.Setenv("FLOTESTRO_TEST_SECRET", "")
	_, err := SecretValue("FLOTESTRO_TEST_SECRET")
	refusal(t, err, SecretReasonEmpty)
	// An empty variable is a mistake in the configuration, not an absent
	// secret: the caller must not fall back to "the feature is off".
	if errors.Is(err, ErrSecretMissing) {
		t.Fatal("an empty variable must not read as a missing secret")
	}
}

func TestSecretValueMissingIsTypedAndOptional(t *testing.T) {
	_, err := SecretValue("FLOTESTRO_TEST_ABSENT_SECRET")
	refusal(t, err, SecretReasonMissing)
	if !errors.Is(err, ErrSecretMissing) {
		t.Fatalf("a missing secret has to wrap ErrSecretMissing: %v", err)
	}
	value, err := OptionalSecretValue("FLOTESTRO_TEST_ABSENT_SECRET")
	if err != nil || value != "" {
		t.Fatalf("an optional secret that is absent has to come back empty and without an error: %q, %v", value, err)
	}
	if SecretConfigured("FLOTESTRO_TEST_ABSENT_SECRET") {
		t.Fatal("an absent secret must not read as configured")
	}
}

func TestSecretValueEmptyFileVariableIsMissing(t *testing.T) {
	// Setting the file form to nothing names no file, which is the same
	// statement as not setting it at all.
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", "")
	_, err := SecretValue("FLOTESTRO_TEST_SECRET")
	refusal(t, err, SecretReasonMissing)
	if SecretConfigured("FLOTESTRO_TEST_SECRET") {
		t.Fatal("an empty file variable must not read as configured")
	}
}

func TestSecretConfigured(t *testing.T) {
	t.Setenv("FLOTESTRO_TEST_SECRET", "value")
	if !SecretConfigured("FLOTESTRO_TEST_SECRET") {
		t.Fatal("the environment form has to read as configured")
	}
	t.Setenv("FLOTESTRO_TEST_SECRET", "")
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", "/run/secrets/test")
	if !SecretConfigured("FLOTESTRO_TEST_SECRET") {
		t.Fatal("the file form has to read as configured")
	}
}

func TestSecretValueNewlineRule(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{name: "a single newline is removed", content: "s3cr3t\n", want: "s3cr3t"},
		{name: "the carriage return of a CR LF ending goes with it", content: "s3cr3t\r\n", want: "s3cr3t"},
		{name: "only the last newline is removed", content: "s3cr3t\n\n", want: "s3cr3t\n"},
		{name: "a file without a newline is taken whole", content: "s3cr3t", want: "s3cr3t"},
		{name: "the spaces of a password survive", content: "  pass word  \n", want: "  pass word  "},
		{name: "a lone carriage return belongs to the value", content: "s3cr3t\r", want: "s3cr3t\r"},
		{name: "an inner newline is untouched", content: "first\nsecond\n", want: "first\nsecond"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := writeSecretFile(t, "secret", testCase.content)
			t.Setenv("FLOTESTRO_TEST_SECRET_FILE", path)
			value, err := SecretValue("FLOTESTRO_TEST_SECRET")
			if err != nil {
				t.Fatalf("the secret was refused: %v", err)
			}
			if value != testCase.want {
				t.Fatalf("the value is %q rather than %q", value, testCase.want)
			}
		})
	}
}

func TestSecretValueRefusesEmptyFile(t *testing.T) {
	for _, content := range []string{"", "\n", "\r\n"} {
		path := writeSecretFile(t, "secret", content)
		t.Setenv("FLOTESTRO_TEST_SECRET_FILE", path)
		_, err := SecretValue("FLOTESTRO_TEST_SECRET")
		refusal(t, err, SecretReasonEmpty)
	}
}

func TestSecretValueRefusesSymlink(t *testing.T) {
	target := writeSecretFile(t, "secret", "s3cr3t\n")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("the symlink could not be created: %v", err)
	}
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", link)

	_, err := SecretValue("FLOTESTRO_TEST_SECRET")
	refused := refusal(t, err, SecretReasonNotRegular)
	if !strings.Contains(refused.Error(), "a symlink") {
		t.Fatalf("the refusal does not say it was a symlink: %v", err)
	}
	if !strings.Contains(refused.Error(), "FLOTESTRO_TEST_SECRET_FILE") {
		t.Fatalf("the refusal does not name the variable: %v", err)
	}
}

func TestSecretValueRefusesNamedPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("the named pipe could not be created: %v", err)
	}
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", path)

	// A pipe would also hold the start of the panel until somebody writes
	// to it, which is why it is refused before it is opened.
	_, err := SecretValue("FLOTESTRO_TEST_SECRET")
	refused := refusal(t, err, SecretReasonNotRegular)
	if !strings.Contains(refused.Error(), "a named pipe") {
		t.Fatalf("the refusal does not say it was a named pipe: %v", err)
	}
}

func TestSecretValueRefusesDirectory(t *testing.T) {
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", t.TempDir())
	_, err := SecretValue("FLOTESTRO_TEST_SECRET")
	refused := refusal(t, err, SecretReasonNotRegular)
	if !strings.Contains(refused.Error(), "a directory") {
		t.Fatalf("the refusal does not say it was a directory: %v", err)
	}
}

func TestSecretValueRefusesSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socket")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("a unix socket could not be created here: %v", err)
	}
	defer listener.Close()
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", path)

	_, err = SecretValue("FLOTESTRO_TEST_SECRET")
	refused := refusal(t, err, SecretReasonNotRegular)
	if !strings.Contains(refused.Error(), "a socket") {
		t.Fatalf("the refusal does not say it was a socket: %v", err)
	}
}

func TestSecretValueRefusesDevice(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("there is no device to check against here")
	}
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", "/dev/null")
	_, err := SecretValue("FLOTESTRO_TEST_SECRET")
	refused := refusal(t, err, SecretReasonNotRegular)
	if !strings.Contains(refused.Error(), "a device") {
		t.Fatalf("the refusal does not say it was a device: %v", err)
	}
}

func TestSecretValueRefusesFileReadableByOthers(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o606} {
		path := writeSecretFile(t, "secret", "s3cr3t\n")
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("the mode could not be set: %v", err)
		}
		t.Setenv("FLOTESTRO_TEST_SECRET_FILE", path)

		_, err := SecretValue("FLOTESTRO_TEST_SECRET")
		refused := refusal(t, err, SecretReasonExposed)
		if !strings.Contains(refused.Error(), "readable by the group or by others") {
			t.Fatalf("the refusal does not say what was wrong with the mode: %v", err)
		}
		if strings.Contains(refused.Error(), "s3cr3t") {
			t.Fatalf("the refusal carries the value: %v", err)
		}
	}
}

func TestSecretValueAcceptsNarrowModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		path := writeSecretFile(t, "secret", "s3cr3t\n")
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("the mode could not be set: %v", err)
		}
		t.Setenv("FLOTESTRO_TEST_SECRET_FILE", path)

		value, err := SecretValue("FLOTESTRO_TEST_SECRET")
		if err != nil {
			t.Fatalf("mode %04o was refused: %v", mode, err)
		}
		if value != "s3cr3t" {
			t.Fatalf("the value is %q rather than the one in the file", value)
		}
	}
}

func TestSecretValueRefusesFileOverTheLimit(t *testing.T) {
	path := writeSecretFile(t, "secret", strings.Repeat("a", maxSecretFileSize+1))
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", path)

	_, err := SecretValue("FLOTESTRO_TEST_SECRET")
	refused := refusal(t, err, SecretReasonTooLarge)
	if !strings.Contains(refused.Error(), "64 KiB") {
		t.Fatalf("the refusal does not name the limit: %v", err)
	}

	// Exactly at the limit is a secret, not a mistake.
	atTheLimit := writeSecretFile(t, "at-the-limit", strings.Repeat("a", maxSecretFileSize))
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", atTheLimit)
	value, err := SecretValue("FLOTESTRO_TEST_SECRET")
	if err != nil {
		t.Fatalf("a file of exactly the limit was refused: %v", err)
	}
	if len(value) != maxSecretFileSize {
		t.Fatalf("the value is %d bytes rather than %d", len(value), maxSecretFileSize)
	}
}

func TestSecretValueRefusesAbsentFile(t *testing.T) {
	t.Setenv("FLOTESTRO_TEST_SECRET_FILE", filepath.Join(t.TempDir(), "nothing-here"))
	_, err := SecretValue("FLOTESTRO_TEST_SECRET")
	refusal(t, err, SecretReasonUnreadable)
	// A mount that is not there is a broken installation, not an absent
	// optional secret: the optional form has to refuse it too.
	if errors.Is(err, ErrSecretMissing) {
		t.Fatal("an unreadable file must not read as a missing secret")
	}
	if _, err := OptionalSecretValue("FLOTESTRO_TEST_SECRET"); err == nil {
		t.Fatal("the optional form accepted a file that cannot be read")
	}
}

func TestCheckSecretFile(t *testing.T) {
	path := writeSecretFile(t, "keytab", "binary keytab bytes")
	if err := CheckSecretFile(path); err != nil {
		t.Fatalf("a keytab with a narrow mode was refused: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("the mode could not be set: %v", err)
	}
	err := CheckSecretFile(path)
	refused := refusal(t, err, SecretReasonExposed)
	if refused.Name != "" {
		t.Fatalf("a file checked on its own carries no variable name: %q", refused.Name)
	}
	if !strings.Contains(refused.Error(), path) {
		t.Fatalf("the refusal does not name the file: %v", err)
	}
}
