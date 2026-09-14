package ctl

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ReadToken takes an enrollment token without leaving it in the arguments
// or in the environment of the process.
//
// Every user of the machine sees a command line argument in the process
// list, and an environment variable stays in the file of the service. What
// is left is a file with narrowed permissions, a pipe or a question with
// the echo turned off.
func ReadToken(path string, in_ io.Reader, errOut io.Writer) ([]byte, error) {
	if path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSpace(content), nil
	}
	if file, ok := in_.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprint(errOut, "Enrollment token: ")
		value, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(errOut)
		return bytes.TrimSpace(value), err
	}
	content, err := io.ReadAll(io.LimitReader(in_, 4096))
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(content), nil
}

// Wipe overwrites a secret in memory.
//
// Without illusions: the runtime and the kernel may hold copies of their
// own, and the only real protection is a short validity, a single use and a
// revocation after the registration. This is cleaning up after oneself
// rather than a guarantee.
func Wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
