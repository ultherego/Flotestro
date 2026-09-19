package ctl

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ReadToken takes an enrollment token without leaving it in the arguments or
// in the environment of the process.
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
func Wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
