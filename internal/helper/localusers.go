package helper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
)

// readLocalAccounts reads the account data that needs root: the lock state
// from /etc/shadow and the SSH keys from the home directories.
//
// The agent has no access to these files and should have none: /etc/shadow
// holds password hashes, and the home directories belong to the users.
func (s *Server) readLocalAccounts(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.LocalAccountsRequest) *helperv1.HelperResponse {
	result := &helperv1.LocalAccountsResult{}
	var problems []string

	shadow, err := readShadowStates()
	if err != nil {
		problems = append(problems, "shadow: "+err.Error())
	}

	for _, name := range action.GetNames() {
		if !localUserNamePattern.MatchString(name) {
			continue
		}
		detail := &helperv1.LocalAccountDetail{Name: name}
		if state, known := shadow[name]; known {
			locked, password := state.locked, state.passwordSet
			detail.Locked = &locked
			detail.PasswordSet = &password
		}
		keys, keyErr := readAuthorizedKeys(ctx, name)
		if keyErr != nil {
			problems = append(problems, name+": "+keyErr.Error())
		}
		detail.SshKeys = keys
		result.Accounts = append(result.Accounts, detail)
	}

	if len(problems) > 0 {
		// Missing parts of the data are reported and not passed over in silence:
		// an empty result would look like an account without keys.
		result.UnavailableReason = strings.Join(problems, "; ")
	}
	s.log.Debug("the local accounts were read",
		"task_id", request.GetTaskId(), "accounts", len(result.Accounts))
	return &helperv1.HelperResponse{Accepted: true, AccountsResult: result}
}

// shadowState describes the state of password authentication. A lock and a
// missing password are two different states: an account created by the panel
// has no password but is not cut off, because it logs in with an SSH key.
type shadowState struct {
	locked      bool
	passwordSet bool
}

// readShadowStates reads the password state of the accounts. The password
// hashes never leave the file: all that matters is whether a password exists
// and whether it is locked.
func readShadowStates() (map[string]shadowState, error) {
	return parseShadow("/etc/shadow")
}

// parseShadow reads the password state from the given file. The path is a
// parameter so that the meaning of the prefixes can be checked without access
// to /etc/shadow.
func parseShadow(path string) (map[string]shadowState, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	states := map[string]shadowState{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		hash := fields[1]
		// The exclamation mark at the start is put there by usermod -L; it is
		// the only marker of an administrative lock. An asterisk means password
		// login is disabled and is the normal state of an account served by an
		// SSH key.
		state := shadowState{locked: strings.HasPrefix(hash, "!")}
		remaining := strings.TrimLeft(hash, "!")
		state.passwordSet = remaining != "" && remaining != "*"
		states[fields[0]] = state
	}
	return states, scanner.Err()
}

// readAuthorizedKeys returns the fingerprints of the public keys of an
// account. The key content itself is not returned: the fingerprint is enough
// to identify it.
func readAuthorizedKeys(ctx context.Context, name string) ([]*helperv1.LocalSSHKey, error) {
	home, err := homeDirectory(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".ssh", "authorized_keys")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A missing file is a normal state, not an error.
			return nil, nil
		}
		// A file the helper cannot see is something other than an account
		// without keys. Silently returning an empty list would tell the panel
		// that the account has no access, while the state simply could not be
		// determined.
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	stdout, _, err := runIdentityTool(ctx, 15*time.Second, "ssh-keygen", "-l", "-f", path)
	if err != nil {
		return nil, fmt.Errorf("reading the keys: %v", err)
	}

	var keys []*helperv1.LocalSSHKey
	for _, line := range strings.Split(stdout, "\n") {
		// Format: <bits> <fingerprint> <comment> (<type>)
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		keyType := strings.Trim(fields[len(fields)-1], "()")
		comment := strings.Join(fields[2:len(fields)-1], " ")
		keys = append(keys, &helperv1.LocalSSHKey{
			Fingerprint: fields[1], Type: keyType, Comment: comment,
		})
	}
	return keys, nil
}

func homeDirectory(name string) (string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 6 && fields[0] == name {
			return fields[5], nil
		}
	}
	return "", fmt.Errorf("the account has no entry in /etc/passwd")
}
