package helper

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/accounts"
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

	// The key files are read one account after another; the limit of the
	// order binds the whole read.
	ctx, cancel := deadline(ctx, request, 2*time.Minute, 10*time.Minute)
	defer cancel()

	shadow, err := shadowReader()
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
			detail.ExpiresAt = state.expiresAt
		}
		if ctx.Err() != nil {
			problems = append(problems, "the read ran out of time")
			result.Accounts = append(result.Accounts, detail)
			break
		}
		keys, keyErr := readAuthorizedKeys(name)
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
	// expiresAt is the account expiry date as YYYY-MM-DD; empty means no
	// expiry.
	expiresAt string
}

// readShadowStates reads the password state of the accounts. The password
// hashes never leave the file: all that matters is whether a password exists
// and whether it is locked.
func readShadowStates() (map[string]shadowState, error) {
	return parseShadow("/etc/shadow")
}

// shadowReader is the read the handlers use; a test replaces it, because
// the machine running the tests has no account of the test's in its
// shadow file.
var shadowReader = readShadowStates

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
		// The eighth field is the expiry as days since the epoch. Empty
		// means no expiry; the panel shows a date, not a day count.
		if len(fields) >= 8 {
			state.expiresAt = expiryDate(fields[7])
		}
		states[fields[0]] = state
	}
	return states, scanner.Err()
}

// expiryDate turns the shadow day count into a calendar date. A value that
// is not a day count - empty, negative, garbage - means no expiry.
func expiryDate(field string) string {
	days, err := strconv.ParseInt(strings.TrimSpace(field), 10, 64)
	if err != nil || days < 0 {
		return ""
	}
	return time.Unix(0, 0).UTC().AddDate(0, 0, int(days)).Format("2006-01-02")
}

// The sources of a key, as the panel names them.
const (
	keySourceUserFile = "authorized_keys"
	keySourceManaged  = "managed"
)

// readAuthorizedKeys returns the fingerprints of the public keys of an
// account: the user's own authorized_keys and the panel's managed file,
// each key with the source it came from. The key content itself is not
// returned: the fingerprint is enough to identify it.
//
// The files are read without following a link anywhere on the way and
// parsed here rather than handed to ssh-keygen by path: the helper runs as
// root, and a link planted as ~/.ssh would otherwise make it read somebody
// else's file.
func readAuthorizedKeys(name string) ([]*helperv1.LocalSSHKey, error) {
	home, err := homeDirectory(name)
	if err != nil {
		return nil, err
	}
	content, err := readAuthorizedKeysFile(home)
	if err != nil {
		// A file the helper cannot see is something other than an account
		// without keys. Silently returning an empty list would tell the panel
		// that the account has no access, while the state simply could not be
		// determined.
		return nil, err
	}
	// A missing file is a normal state, not an error; the parser takes it
	// as a file with no lines.
	keys := parseAuthorizedKeys(content)
	managed, err := readManagedKeysFile(name)
	if err != nil {
		return keys, err
	}
	for _, key := range accounts.ParseKeyFile(managed) {
		if key.Fingerprint == "" {
			continue
		}
		keys = append(keys, &helperv1.LocalSSHKey{
			Fingerprint: key.Fingerprint, Type: key.Type, Comment: key.Comment, Source: keySourceManaged,
		})
	}
	return keys, nil
}

// parseAuthorizedKeys turns the lines of the user's key file into
// fingerprints. Lines that are not a key - comments, options without
// material, damaged entries - are skipped: they grant no access, so they
// are not reported as one.
func parseAuthorizedKeys(content []byte) []*helperv1.LocalSSHKey {
	var keys []*helperv1.LocalSSHKey
	for _, line := range accounts.ParseKeyFile(content) {
		if line.Fingerprint == "" {
			continue
		}
		keys = append(keys, &helperv1.LocalSSHKey{
			Fingerprint: line.Fingerprint, Type: line.Type, Comment: line.Comment, Source: keySourceUserFile,
		})
	}
	return keys
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
