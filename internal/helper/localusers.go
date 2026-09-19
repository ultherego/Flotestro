package helper

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/accounts"
)

// readLocalAccounts reads the account data that needs root: the lock state
// from /etc/shadow and the SSH keys from the home directories.
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

// shadowState describes the state of password authentication.
type shadowState struct {
	locked      bool
	passwordSet bool
	// expiresAt is the account expiry date as YYYY-MM-DD; empty means no
	// expiry.
	expiresAt string
}

// readShadowStates reads the password state of the accounts.
func readShadowStates() (map[string]shadowState, error) {
	return parseShadow("/etc/shadow")
}

// shadowReader is the read the handlers use; a test replaces it, because the
// machine running the tests has no account of the test's in its shadow file.
var shadowReader = readShadowStates

// parseShadow reads the password state from the given file.
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
		// The exclamation mark at the start is put there by usermod -L; it is the
		// only marker of an administrative lock.
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
// account: the user's own authorized_keys and the panel's managed file, each
// key with the source it came from.
func readAuthorizedKeys(name string) ([]*helperv1.LocalSSHKey, error) {
	home, err := homeDirectory(name)
	if err != nil {
		return nil, err
	}
	content, err := readAuthorizedKeysFile(home)
	if err != nil {
		// A file the helper cannot see is something other than an account without
		// keys.
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
// fingerprints.
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

// The tools the module changes accounts with.
const (
	toolUseradd = "useradd"
	toolUsermod = "usermod"
	toolUserdel = "userdel"
	toolChage   = "chage"
)

// LocalAccountTools are the tools the mutations of the module need.
var LocalAccountTools = []string{toolUseradd, toolUsermod, toolUserdel, toolChage}

// LocalAccountToolsPackage names what restores them.
const LocalAccountToolsPackage = "passwd on Debian and Ubuntu, shadow-utils on Fedora and RHEL, shadow on Arch"

// accountToolDirectories are the directories the tools are looked for in.
var accountToolDirectories = []string{"/usr/bin", "/usr/sbin", "/sbin"}

// accountToolPresent says whether the host has the tool.
var accountToolPresent = func(tool string) bool {
	for _, directory := range accountToolDirectories {
		info, err := os.Stat(filepath.Join(directory, tool))
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

// MissingLocalAccountTools lists the tools of LocalAccountTools this host has
// not got, in the order of the list.
func MissingLocalAccountTools() []string {
	var missing []string
	for _, tool := range LocalAccountTools {
		if !accountToolPresent(tool) {
			missing = append(missing, tool)
		}
	}
	return missing
}

// The features of the local account capability.
const (
	FeatureAccountCreate  = "create"
	FeatureAccountLock    = "lock"
	FeatureAccountGroups  = "groups"
	FeatureAccountExpiry  = "expiry"
	FeatureAccountDelete  = "delete"
	FeatureAccountSSHKeys = "sshkeys"
)

// LocalAccountFeatures says which operations of the module this host can carry
// out.
func LocalAccountFeatures() map[string]bool {
	usermod := accountToolPresent(toolUsermod)
	return map[string]bool{
		FeatureAccountCreate:  accountToolPresent(toolUseradd),
		FeatureAccountLock:    usermod,
		FeatureAccountGroups:  usermod,
		FeatureAccountExpiry:  accountToolPresent(toolChage),
		FeatureAccountDelete:  accountToolPresent(toolUserdel),
		FeatureAccountSSHKeys: true,
	}
}

// LocalAccountsReason explains what the module cannot do here.
func LocalAccountsReason() string {
	missing := MissingLocalAccountTools()
	if len(missing) == 0 {
		return ""
	}
	return "this host has no " + strings.Join(missing, ", ") +
		", so the accounts can be read and not changed here; install " + LocalAccountToolsPackage
}
