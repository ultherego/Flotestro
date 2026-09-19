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

// The tools the module changes accounts with. Every one of them comes from
// one package of the distribution - passwd on Debian and Ubuntu,
// shadow-utils on Fedora and RHEL, shadow on Arch - and the agent package
// depends on it, so a host installed from our packages has them all. A host
// that lost them keeps the module: reading the accounts needs nothing but
// NSS and /etc/shadow, and only the mutation that uses the missing tool is
// gone.
const (
	toolUseradd = "useradd"
	toolUsermod = "usermod"
	toolUserdel = "userdel"
	toolChage   = "chage"
)

// LocalAccountTools are the tools the mutations of the module need.
var LocalAccountTools = []string{toolUseradd, toolUsermod, toolUserdel, toolChage}

// LocalAccountToolsPackage names what restores them. The panel shows the
// name of a package rather than the name of a binary, because that is what
// an operator installs; the families name the same tools differently.
const LocalAccountToolsPackage = "passwd on Debian and Ubuntu, shadow-utils on Fedora and RHEL, shadow on Arch"

// accountToolDirectories are the directories the tools are looked for in.
// They are the search path of the runner that starts them, so the capability
// and the operation cannot disagree about what the host has.
var accountToolDirectories = []string{"/usr/bin", "/usr/sbin", "/sbin"}

// accountToolPresent says whether the host has the tool. It is a variable so
// a test can answer for a host it is not running on; nothing is started, as
// the capability registry must not run a process to find out what is there.
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

// The features of the local account capability. One feature is one operation
// of the panel, because one missing tool takes away one operation and not
// the module: a host without chage still creates and locks accounts.
const (
	FeatureAccountCreate  = "create"
	FeatureAccountLock    = "lock"
	FeatureAccountGroups  = "groups"
	FeatureAccountExpiry  = "expiry"
	FeatureAccountDelete  = "delete"
	FeatureAccountSSHKeys = "sshkeys"
)

// LocalAccountFeatures says which operations of the module this host can
// carry out. The keys are written by the helper itself into the file of the
// account, so they need no tool of the distribution and are there wherever
// the module is.
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

// LocalAccountsReason explains what the module cannot do here. A host with
// every tool gets no sentence: the reason exists to name the missing tool
// and the package that brings it back, and the panel shows it next to the
// operations it has hidden.
func LocalAccountsReason() string {
	missing := MissingLocalAccountTools()
	if len(missing) == 0 {
		return ""
	}
	return "this host has no " + strings.Join(missing, ", ") +
		", so the accounts can be read and not changed here; install " + LocalAccountToolsPackage
}
