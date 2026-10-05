package accounts

import (
	"path"
	"strings"
)

// The file the panel manages apart from the user's own authorized_keys. A key
// the panel puts into ~/.
const (
	ManagedKeysDir      = "/etc/ssh/authorized_keys.d"
	ManagedKeysFileName = "60-flotestro.keys"
	// ManagedKeysPattern is the AuthorizedKeysFile entry sshd has to carry
	// for the managed file to be read at all.
	ManagedKeysPattern = ManagedKeysDir + "/%u/" + ManagedKeysFileName
	// HomeKeysPath is the account's own key file, as AuthorizedKeysFile names
	// it relative to the home directory.
	HomeKeysPath = ".ssh/authorized_keys"
)

// ManagedKeysPath returns the managed file of one account.
func ManagedKeysPath(account string) string {
	return path.Join(ManagedKeysDir, account, ManagedKeysFileName)
}

// ManagedFileReadBySSHD says whether the effective sshd configuration (the
// output of sshd -T) lists the managed file among the files it reads keys
// from.
func ManagedFileReadBySSHD(effective string) bool {
	for _, line := range strings.Split(effective, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "authorizedkeysfile") {
			continue
		}
		for _, file := range fields[1:] {
			if file == ManagedKeysPattern {
				return true
			}
		}
	}
	return false
}

// HomeFileReadBySSHD says whether the effective sshd configuration reads the
// account's own ~/.ssh/authorized_keys, and whether the configuration said
// anything about the matter at all. An AuthorizedKeysFile naming only the
// managed pattern leaves the home file unread, so the keys in it are no way
// into the account.
func HomeFileReadBySSHD(effective string) (reads, stated bool) {
	for _, line := range strings.Split(effective, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "authorizedkeysfile") {
			continue
		}
		stated = true
		for _, file := range fields[1:] {
			if homeAuthorizedKeys(file) {
				return true, true
			}
		}
	}
	return false, stated
}

// homeAuthorizedKeys says whether one AuthorizedKeysFile entry resolves to the
// account's own key file: a relative path, or the same path under %h.
func homeAuthorizedKeys(entry string) bool {
	entry = strings.TrimPrefix(entry, "%h/")
	if entry == "" || strings.HasPrefix(entry, "/") {
		return false
	}
	return path.Clean(entry) == HomeKeysPath
}
