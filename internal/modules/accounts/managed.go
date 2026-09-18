package accounts

import (
	"path"
	"strings"
)

// The file the panel manages apart from the user's own authorized_keys.
//
// A key the panel puts into ~/.ssh/authorized_keys sits next to keys the
// user added by hand, and the two histories blur. An installation that
// wants the panel's keys apart points sshd at a second file under a
// root-owned directory: the user cannot edit it, the panel edits nothing
// else, and a replace there touches nothing the user wrote. sshd expands
// %u to the account name, so the file has a directory per account.
const (
	ManagedKeysDir      = "/etc/ssh/authorized_keys.d"
	ManagedKeysFileName = "60-flotestro.keys"
	// ManagedKeysPattern is the AuthorizedKeysFile entry sshd has to carry
	// for the managed file to be read at all.
	ManagedKeysPattern = ManagedKeysDir + "/%u/" + ManagedKeysFileName
)

// ManagedKeysPath returns the managed file of one account.
func ManagedKeysPath(account string) string {
	return path.Join(ManagedKeysDir, account, ManagedKeysFileName)
}

// ManagedFileReadBySSHD says whether the effective sshd configuration
// (the output of sshd -T) lists the managed file among the files it reads
// keys from. A managed file sshd never opens grants nothing; writing keys
// there and reporting them as access would be the panel lying about what
// the host does.
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
