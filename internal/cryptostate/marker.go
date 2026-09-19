package cryptostate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The state directory says which installation it belongs to.
//
// The database and the state directory are one inseparable set: the row of
// crypto_installation_state names the key that opens the secrets and the CA
// that issues the certificates, and the files that are those two live in the
// directory. Until now only the database could say which installation it
// described; the directory said nothing, and so a directory could be paired
// with any database at all and the mismatch was found - if at all - as a key
// that does not open a sentinel.
//
// That is the shape of the deployment mistake the containerisation document
// forbids in chapter 21: a second control plane started with a state volume
// of its own against the database of the first. The second one finds an
// empty directory, and every reaction but refusing is wrong - a control
// plane that made itself a key and a CA there would be a second certificate
// authority and a second secret store key for one installation, and the
// fleet would split slowly and silently.
//
// The marker is the directory's half of the pair. It is written once, when
// the installation is created or when a directory from before the marker
// passes every other check, and it is compared at every start afterwards.
// Comparing two identifiers is what lets the refusal name which of the two
// is the stranger, which is the only thing an operator needs to know before
// deciding whether to restore the directory or to repoint the database.

// MarkerFile is the name of the marker in the state directory. It sits next
// to ca.pem and keys/ because it describes exactly that set of files.
const MarkerFile = "installation.id"

// Stranger names which half of the pair the refusal blames: the one that
// does not belong to the installation the other one describes. It is typed
// because the log line, the runbook and the laboratory all branch on it, and
// a sentence they have to parse is not a contract.
type Stranger string

const (
	// StrangerStateDirectory: the database describes the installation and
	// the state directory is another one's, or nobody's.
	StrangerStateDirectory Stranger = "state_directory"
	// StrangerDatabase: the state directory belongs to an installation and
	// the database does not describe it - an empty or a foreign database
	// under a directory that has a history.
	StrangerDatabase Stranger = "database"
)

// MarkerPath is where the marker of a state directory lives.
func MarkerPath(dir string) string { return filepath.Join(dir, MarkerFile) }

// readMarker returns the installation the state directory belongs to. An
// empty string means the directory carries no marker at all, which is either
// a directory that has never held an installation or one from before the
// marker existed; the two are told apart by what else is in the directory.
func readMarker(dir string) (string, error) {
	data, err := os.ReadFile(MarkerPath(dir))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", MarkerPath(dir), err)
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		// Not treated as "no marker": a file that is there and says nothing
		// is a truncated write or an edit by hand, and guessing that the
		// directory is fresh is how material gets created over an
		// installation that exists.
		return "", fmt.Errorf("%s is empty; it names the installation this state directory belongs to, "+
			"and an empty one cannot be told from a directory of another installation", MarkerPath(dir))
	}
	return id, nil
}

// writeMarker names the installation of the state directory. It is written
// through a temporary file and a rename, so a directory never holds half an
// identifier, and the directory is synced afterwards so the name survives
// the power cut that follows the first start.
func writeMarker(dir, installationID string) error {
	if installationID == "" {
		return errors.New("the marker of the state directory needs an installation identifier")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := MarkerPath(dir)
	temporary := path + ".new"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(installationID + "\n"); err != nil {
		file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}
