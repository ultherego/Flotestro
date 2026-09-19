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

// MarkerFile is the name of the marker in the state directory. It sits next
// to ca.pem and keys/ because it describes exactly that set of files.
const MarkerFile = "installation.id"

// Stranger names which half of the pair the refusal blames: the one that does
// not belong to the installation the other one describes.
type Stranger string

const (
	// StrangerStateDirectory: the database describes the installation and
	// the state directory is another one's, or nobody's.
	StrangerStateDirectory Stranger = "state_directory"
	// StrangerDatabase: the state directory belongs to an installation and the
	// database does not describe it - an empty or a foreign database under a
	// directory that has a history.
	StrangerDatabase Stranger = "database"
)

// MarkerPath is where the marker of a state directory lives.
func MarkerPath(dir string) string { return filepath.Join(dir, MarkerFile) }

// readMarker returns the installation the state directory belongs to.
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
		// Not treated as "no marker": a file that is there and says nothing is a
		// truncated write or an edit by hand, and guessing that the directory is
		// fresh is how material gets created over an installation that exists.
		return "", fmt.Errorf("%s is empty; it names the installation this state directory belongs to, "+
			"and an empty one cannot be told from a directory of another installation", MarkerPath(dir))
	}
	return id, nil
}

// writeMarker names the installation of the state directory.
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
