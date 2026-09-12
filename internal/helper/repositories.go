package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	filesmodul "github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/packages"
)

// applyRepository writes or removes a package source.
//
// The order here is the same as with certificates and for the same reason:
// everything that can be checked without touching the disk is checked before
// the first write, the previous content is kept in memory, and if the metadata
// of the new source cannot be fetched - the state from before the change comes
// back. A source that does not answer would block every next package operation
// on this host.
func (s *Server) applyRepository(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.RepositoryRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 10 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	manager, err := packages.Detect()
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	managerName := manager.Name()

	repo := packages.Repository{
		ID: action.GetId(), Name: action.GetName(), URL: action.GetUrl(),
		Suites: action.GetSuites(), Components: action.GetComponents(),
		Architectures: action.GetArchitectures(), Enabled: action.GetEnabled(),
		Priority: int(action.GetPriority()), Signed: !action.GetAllowUnsigned(),
		Username: action.GetUsername(), SecretName: action.GetSecretName(),
	}
	if action.GetRemove() {
		repo.URL = ""
	}
	if err := packages.ValidateRepository(repo, managerName,
		len(action.GetPassword()) > 0); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	// The lock is not worked around: writing a source ends with a metadata
	// refresh, and two operations on the same package database can damage it.
	if held, path := manager.LockHeld(); held {
		return reject(packages.ErrorLocked, "the package manager is busy: "+path)
	}

	// The key is checked before the write: it decides whose packages the host
	// will install. The fingerprint comes back in the result so that a human has
	// something to compare with the fingerprint given by the vendor.
	fingerprint := ""
	if !action.GetRemove() && repo.Signed {
		fingerprint, err = packages.KeyFingerprint(action.GetGpgKey())
		if err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		repo.GPGKeyFingerprint = fingerprint
	}

	paths := packages.SourcePaths(repo.ID, managerName)
	copies := make([]fileCopy, 0, len(paths))
	for _, path := range paths {
		saved, err := rememberFile(path)
		if err != nil {
			return reject(ErrorExecFailed, "the previous state was not read: "+err.Error())
		}
		copies = append(copies, saved)
	}
	undo := func() bool {
		succeeded := true
		for _, saved := range copies {
			if err := saved.restore(); err != nil {
				succeeded = false
			}
		}
		return succeeded
	}

	if action.GetRemove() {
		for _, path := range paths {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				undo()
				return reject(ErrorExecFailed, path+" was not removed: "+err.Error())
			}
		}
		return repositoryResponse(s, managerName, "the source "+repo.ID+" was removed", "", false)
	}

	files, err := packages.SourceFiles(repo, managerName, action.GetGpgKey(), action.GetPassword())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	var sourcePath string
	for _, file := range files {
		if err := os.MkdirAll(filepath.Dir(file.Path), 0o755); err != nil {
			undo()
			return reject(ErrorExecFailed, err.Error())
		}
		if err := filesmodul.ZapiszAtomowo(file.Path, file.Content, file.Mode, -1, -1); err != nil {
			undo()
			// The message carries the path, never the content: one of these
			// files holds a password.
			return reject(ErrorExecFailed, file.Path+" was not written: "+err.Error())
		}
		if filepath.Dir(file.Path) == packages.APTSourcesDir ||
			filepath.Dir(file.Path) == packages.DNFSourcesDir {
			sourcePath = file.Path
		}
	}

	// A write does not mean an effect: the manager is asked whether anything can
	// be fetched from this source. A disabled source is skipped - there is
	// nothing to fetch.
	message := "the source " + repo.ID + " was written"
	if repo.Enabled {
		if err := packages.RefreshSource(actionCtx, managerName, repo.ID, sourcePath); err != nil {
			undone := undo()
			reason := "the source metadata could not be fetched: " + err.Error()
			if undone {
				reason += "; the previous state was restored"
			} else {
				reason += "; the previous state was NOT restored"
			}
			return &helperv1.HelperResponse{
				Accepted:  false,
				ErrorCode: ErrorPreconditionFailed,
				Message:   reason,
				RepositoryResult: &helperv1.RepositoryResult{
					Message: reason, GpgKeyFingerprint: fingerprint, RolledBack: undone,
				},
			}
		}
		message += "; the metadata was fetched"
	} else {
		message += "; the source is disabled, so no metadata was fetched"
	}
	return repositoryResponse(s, managerName, message, fingerprint, false)
}

// repositoryResponse assembles the result together with the picture of the
// sources after the change.
func repositoryResponse(s *Server, manager, message, fingerprint string, undone bool) *helperv1.HelperResponse {
	snapshot := packages.ReadRepositories(manager)
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		RepositoryResult: &helperv1.RepositoryResult{
			Snapshot: encoded, Message: message,
			GpgKeyFingerprint: fingerprint, RolledBack: undone,
		},
	}
}

// fileCopy holds the previous content of a file for the duration of an
// operation.
//
// In memory and not next to the file: one of these files carries a password,
// and a copy next to it would stay on the disk also after a successful change.
type fileCopy struct {
	path     string
	existed  bool
	content  []byte
	mode     os.FileMode
	uid, gid int
}

func rememberFile(path string) (fileCopy, error) {
	saved := fileCopy{path: path, mode: 0o644, uid: -1, gid: -1}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return saved, nil
	}
	if err != nil {
		return saved, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return saved, err
	}
	saved.existed = true
	saved.content = data
	saved.mode = info.Mode().Perm()
	return saved, nil
}

// restore goes back to the remembered content of the file.
func (c fileCopy) restore() error {
	if !c.existed {
		if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return filesmodul.ZapiszAtomowo(c.path, c.content, c.mode, c.uid, c.gid)
}
