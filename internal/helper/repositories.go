package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	filesmodule "github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/packages"
)

// applyRepository writes or removes a package source.
func (s *Server) applyRepository(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.RepositoryRequest) *helperv1.HelperResponse {
	// A source write ends with a metadata refresh on the same package
	// database a transaction uses, so it shares the guard of the packages.
	release, busy := s.hold(GuardPackages, request)
	if busy != nil {
		return busy
	}
	defer release()

	actionCtx, cancel := deadline(ctx, request, 10*time.Minute, 30*time.Minute)
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
	// will install.
	fingerprint := ""
	if !action.GetRemove() && repo.Signed {
		fingerprint, err = packages.KeyFingerprint(action.GetGpgKey())
		if err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		repo.GPGKeyFingerprint = fingerprint
	}

	paths := packages.SourcePaths(repo.ID, managerName)
	// A pacman source is a section of the shared configuration file rather than a
	// file of its own: the file is remembered for the undo like the rest, but it
	// is never removed with the source.
	remembered := paths
	if managerName == packages.PacmanName {
		remembered = append(append([]string{}, paths...), packages.PacmanConfPath)
	}
	copies := make([]fileCopy, 0, len(remembered))
	for _, path := range remembered {
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
		if managerName == packages.PacmanName {
			// The section and the key in the keyring go first, while the key
			// file still says which key that is.
			if err := packages.DropPacmanSource(actionCtx, repo.ID); err != nil {
				undo()
				return reject(ErrorExecFailed, err.Error())
			}
		}
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
		if err := filesmodule.WriteAtomically(file.Path, file.Content, file.Mode, -1, -1); err != nil {
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
	if managerName == packages.PacmanName {
		// The section is edited into pacman.
		if err := packages.WritePacmanSource(actionCtx, repo); err != nil {
			undo()
			return reject(ErrorExecFailed, err.Error())
		}
		sourcePath = packages.PacmanConfPath
	}

	// A write does not mean an effect: the manager is asked whether anything can
	// be fetched from this source.
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
	return filesmodule.WriteAtomically(c.path, c.content, c.mode, c.uid, c.gid)
}
