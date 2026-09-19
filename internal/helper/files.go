package helper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/config"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/files"

	"golang.org/x/sys/unix"
)

// FileRegistryPath holds the paths the panel has written on this host.
const FileRegistryPath = "/var/lib/flotestro-helper/files.json"

// ErrorValidatorUnavailable means a content check the order relies on that
// this host cannot run: the tool is not installed.
const ErrorValidatorUnavailable = "validator_unavailable"

// ErrorFileVersionUnknown means a rollback to content this host never kept.
const ErrorFileVersionUnknown = "file_version_unknown"

// ErrorFileVersionNotKept means the content about to be replaced could not be
// copied aside.
const ErrorFileVersionNotKept = "file_version_not_kept"

// fileVersionRoot is the store of previous contents.
var fileVersionRoot = files.VersionDir

// fileVersions returns the store of previous contents with the bounds the host
// administrator set.
func fileVersions() files.VersionStore {
	return files.VersionStore{
		Root:        config.Env("FLOTESTRO_HELPER_FILE_VERSION_DIR", fileVersionRoot),
		KeepPerPath: config.EnvInt("FLOTESTRO_HELPER_FILE_VERSIONS", files.DefaultVersionsPerPath),
		MaxBytes:    int64(config.EnvInt("FLOTESTRO_HELPER_FILE_VERSION_BYTES", files.DefaultVersionBytes)),
	}
}

// PermissionFileWriteUnvalidated is the grant that, together with an order
// saying so, lets a file be written when its validator is missing.
const PermissionFileWriteUnvalidated = "file.write.unvalidated"

// allowsMissingValidator says whether an order may go on without its
// validator: the order has to say so and the capability has to carry the
// grant.
func allowsMissingValidator(request *helperv1.HelperRequest, action *helperv1.FileRequest) bool {
	return action.GetAllowMissingValidator() && hasGrant(grantsOf(request), PermissionFileWriteUnvalidated)
}

// errValidatorUnavailable marks a validator whose tool the host lacks.
var errValidatorUnavailable = errors.New("the validator is not installed on this host")

// applyFile handles the operations on configuration files.
func (s *Server) applyFile(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.FileRequest) *helperv1.HelperResponse {
	release, busy := s.hold(fileGuard(action.GetOperation()), request)
	if busy != nil {
		return busy
	}
	defer release()

	actionCtx, cancel := deadline(ctx, request, 5*time.Minute, 30*time.Minute)
	defer cancel()

	allowlist := files.LoadAllowlist(files.AllowlistPath)

	switch action.GetOperation() {
	case helperv1.FileRequest_OPERATION_LIST:
		return fileResponse(s.fileState(), "", nil, "")
	case helperv1.FileRequest_OPERATION_READ:
		return s.readFile(allowlist, action)
	case helperv1.FileRequest_OPERATION_ENSURE:
		return s.writeFile(actionCtx, request, allowlist, action)
	case helperv1.FileRequest_OPERATION_REMOVE:
		return s.removeFile(allowlist, action)
	case helperv1.FileRequest_OPERATION_PLAN:
		return s.planFile(actionCtx, request, allowlist, action)
	}
	return reject(ErrorUnknownAction, "unknown file operation")
}

// fileGuard names the guard of a file operation. A write and a removal both
// rewrite the registry of managed files; a list, a read and a plan only look.
func fileGuard(operation helperv1.FileRequest_Operation) string {
	switch operation {
	case helperv1.FileRequest_OPERATION_ENSURE, helperv1.FileRequest_OPERATION_REMOVE:
		return GuardFiles
	}
	return ""
}

// readFile returns the content of a file within the scope.
func (s *Server) readFile(allowlist files.Allowlist, action *helperv1.FileRequest) *helperv1.HelperResponse {
	if response := checkScope(allowlist, action.GetPath()); response != nil {
		return response
	}
	description := files.Describe(action.GetPath())
	if !description.Exists {
		return reject(ErrorUnsupported, "the file "+action.GetPath()+" does not exist on this host")
	}
	if description.UnavailableReason != "" {
		return reject(ErrorUnsupported, description.UnavailableReason)
	}

	file, err := files.OpenWithoutSymlinks(action.GetPath(), unix.O_RDONLY, 0)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	defer file.Close()

	// One byte more than the boundary is read: otherwise a file exactly at the
	// boundary would look truncated and a bigger one - whole.
	content, err := io.ReadAll(io.LimitReader(file, files.MaxSize+1))
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	truncated := false
	if len(content) > files.MaxSize {
		content = content[:files.MaxSize]
		truncated = true
	}

	response := fileResponse(s.fileState(), "", content, files.Fingerprint(content))
	response.FileResult.Truncated = truncated
	return response
}

// writeFile writes the content of a file.
func (s *Server) writeFile(ctx context.Context, request *helperv1.HelperRequest,
	allowlist files.Allowlist, action *helperv1.FileRequest) *helperv1.HelperResponse {
	path := action.GetPath()
	if response := checkScope(allowlist, path); response != nil {
		return response
	}

	content := action.GetContent()
	requestedMode := action.GetMode()
	owner, group := action.GetOwner(), action.GetGroup()
	var restored *files.KeptVersion
	if digest := action.GetVersionSha256(); digest != "" {
		version, kept, response := s.versionToRestore(path, digest, content)
		if response != nil {
			return response
		}
		restored, content = &version, kept
		// The inode is restored together with the bytes unless the order says
		// otherwise: putting back old content under the permissions of the newer
		// file restores a state that never existed on this host.
		if requestedMode == "" {
			requestedMode = version.Mode
		}
		if owner == "" {
			owner = version.Owner
		}
		if group == "" {
			group = version.Group
		}
	}

	if err := files.ValidateContent(string(content)); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	mode, err := files.ValidateMode(requestedMode)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	uid, gid, err := files.Ownership(owner, group)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	current := files.Describe(path)
	if current.UnavailableReason != "" {
		return reject(ErrorUnsupported, current.UnavailableReason)
	}
	current.FromSecret = s.managedFromSecret(path)
	// A change made after the operator looked at the file must not disappear
	// under a write from the panel.
	if expected := action.GetExpectedSha256(); expected != "" {
		actual, err := fileDigest(path)
		if err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
		if actual != expected {
			return reject(ErrorPreconditionFailed,
				"the file changed since the plan (digest "+shorten(actual)+
					" instead of "+shorten(expected)+")")
		}
		current.SHA256 = actual
	} else if current.Exists {
		return reject(ErrorPreconditionFailed,
			"the file already exists; a write needs the digest of the content that was looked at")
	}

	validator, hasValidator, err := files.SelectValidator(path, action.GetValidator())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	identity := s.validatorIdentity(ctx, validator, hasValidator)
	validatorOutput := ""
	unvalidated := ""
	if hasValidator {
		validatorOutput, err = s.checkContent(ctx, validator, path, content)
		switch {
		case errors.Is(err, errValidatorUnavailable) && allowsMissingValidator(request, action):
			// The order said the check may be skipped and the grant allows
			// it: the write goes on, and the result says it went unchecked.
			unvalidated = "; the validator " + validator.Name + " is not installed on this host, " +
				"so the content was written unchecked as the order allows"
		case errors.Is(err, errValidatorUnavailable):
			// A tool the host does not have is not faked and is not skipped: the write
			// was ordered with a check, so without the check it is a different write
			// than the one ordered.
			return reject(ErrorValidatorUnavailable, "the validator "+validator.Name+
				" is not installed on this host ("+validator.Command[0]+"); nothing was written")
		case err != nil:
			// A version the validator accepted when it was written can be content the
			// validator refuses now - the service was upgraded, or another file it
			// includes changed.
			return reject(ErrorMalformed, "the validator "+validator.Name+": "+err.Error()+
				" "+validatorOutput)
		}
	}

	var kept *files.KeptVersion
	if current.Exists {
		version, err := s.keepPreviousVersion(path, current, request.GetTaskId())
		if err != nil {
			return reject(ErrorFileVersionNotKept, "the content being replaced could not be kept on "+
				"the host, so nothing was written: "+err.Error())
		}
		kept = &version
	}

	if err := files.WriteAtomically(path, content, mode, uid, gid); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	fromSecret := action.GetFromSecret() || (restored != nil && restored.FromSecret)
	s.rememberManagedFile(path, fromSecret)

	message := "the file was written" + unvalidated
	if restored != nil {
		message = "the file was restored to the version " + shorten(restored.SHA256) +
			" kept on " + restored.KeptAt.Format(time.RFC3339) + unvalidated
	}
	if !hasValidator {
		// A missing check is a fact, not silence: the operator is to know that
		// the host accepted the content without checking its meaning.
		message += "; the panel knows no validator for this file, so the content was not checked"
	}
	if kept != nil {
		message += "; the previous content is kept as the version " + shorten(kept.SHA256)
	}

	written := files.Describe(path)
	change := files.Change{
		Path: path, Action: files.ChangeUpdate,
		BeforeSHA256: current.SHA256, AfterSHA256: files.Fingerprint(content),
		BeforeMode: current.Mode, AfterMode: written.Mode,
		BeforeOwner: current.Owner, AfterOwner: written.Owner,
		BeforeGroup: current.Group, AfterGroup: written.Group,
		Existed: current.Exists, FromSecret: fromSecret,
		SymlinkPolicy: files.SymlinkPolicyNoFollow,
		Validator:     identity, ValidatorOutput: validatorOutput,
		Unvalidated:  unvalidated != "",
		KeptVersion:  kept,
		RestoredFrom: restored,
		AppliedAt:    time.Now().UTC(),
	}
	switch {
	case restored != nil:
		change.Action = files.ChangeRollback
	case !current.Exists:
		change.Action = files.ChangeCreate
	}
	change.Consumers, change.ConsumersReason = files.Consumers(path)

	// The digest of what was written answers this one job and is what the
	// verifier compares the host against a moment later; the standing record of a
	// file from the secret store still carries no digest, which is what the
	response := fileResponse(s.fileState(), message, nil, files.Fingerprint(content))
	if response.GetFileResult() != nil {
		if encoded, err := json.Marshal(change); err == nil {
			response.FileResult.Change = encoded
		}
		response.FileResult.ValidatorOutput = validatorOutput
		if restored != nil && !restored.FromSecret {
			// The content that was put back travels with the result: the panel keeps a
			// history of what it sent itself, and a version only the host had would
			// otherwise stay a digest the panel cannot show or record.
			response.FileResult.Content = content
		}
	}
	return response
}

// versionToRestore reads the version an order names out of the host's own
// store.
func (s *Server) versionToRestore(path, digest string, ordered []byte) (files.KeptVersion,
	[]byte, *helperv1.HelperResponse) {
	store := fileVersions()
	version, content, err := store.Lookup(path, digest)
	switch {
	case errors.Is(err, files.ErrNoSuchVersion):
		return files.KeptVersion{}, nil, reject(ErrorFileVersionUnknown,
			"this host keeps no version of "+path+" with the digest "+shorten(digest)+
				"; it keeps "+describeKeptVersions(store.List(path)))
	case errors.Is(err, files.ErrVersionCorrupted):
		return files.KeptVersion{}, nil, reject(ErrorFileVersionNotKept,
			"the kept version "+shorten(digest)+" of "+path+
				" no longer matches its digest and was not written")
	case err != nil:
		return files.KeptVersion{}, nil, reject(ErrorExecFailed, err.Error())
	}
	// An order that carries both a version and content has to agree with itself.
	if len(ordered) > 0 && files.Fingerprint(ordered) != digest {
		return files.KeptVersion{}, nil, reject(ErrorMalformed,
			"the order names the version "+shorten(digest)+
				" and carries content that is not that version")
	}
	return version, content, nil
}

// describeKeptVersions names the versions a host has, for the refusal of a
// rollback to one it does not.
func describeKeptVersions(versions []files.KeptVersion) string {
	if len(versions) == 0 {
		return "no version of this file at all"
	}
	names := make([]string, 0, len(versions))
	for _, version := range versions {
		if version.FromSecret {
			names = append(names, "a version from the secret store kept on "+
				version.KeptAt.Format(time.RFC3339))
			continue
		}
		names = append(names, shorten(version.SHA256)+" from "+version.KeptAt.Format(time.RFC3339))
	}
	return strings.Join(names, ", ")
}

// keepPreviousVersion copies the content about to be replaced into the store
// of versions.
func (s *Server) keepPreviousVersion(path string, current files.File,
	orderedBy string) (files.KeptVersion, error) {
	content, err := readFileContent(path)
	if err != nil {
		return files.KeptVersion{}, err
	}
	if len(content) > files.MaxSize {
		return files.KeptVersion{}, fmt.Errorf(
			"the file is bigger than %d bytes, so the previous content cannot be kept whole",
			files.MaxSize)
	}
	return fileVersions().Keep(path, current, content, orderedBy)
}

// planFile computes the difference between the file found and the desired
// state.
func (s *Server) planFile(ctx context.Context, request *helperv1.HelperRequest,
	allowlist files.Allowlist, action *helperv1.FileRequest) *helperv1.HelperResponse {
	path := action.GetPath()
	if response := checkScope(allowlist, path); response != nil {
		return response
	}
	// A plan without content and without a mode is a removal plan.
	removal := len(action.GetContent()) == 0 && action.GetMode() == "" &&
		!action.GetFromSecret() && action.GetVersionSha256() == ""

	// A plan for a return to a kept version describes that version: the content
	// lies on this host, so the difference is computed against it rather than
	// against the empty order the panel could send.
	content := action.GetContent()
	mode, owner, group := action.GetMode(), action.GetOwner(), action.GetGroup()
	if digest := action.GetVersionSha256(); digest != "" {
		version, kept, response := s.versionToRestore(path, digest, content)
		if response != nil {
			return response
		}
		content = kept
		if mode == "" {
			mode = version.Mode
		}
		if owner == "" {
			owner = version.Owner
		}
		if group == "" {
			group = version.Group
		}
	}

	if !removal {
		if err := files.ValidateContent(string(content)); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if _, err := files.ValidateMode(mode); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if _, _, err := files.Ownership(owner, group); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
	}

	current := files.Describe(path)
	if current.Exists && current.UnavailableReason == "" {
		// The digest of the content found is the heart of the plan: it binds the
		// later write to the file the operator really looked at.
		digest, err := fileDigest(path)
		if err != nil {
			current.UnavailableReason = err.Error()
		} else {
			current.SHA256 = digest
		}
	}

	// The identity of the check is part of the plan, not a detail of the answer:
	// "the content is valid" invites the question valid according to what, and
	// only the host can say which tool it has and in which version.
	validator, hasValidator := files.Validator{}, false
	if !removal {
		var err error
		validator, hasValidator, err = files.SelectValidator(path, action.GetValidator())
		if err != nil {
			return reject(ErrorMalformed, err.Error())
		}
	}
	identity := s.validatorIdentity(ctx, validator, hasValidator)

	plan := files.Compute(current, files.Desired{
		Content: content, Mode: mode, Owner: owner, Group: group,
		FromSecret: action.GetFromSecret(), Removal: removal,
		Validator: identity, KeptVersions: len(fileVersions().List(path)),
	})

	// The validator checks the desired content and not the one found: the
	// question is whether what we want to write makes sense for this service.
	if !removal {
		if hasValidator {
			output, err := s.checkContent(ctx, validator, path, content)
			plan.ValidatorOutput = output
			switch {
			case errors.Is(err, errValidatorUnavailable):
				// A missing tool is not a passed check.
				plan.ValidatorFailed = !allowsMissingValidator(request, action)
				plan.ValidatorOutput = "validator: unavailable; " + validator.Name +
					" is not installed on this host (" + validator.Command[0] + ")"
			case err != nil:
				// Content the validator does not accept is a result of the plan and not a
				// failure: the operator is to see it before approving, instead of finding
				// out during a write on half the fleet.
				plan.ValidatorFailed = true
				plan.ValidatorOutput = err.Error() + " " + output
			}
		}
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := describePlan(plan)
	if strings.HasPrefix(plan.ValidatorOutput, "validator: unavailable") {
		message += "; validator: unavailable"
	}
	response := fileResponse(s.fileState(), message, nil, plan.SHA256)
	if response.GetFileResult() != nil {
		response.FileResult.Plan = encoded
	}
	return response
}

// describePlan sums the plan up in one sentence for the operation journal.
func describePlan(plan files.Plan) string {
	switch plan.Action {
	case files.PlanNoChange:
		return "the file is already in the desired state"
	case files.PlanCreate:
		return "the file will be created"
	case files.PlanRemoveAbsent:
		return "the file does not exist, so there is nothing to remove"
	case files.PlanRemove:
		return "the file will be removed"
	default:
		return "what will change: " + strings.Join(plan.Changes, ", ")
	}
}

// removeFile deletes a file within the scope.
func (s *Server) removeFile(allowlist files.Allowlist, action *helperv1.FileRequest) *helperv1.HelperResponse {
	path := action.GetPath()
	if response := checkScope(allowlist, path); response != nil {
		return response
	}
	if expected := action.GetExpectedSha256(); expected != "" {
		actual, err := fileDigest(path)
		if err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
		if actual != expected {
			return reject(ErrorPreconditionFailed,
				"the file changed since the plan; a removal would take away content nobody looked at")
		}
	}
	// The content is copied aside before it is taken away, for the same reason as
	// before a write: a removal nothing can undo is a removal the operator has to
	// be certain about, and certainty is not something this module can hand out.
	kept := ""
	current := files.Describe(path)
	if current.Exists && current.UnavailableReason == "" {
		current.FromSecret = s.managedFromSecret(path)
		version, err := s.keepPreviousVersion(path, current, "")
		if err != nil {
			return reject(ErrorFileVersionNotKept, "the content being removed could not be kept on "+
				"the host, so nothing was removed: "+err.Error())
		}
		kept = "; its content is kept as the version " + shorten(version.SHA256)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return reject(ErrorExecFailed, err.Error())
	}
	s.forgetManagedFile(path)
	return fileResponse(s.fileState(), "the file was removed"+kept, nil, "")
}

// checkContent runs the validator on the content staged next to the target
// file.
func (s *Server) checkContent(ctx context.Context, validator files.Validator,
	path string, content []byte) (string, error) {
	if validator.BuiltIn != nil {
		return "", validator.BuiltIn(string(content))
	}
	if !exists(validator.Command[0]) {
		return "", errValidatorUnavailable
	}

	directory, err := files.OpenWithoutSymlinks(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return "", err
	}
	defer directory.Close()

	staged, err := stageForValidation(int(directory.Fd()), content, 0o600,
		filepath.Ext(path), !validator.NeedsName)
	if err != nil {
		return "", err
	}
	defer staged.Discard(int(directory.Fd()))

	arguments := append([]string{}, validator.Command...)
	cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	cmd.Env = toolEnvironment()
	if staged.Anonymous {
		// The file has no name, so the tool gets the descriptor: it lands as the
		// first descriptor after the standard three and the path names it in the
		// tool's own process, not in the helper's.
		cmd.ExtraFiles = []*os.File{staged.File}
		cmd.Args = append(cmd.Args, "/proc/self/fd/3")
	} else {
		cmd.Args = append(cmd.Args, filepath.Join(filepath.Dir(path), staged.Name))
	}
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// stagedContent is the content put in front of a validator: an anonymous
// file, or one under a name nobody could guess.
type stagedContent struct {
	File *os.File
	// Name is the entry in the directory when the file has one; empty for
	// an anonymous file.
	Name      string
	Anonymous bool
}

// Discard removes the staged content.
func (c *stagedContent) Discard(dirfd int) {
	if c == nil || c.File == nil {
		return
	}
	_ = c.File.Close()
	if !c.Anonymous && c.Name != "" {
		_ = unix.Unlinkat(dirfd, c.Name, 0)
	}
}

// stageForValidation puts the content into the directory for a validator to
// read.
func stageForValidation(dirfd int, content []byte, mode uint32,
	suffix string, anonymousAllowed bool) (*stagedContent, error) {
	if anonymousAllowed {
		fd, err := unix.Openat(dirfd, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, mode)
		if err == nil {
			file := os.NewFile(uintptr(fd), "validation")
			if err := writeFsyncRewind(file, content); err != nil {
				_ = file.Close()
				return nil, err
			}
			return &stagedContent{File: file, Anonymous: true}, nil
		}
	}
	name, err := randomStagingName(suffix)
	if err != nil {
		return nil, err
	}
	return stageNamed(dirfd, name, content, mode)
}

// stageNamed creates the staging file under the given name in the opened
// directory.
func stageNamed(dirfd int, name string, content []byte, mode uint32) (*stagedContent, error) {
	fd, err := unix.Openat(dirfd, name,
		unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return nil, fmt.Errorf("staging the content for validation: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if err := writeFsyncRewind(file, content); err != nil {
		_ = file.Close()
		_ = unix.Unlinkat(dirfd, name, 0)
		return nil, err
	}
	return &stagedContent{File: file, Name: name}, nil
}

// randomStagingName returns a name with 128 bits of randomness. The suffix
// of the target is kept for the tools that read the kind of file from it.
func randomStagingName(suffix string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return ".flotestro-validate-" + hex.EncodeToString(random[:]) + suffix, nil
}

// writeFsyncRewind writes the content, syncs it and moves the offset back to
// the start, so a tool given the descriptor reads from the beginning.
func writeFsyncRewind(file *os.File, content []byte) error {
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	_, err := file.Seek(0, io.SeekStart)
	return err
}

// fileState describes the files the panel has written on this host.
func (s *Server) fileState() files.Snapshot {
	snapshot := files.Snapshot{ObservedAt: time.Now().UTC()}
	store := fileVersions()
	for _, entry := range s.fileRegistry() {
		description := files.Describe(entry.Path)
		description.Managed = true
		description.FromSecret = entry.FromSecret
		// The versions the host kept are reported with the file: the panel can then
		// offer a content to go back to, instead of asking the operator for the
		// digest of something they have never seen.
		description.Versions = store.Reported(entry.Path)
		switch {
		case !description.Exists || description.UnavailableReason != "":
		case entry.FromSecret:
			// The digest of content from the store is never reported: for a short value
			// the digest alone is a hint, and the store is to leave no hints outside
			// itself.
			description.UnavailableReason = "the content comes from the secret store; the digest is not reported"
		default:
			if digest, err := fileDigest(entry.Path); err == nil {
				description.SHA256 = digest
			} else {
				description.UnavailableReason = err.Error()
			}
		}
		snapshot.Files = append(snapshot.Files, description)
	}
	return snapshot
}

// registryEntry describes one file written by the panel.
type registryEntry struct {
	Path string `json:"path"`
	// FromSecret marks a file whose content came from the secret store.
	FromSecret bool `json:"from_secret,omitempty"`
}

func (s *Server) fileRegistry() []registryEntry {
	data, err := os.ReadFile(FileRegistryPath)
	if err != nil {
		return nil
	}
	var entries []registryEntry
	if err := json.Unmarshal(data, &entries); err == nil {
		return entries
	}
	// The registry from before secrets were introduced was a bare list of paths.
	var paths []string
	if err := json.Unmarshal(data, &paths); err != nil {
		return nil
	}
	entries = make([]registryEntry, 0, len(paths))
	for _, path := range paths {
		entries = append(entries, registryEntry{Path: path})
	}
	return entries
}

func (s *Server) rememberManagedFile(path string, fromSecret bool) {
	entries := s.fileRegistry()
	for i := range entries {
		if entries[i].Path == path {
			entries[i].FromSecret = fromSecret
			s.writeFileRegistry(entries)
			return
		}
	}
	entries = append(entries, registryEntry{Path: path, FromSecret: fromSecret})
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	s.writeFileRegistry(entries)
}

func (s *Server) forgetManagedFile(path string) {
	entries := s.fileRegistry()
	remaining := make([]registryEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Path != path {
			remaining = append(remaining, entry)
		}
	}
	s.writeFileRegistry(remaining)
}

func (s *Server) writeFileRegistry(entries []registryEntry) {
	data, err := json.Marshal(entries)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(FileRegistryPath), 0o700)
	temporary := FileRegistryPath + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(temporary, FileRegistryPath)
}

func checkScope(allowlist files.Allowlist, path string) *helperv1.HelperResponse {
	if err := allowlist.Allows(path); err != nil {
		if errors.Is(err, files.ErrForbidden) {
			return reject(ErrorUnsupported, err.Error())
		}
		return reject(ErrorUnsupported, err.Error()+
			"; the scope is set by the host administrator in "+files.AllowlistPath)
	}
	return nil
}

func fileDigest(path string) (string, error) {
	file, err := files.OpenWithoutSymlinks(path, unix.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer file.Close()
	// The boundary is the module's: the panel compares this digest with the
	// one it computed from a read, and a read stops at the same place.
	data, err := io.ReadAll(io.LimitReader(file, files.MaxSize))
	if err != nil {
		return "", err
	}
	return files.Fingerprint(data), nil
}

// readFileContent reads a file without passing through a symbolic link.
func readFileContent(path string) ([]byte, error) {
	file, err := files.OpenWithoutSymlinks(path, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, files.MaxSize+1))
}

// managedFromSecret says whether the content of a file the panel manages came
// from the secret store.
func (s *Server) managedFromSecret(path string) bool {
	for _, entry := range s.fileRegistry() {
		if entry.Path == path {
			return entry.FromSecret
		}
	}
	return false
}

// validatorIdentity describes the check that applies to a file: which tool,
// from where, and in which version it answers.
func (s *Server) validatorIdentity(ctx context.Context, validator files.Validator,
	known bool) files.ValidatorIdentity {
	if !known {
		return files.ValidatorIdentity{}
	}
	identity := files.ValidatorIdentity{Known: true, Name: validator.Name}
	if validator.BuiltIn != nil {
		identity.Available = true
		identity.Version = files.BuiltInVersion
		return identity
	}
	identity.Command = validator.Command[0]
	if !exists(validator.Command[0]) {
		identity.VersionUnavailableReason = "the tool is not installed on this host"
		return identity
	}
	identity.Available = true
	if len(validator.VersionCommand) == 0 {
		identity.VersionUnavailableReason = "the panel knows no way of asking this tool for its version"
		return identity
	}

	versionCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(versionCtx, validator.VersionCommand[0], validator.VersionCommand[1:]...)
	cmd.Env = toolEnvironment()
	// Several of these tools print their version on the error output and leave
	// with a non-zero status, so the output decides and the status only explains
	// an empty one.
	output, err := cmd.CombinedOutput()
	identity.Version = firstLine(string(output))
	if identity.Version == "" {
		identity.VersionUnavailableReason = "the tool answered nothing when asked for its version"
		if err != nil {
			identity.VersionUnavailableReason += ": " + err.Error()
		}
	}
	return identity
}

// firstLine takes the first line of a tool's answer and keeps it short.
func firstLine(output string) string {
	line := strings.TrimSpace(output)
	if index := strings.IndexByte(line, '\n'); index >= 0 {
		line = strings.TrimSpace(line[:index])
	}
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}

func shorten(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func fileResponse(snapshot files.Snapshot, message string,
	content []byte, digest string) *helperv1.HelperResponse {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		FileResult: &helperv1.FileResult{
			Snapshot: encoded, Message: message,
			Content: content, Sha256: digest,
		},
	}
}
