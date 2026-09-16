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

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/files"

	"golang.org/x/sys/unix"
)

// FileRegistryPath holds the paths the panel has written on this host.
//
// The registry is local, because it is the host that has to be able to answer
// what the files managed by the panel look like now - also when the panel is
// not asking. Without it a drift would show only at the next operation.
const FileRegistryPath = "/var/lib/flotestro-helper/files.json"

// ErrorValidatorUnavailable means a content check the order relies on that
// this host cannot run: the tool is not installed. The write does not
// happen, because a write nobody checked is not the write that was ordered.
const ErrorValidatorUnavailable = "validator_unavailable"

// PermissionFileWriteUnvalidated is the grant that, together with an order
// saying so, lets a file be written when its validator is missing. The name
// repeats the panel's permission.
const PermissionFileWriteUnvalidated = "file.write.unvalidated"

// allowsMissingValidator says whether an order may go on without its
// validator: the order has to say so and the capability has to carry the
// grant. A request without a capability carries no grant, so a missing
// validator refuses the write - the safe side - whatever the order says.
func allowsMissingValidator(request *helperv1.HelperRequest, action *helperv1.FileRequest) bool {
	return action.GetAllowMissingValidator() && hasGrant(grantsOf(request), PermissionFileWriteUnvalidated)
}

// errValidatorUnavailable marks a validator whose tool the host lacks. The
// caller tells it from a failed check: one refuses with its own code, the
// other reports the tool's verdict.
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
//
// The order is the whole content of the operation: the scope is checked, then
// the state of the host against what the operator looked at, then the content
// is checked with a validator - and only then is it written, atomically. A
// write before the check would leave a file on the host that no service can
// load.
func (s *Server) writeFile(ctx context.Context, request *helperv1.HelperRequest,
	allowlist files.Allowlist, action *helperv1.FileRequest) *helperv1.HelperResponse {
	path := action.GetPath()
	if response := checkScope(allowlist, path); response != nil {
		return response
	}
	if err := files.ValidateContent(string(action.GetContent())); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	mode, err := files.ValidateMode(action.GetMode())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	uid, gid, err := files.Ownership(action.GetOwner(), action.GetGroup())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	current := files.Describe(path)
	if current.UnavailableReason != "" {
		return reject(ErrorUnsupported, current.UnavailableReason)
	}
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
	} else if current.Exists {
		return reject(ErrorPreconditionFailed,
			"the file already exists; a write needs the digest of the content that was looked at")
	}

	validator, hasValidator, err := files.SelectValidator(path, action.GetValidator())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	validatorOutput := ""
	unvalidated := ""
	if hasValidator {
		validatorOutput, err = s.checkContent(ctx, validator, path, action.GetContent())
		switch {
		case errors.Is(err, errValidatorUnavailable) && allowsMissingValidator(request, action):
			// The order said the check may be skipped and the grant allows
			// it: the write goes on, and the result says it went unchecked.
			unvalidated = "; the validator " + validator.Name + " is not installed on this host, " +
				"so the content was written unchecked as the order allows"
		case errors.Is(err, errValidatorUnavailable):
			// A tool the host does not have is not faked and is not skipped:
			// the write was ordered with a check, so without the check it is
			// a different write than the one ordered.
			return reject(ErrorValidatorUnavailable, "the validator "+validator.Name+
				" is not installed on this host ("+validator.Command[0]+"); nothing was written")
		case err != nil:
			return reject(ErrorMalformed, "the validator "+validator.Name+": "+err.Error()+
				" "+validatorOutput)
		}
	}

	if err := files.WriteAtomically(path, action.GetContent(), mode, uid, gid); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	s.rememberManagedFile(path, action.GetFromSecret())

	message := "the file was written" + unvalidated
	if !hasValidator {
		// A missing check is a fact, not silence: the operator is to know that
		// the host accepted the content without checking its meaning.
		message += "; the panel knows no validator for this file, so the content was not checked"
	}
	return fileResponse(s.fileState(), message, nil, files.Fingerprint(action.GetContent()))
}

// planFile computes the difference between the file found and the desired
// state.
//
// It changes nothing and cannot change anything: it is the answer to the
// question of what would happen. The host is the only place where it can be
// computed - the panel does not know what really lies on this machine, and two
// machines with the same desired state have two different diffs.
//
// The input checks are the same as during a write. A plan that passed and a
// write that falls out on the mode validation would be an untrue plan.
func (s *Server) planFile(ctx context.Context, request *helperv1.HelperRequest,
	allowlist files.Allowlist, action *helperv1.FileRequest) *helperv1.HelperResponse {
	path := action.GetPath()
	if response := checkScope(allowlist, path); response != nil {
		return response
	}
	// A plan without content and without a mode is a removal plan. The kind of
	// change does not travel in the envelope as a separate field, because the
	// planner for a write, a return and a removal is the same operation - they
	// are told apart by the payload, which the panel passes through unchanged.
	// There is no guessing here: a write always carries content or a reference
	// to a secret, a removal never does.
	//
	// The result names this directly in the action field of the plan, so an
	// operator who asked about something else sees what the panel really
	// computed.
	removal := len(action.GetContent()) == 0 && action.GetMode() == "" &&
		!action.GetFromSecret()

	if !removal {
		if err := files.ValidateContent(string(action.GetContent())); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if _, err := files.ValidateMode(action.GetMode()); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if _, _, err := files.Ownership(action.GetOwner(), action.GetGroup()); err != nil {
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

	plan := files.Compute(current, action.GetContent(), action.GetMode(),
		action.GetOwner(), action.GetGroup(), action.GetFromSecret(), removal)

	// The validator checks the desired content and not the one found: the
	// question is whether what we want to write makes sense for this service.
	if !removal {
		validator, hasValidator, err := files.SelectValidator(path, action.GetValidator())
		if err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if hasValidator {
			output, err := s.checkContent(ctx, validator, path, action.GetContent())
			plan.ValidatorOutput = output
			switch {
			case errors.Is(err, errValidatorUnavailable):
				// A missing tool is not a passed check. The plan says so in
				// the same place a failed check would, because the write that
				// follows this plan will refuse for the same reason - unless
				// the order allows an unchecked write and the grant is there.
				plan.ValidatorFailed = !allowsMissingValidator(request, action)
				plan.ValidatorOutput = "validator: unavailable; " + validator.Name +
					" is not installed on this host (" + validator.Command[0] + ")"
			case err != nil:
				// Content the validator does not accept is a result of the plan
				// and not a failure: the operator is to see it before approving,
				// instead of finding out during a write on half the fleet.
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
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return reject(ErrorExecFailed, err.Error())
	}
	s.forgetManagedFile(path)
	return fileResponse(s.fileState(), "the file was removed", nil, "")
}

// checkContent runs the validator on the content staged next to the target
// file.
//
// The validator gets a temporary file in the same directory, because some
// tools read relative paths relative to the file they check. The staging is
// what makes this safe to do as root: the directory is opened without
// following symlinks, and the file is created where nobody could have put a
// link in advance - it has no name at all, or a name nobody can guess.
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
		// The file has no name, so the tool gets the descriptor: it lands as
		// the first descriptor after the standard three and the path names it
		// in the tool's own process, not in the helper's.
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

// Discard removes the staged content. An anonymous file disappears with its
// descriptor; a named one is unlinked through the same directory descriptor
// it was created in, so a directory swapped in the meantime is not touched.
func (c *stagedContent) Discard(dirfd int) {
	if c == nil || c.File == nil {
		return
	}
	_ = c.File.Close()
	if !c.Anonymous && c.Name != "" {
		_ = unix.Unlinkat(dirfd, c.Name, 0)
	}
}

// stageForValidation puts the content into the directory for a validator
// to read.
//
// The file used to be written under a name derived from the target, with a
// call that follows symlinks: anyone able to plant a link under that name
// in the directory had the helper overwrite a file of their choosing, as
// root. Now the file is created relative to an already-opened directory
// descriptor and either has no name at all - O_TMPFILE - or gets a random
// 128-bit name, created with O_EXCL and O_NOFOLLOW, so a link planted in
// advance is refused instead of followed. The content is synced before the
// tool reads it. A tool that infers the kind of file from its name gets a
// named file that keeps the suffix of the target; a file system without
// O_TMPFILE gets the named file too.
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
// directory. The name has to be new: an entry already there, a symlink
// above all, is refused rather than opened.
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
	for _, entry := range s.fileRegistry() {
		description := files.Describe(entry.Path)
		description.Managed = true
		description.FromSecret = entry.FromSecret
		switch {
		case !description.Exists || description.UnavailableReason != "":
		case entry.FromSecret:
			// The digest of content from the store is never reported: for a short
			// value the digest alone is a hint, and the store is to leave no
			// hints outside itself. The panel knows which version of the secret
			// was deployed, and that is all it has to know.
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
	// The registry from before secrets were introduced was a bare list of
	// paths. The older format is still read: the helper must not forget after
	// an upgrade which files the panel has written.
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
	data, err := io.ReadAll(io.LimitReader(file, files.MaxSize))
	if err != nil {
		return "", err
	}
	return files.Fingerprint(data), nil
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
