package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
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

// applyFile handles the operations on configuration files.
func (s *Server) applyFile(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.FileRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	allowlist := files.WczytajAllowliste(files.SciezkaAllowlisty)

	switch action.GetOperation() {
	case helperv1.FileRequest_OPERATION_LIST:
		return fileResponse(s.fileState(), "", nil, "")
	case helperv1.FileRequest_OPERATION_READ:
		return s.readFile(allowlist, action)
	case helperv1.FileRequest_OPERATION_ENSURE:
		return s.writeFile(actionCtx, allowlist, action)
	case helperv1.FileRequest_OPERATION_REMOVE:
		return s.removeFile(allowlist, action)
	case helperv1.FileRequest_OPERATION_PLAN:
		return s.planFile(actionCtx, allowlist, action)
	}
	return reject(ErrorUnknownAction, "unknown file operation")
}

// readFile returns the content of a file within the scope.
func (s *Server) readFile(allowlist files.Allowlist, action *helperv1.FileRequest) *helperv1.HelperResponse {
	if response := checkScope(allowlist, action.GetPath()); response != nil {
		return response
	}
	description := files.OpiszPlik(action.GetPath())
	if !description.Exists {
		return reject(ErrorUnsupported, "the file "+action.GetPath()+" does not exist on this host")
	}
	if description.UnavailableReason != "" {
		return reject(ErrorUnsupported, description.UnavailableReason)
	}

	file, err := files.OtworzBezDowiazan(action.GetPath(), unix.O_RDONLY, 0)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	defer file.Close()

	// One byte more than the boundary is read: otherwise a file exactly at the
	// boundary would look truncated and a bigger one - whole.
	content, err := io.ReadAll(io.LimitReader(file, files.MaksymalnyRozmiar+1))
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	truncated := false
	if len(content) > files.MaksymalnyRozmiar {
		content = content[:files.MaksymalnyRozmiar]
		truncated = true
	}

	response := fileResponse(s.fileState(), "", content, files.Odcisk(content))
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
func (s *Server) writeFile(ctx context.Context, allowlist files.Allowlist,
	action *helperv1.FileRequest) *helperv1.HelperResponse {
	path := action.GetPath()
	if response := checkScope(allowlist, path); response != nil {
		return response
	}
	if err := files.WalidujTresc(string(action.GetContent())); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	mode, err := files.WalidujTryb(action.GetMode())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	uid, gid, err := files.Wlasciciel(action.GetOwner(), action.GetGroup())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	current := files.OpiszPlik(path)
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

	validator, hasValidator, err := files.WybierzWalidator(path, action.GetValidator())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	validatorOutput := ""
	if hasValidator {
		validatorOutput, err = s.checkContent(ctx, validator, path, action.GetContent())
		if err != nil {
			return reject(ErrorMalformed, "the validator "+validator.Nazwa+": "+err.Error()+
				" "+validatorOutput)
		}
	}

	if err := files.ZapiszAtomowo(path, action.GetContent(), mode, uid, gid); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	s.rememberManagedFile(path, action.GetFromSecret())

	message := "the file was written"
	if !hasValidator {
		// A missing check is a fact, not silence: the operator is to know that
		// the host accepted the content without checking its meaning.
		message += "; the panel knows no validator for this file, so the content was not checked"
	}
	return fileResponse(s.fileState(), message, nil, files.Odcisk(action.GetContent()))
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
func (s *Server) planFile(ctx context.Context, allowlist files.Allowlist,
	action *helperv1.FileRequest) *helperv1.HelperResponse {
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
		if err := files.WalidujTresc(string(action.GetContent())); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if _, err := files.WalidujTryb(action.GetMode()); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if _, _, err := files.Wlasciciel(action.GetOwner(), action.GetGroup()); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
	}

	current := files.OpiszPlik(path)
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

	plan := files.Zaplanuj(current, action.GetContent(), action.GetMode(),
		action.GetOwner(), action.GetGroup(), action.GetFromSecret(), removal)

	// The validator checks the desired content and not the one found: the
	// question is whether what we want to write makes sense for this service.
	if !removal {
		validator, hasValidator, err := files.WybierzWalidator(path, action.GetValidator())
		if err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if hasValidator {
			output, err := s.checkContent(ctx, validator, path, action.GetContent())
			plan.ValidatorOutput = output
			if err != nil {
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
	response := fileResponse(s.fileState(), describePlan(plan), nil, plan.SHA256)
	if response.GetFileResult() != nil {
		response.FileResult.Plan = encoded
	}
	return response
}

// describePlan sums the plan up in one sentence for the operation journal.
func describePlan(plan files.Plan) string {
	switch plan.Action {
	case files.PlanBezZmian:
		return "the file is already in the desired state"
	case files.PlanTworzy:
		return "the file will be created"
	case files.PlanJuzUsuniety:
		return "the file does not exist, so there is nothing to remove"
	case files.PlanUsuwa:
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

// checkContent runs the validator on the content written next to the target
// file.
//
// The validator gets a temporary file in the same directory, because some tools
// read relative paths relative to the file they check.
func (s *Server) checkContent(ctx context.Context, validator files.Walidator,
	path string, content []byte) (string, error) {
	if validator.Wbudowany != nil {
		return "", validator.Wbudowany(string(content))
	}
	if !exists(validator.Polecenie[0]) {
		// A tool the host does not have is not faked: a write without a check is
		// then a deliberate decision and not an oversight.
		return "", nil
	}
	temporary := filepath.Join(filepath.Dir(path), ".flotestro-validation-"+filepath.Base(path))
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return "", err
	}
	defer os.Remove(temporary)

	arguments := append(append([]string{}, validator.Polecenie...), temporary)
	output, err := runTool(ctx, arguments)
	return output, err
}

// fileState describes the files the panel has written on this host.
func (s *Server) fileState() files.Snapshot {
	snapshot := files.Snapshot{ObservedAt: time.Now().UTC()}
	for _, entry := range s.fileRegistry() {
		description := files.OpiszPlik(entry.Path)
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
	if err := allowlist.Dopuszcza(path); err != nil {
		if errors.Is(err, files.ErrZakazana) {
			return reject(ErrorUnsupported, err.Error())
		}
		return reject(ErrorUnsupported, err.Error()+
			"; the scope is set by the host administrator in "+files.SciezkaAllowlisty)
	}
	return nil
}

func fileDigest(path string) (string, error) {
	file, err := files.OtworzBezDowiazan(path, unix.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, files.MaksymalnyRozmiar))
	if err != nil {
		return "", err
	}
	return files.Odcisk(data), nil
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
