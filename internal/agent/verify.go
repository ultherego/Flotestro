package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/helper"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/dns"
	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/modules/firewall"
	"github.com/ultherego/flotestro/internal/modules/kernel"
	"github.com/ultherego/flotestro/internal/modules/network"
	"github.com/ultherego/flotestro/internal/modules/schedules"
	"github.com/ultherego/flotestro/internal/modules/security"
	sshmodule "github.com/ultherego/flotestro/internal/modules/ssh"
	"github.com/ultherego/flotestro/internal/modules/storage"
	hosttime "github.com/ultherego/flotestro/internal/modules/time"
	"github.com/ultherego/flotestro/internal/opspec"
	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/systemd"
)

// The verification of a change: the host is read after the apply and
// compared with what the payload or the plan promised, and only that read
// turns the change into a success.
//
// An exit code of zero says a tool ran. It does not say that the unit is
// active, that the file has the digest of the plan, that the package is at
// the candidate version or that the mount is there - and a job that says
// succeeded on the exit code alone tells the operator something nobody
// observed. Every mutating operation therefore declares a verifier in the
// contract (opspec.Verifier), and the executor runs it between the module's
// result and the settlement. A verifier that finds another state settles
// the job failed with applied_unverified: the change was made, the state
// the operator asked for was not observed. Where the contract says so, the
// host puts the previous state back first and says so in the reason.
//
// The verifiers read the host through the same readers the inventory and
// the module tabs use; the readers are a value on the executor so that a
// test can hand it a host of its own.

// verifyTimeout bounds one verification. A read of the host is short; a
// verification that cannot read the host in this time reports that it
// could not, rather than holding the result.
const verifyTimeout = 90 * time.Second

// observation is what a verifier found on the host next to what it
// expected. Neither side ever carries the content of a file or a secret:
// a digest, a state word, a version.
type observation struct {
	expected string
	observed string
	verified bool
	// reason says why the change did not verify, or what the verifier
	// could not read. Empty on a verified change.
	reason string
}

// unverified is the observation of a mismatch.
func unverified(expected, observed, reason string) observation {
	return observation{expected: expected, observed: observed, reason: reason}
}

// verified is the observation of a match.
func verified(expected, observed string) observation {
	return observation{expected: expected, observed: observed, verified: true}
}

// unreadable is the observation of a host that could not be read: the
// state is unknown, and unknown is never a success.
func unreadable(expected, why string) observation {
	return observation{expected: expected, observed: "unknown", reason: "the verifier could not read the host: " + why}
}

// hostReaders are the reads the verifiers observe the host through. The
// executor fills them with the real readers; a test replaces the ones its
// case needs. A nil reader means the host cannot be read that way and the
// verifier says so.
type hostReaders struct {
	unit         func(ctx context.Context, unit string) (systemd.UnitState, error)
	schedules    func(ctx context.Context) (schedules.Snapshot, error)
	installed    func(ctx context.Context) packages.InstalledList
	holds        func(ctx context.Context) ([]string, string)
	packageState func(ctx context.Context) *agentv1.PackageApplyResult
	repositories func(ctx context.Context) packages.RepositoryImage
	file         func(ctx context.Context, path string) (fileState, error)
	storage      func(ctx context.Context) storage.Snapshot
	volumes      func(ctx context.Context) (storage.Snapshot, error)
	hostname     func() (string, error)
	sysctl       func(key string) (string, error)
	modules      func() (map[string]bool, error)
	kernel       func(ctx context.Context) (kernel.Snapshot, error)
	ssh          func(ctx context.Context) (sshmodule.Snapshot, error)
	resolver     func(ctx context.Context) dns.Snapshot
	clock        func(ctx context.Context) hosttime.Snapshot
	network      func(ctx context.Context) network.Snapshot
	firewall     func(ctx context.Context) (firewall.Snapshot, error)
	security     func(ctx context.Context) (security.Snapshot, error)
	certificates func(ctx context.Context) (certificates.Snapshot, error)
	account      func(ctx context.Context, name string) *LocalAccount
	docker       func(ctx context.Context) (docker.Snapshot, error)
	identity     func(ctx context.Context) IdentityState
	keytabKVNO   func(ctx context.Context, domain string) (*uint32, error)
	backupState  func(ctx context.Context, task *agentv1.TaskEnvelope, payload *opspec.BackupPayload) (backupRepositoryState, error)
	directory    func(path string) (exists bool, entries int, err error)
}

// fileState is what the verifier reads of one file: whether it is there,
// the digest of its content, and the content itself only while a rollback
// baseline needs it. The content never reaches a result.
type fileState struct {
	exists    bool
	sha256    string
	mode      string
	owner     string
	group     string
	content   []byte
	truncated bool
}

// backupRepositoryState is what the repository lists after a run: the
// identifiers of the snapshots it holds.
type backupRepositoryState struct {
	snapshotIDs []string
}

// readers returns the readers of the executor: the ones a test set, or the
// real ones assembled on first use.
func (e *TaskExecutor) readers() *hostReaders {
	if e.verifyReaders == nil {
		e.verifyReaders = e.defaultReaders()
	}
	return e.verifyReaders
}

// defaultReaders assembles the real readers: the inventory collectors for
// what the agent reads on its own, the helper probes for what only root
// sees.
func (e *TaskExecutor) defaultReaders() *hostReaders {
	return &hostReaders{
		unit:      systemd.Show,
		schedules: e.ProbeSchedules,
		installed: func(ctx context.Context) packages.InstalledList {
			return packages.Installed(ctx, hostManager(ctx))
		},
		holds:        packageHolds,
		packageState: packageStateNow,
		repositories: func(ctx context.Context) packages.RepositoryImage {
			return CollectRepositories(hostManager(ctx))
		},
		file:     e.readFileState,
		storage:  CollectStorage,
		volumes:  e.ProbeLVM,
		hostname: os.Hostname,
		sysctl:   readSysctl,
		modules:  loadedModules,
		kernel:   e.ProbeKernel,
		ssh:      e.ProbeSSH,
		resolver: CollectDNS,
		clock:    CollectTime,
		network: func(ctx context.Context) network.Snapshot {
			address, _ := managementChannel()
			return CollectNetwork(ctx, address)
		},
		firewall:     e.ProbeFirewall,
		security:     e.ProbeSecurity,
		certificates: e.ProbeCertificates,
		account:      e.readSingleAccount,
		docker: func(ctx context.Context) (docker.Snapshot, error) {
			// The full read, not the summary: a verifier asks about one
			// container, one image, one project - and the summary carries
			// none of the lists it would have to look in.
			return e.ProbeDocker(ctx, true)
		},
		identity: ReadIdentityState,
		keytabKVNO: func(ctx context.Context, domain string) (*uint32, error) {
			privileged, err := e.ProbePrivilegedIdentity(ctx, domain)
			if err != nil {
				return nil, err
			}
			return privileged.KeytabKVNO, nil
		},
		backupState: e.readBackupRepository,
		directory:   readDirectory,
	}
}

// readFileState reads one file through the helper: the digest and the
// attributes always, the content with them - a rollback baseline needs it
// and nothing else keeps it.
func (e *TaskExecutor) readFileState(ctx context.Context, path string) (fileState, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_File{
			File: &helperv1.FileRequest{Operation: helperv1.FileRequest_OPERATION_READ, Path: path},
		},
	}, time.Minute)
	if err != nil {
		return fileState{}, err
	}
	result := response.GetFileResult()
	if !response.GetAccepted() {
		// A file that is not there is a state, not an error: a removal
		// expects exactly that. Any other refusal is a read that failed.
		if response.GetErrorCode() == "unsupported" && strings.Contains(response.GetMessage(), "does not exist") {
			return fileState{}, nil
		}
		return fileState{}, fmt.Errorf("%s: %s", response.GetErrorCode(), response.GetMessage())
	}
	state := fileState{exists: true, sha256: result.GetSha256(), content: result.GetContent(),
		truncated: result.GetTruncated()}
	// The attributes come from the snapshot the helper sends with every
	// file answer; a file outside the managed set has none there and the
	// verifier compares only the digest.
	var snapshot files.Snapshot
	if data := result.GetSnapshot(); len(data) > 0 && json.Unmarshal(data, &snapshot) == nil {
		for _, file := range snapshot.Files {
			if file.Path == path {
				state.mode, state.owner, state.group = file.Mode, file.Owner, file.Group
			}
		}
	}
	return state, nil
}

// readBackupRepository lists the snapshots of the repository the order
// names, through the helper's plan read, with the credentials fetched the
// way the run fetched them: the value lives for the read and no longer.
func (e *TaskExecutor) readBackupRepository(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.BackupPayload) (backupRepositoryState, error) {
	request := &helperv1.BackupRequest{
		Operation: helperv1.BackupRequest_OPERATION_PLAN,
		Id:        payload.ID, Tool: payload.Tool, Repository: payload.Repository,
		Paths: payload.Paths, Excludes: payload.Excludes, Tags: payload.Tags,
	}
	if !payload.PasswordSecret.Empty() {
		value, refusal := e.fetchSecret(ctx, task, *payload.PasswordSecret)
		if refusal != nil {
			return backupRepositoryState{}, fmt.Errorf("the repository password was not fetched: %s", refusal.GetMessage())
		}
		request.Password = value
	}
	if len(payload.EnvSecrets) > 0 {
		request.Env = map[string][]byte{}
		for name, reference := range payload.EnvSecrets {
			value, refusal := e.fetchSecret(ctx, task, reference)
			if refusal != nil {
				return backupRepositoryState{}, fmt.Errorf("the secret %s was not fetched: %s", name, refusal.GetMessage())
			}
			request.Env[name] = value
		}
	}
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId: task.GetTaskId(), TimeoutSeconds: 600,
		Action: &helperv1.HelperRequest_Backup{Backup: request},
	}, 10*time.Minute)
	if err != nil {
		return backupRepositoryState{}, err
	}
	if !response.GetAccepted() {
		if response.GetErrorCode() == helper.ErrorRepositoryAbsent {
			return backupRepositoryState{}, fmt.Errorf("%s: %s: %w",
				response.GetErrorCode(), response.GetMessage(), errRepositoryAbsent)
		}
		return backupRepositoryState{}, fmt.Errorf("%s: %s", response.GetErrorCode(), response.GetMessage())
	}
	var state struct {
		Snapshots []struct {
			ID string `json:"id"`
		} `json:"snapshots"`
	}
	if err := json.Unmarshal(response.GetBackupResult().GetState(), &state); err != nil {
		return backupRepositoryState{}, err
	}
	ids := make([]string, 0, len(state.Snapshots))
	for _, snapshot := range state.Snapshots {
		ids = append(ids, snapshot.ID)
	}
	return backupRepositoryState{snapshotIDs: ids}, nil
}

// readSysctl reads one key from /proc/sys. The path form of the key is the
// dotted form with the dots replaced; a key with a slash in a name (the
// net.ipv4.conf.eth0/1 case) is not one the panel writes.
func readSysctl(key string) (string, error) {
	content, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(content)), nil
}

// loadedModules reads the names of the loaded kernel modules.
func loadedModules() (map[string]bool, error) {
	content, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}
	loaded := map[string]bool{}
	for _, line := range strings.Split(string(content), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			loaded[fields[0]] = true
		}
	}
	return loaded, nil
}

// readDirectory says whether a directory is there and how many entries it
// holds.
func readDirectory(path string) (bool, int, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, 0, nil
		}
		return false, 0, err
	}
	return true, len(entries), nil
}

// baseline is what the host looked like right before a change whose
// contract lets the host put it back, or whose verifier compares before
// with after. It is read after the claims are held, so it is the state the
// change lands on; a baseline that could not be read leaves the rollback
// out and the reason says so.
type baseline struct {
	// file is the previous state of a managed file, content included:
	// the rollback of an unverified write is the write of this content
	// back, or the removal of a file that was not there.
	file *fileState
	// sysctl holds the previous values of the keys of the order.
	sysctl map[string]string
	// hostKeys are the fingerprints of the host keys by type before a
	// rotation.
	hostKeys map[string]string
	// certificates are the fingerprints and expiries by path before a
	// renewal.
	certificates map[string]certificateBefore
	// volumeSizes are the sizes of the logical volumes and the filesystems
	// by path before an extension.
	volumeSizes map[string]uint64
	// snapshots are the identifiers the backup repository listed before a
	// run. An empty map is a repository with no copies in it - including
	// one that did not exist yet - and nil is a repository that could not
	// be read, which is a different answer; snapshotsReason says why.
	snapshots       map[string]bool
	snapshotsReason string
}

// errRepositoryAbsent means the host answered that the repository is not
// there yet. It travels as an error because the read did refuse, and it is
// typed because a repository nobody has created holds no copies, which a
// verifier can work with.
var errRepositoryAbsent = errors.New("the repository does not exist yet")

type certificateBefore struct {
	fingerprint string
	notAfter    time.Time
}

// observeBaseline reads the part of the host a verifier compares against
// or a rollback restores. Only the operations that need one read anything;
// the read is bounded and its failure is a fact for the reason, not a
// refusal of the change.
func (e *TaskExecutor) observeBaseline(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload opspec.Payload) *baseline {
	if !action.Mutating() || action.Verifier() == opspec.VerifierNone {
		return nil
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), verifyTimeout)
	defer cancel()
	readers := e.readers()
	before := &baseline{}
	switch action {
	case opspec.ActionFileEnsure, opspec.ActionFileRollback:
		if payload.File == nil || readers.file == nil {
			return before
		}
		state, err := readers.file(readCtx, payload.File.Path)
		if err == nil && !state.truncated {
			before.file = &state
		}
	case opspec.ActionSysctlEnsure:
		if payload.Kernel == nil || readers.sysctl == nil {
			return before
		}
		before.sysctl = map[string]string{}
		for key := range payload.Kernel.Settings {
			if value, err := readers.sysctl(key); err == nil {
				before.sysctl[key] = value
			}
		}
	case opspec.ActionSSHHostKeyRotate:
		if readers.ssh == nil {
			return before
		}
		if snapshot, err := readers.ssh(readCtx); err == nil {
			before.hostKeys = map[string]string{}
			for _, key := range snapshot.HostKeys {
				before.hostKeys[strings.ToLower(key.Type)] = key.Fingerprint
			}
		}
	case opspec.ActionCertificateRenew:
		if readers.certificates == nil {
			return before
		}
		if snapshot, err := readers.certificates(readCtx); err == nil {
			before.certificates = map[string]certificateBefore{}
			for _, cert := range snapshot.Certificates {
				entry := certificateBefore{fingerprint: cert.FingerprintSHA256}
				if cert.NotAfter != nil {
					entry.notAfter = *cert.NotAfter
				}
				before.certificates[cert.Path] = entry
			}
		}
	case opspec.ActionLVMExtend, opspec.ActionFilesystemResize:
		before.volumeSizes = map[string]uint64{}
		if readers.volumes != nil {
			if snapshot, err := readers.volumes(readCtx); err == nil {
				for _, volume := range snapshot.Volumes {
					before.volumeSizes[volume.Path] = volume.SizeBytes
				}
			}
		}
		if readers.storage != nil {
			for _, mount := range readers.storage(readCtx).Mounts {
				if mount.SizeBytes != nil {
					before.volumeSizes[mount.Target] = *mount.SizeBytes
				}
			}
		}
	case opspec.ActionBackupRun:
		if payload.Backup == nil || readers.backupState == nil {
			return before
		}
		state, err := readers.backupState(readCtx, task, payload.Backup)
		switch {
		case err == nil:
			before.snapshots = map[string]bool{}
			for _, id := range state.snapshotIDs {
				before.snapshots[id] = true
			}
		case errors.Is(err, errRepositoryAbsent):
			// The first copy into a fresh repository: there was nothing
			// there, so anything the run leaves behind is what it made.
			// Without this the first backup of every host could be made and
			// never confirmed.
			before.snapshots = map[string]bool{}
		default:
			// The reason travels, so the verdict says why the host could
			// not be read instead of only that it could not.
			before.snapshotsReason = err.Error()
		}
	}
	return before
}

// verifyOutcome runs the verifier of the operation on a result that says
// the change was made, and settles the result by what the host shows.
//
// A refusal, a failure and a read pass through untouched: there is no
// change to confirm. A mutation with a result that already carries a
// verification - a module that settles itself, a power-off nobody can
// observe - keeps it. A verifier the panel runs on the host's return
// (reboot, agent version) leaves nothing here: the module withholds the
// result and the panel settles the job on the next Hello.
func (e *TaskExecutor) verifyOutcome(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload opspec.Payload, before *baseline,
	result *agentv1.TaskResult) *agentv1.TaskResult {
	if result == nil || result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED || !action.Mutating() {
		return result
	}
	if result.GetVerification() != nil {
		return result
	}
	verifier := action.Verifier()
	if verifier == opspec.VerifierNone {
		result.Verification = &agentv1.Verification{Verifier: string(verifier), Verified: true,
			Reason: "the result of the operation is its own observation"}
		return result
	}
	if verifier.PanelSettled() {
		return result
	}

	verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), verifyTimeout)
	defer cancel()
	found := e.observe(verifyCtx, verifier, verifyInput{
		task: task, action: action, payload: payload, result: result, before: before,
	})
	result.Verification = &agentv1.Verification{
		Verifier: string(verifier), Verified: found.verified,
		Observed: found.observed, Expected: found.expected, Reason: found.reason,
	}
	if found.verified {
		return result
	}

	e.log.Warn("the change was made and the host does not show the state asked for",
		"task_id", task.GetTaskId(), "action", action, "verifier", verifier,
		"expected", found.expected, "observed", found.observed, "reason", found.reason)
	reason := found.reason
	if action.OnUnverified() == opspec.UnverifiedRollback {
		reason += "; " + e.rollbackUnverified(verifyCtx, task, action, payload, before, found)
	}
	result.Verification.Reason = reason
	result.Status = agentv1.TaskResult_STATUS_FAILED
	result.ErrorCode = opspec.ErrorAppliedUnverified
	result.Message = "the change was made, but the host does not show the state asked for: " + reason
	return result
}

// verifyInput is what a verifier gets: the order, the module's result and
// the baseline read before the change.
type verifyInput struct {
	task    *agentv1.TaskEnvelope
	action  opspec.ActionType
	payload opspec.Payload
	result  *agentv1.TaskResult
	before  *baseline
}

// observe runs the verifier named by the contract. A verifier the registry
// names and this agent does not carry is a state nobody read: the change
// is not a success on that ground.
func (e *TaskExecutor) observe(ctx context.Context, verifier opspec.Verifier, in verifyInput) observation {
	readers := e.readers()
	switch verifier {
	case opspec.VerifierUnitState:
		return verifyUnitState(ctx, readers, in)
	case opspec.VerifierScheduleEntry:
		return verifyScheduleEntry(ctx, readers, in)
	case opspec.VerifierPackageVersions:
		return verifyPackageVersions(ctx, readers, in)
	case opspec.VerifierPackageHold:
		return verifyPackageHold(ctx, readers, in)
	case opspec.VerifierPackageDatabase:
		return verifyPackageDatabase(ctx, readers)
	case opspec.VerifierRepository:
		return verifyRepository(ctx, readers, in)
	case opspec.VerifierFileContent:
		return verifyFileContent(ctx, readers, in)
	case opspec.VerifierMountState:
		return verifyMountState(ctx, readers, in)
	case opspec.VerifierStorageLayout:
		return verifyStorageLayout(ctx, readers, in)
	case opspec.VerifierHostname:
		return verifyHostname(readers, in)
	case opspec.VerifierSysctl:
		return verifySysctl(readers, in)
	case opspec.VerifierKernelModule:
		return verifyKernelModule(ctx, readers, in)
	case opspec.VerifierSSHDConfig:
		return verifySSHDConfig(ctx, readers, in)
	case opspec.VerifierSSHHostKey:
		return verifySSHHostKey(ctx, readers, in)
	case opspec.VerifierResolver:
		return verifyResolver(ctx, readers, in)
	case opspec.VerifierTimeSource:
		return verifyTimeSource(ctx, readers, in)
	case opspec.VerifierTimezone:
		return verifyTimezone(ctx, readers, in)
	case opspec.VerifierNetworkState:
		return verifyNetworkState(ctx, readers, in)
	case opspec.VerifierFirewallRuleset:
		return verifyFirewallRuleset(ctx, readers, in)
	case opspec.VerifierMACMode:
		return verifyMACMode(ctx, readers, in)
	case opspec.VerifierAuditRules:
		return verifyAuditRules(ctx, readers)
	case opspec.VerifierTrustAnchor:
		return verifyTrustAnchor(ctx, readers, in)
	case opspec.VerifierCertificate:
		return verifyCertificate(ctx, readers, in)
	case opspec.VerifierLocalAccount:
		return verifyLocalAccount(ctx, readers, in)
	case opspec.VerifierContainerState:
		return verifyContainerState(ctx, readers, in)
	case opspec.VerifierImagePresent:
		return verifyImagePresent(ctx, readers, in)
	case opspec.VerifierComposeServices:
		return verifyComposeServices(ctx, readers, in)
	case opspec.VerifierContainerSpec:
		return verifyContainerSpec(ctx, readers, in)
	case opspec.VerifierDockerNetwork:
		return verifyDockerNetwork(ctx, readers, in)
	case opspec.VerifierDockerVolume:
		return verifyDockerVolume(ctx, readers, in)
	case opspec.VerifierBackupRun:
		return verifyBackupRun(ctx, readers, in)
	case opspec.VerifierRestoreTarget:
		return verifyRestoreTarget(readers, in)
	case opspec.VerifierDomainMembership:
		return verifyDomainMembership(ctx, readers, in)
	case opspec.VerifierKeytab:
		return verifyKeytab(ctx, readers, in)
	}
	return unreadable("a state this agent can read", "this agent carries no verifier "+string(verifier)+"; upgrade the agent")
}

// rollbackUnverified puts the state from before the change back where the
// contract asks for it and the baseline was read. It returns the sentence
// the reason ends with: what was put back, or why nothing was.
func (e *TaskExecutor) rollbackUnverified(ctx context.Context, task *agentv1.TaskEnvelope,
	action opspec.ActionType, payload opspec.Payload, before *baseline, found observation) string {
	if strings.HasPrefix(found.reason, "the verifier could not read the host") {
		// A state that could not be read is not a state to overwrite: the
		// rollback would land blind on a host nobody looked at.
		return "no rollback was made, because the state of the host is unknown"
	}
	if before == nil {
		return "no rollback was made, because the state before the change was not read"
	}
	switch action {
	case opspec.ActionFileEnsure, opspec.ActionFileRollback:
		if before.file == nil || payload.File == nil {
			return "no rollback was made, because the previous content of the file was not read"
		}
		return e.rollbackFile(ctx, task, payload.File, *before.file)
	case opspec.ActionSysctlEnsure:
		if payload.Kernel == nil || len(before.sysctl) == 0 {
			return "no rollback was made, because the previous values were not read"
		}
		return e.rollbackSysctl(ctx, task, before.sysctl)
	}
	return "no rollback was made: the operation keeps no previous state to put back"
}

// rollbackFile writes the previous content of the file back, or removes a
// file that was not there before, through the same helper operation the
// write went through. The digests are what the sentence carries.
func (e *TaskExecutor) rollbackFile(ctx context.Context, task *agentv1.TaskEnvelope,
	payload *opspec.FilePayload, previous fileState) string {
	request := &helperv1.FileRequest{Operation: helperv1.FileRequest_OPERATION_REMOVE, Path: payload.Path}
	if previous.exists {
		request = &helperv1.FileRequest{
			Operation: helperv1.FileRequest_OPERATION_ENSURE, Path: payload.Path,
			Content: previous.content, Mode: previous.mode, Owner: previous.owner, Group: previous.group,
			// The previous content went through no validator when it was
			// written by whoever wrote it; putting it back is not the
			// moment to start refusing it.
			AllowMissingValidator: true,
		}
	}
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId: task.GetTaskId(), TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_File{File: request},
	}, time.Minute)
	if err != nil {
		return "the rollback failed: " + err.Error()
	}
	if !response.GetAccepted() {
		return "the rollback failed: " + response.GetErrorCode() + ": " + response.GetMessage()
	}
	if !previous.exists {
		return "the file was removed again, as it was not there before the change"
	}
	return "the previous content was put back (sha256 " + shortDigest(previous.sha256) + ")"
}

// rollbackSysctl sets the keys of the order back to the values read before
// the change, through the helper.
func (e *TaskExecutor) rollbackSysctl(ctx context.Context, task *agentv1.TaskEnvelope,
	previous map[string]string) string {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId: task.GetTaskId(), TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_Kernel{Kernel: &helperv1.KernelRequest{
			Operation: helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE, Settings: previous,
		}},
	}, time.Minute)
	if err != nil {
		return "the rollback failed: " + err.Error()
	}
	if !response.GetAccepted() {
		return "the rollback failed: " + response.GetErrorCode() + ": " + response.GetMessage()
	}
	keys := make([]string, 0, len(previous))
	for key := range previous {
		keys = append(keys, key)
	}
	sortStrings(keys)
	return "the previous values were put back (" + strings.Join(keys, ", ") + ")"
}

// shortDigest keeps a digest readable in a sentence.
func shortDigest(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	if digest == "" {
		return "none"
	}
	return digest
}
