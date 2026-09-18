package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/storage"
	"github.com/ultherego/flotestro/internal/opspec"
	planenvelope "github.com/ultherego/flotestro/internal/plan"
)

// The paths of the mount tools. Fixed, not looked up in PATH.
const (
	mountPath  = "/usr/bin/mount"
	umountPath = "/usr/bin/umount"
	fsckPath   = "/usr/sbin/fsck"
	blkidPath  = "/usr/sbin/blkid"
)

// errorStalePlan is the answer to a change whose plan no longer matches the
// host: the fingerprint computed again under the lock differs from the one
// the operator approved. The code is the one every planned family reports;
// the operator computes the plan again and approves the new one.
const errorStalePlan = planenvelope.ErrorStalePlan

// applyStorage handles the operations on the disk space of the host.
func (s *Server) applyStorage(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.StorageRequest) *helperv1.HelperResponse {
	release, busy := s.hold(storageGuard(action.GetOperation()), request)
	if busy != nil {
		return busy
	}
	defer release()

	actionCtx, cancel := deadline(ctx, request, 10*time.Minute, 60*time.Minute)
	defer cancel()
	// The checks and the resizes run their tools in the resource scope of
	// the storage family; the scope is named after the task.
	actionCtx = withTask(actionCtx, request.GetTaskId())

	switch action.GetOperation() {
	case helperv1.StorageRequest_OPERATION_READ_LVM:
		return storageResponse(s.readLVM(actionCtx), "", "")
	case helperv1.StorageRequest_OPERATION_MOUNT_ENSURE:
		return s.mount(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_MOUNT_REMOVE:
		return s.unmount(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_FS_CHECK:
		return s.checkFilesystem(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_LVM_EXTEND:
		return s.extendVolume(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_FS_RESIZE:
		return s.extendFilesystem(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_FS_CREATE:
		return s.createFilesystem(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_DISK_WIPE:
		return s.wipeDevice(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_MOUNT_PLAN:
		return s.planMount(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_DEVICE_PLAN:
		return s.planDevice(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_SMART_READ:
		return s.readSmart(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_READ_RAID:
		return storageResponse(s.readRAID(actionCtx), "", "")
	case helperv1.StorageRequest_OPERATION_RAID_MEMBER_FAIL,
		helperv1.StorageRequest_OPERATION_RAID_MEMBER_REMOVE,
		helperv1.StorageRequest_OPERATION_RAID_MEMBER_ADD:
		return s.manageArrayMember(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_LVM_LV_CREATE:
		return s.createVolume(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_LVM_LV_REMOVE,
		helperv1.StorageRequest_OPERATION_LVM_SNAPSHOT_REMOVE:
		return s.removeVolume(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_LVM_VG_EXTEND:
		return s.extendGroup(actionCtx, action)
	case helperv1.StorageRequest_OPERATION_LVM_SNAPSHOT_CREATE:
		return s.createSnapshot(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "unknown disk space operation")
}

// readSmart asks the SMART tool about one device.
//
// The tool needs root to talk to the device, so the read goes through the
// helper; it takes no guard, because it changes nothing. A missing tool is
// an unsupported read with a reason, not an invented healthy disk.
func (s *Server) readSmart(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	device := action.GetDevice()
	if err := storage.ValidateSmartDevice(device); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if !exists(storage.SmartctlPath) {
		return reject(ErrorUnsupported, "this host has no smartctl ("+storage.SmartctlPath+")")
	}
	report := storage.ReadSmart(ctx, smartRunner, device)
	return &helperv1.HelperResponse{Accepted: true, SmartResult: smartResultToProto(report)}
}

// smartRunner runs the SMART tool and hands back its output together with
// the exit code: the code carries the verdict bit by bit, so a non-zero
// code with a full JSON is a device with findings rather than a failed
// read.
func smartRunner(ctx context.Context, path string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = toolEnvironment()
	output, err := cmd.Output()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
			// The tool printed its answer and ended with a status: that is
			// the answer, not a failure of the read.
			return string(output), code, nil
		}
		return string(output), -1, err
	}
	return string(output), code, nil
}

func smartResultToProto(report storage.SmartReport) *helperv1.SmartResult {
	result := &helperv1.SmartResult{
		Device:             report.Device,
		Model:              report.Model,
		Serial:             report.Serial,
		Health:             report.Health,
		HealthReason:       report.HealthReason,
		TemperatureC:       report.TemperatureC,
		PowerOnHours:       report.PowerOnHours,
		ReallocatedSectors: report.ReallocatedSectors,
		PendingSectors:     report.PendingSectors,
		WearPercent:        report.WearPercent,
		Unsupported:        report.Unsupported,
		UnsupportedReason:  report.UnsupportedReason,
		Output:             report.Output,
	}
	for _, attribute := range report.Attributes {
		result.Attributes = append(result.Attributes, &helperv1.SmartAttribute{
			Id:        attribute.ID,
			Name:      attribute.Name,
			Value:     attribute.Value,
			Worst:     attribute.Worst,
			Threshold: attribute.Threshold,
			Raw:       attribute.Raw,
			RawString: attribute.RawString,
			Failing:   attribute.Failing,
		})
	}
	return result
}

// storageGuard names the guard of a disk space operation. The reads and the
// plans change nothing and take none.
func storageGuard(operation helperv1.StorageRequest_Operation) string {
	switch operation {
	case helperv1.StorageRequest_OPERATION_READ_LVM,
		helperv1.StorageRequest_OPERATION_READ_RAID,
		helperv1.StorageRequest_OPERATION_MOUNT_PLAN,
		helperv1.StorageRequest_OPERATION_DEVICE_PLAN,
		helperv1.StorageRequest_OPERATION_SMART_READ:
		return ""
	}
	return GuardStorage
}

// planMount computes the difference between the mount found and the one
// requested.
//
// It changes nothing. The input checks are the same as during a mount, and on
// top of that the plan resolves the source to the UUID of the filesystem this
// host has: that UUID then travels in the change, so a disk that got a
// different path after a restart is not mounted in somebody else's place.
func (s *Server) planMount(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	plan, state, refused := s.computeMountPlan(ctx, action)
	if refused != nil {
		return refused
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	response := storageResponse(state, describeMountPlan(plan), "")
	if response.GetStorageResult() != nil {
		response.StorageResult.Plan = encoded
	}
	return response
}

// computeMountPlan is the one place a mount plan is computed: the plan
// operation and the change before it run the same code, so the fingerprint
// the change carries is compared with a plan of the same shape. The plan
// covers the device identity, the fstab revision and the state of the mount
// point; any of them moving between the plan and the change is a stale
// plan.
func (s *Server) computeMountPlan(ctx context.Context, action *helperv1.StorageRequest) (
	storage.MountPlan, storage.Snapshot, *helperv1.HelperResponse) {
	if err := storage.ValidateTarget(action.GetTarget()); err != nil {
		return storage.MountPlan{}, storage.Snapshot{}, reject(ErrorMalformed, err.Error())
	}
	// A plan without a source is an unmount plan: a mount always has a source,
	// an unmount never does. The result names this directly in the action field.
	unmounting := action.GetSource() == ""
	if !unmounting {
		if err := storage.ValidateSource(action.GetSource()); err != nil {
			return storage.MountPlan{}, storage.Snapshot{}, reject(ErrorMalformed, err.Error())
		}
		if err := storage.ValidateOptions(action.GetOptions(), action.GetFsType()); err != nil {
			return storage.MountPlan{}, storage.Snapshot{}, reject(ErrorMalformed, err.Error())
		}
	}

	state := s.storagePicture(ctx)
	if state.UnavailableReason != "" {
		return storage.MountPlan{}, state, reject(ErrorUnsupported, state.UnavailableReason)
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return storage.MountPlan{}, state, reject(ErrorExecFailed, "mountinfo: "+err.Error())
	}
	fstab, _ := os.ReadFile(storage.FstabPath)
	state.Mounts = storage.MergeMounts(
		storage.ParseMountinfo(string(mountinfo)), storage.ParseFstab(string(fstab)))
	state.FstabRevision = storage.FstabRevision(fstab)

	var plan storage.MountPlan
	if unmounting {
		plan = storage.ComputeUnmount(state, action.GetTarget())
		if plan.Action == storage.PlanRemove {
			// Unmounting a busy filesystem will not succeed; better to say so in
			// the plan than on half the fleet during execution.
			if users := s.processesOnFilesystem(ctx, action.GetTarget()); users != "" {
				plan.Refuse("the filesystem is in use by: " + users)
			}
		}
	} else {
		plan = storage.ComputeMount(state, action.GetSource(), action.GetTarget(),
			action.GetFsType(), action.GetOptions(), action.GetPersist())
	}
	plan.ObserveTarget(targetState(action.GetTarget()))
	// A plan computed in a private mount namespace would describe a change that
	// never enters the host. The refusal is to stand in the plan, not in the
	// execution.
	if plan.Refusal == "" && plan.Action != storage.PlanNoChange &&
		plan.Action != storage.PlanRemoveAbsent {
		if err := sharedMountNamespace(); err != nil {
			plan.Refuse(err.Error())
		}
	}
	return plan, state, nil
}

// targetState says what stat finds at the mount point.
func targetState(target string) string {
	info, err := os.Stat(target)
	switch {
	case err != nil:
		return storage.TargetMissing
	case info.IsDir():
		return storage.TargetDirectory
	}
	return storage.TargetNotADirectory
}

// checkMountPlanDigest compares the plan computed now with the one the
// operator consented to. The comparison runs under the storage guard, right
// before the change: a different fingerprint means the device, the fstab or
// the mount point moved since the planning - and that is a stale plan, not
// a warning.
func (s *Server) checkMountPlanDigest(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	expected := action.GetPlanHash()
	if expected == "" {
		return nil
	}
	plan, _, refused := s.computeMountPlan(ctx, action)
	if refused != nil {
		return refused
	}
	if plan.PlanHash != expected {
		return reject(errorStalePlan,
			"the mount "+action.GetTarget()+" changed since the planning (device, fstab or mount point); the change needs a new plan")
	}
	return nil
}

// describeMountPlan sums the plan up in one sentence for the operation journal.
func describeMountPlan(plan storage.MountPlan) string {
	if plan.Refusal != "" {
		return "the change will not enter this host: " + plan.Refusal
	}
	switch plan.Action {
	case storage.PlanNoChange:
		return "the mount is already in the desired state"
	case storage.PlanCreate:
		return "the mount will be created from the source " + plan.ResolvedSource
	case storage.PlanRemoveAbsent:
		return "the mount does not exist, so there is nothing to remove"
	case storage.PlanRemove:
		return "the mount will be removed"
	default:
		return "what will change: " + strings.Join(plan.Changes, ", ")
	}
}

// mount creates the fstab entry and mounts the filesystem.
//
// The order matters: first the entry, then the mount. The opposite would leave
// a host that works now but comes up after a restart without that filesystem -
// and that is a failure that shows itself at the worst moment.
func (s *Server) mount(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if err := storage.ValidateSource(action.GetSource()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := storage.ValidateTarget(action.GetTarget()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := storage.ValidateOptions(action.GetOptions(), action.GetFsType()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	if err := sharedMountNamespace(); err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	if response := s.checkMountPlanDigest(ctx, action); response != nil {
		return response
	}

	// A filesystem the host does not see cannot be mounted - and it is better to
	// say so now than to leave in fstab an entry that will stop the restart.
	if err := s.checkSourceExists(ctx, action.GetSource()); err != nil {
		return reject(ErrorUnsupported, err.Error())
	}

	if err := ensureDirectory(action.GetTarget()); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}

	if action.GetPersist() {
		if err := storage.WriteFstabEntry(storage.FstabPath, action.GetSource(),
			action.GetTarget(), action.GetFsType(), action.GetOptions()); err != nil {
			return reject(ErrorExecFailed, "writing fstab: "+err.Error())
		}
	}

	output, err := runTool(ctx, []string{mountPath, action.GetTarget()})
	if err != nil {
		// An entry that cannot be mounted now would stop the host at the
		// restart. It is withdrawn together with the failed mount.
		if action.GetPersist() {
			_ = storage.RemoveFstabEntry(storage.FstabPath, action.GetTarget())
		}
		return reject(ErrorExecFailed, "mounting: "+err.Error()+": "+output)
	}

	message := action.GetTarget() + " was mounted"
	if !action.GetPersist() {
		message += "; without an fstab entry it disappears after a restart"
	}
	return storageResponse(s.readLVM(ctx), message, "")
}

// unmount removes the mount and the panel entry.
func (s *Server) unmount(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if err := storage.ValidateTarget(action.GetTarget()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := sharedMountNamespace(); err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	if response := s.checkMountPlanDigest(ctx, action); response != nil {
		return response
	}
	// Unmounting a busy filesystem will not succeed, and the message of umount
	// itself does not say who holds it.
	if users := s.processesOnFilesystem(ctx, action.GetTarget()); users != "" {
		return reject(ErrorUnsupported,
			"the filesystem is in use by: "+users)
	}
	output, err := runTool(ctx, []string{umountPath, action.GetTarget()})
	if err != nil {
		return reject(ErrorExecFailed, "unmounting: "+err.Error()+": "+output)
	}
	if err := storage.RemoveFstabEntry(storage.FstabPath, action.GetTarget()); err != nil {
		return reject(ErrorExecFailed, "writing fstab: "+err.Error())
	}
	return storageResponse(s.readLVM(ctx), action.GetTarget()+" was unmounted", "")
}

// checkFilesystem runs fsck on an unmounted filesystem.
func (s *Server) checkFilesystem(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	device := action.GetDevice()
	if err := storage.ValidateSource(device); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if response := s.checkDevicePlanDigest(ctx, action); response != nil {
		return response
	}
	// fsck on a mounted filesystem can damage it. This is not a warning but a
	// reason for a refusal.
	if point := s.mountPoint(ctx, device); point != "" {
		return reject(ErrorUnsupported,
			"the filesystem is mounted at "+point+"; the check needs it unmounted")
	}

	arguments := []string{fsckPath, "-n", device}
	if action.GetRepair() {
		// A repair needs consent to every question up front: there is nobody to
		// handle the interaction, and an fsck waiting for an answer hangs until
		// the timeout.
		arguments = []string{fsckPath, "-y", device}
	}
	output, err := s.runScoped(ctx, opspec.FamilyStorage, arguments)
	code, known := exitCode(err)
	if err != nil && !known {
		// The tool did not run at all: a missing binary, a killed process,
		// a deadline. That is a failed operation, not a filesystem finding.
		return reject(ErrorExecFailed, "fsck: "+err.Error()+": "+output)
	}
	// fsck answers in a bit field, not with a verdict: 1 means it corrected
	// something, 2 that a reboot is wanted, 4 that errors were left behind,
	// and 8 and above that the tool itself failed. A repair that left errors
	// is not a successful repair, and reporting one as a success is the
	// false success this operation used to produce.
	switch {
	case code&fsckOperationalError != 0:
		return reject(ErrorExecFailed,
			"fsck could not run the check on "+device+" (code "+strconv.Itoa(code)+"): "+output)
	case action.GetRepair() && code&fsckErrorsRemain != 0:
		return reject(storage.CodeFilesystemErrorsRemain,
			"the repair of "+device+" left errors behind (fsck code "+strconv.Itoa(code)+
				"); the filesystem needs a person at the console")
	}
	message := "the filesystem on " + device + " has no errors"
	switch {
	case code&fsckErrorsRemain != 0:
		// A read-only check found errors. The check itself succeeded: that
		// is the fact the operator asked for, and the panel judges it.
		message = "the filesystem on " + device + " has errors that a read-only check does not correct (fsck code " +
			strconv.Itoa(code) + ")"
	case code&fsckCorrected != 0:
		message = "the repair corrected errors on " + device
		// The repair is confirmed by reading the filesystem again rather
		// than by the code of the pass that wrote to it.
		second, secondErr := s.runScoped(ctx, opspec.FamilyStorage, []string{fsckPath, "-n", device})
		output += "\n" + second
		if secondCode, ok := exitCode(secondErr); ok && secondCode&(fsckErrorsRemain|fsckOperationalError) != 0 {
			return reject(storage.CodeFilesystemErrorsRemain,
				"the repair of "+device+" ran and a second, read-only pass still finds errors (fsck code "+
					strconv.Itoa(secondCode)+")")
		}
		message += " and a second, read-only pass finds none"
	case code&fsckRebootWanted != 0:
		message = "the check corrected the root filesystem of " + device + "; it asks for a reboot"
	}
	return storageResponse(s.deviceState(ctx), message, output)
}

// The bits fsck answers with. They are named because the number alone is
// read wrongly by everybody: 4 is not "four errors", it is "errors left
// uncorrected", and that is the difference between a repaired filesystem
// and one that still needs a person.
const (
	fsckCorrected        = 1
	fsckRebootWanted     = 2
	fsckErrorsRemain     = 4
	fsckOperationalError = 8 | 16 | 32 | 128
)

// exitCode reads the status a tool ended with. The second value says
// whether the process ran at all: a tool that never started has no code,
// and treating its absence as zero would call a check that never happened
// a clean filesystem.
func exitCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), true
	}
	return 0, false
}

// extendVolume grows a logical volume together with its filesystem.
func (s *Server) extendVolume(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if !exists(storage.LVExtendPath) {
		return reject(ErrorUnsupported, "this host has no LVM tools")
	}
	arguments, err := storage.LVExtendArguments(action.GetDevice(), action.GetSize(), true)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if response := s.checkDevicePlanDigest(ctx, action); response != nil {
		return response
	}
	// A group without free space will not grow any volume. Better to say so now
	// than to leave the operator with an lvextend error.
	if reason := s.noSpaceInGroup(ctx, action.GetDevice()); reason != "" {
		return reject(ErrorPreconditionFailed, reason)
	}
	output, err := s.runScoped(ctx, opspec.FamilyStorage, arguments)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+output)
	}
	return storageResponse(s.readLVM(ctx), "the volume was extended", output)
}

// extendFilesystem grows the filesystem to the size of the device.
func (s *Server) extendFilesystem(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if response := s.checkDevicePlanDigest(ctx, action); response != nil {
		return response
	}
	state := s.storagePicture(ctx)
	device := state.DeviceAt(action.GetDevice())
	if err := (storage.DeviceIdentity{
		Path:   action.GetDevice(),
		ByID:   action.GetExpectedById(),
		WWN:    action.GetExpectedWwn(),
		Serial: action.GetExpectedSerial(),
		UUID:   action.GetExpectedUuid(),
	}).Matches(device); err != nil {
		return reject(ErrorPreconditionFailed, err.Error())
	}
	point := ""
	if len(device.Mountpoints) > 0 {
		point = device.Mountpoints[0]
	}
	arguments, err := storage.FSResizeArguments(action.GetDevice(), device.FSType, point)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	output, err := s.runScoped(ctx, opspec.FamilyStorage, arguments)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+output)
	}
	return storageResponse(s.readLVM(ctx), "the filesystem was extended", output)
}

// createFilesystem formats a device.
//
// This is an operation after which the data cannot be recovered, so the host
// checks everything the panel gave: the identity of the device and whether
// anything stands on it. The operator consent was already collected in the
// panel; here the fact decides.
func (s *Server) createFilesystem(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if response := s.checkDestructiveTarget(ctx, action); response != nil {
		return response
	}
	arguments, err := storage.FormatArguments(action.GetDevice(),
		action.GetFsType(), action.GetLabel())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	output, err := runTool(ctx, arguments)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+output)
	}
	return storageResponse(s.readLVM(ctx),
		"the filesystem "+action.GetFsType()+" was created on "+action.GetDevice(), output)
}

// wipeDevice removes the filesystem signatures.
func (s *Server) wipeDevice(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if response := s.checkDestructiveTarget(ctx, action); response != nil {
		return response
	}
	arguments, err := storage.WipeArguments(action.GetDevice())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	output, err := runTool(ctx, arguments)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+output)
	}
	// The data is still physically on the platters: the signatures were removed,
	// not the content. The operator is to read this before handing the disk over
	// to somebody else.
	return storageResponse(s.readLVM(ctx),
		"the filesystem signatures were removed from "+action.GetDevice()+
			"; the content of the medium was not overwritten", output)
}

// checkDestructiveTarget makes sure the operation hits the device the operator
// looked at and that nothing stands on it.
//
// The state is read again here, under the storage guard the operation holds,
// not taken from the request: the request says what the operator saw, the
// host says what is there now. The plan is computed once more and compared
// with the approved fingerprint where the order carries one; then the
// identity the order carries - by-id, WWN, serial - is compared with the
// device under the path. A missing identity is a refusal, not a pass: the
// size of the device is a description and matches nothing.
func (s *Server) checkDestructiveTarget(ctx context.Context,
	action *helperv1.StorageRequest) *helperv1.HelperResponse {
	state := s.deviceState(ctx)
	if state.UnavailableReason != "" {
		return reject(ErrorUnsupported, state.UnavailableReason)
	}
	if expected := action.GetPlanHash(); expected != "" {
		if now := devicePlan(state, action); now.PlanHash != expected {
			return reject(errorStalePlan,
				"the device "+action.GetDevice()+" changed since the planning; the change needs a new plan")
		}
	}
	observed := state.DeviceAt(action.GetDevice())
	if observed == nil {
		return reject(ErrorPreconditionFailed, "the device "+action.GetDevice()+" does not exist on this host")
	}
	consented := storage.DevicePlan{
		Device: action.GetDevice(),
		ByID:   action.GetExpectedById(),
		WWN:    action.GetExpectedWwn(),
		Serial: action.GetExpectedSerial(),
	}
	if err := storage.ValidateDestructiveTarget(consented, *observed); err != nil {
		return reject(refusalCode(err), err.Error())
	}
	if expected := action.GetExpectedUuid(); expected != "" && observed.UUID != expected {
		return reject(storage.CodeDiskChanged,
			"the device "+action.GetDevice()+" carries the filesystem "+observed.UUID+
				", and the plan was computed for "+expected)
	}
	return nil
}

// refusalCode reads the typed code out of a storage refusal; a plain error
// is a failed precondition.
func refusalCode(err error) string {
	var refusal *storage.Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ErrorPreconditionFailed
}

// noSpaceInGroup returns the reason when the volume group has no space left.
func (s *Server) noSpaceInGroup(ctx context.Context, volume string) string {
	lvm := s.readLVM(ctx)
	for _, entry := range lvm.Volumes {
		if !storage.MatchesVolume(entry, volume) {
			continue
		}
		for _, group := range lvm.Groups {
			if group.Name == entry.Group && group.FreeBytes == 0 {
				return "the group " + group.Name + " has no free space; " +
					"the volume cannot be extended without adding a disk"
			}
		}
	}
	return ""
}

// storagePicture reads the device topology on the helper side.
func (s *Server) storagePicture(ctx context.Context) storage.Snapshot {
	output, err := toolOutput(ctx, storage.LsblkPath, "-J", "-b", "-o",
		storage.Columns(storage.IdentityColumns))
	if err != nil {
		return storage.Snapshot{UnavailableReason: "lsblk: " + err.Error()}
	}
	devices, err := storage.ParseDevices(output)
	if err != nil {
		return storage.Snapshot{UnavailableReason: err.Error()}
	}
	// The by-id links and the holders come from udev and sysfs, not from
	// lsblk; without them a plan has no stable identity to bind to.
	storage.ReadIdentity(devices)
	return storage.Snapshot{Devices: devices}
}

// planDevice computes the plan of a check, an extension, a format or a wipe
// without touching the host. A device that does not exist, a filesystem
// mounted before an fsck, a group without space and a disk without a stable
// identity are a refusal in the plan, not a failure of the execution.
func (s *Server) planDevice(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	state := s.deviceState(ctx)
	plan := devicePlan(state, action)
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the change will not enter this host: " + plan.Refusal
	if plan.Refusal == "" {
		message = strings.Join(plan.Changes, "; ")
	}
	response := storageResponse(state, message, "")
	if response.GetStorageResult() != nil {
		response.StorageResult.Plan = encoded
	}
	return response
}

// devicePlan computes the plan by the kind named in the order; mutating
// operations name it directly.
func devicePlan(state storage.Snapshot, action *helperv1.StorageRequest) storage.DevicePlan {
	kind := action.GetPlan()
	switch action.GetOperation() {
	case helperv1.StorageRequest_OPERATION_FS_CHECK:
		kind = storage.PlanCheck
	case helperv1.StorageRequest_OPERATION_FS_RESIZE:
		kind = storage.PlanFSResize
	case helperv1.StorageRequest_OPERATION_LVM_EXTEND:
		kind = storage.PlanLVExtend
	case helperv1.StorageRequest_OPERATION_FS_CREATE:
		kind = storage.PlanFormat
	case helperv1.StorageRequest_OPERATION_DISK_WIPE:
		kind = storage.PlanWipe
	case helperv1.StorageRequest_OPERATION_RAID_MEMBER_FAIL:
		kind = storage.PlanRAIDMemberFail
	case helperv1.StorageRequest_OPERATION_RAID_MEMBER_REMOVE:
		kind = storage.PlanRAIDMemberRemove
	case helperv1.StorageRequest_OPERATION_RAID_MEMBER_ADD:
		kind = storage.PlanRAIDMemberAdd
	case helperv1.StorageRequest_OPERATION_LVM_LV_CREATE:
		kind = storage.PlanLVCreate
	case helperv1.StorageRequest_OPERATION_LVM_LV_REMOVE:
		kind = storage.PlanLVRemove
	case helperv1.StorageRequest_OPERATION_LVM_VG_EXTEND:
		kind = storage.PlanVGExtend
	case helperv1.StorageRequest_OPERATION_LVM_SNAPSHOT_CREATE:
		kind = storage.PlanSnapshotCreate
	case helperv1.StorageRequest_OPERATION_LVM_SNAPSHOT_REMOVE:
		kind = storage.PlanSnapshotRemove
	}
	switch kind {
	case storage.PlanFSResize:
		return storage.ComputeFSResize(state, action.GetDevice())
	case storage.PlanLVExtend:
		return storage.ComputeLVExtend(state, action.GetDevice(), action.GetSize())
	case storage.PlanCheck:
		return storage.ComputeCheck(state, action.GetDevice(), action.GetRepair())
	case storage.PlanFormat:
		return storage.ComputeFormat(state, action.GetDevice(), action.GetFsType(), action.GetLabel())
	case storage.PlanWipe:
		return storage.ComputeWipe(state, action.GetDevice())
	case storage.PlanRAIDMemberFail:
		return storage.ComputeRAIDMemberFail(state, action.GetArray(), action.GetDevice())
	case storage.PlanRAIDMemberRemove:
		return storage.ComputeRAIDMemberRemove(state, action.GetArray(), action.GetDevice())
	case storage.PlanRAIDMemberAdd:
		return storage.ComputeRAIDMemberAdd(state, action.GetArray(), action.GetDevice())
	case storage.PlanLVCreate:
		return storage.ComputeLVCreate(state, action.GetGroup(), action.GetVolume(), action.GetSize())
	case storage.PlanLVRemove:
		return storage.ComputeLVRemove(state, action.GetDevice())
	case storage.PlanVGExtend:
		return storage.ComputeVGExtend(state, action.GetGroup(), action.GetDevice())
	case storage.PlanSnapshotCreate:
		return storage.ComputeSnapshotCreate(state, action.GetDevice(), action.GetVolume(), action.GetSize())
	case storage.PlanSnapshotRemove:
		return storage.ComputeSnapshotRemove(state, action.GetDevice())
	}
	plan := storage.DevicePlan{Operation: kind, Device: action.GetDevice()}
	plan.Refuse("unknown plan kind " + kind)
	return plan
}

// checkDevicePlanDigest compares the plan computed now with the one the
// operator consented to. A different digest means the device or the group
// changed since the planning - and that is a refusal, not a warning.
func (s *Server) checkDevicePlanDigest(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	expected := action.GetPlanHash()
	if expected == "" {
		return nil
	}
	if now := devicePlan(s.deviceState(ctx), action); now.PlanHash != expected {
		return reject(errorStalePlan,
			"the device "+action.GetDevice()+" changed since the planning; the change needs a new plan")
	}
	return nil
}

// deviceState assembles the device topology together with LVM and the
// software arrays.
//
// A plan of a layer above the bare disk is computed against all three at
// once: a volume is a device, a group and a UUID, and an array member is a
// device the array knows under a slot. Reading one of them without the
// others would give a plan that binds to a name.
func (s *Server) deviceState(ctx context.Context) storage.Snapshot {
	state := s.storagePicture(ctx)
	lvm := s.readLVM(ctx)
	state.Groups, state.Volumes = lvm.Groups, lvm.Volumes
	state.PhysicalVolumes = lvm.PhysicalVolumes
	state.LVMUnavailableReason = lvm.LVMUnavailableReason
	raid := s.readRAID(ctx)
	state.Arrays, state.RAIDUnavailableReason = raid.Arrays, raid.RAIDUnavailableReason
	return state
}

// readLVM collects the groups and the logical volumes.
func (s *Server) readLVM(ctx context.Context) storage.Snapshot {
	snapshot := storage.Snapshot{ObservedAt: time.Now().UTC()}
	if !exists(storage.VGSPath) || !exists(storage.LVSPath) {
		// A host without LVM is not a host without an answer.
		snapshot.LVMUnavailableReason = "this host has no LVM tools (vgs, lvs)"
		return snapshot
	}
	// The field lists are the module's, so the query and the parser cannot
	// drift apart: a column the query leaves out comes back empty, and an
	// empty string read as a size is a zero nobody measured.
	if output, err := toolOutput(ctx, storage.VGSPath,
		"--reportformat", "json", "--units", "b", "-o", storage.VGSFields); err == nil {
		if groups, err := storage.ParseGroups(output); err == nil {
			snapshot.Groups = groups
		}
	}
	if output, err := toolOutput(ctx, storage.LVSPath,
		"--reportformat", "json", "--units", "b",
		"-o", storage.LVSFields); err == nil {
		if volumes, err := storage.ParseVolumes(output); err == nil {
			snapshot.Volumes = volumes
		}
	}
	// The physical volumes say which disk carries which group and how much
	// of it is still unallocated: that is what an extension of a group is
	// confirmed against afterwards, and a disk prepared for LVM but in no
	// group is a fact of its own, not a broken one.
	if exists(storage.PVSPath) {
		if output, err := toolOutput(ctx, storage.PVSPath,
			"--reportformat", "json", "--units", "b", "-o", storage.PVSFields); err == nil {
			if volumes, err := storage.ParsePhysicalVolumes(output); err == nil {
				snapshot.PhysicalVolumes = volumes
			}
		}
	}
	return snapshot
}

// readRAID reads the software arrays of the host.
//
// Two sources answer two different questions, and both are needed. The
// kernel's own /proc/mdstat says which arrays are assembled, at which
// level and how far a rebuild has got; it needs no privilege and cannot be
// out of date. mdadm --detail adds what the superblock carries - above all
// the UUID, which is the only name of an array that means the same array
// after a reboot - and it needs root, which is why this read is here.
//
// A kernel without the md driver has no /proc/mdstat, and that is an
// answer: it is not a host with zero arrays. A host with the driver and no
// mdadm reports its arrays without a UUID and says why, so the panel shows
// the degraded array and refuses to operate on it for a named reason.
func (s *Server) readRAID(ctx context.Context) storage.Snapshot {
	snapshot := storage.Snapshot{ObservedAt: time.Now().UTC()}
	content, err := os.ReadFile(storage.MDStatPath)
	if err != nil {
		snapshot.RAIDUnavailableReason = "this kernel has no software RAID (" +
			storage.MDStatPath + "): " + err.Error()
		return snapshot
	}
	arrays, err := storage.ParseMDStat(string(content))
	if err != nil {
		snapshot.RAIDUnavailableReason = "reading " + storage.MDStatPath + ": " + err.Error()
		return snapshot
	}
	snapshot.Arrays = arrays
	if len(arrays) == 0 {
		// The driver is there and no array is assembled. That is a host with
		// no arrays, which is a different answer from a host that cannot be
		// asked - and it carries no reason.
		return snapshot
	}
	detail, reason := s.arrayDetail(ctx, arrays)
	storage.MergeArrayDetail(snapshot.Arrays, detail, reason)
	// The identity a member operation binds to comes from the same place as
	// a disk's: mdadm knows nothing about /dev/disk/by-id.
	storage.FillMemberIdentity(snapshot.Arrays, s.storagePicture(ctx).Devices)
	return snapshot
}

// arrayDetail reads the superblock of every array, and says why when it
// cannot. The scan is read first, because it names every array's UUID in
// one call; the per-array detail adds the state of each member, including
// the slots with nothing in them.
func (s *Server) arrayDetail(ctx context.Context, arrays []storage.RAIDArray) (
	map[string]storage.RAIDArray, string) {
	if !exists(storage.MDAdmPath) {
		return nil, "this host has no mdadm (" + storage.MDAdmPath +
			"), so the arrays carry no UUID and no per-member state"
	}
	detail := map[string]storage.RAIDArray{}
	if output, err := toolOutput(ctx, storage.MDAdmPath, "--detail", "--scan"); err == nil {
		detail = storage.ParseMDAdmScan(output)
	}
	for _, array := range arrays {
		if storage.ValidateArray(array.Path) != nil {
			continue
		}
		output, err := toolOutput(ctx, storage.MDAdmPath, "--detail", array.Path)
		if err != nil {
			continue
		}
		full, err := storage.ParseMDAdmDetail(output)
		if err != nil {
			continue
		}
		// The scan line carries the UUID in the form mdadm.conf uses; the
		// detail carries the same UUID and everything else. Where the detail
		// could be read it wins, and the scan stays for the arrays it could
		// not.
		if full.UUID == "" {
			if scanned, ok := detail[array.Path]; ok {
				full.UUID = scanned.UUID
			}
		}
		detail[array.Path] = full
	}
	return detail, "mdadm did not report the detail of this array"
}

// checkSourceExists makes sure the host sees the given filesystem.
func (s *Server) checkSourceExists(ctx context.Context, source string) error {
	if strings.HasPrefix(source, "/dev/") {
		if !exists(source) {
			return fmt.Errorf("the device %s does not exist on this host", source)
		}
		return nil
	}
	if !exists(blkidPath) {
		// Without blkid the identifier cannot be checked. A missing check is a
		// fact here, not a consent.
		return fmt.Errorf("the host has no blkid; %s cannot be checked before writing to fstab", source)
	}
	key, value, _ := strings.Cut(source, "=")
	if _, err := toolOutput(ctx, blkidPath, "-t", key+"="+value, "-o", "device"); err != nil {
		return fmt.Errorf("the host does not see the filesystem %s", source)
	}
	return nil
}

// mountPoint returns the place where the device is mounted.
func (s *Server) mountPoint(ctx context.Context, device string) string {
	output, err := toolOutput(ctx, storage.LsblkPath, "-J", "-b", "-o",
		"NAME,PATH,TYPE,SIZE,MOUNTPOINTS")
	if err != nil {
		return ""
	}
	devices, err := storage.ParseDevices(output)
	if err != nil {
		return ""
	}
	for _, entry := range devices {
		if entry.Path == device && len(entry.Mountpoints) > 0 {
			return entry.Mountpoints[0]
		}
	}
	return ""
}

// processesOnFilesystem lists the processes holding the filesystem.
//
// The message "target is busy" alone does not say who holds it, and that is the
// only piece of information the operator needs at that moment.
func (s *Server) processesOnFilesystem(ctx context.Context, target string) string {
	const lsofPath = "/usr/bin/lsof"
	if !exists(lsofPath) {
		return ""
	}
	output, err := toolOutput(ctx, lsofPath, "-t", target)
	if err != nil || strings.TrimSpace(output) == "" {
		return ""
	}
	pids := strings.Fields(output)
	if len(pids) > 10 {
		pids = append(pids[:10], "...")
	}
	return "PID " + strings.Join(pids, ", ")
}

// sharedMountNamespace checks whether the helper shares the mount namespace
// with the host.
//
// A service started with PrivateTmp, ProtectSystem or another directive that
// creates a mount namespace gets its own copy of the tree, from which nothing
// comes back to the host. mount then ends in success, the helper reports
// "mounted", and the host does not have the filesystem. This is the worst of
// results: a silent one. Better to refuse and name the reason.
func sharedMountNamespace() error {
	hostNamespace, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return fmt.Errorf("the mount namespace of the host: %w", err)
	}
	helperNamespace, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("the mount namespace of the helper: %w", err)
	}
	if hostNamespace != helperNamespace {
		return fmt.Errorf("the helper runs in a private mount namespace " +
			"(PrivateTmp or a similar service directive); the mount would not be visible to the host")
	}
	return nil
}

func ensureDirectory(target string) error {
	if exists(target) {
		return nil
	}
	cmd := exec.Command("/usr/bin/mkdir", "-p", target)
	cmd.Env = toolEnvironment()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("the directory %s: %w: %s", target, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func storageResponse(snapshot storage.Snapshot, message, output string) *helperv1.HelperResponse {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		StorageResult: &helperv1.StorageResult{
			Snapshot: encoded, Message: message, Output: output,
		},
	}
}

// The layers above a bare disk: the software array and the volume manager.
//
// Every one of these operations goes the same way. The plan is computed
// again here, under the storage guard, against the host as it is now; the
// digest is compared with the one the operator approved; every identity the
// order carries - the UUID of the array, of the group, of the volume, the
// by-id link of the device - is compared with what the host has; and only
// then does a tool run. Afterwards the state is read again and the answer
// is what the read says, never the exit code of the tool.

// layerTarget recomputes the plan and compares the identities the order
// binds to. The returned plan is the one computed here, not the one the
// panel sent: what the host does is decided by what the host sees.
func (s *Server) layerTarget(ctx context.Context, action *helperv1.StorageRequest) (
	storage.DevicePlan, *helperv1.HelperResponse) {
	state := s.deviceState(ctx)
	if state.UnavailableReason != "" {
		return storage.DevicePlan{}, reject(ErrorUnsupported, state.UnavailableReason)
	}
	plan := devicePlan(state, action)
	if plan.Refusal != "" {
		// The plan refuses on this host now. Whatever the order carries, the
		// refusal is the answer - with its own typed code where it has one.
		return plan, reject(planRefusalCode(plan), plan.Refusal)
	}
	if expected := action.GetPlanHash(); expected != "" && plan.PlanHash != expected {
		return plan, reject(errorStalePlan,
			"the plan of "+plan.Operation+" changed since the operator approved it; the change needs a new plan")
	}
	// The identities. An order that names none of them never gets here: the
	// panel refuses it before the task is created, and the host repeats the
	// check because the panel's word is not a fact about this host.
	if expected := action.GetExpectedArrayUuid(); expected != "" && plan.ArrayUUID != expected {
		return plan, reject(storage.CodeDiskChanged,
			"the array under "+action.GetArray()+" carries the UUID "+orNone(plan.ArrayUUID)+
				", and the plan was computed for "+expected)
	}
	if expected := action.GetExpectedGroupUuid(); expected != "" && plan.GroupUUID != expected {
		return plan, reject(storage.CodeDiskChanged,
			"the group "+plan.Group+" carries the UUID "+orNone(plan.GroupUUID)+
				", and the plan was computed for "+expected)
	}
	if expected := action.GetExpectedVolumeUuid(); expected != "" && plan.VolumeUUID != expected {
		return plan, reject(storage.CodeDiskChanged,
			"the volume "+action.GetDevice()+" carries the UUID "+orNone(plan.VolumeUUID)+
				", and the plan was computed for "+expected)
	}
	if expected := action.GetExpectedById(); expected != "" && plan.ByID != expected {
		return plan, reject(storage.CodeDiskChanged,
			"the device "+action.GetDevice()+" is reached through "+orNone(plan.ByID)+
				", and the plan was computed for "+expected)
	}
	return plan, nil
}

// planRefusalCode is the typed code of a refusing plan; a plan that refuses
// without one is a failed precondition.
func planRefusalCode(plan storage.DevicePlan) string {
	if plan.RefusalCode != "" {
		return plan.RefusalCode
	}
	return ErrorPreconditionFailed
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

// manageArrayMember marks a member of an array bad, takes one out, or puts
// a device in.
//
// The three are one function because they are one decision with three
// verbs: what happens to a member of an array that exists. What none of
// them is, is a way to build or destroy an array: the panel refuses that
// by name before a task is ever created, so nothing here has to handle it.
func (s *Server) manageArrayMember(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if !exists(storage.MDAdmPath) {
		return reject(ErrorUnsupported, "this host has no mdadm ("+storage.MDAdmPath+")")
	}
	verb := storage.RAIDFail
	switch action.GetOperation() {
	case helperv1.StorageRequest_OPERATION_RAID_MEMBER_REMOVE:
		verb = storage.RAIDRemove
	case helperv1.StorageRequest_OPERATION_RAID_MEMBER_ADD:
		verb = storage.RAIDAdd
	}
	arguments, err := storage.RAIDMemberArguments(action.GetArray(), action.GetDevice(), verb)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	plan, refused := s.layerTarget(ctx, action)
	if refused != nil {
		return refused
	}
	if plan.Action == storage.PlanNoChange {
		// The array is already in the state the order asks for. Nothing runs
		// and the answer says what the host found, so the operator does not
		// read a change into it.
		return storageResponse(s.deviceState(ctx), strings.Join(plan.Changes, "; "), "")
	}
	output, err := s.runScoped(ctx, opspec.FamilyStorage, arguments)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+output)
	}
	// The array is read again: mdadm exits zero on a member it has accepted
	// and on one it has already forgotten, and the two are not the same
	// state. The verifier on the agent reads it a second time; this read is
	// what the operator sees in the result.
	state := s.deviceState(ctx)
	return storageResponse(state, describeArrayAfter(state, action.GetArray(), action.GetDevice(), verb), output)
}

// describeArrayAfter says what the array looks like now, in the numbers the
// operator came for.
func describeArrayAfter(state storage.Snapshot, arrayPath, member, verb string) string {
	array := state.ArrayAt(arrayPath)
	if array == nil {
		return "the host no longer reports the array " + arrayPath
	}
	sentence := arrayPath + ": " + strconv.Itoa(array.ActiveDevices) + " of " +
		strconv.Itoa(array.RaidDevices) + " slots filled"
	if array.Degraded {
		sentence += ", degraded"
	}
	if array.SyncAction != "" {
		sentence += ", " + array.SyncAction + " running"
	}
	found := array.MemberAt(member)
	switch {
	case found == nil && verb == storage.RAIDRemove:
		return sentence + "; " + member + " is out of the array"
	case found == nil:
		return sentence + "; the array does not report " + member
	default:
		return sentence + "; " + member + " is " + found.Role
	}
}

// createVolume creates a logical volume in a group that exists.
func (s *Server) createVolume(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if !exists(storage.LVCreatePath) {
		return reject(ErrorUnsupported, "this host has no LVM tools ("+storage.LVCreatePath+")")
	}
	arguments, err := storage.LVCreateArguments(action.GetGroup(), action.GetVolume(), action.GetSize())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if _, refused := s.layerTarget(ctx, action); refused != nil {
		return refused
	}
	output, err := s.runScoped(ctx, opspec.FamilyStorage, arguments)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+output)
	}
	// The size is read back out of LVM rather than repeated from the order:
	// a request that is not a whole number of extents is rounded up, and the
	// operator is to see the size the host really gave them.
	state := s.deviceState(ctx)
	return storageResponse(state, describeVolumeAfter(state, action.GetGroup(), action.GetVolume(),
		"the volume was created"), output)
}

// createSnapshot takes a snapshot of a logical volume.
func (s *Server) createSnapshot(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if !exists(storage.LVCreatePath) {
		return reject(ErrorUnsupported, "this host has no LVM tools ("+storage.LVCreatePath+")")
	}
	arguments, err := storage.SnapshotArguments(action.GetDevice(), action.GetVolume(), action.GetSize())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	plan, refused := s.layerTarget(ctx, action)
	if refused != nil {
		return refused
	}
	output, err := s.runScoped(ctx, opspec.FamilyStorage, arguments)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+output)
	}
	state := s.deviceState(ctx)
	return storageResponse(state, describeVolumeAfter(state, plan.Group, action.GetVolume(),
		"the snapshot of "+action.GetDevice()+" was created"), output)
}

// describeVolumeAfter reads the new volume back out of LVM.
func describeVolumeAfter(state storage.Snapshot, group, name, what string) string {
	for _, volume := range state.Volumes {
		if volume.Group != group || volume.Name != name {
			continue
		}
		sentence := what + ": " + volume.Path + ", " +
			strconv.FormatUint(volume.SizeBytes>>20, 10) + " MiB"
		if origin := volume.Origin; origin != "" {
			sentence += ", a snapshot of " + origin
		}
		return sentence
	}
	// The tool exited zero and LVM does not list the volume. That is not a
	// success with a missing detail; it is the state the operator has to
	// see, and the verifier will say the same.
	return "the tool reported no error and the group " + group + " does not list a volume named " + name
}

// removeVolume deletes a logical volume or drops a snapshot.
//
// The two verbs run the same tool and mean two different things, so they
// are two operations with two permissions: the plan of a snapshot removal
// refuses an ordinary volume, and the plan of a volume removal takes the
// treatment of a format.
func (s *Server) removeVolume(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if !exists(storage.LVRemovePath) {
		return reject(ErrorUnsupported, "this host has no LVM tools ("+storage.LVRemovePath+")")
	}
	arguments, err := storage.LVRemoveArguments(action.GetDevice())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	plan, refused := s.layerTarget(ctx, action)
	if refused != nil {
		return refused
	}
	output, err := s.runScoped(ctx, opspec.FamilyStorage, arguments)
	if err != nil {
		return reject(ErrorExecFailed, err.Error()+": "+output)
	}
	state := s.deviceState(ctx)
	message := "the volume " + action.GetDevice() + " was deleted and its extents went back to " + plan.Group
	if state.VolumeAt(action.GetDevice()) != nil {
		message = "the tool reported no error and LVM still lists " + action.GetDevice()
	}
	return storageResponse(state, message, output)
}

// extendGroup adds a disk to a volume group.
//
// Two tools run one after the other: pvcreate writes an LVM label over
// whatever the disk carried, vgextend joins it to the group. The first is
// the destructive half, which is why the plan bound this operation to the
// stable identity of the disk and refused anything in use.
func (s *Server) extendGroup(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if !exists(storage.VGExtendPath) || !exists(storage.PVCreatePath) {
		return reject(ErrorUnsupported, "this host has no LVM tools ("+storage.VGExtendPath+")")
	}
	commands, err := storage.VGExtendArguments(action.GetGroup(), action.GetDevice())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	plan, refused := s.layerTarget(ctx, action)
	if refused != nil {
		return refused
	}
	if plan.Action == storage.PlanNoChange {
		return storageResponse(s.deviceState(ctx), strings.Join(plan.Changes, "; "), "")
	}
	var transcript []string
	for _, arguments := range commands {
		output, err := s.runScoped(ctx, opspec.FamilyStorage, arguments)
		transcript = append(transcript, output)
		if err != nil {
			// The label may already be written: the disk is then a physical
			// volume in no group, which the next plan will see and say.
			return reject(ErrorExecFailed, err.Error()+": "+strings.Join(transcript, "\n"))
		}
	}
	state := s.deviceState(ctx)
	message := "the tool reported no error and " + action.GetDevice() +
		" is not listed as a physical volume of " + action.GetGroup()
	if physical := state.PhysicalVolumeAt(action.GetDevice()); physical != nil && physical.Group == action.GetGroup() {
		if group := state.GroupAt(action.GetGroup()); group != nil {
			message = action.GetDevice() + " joined " + action.GetGroup() + ", which now holds " +
				strconv.FormatUint(group.SizeBytes>>20, 10) + " MiB with " +
				strconv.FormatUint(group.FreeBytes>>20, 10) + " MiB free"
		}
	}
	return storageResponse(state, message, strings.Join(transcript, "\n"))
}
