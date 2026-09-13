package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/storage"
)

// The paths of the mount tools. Fixed, not looked up in PATH.
const (
	mountPath  = "/usr/bin/mount"
	umountPath = "/usr/bin/umount"
	fsckPath   = "/usr/sbin/fsck"
	blkidPath  = "/usr/sbin/blkid"
)

// applyStorage handles the operations on the disk space of the host.
func (s *Server) applyStorage(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.StorageRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 60*time.Minute {
		timeout = 10 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

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
	}
	return reject(ErrorUnknownAction, "unknown disk space operation")
}

// planMount computes the difference between the mount found and the one
// requested.
//
// It changes nothing. The input checks are the same as during a mount, and on
// top of that the plan resolves the source to the UUID of the filesystem this
// host has: that UUID then travels in the change, so a disk that got a
// different path after a restart is not mounted in somebody else's place.
func (s *Server) planMount(ctx context.Context, action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if err := storage.ValidateTarget(action.GetTarget()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	// A plan without a source is an unmount plan: a mount always has a source,
	// an unmount never does. The result names this directly in the action field.
	unmounting := action.GetSource() == ""
	if !unmounting {
		if err := storage.ValidateSource(action.GetSource()); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if err := storage.ValidateOptions(action.GetOptions(), action.GetFsType()); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
	}

	state := s.storagePicture(ctx)
	if state.UnavailableReason != "" {
		return reject(ErrorUnsupported, state.UnavailableReason)
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return reject(ErrorExecFailed, "mountinfo: "+err.Error())
	}
	fstab, _ := os.ReadFile(storage.FstabPath)
	state.Mounts = storage.MergeMounts(
		storage.ParseMountinfo(string(mountinfo)), storage.ParseFstab(string(fstab)))

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
	// A plan computed in a private mount namespace would describe a change that
	// never enters the host. The refusal is to stand in the plan, not in the
	// execution.
	if plan.Refusal == "" && plan.Action != storage.PlanNoChange &&
		plan.Action != storage.PlanRemoveAbsent {
		if err := sharedMountNamespace(); err != nil {
			plan.Refuse(err.Error())
		}
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
	output, err := runTool(ctx, arguments)
	message := "the filesystem was checked without errors"
	if err != nil {
		// fsck returns bit codes: 1 means corrected errors, 4 errors left
		// behind. A non-zero code does not always mean a failure of the
		// operation, so the result is described by its content, not by the code
		// alone.
		message = "fsck reported remarks: " + err.Error()
	}
	return storageResponse(s.readLVM(ctx), message, output)
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
	output, err := runTool(ctx, arguments)
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
		Path:      action.GetDevice(),
		Serial:    action.GetExpectedSerial(),
		UUID:      action.GetExpectedUuid(),
		SizeBytes: action.GetExpectedSizeBytes(),
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
	output, err := runTool(ctx, arguments)
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
	state := s.storagePicture(ctx)
	if response := s.checkDestructiveTarget(state, action); response != nil {
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
	state := s.storagePicture(ctx)
	if response := s.checkDestructiveTarget(state, action); response != nil {
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
func (s *Server) checkDestructiveTarget(state storage.Snapshot,
	action *helperv1.StorageRequest) *helperv1.HelperResponse {
	if err := (storage.DeviceIdentity{
		Path:      action.GetDevice(),
		Serial:    action.GetExpectedSerial(),
		UUID:      action.GetExpectedUuid(),
		SizeBytes: action.GetExpectedSizeBytes(),
	}).Matches(state.DeviceAt(action.GetDevice())); err != nil {
		return reject(ErrorPreconditionFailed, err.Error())
	}
	if point := storage.InUse(state, action.GetDevice()); point != "" {
		return reject(ErrorUnsupported,
			"the device is in use (mounted at "+point+"); a destructive operation needs it unmounted")
	}
	return nil
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
		"NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,UUID,PARTUUID,MOUNTPOINTS,MODEL,SERIAL,WWN,ROTA,RO,PKNAME")
	if err != nil {
		return storage.Snapshot{UnavailableReason: "lsblk: " + err.Error()}
	}
	devices, err := storage.ParseDevices(output)
	if err != nil {
		return storage.Snapshot{UnavailableReason: err.Error()}
	}
	return storage.Snapshot{Devices: devices}
}

// planDevice computes the plan of a check or an extension without touching the
// host. A device that does not exist, a filesystem mounted before an fsck and a
// group without space are a refusal in the plan, not a failure of the execution.
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
	}
	switch kind {
	case storage.PlanFSResize:
		return storage.ComputeFSResize(state, action.GetDevice())
	case storage.PlanLVExtend:
		return storage.ComputeLVExtend(state, action.GetDevice(), action.GetSize())
	case storage.PlanCheck:
		return storage.ComputeCheck(state, action.GetDevice(), action.GetRepair())
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
		return reject(ErrorPreconditionFailed,
			"the device "+action.GetDevice()+" changed since the planning; the change needs a new plan")
	}
	return nil
}

// deviceState assembles the device topology together with LVM.
func (s *Server) deviceState(ctx context.Context) storage.Snapshot {
	state := s.storagePicture(ctx)
	lvm := s.readLVM(ctx)
	state.Groups, state.Volumes = lvm.Groups, lvm.Volumes
	state.LVMUnavailableReason = lvm.LVMUnavailableReason
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
	if output, err := toolOutput(ctx, storage.VGSPath,
		"--reportformat", "json", "--units", "b"); err == nil {
		if groups, err := storage.ParseGroups(output); err == nil {
			snapshot.Groups = groups
		}
	}
	if output, err := toolOutput(ctx, storage.LVSPath,
		"--reportformat", "json", "--units", "b",
		"-o", "lv_name,vg_name,lv_size,lv_path"); err == nil {
		if volumes, err := storage.ParseVolumes(output); err == nil {
			snapshot.Volumes = volumes
		}
	}
	return snapshot
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
