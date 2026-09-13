package helper

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/kernel"
)

// applyKernel handles the operations on the kernel settings.
func (s *Server) applyKernel(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.KernelRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.KernelRequest_OPERATION_READ:
		return kernelResponse(s.readKernel(actionCtx, action.GetKeys()), "", nil, nil)
	case helperv1.KernelRequest_OPERATION_SYSCTL_ENSURE:
		return s.writeSysctl(actionCtx, action)
	case helperv1.KernelRequest_OPERATION_MODULE_LOAD:
		return s.loadModule(actionCtx, action)
	case helperv1.KernelRequest_OPERATION_MODULE_BLACKLIST:
		return s.blockModule(actionCtx, action)
	case helperv1.KernelRequest_OPERATION_MODULE_PLAN:
		return s.planBlock(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "unknown kernel operation")
}

// writeSysctl writes the settings persistently and applies them right away.
//
// A write and an effect are two different things: some settings the kernel
// takes immediately, and some only at boot. The panel separates them in the
// result instead of reporting a success and leaving the operator with a value
// that does not apply.
func (s *Server) writeSysctl(ctx context.Context, action *helperv1.KernelRequest) *helperv1.HelperResponse {
	settings := action.GetSettings()
	if len(settings) == 0 {
		return reject(ErrorMalformed, "the change contains no setting")
	}
	if !exists(kernel.SysctlPath) {
		return reject(ErrorUnsupported, "this host has no sysctl tool")
	}

	// A key the host does not know would stay in the file forever and do
	// nothing. Its existence is checked before anything is written.
	for key := range settings {
		if err := kernel.ValidateKey(key); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if _, err := toolOutput(ctx, kernel.SysctlPath, "-n", key); err != nil {
			return reject(ErrorPreconditionFailed,
				"this kernel does not know the setting "+key)
		}
	}

	// The file receives the existing set enlarged by the change: the panel
	// manages its whole file, so writing one key must not erase the others.
	current := map[string]string{}
	if content, err := os.ReadFile(kernel.SysctlFile); err == nil {
		current = kernel.ParseSysctlFile(string(content))
	}
	for key, value := range settings {
		current[key] = value
	}
	content, err := kernel.ComposeSysctlFile(current)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := writeKernelFile(kernel.SysctlFile, content, 0o644); err != nil {
		return reject(ErrorExecFailed, "writing "+kernel.SysctlFile+": "+err.Error())
	}

	// Only the keys of this change are applied: reloading the whole file would
	// touch settings nobody asked about now.
	var applied, pending []string
	for key, value := range settings {
		if _, err := runTool(ctx,
			[]string{kernel.SysctlPath, "-w", key + "=" + value}); err != nil {
			pending = append(pending, key+" = "+value)
			continue
		}
		now, err := toolOutput(ctx, kernel.SysctlPath, "-n", key)
		if err != nil || strings.Join(strings.Fields(now), " ") != strings.Join(strings.Fields(value), " ") {
			pending = append(pending, key+" = "+value)
			continue
		}
		applied = append(applied, key+" = "+value)
	}

	message := "the settings were written and applied"
	if len(pending) > 0 {
		message = "the settings were written; some will take effect only after a restart"
	}
	return kernelResponse(s.readKernel(ctx, nil), message, pending, applied)
}

// loadModule loads a kernel module.
func (s *Server) loadModule(ctx context.Context, action *helperv1.KernelRequest) *helperv1.HelperResponse {
	if err := kernel.ValidateModule(action.GetModule()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if !exists(kernel.ModprobePath) {
		return reject(ErrorUnsupported, "this host has no modprobe")
	}
	output, err := runTool(ctx, []string{kernel.ModprobePath, action.GetModule()})
	if err != nil {
		return reject(ErrorExecFailed, "modprobe: "+err.Error()+": "+output)
	}
	return kernelResponse(s.readKernel(ctx, nil), "the module "+action.GetModule()+" was loaded", nil, nil)
}

// blockModule adds a module to the block list or removes it from it.
func (s *Server) blockModule(ctx context.Context, action *helperv1.KernelRequest) *helperv1.HelperResponse {
	if err := kernel.ValidateModule(action.GetModule()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	// A change approved on the basis of a plan is to enter the state the
	// operator looked at: a different block file or a different module state
	// than at planning time is a refusal, not a warning.
	if expected := action.GetPlanHash(); expected != "" {
		now := kernel.PlanBlacklist(s.readKernel(ctx, nil), action.GetModule(), action.GetBlacklist())
		if now.PlanHash != expected {
			return reject(ErrorPreconditionFailed,
				"the module blocks changed since the planning; the change needs a new plan")
		}
	}

	current := []string{}
	if content, err := os.ReadFile(kernel.BlacklistFile); err == nil {
		current = kernel.ParseBlacklist(string(content))
	}
	updated := make([]string, 0, len(current)+1)
	for _, name := range current {
		if name != action.GetModule() {
			updated = append(updated, name)
		}
	}
	if action.GetBlacklist() {
		updated = append(updated, action.GetModule())
	}

	content, err := kernel.ComposeBlacklist(updated)
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := writeKernelFile(kernel.BlacklistFile, content, 0o644); err != nil {
		return reject(ErrorExecFailed, "writing "+kernel.BlacklistFile+": "+err.Error())
	}

	message := "the module " + action.GetModule() + " was unblocked"
	if action.GetBlacklist() {
		message = "the module " + action.GetModule() + " was blocked"
		// A block does not unload a module that already runs, and for modules
		// pulled in by the initramfs it does not work even after a restart until
		// the initramfs is rebuilt. The panel says this directly.
		if reason := kernel.InitramfsRequired(action.GetModule(), s.moduleLoaded(action.GetModule())); reason != "" {
			message += "; " + reason
		}
	}
	return kernelResponse(s.readKernel(ctx, nil), message, nil, nil)
}

// planBlock computes the difference for a module block without touching the
// host. A protected module and a wrong name are a refusal in the plan, not an
// error of the order.
func (s *Server) planBlock(ctx context.Context, action *helperv1.KernelRequest) *helperv1.HelperResponse {
	state := s.readKernel(ctx, nil)
	plan := kernel.PlanBlacklist(state, action.GetModule(), action.GetBlacklist())
	encoded, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	message := "the change will not enter this host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == kernel.PlanNoChange:
		message = "the block of the module " + plan.Module + " is already in the desired state"
	default:
		message = strings.Join(plan.Changes, "; ")
	}
	response := kernelResponse(state, message, nil, nil)
	if response.GetKernelResult() != nil {
		response.KernelResult.Plan = encoded
	}
	return response
}

// readKernel assembles the picture of the kernel settings.
func (s *Server) readKernel(ctx context.Context, extra []string) kernel.Snapshot {
	snapshot := kernel.Snapshot{ObservedAt: time.Now().UTC(), ManagedPath: kernel.SysctlFile}

	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		snapshot.CommandLine = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		snapshot.Release = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/proc/modules"); err == nil {
		snapshot.Modules = kernel.ParseModules(string(data))
	}

	written := map[string]string{}
	if content, err := os.ReadFile(kernel.SysctlFile); err == nil {
		snapshot.Managed = string(content)
		written = kernel.ParseSysctlFile(string(content))
	}
	if content, err := os.ReadFile(kernel.BlacklistFile); err == nil {
		snapshot.Blacklist = kernel.ParseBlacklist(string(content))
	}
	for i := range snapshot.Modules {
		for _, blocked := range snapshot.Blacklist {
			if snapshot.Modules[i].Name == blocked {
				snapshot.Modules[i].Blacklisted = true
			}
		}
	}

	// The profile plus what the panel has already written plus what was asked
	// for now. Enumerating the whole of /proc/sys would be a cost without an
	// answer.
	keys := append([]string{}, kernel.DefaultProfile...)
	for key := range written {
		keys = append(keys, key)
	}
	keys = append(keys, extra...)
	snapshot.Settings = s.readSettings(ctx, keys, written)
	return snapshot
}

// readSettings reads the current values of the given keys.
func (s *Server) readSettings(ctx context.Context, keys []string,
	written map[string]string) []kernel.Setting {
	seen := map[string]bool{}
	var result []kernel.Setting
	for _, key := range keys {
		if seen[key] || kernel.ValidateKey(key) != nil {
			continue
		}
		seen[key] = true
		setting := kernel.Setting{Key: key}
		if value, ok := written[key]; ok {
			setting.Desired = value
			setting.Managed = true
			setting.Source = kernel.SysctlFile
		}
		if output, err := toolOutput(ctx, kernel.SysctlPath, "-n", key); err == nil {
			setting.Current = strings.Join(strings.Fields(output), " ")
		}
		// A key the kernel does not know is not shown with an empty value: it
		// would look like a setting whose value is zero.
		if setting.Current == "" && setting.Desired == "" {
			continue
		}
		result = append(result, setting)
	}
	return result
}

func (s *Server) moduleLoaded(name string) bool {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	for _, module := range kernel.ParseModules(string(data)) {
		if module.Name == name {
			return true
		}
	}
	return false
}

func writeKernelFile(path, content string, mode os.FileMode) error {
	temporary := path + ".new"
	if err := os.WriteFile(temporary, []byte(content), mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func kernelResponse(snapshot kernel.Snapshot, message string,
	pending, applied []string) *helperv1.HelperResponse {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		KernelResult: &helperv1.KernelResult{
			Snapshot: encoded, Message: message,
			PendingReboot: pending, AppliedRuntime: applied,
		},
	}
}
