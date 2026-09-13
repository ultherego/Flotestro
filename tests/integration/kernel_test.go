//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type settingView struct {
	Key     string `json:"key"`
	Current string `json:"current"`
	Desired string `json:"desired"`
	Managed bool   `json:"managed"`
}

type moduleView struct {
	Name        string `json:"name"`
	SizeBytes   uint64 `json:"size_bytes"`
	Blacklisted bool   `json:"blacklisted"`
}

type kernelSnapshot struct {
	Release           string        `json:"release"`
	CommandLine       string        `json:"command_line"`
	Settings          []settingView `json:"settings"`
	Modules           []moduleView  `json:"modules"`
	Blacklist         []string      `json:"blacklist"`
	ManagedPath       string        `json:"managed_path"`
	UnavailableReason string        `json:"unavailable_reason"`
}

const kernelReason = "integration test of the kernel module"

// TestKernelShowsAProfileNotAllOfProcSys checks that the module shows a
// profile of settings and the modules, not a few thousand /proc/sys keys.
func TestKernelShowsAProfileNotAllOfProcSys(t *testing.T) {
	h := newHarness(t)

	for _, family := range []string{"debian", "rhel"} {
		t.Run(family, func(t *testing.T) {
			host := h.hostByFamily(family)
			state := hostKernelSnapshot(t, h, host.ID)
			if state.UnavailableReason != "" {
				t.Fatalf("the kernel state was not read: %s", state.UnavailableReason)
			}
			if state.Release == "" || state.CommandLine == "" {
				t.Errorf("state = %+v", state.Release)
			}
			if len(state.Settings) == 0 || len(state.Settings) > 200 {
				t.Errorf("settings = %d; the profile is to be a set, not the whole tree", len(state.Settings))
			}
			for _, setting := range state.Settings {
				// A key with neither a current nor a desired value says
				// nothing; shown, it would look like a setting with a zero
				// value.
				if setting.Current == "" && setting.Desired == "" {
					t.Errorf("setting without a value: %+v", setting)
				}
			}
			if len(state.Modules) == 0 {
				t.Error("the host reported no module at all")
			}
		})
	}
}

// TestKernelSettingIsWrittenAndPersistent checks the full path: the write
// to the panel file, immediate application and visibility in the inventory.
func TestKernelSettingIsWrittenAndPersistent(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "sysctl.ensure", "reason": kernelReason,
			"payload": map[string]any{"kernel": map[string]any{
				"settings": map[string]string{"vm.swappiness": "60"}}},
		}, 2*time.Minute)
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "sysctl.ensure", "reason": kernelReason,
		"payload": map[string]any{"kernel": map[string]any{
			"settings": map[string]string{"vm.swappiness": "25"}}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("writing the setting: state = %s, %s", job.State, lastMessage(attempts))
	}

	state := hostKernelSnapshot(t, h, host.ID)
	var swappiness settingView
	for _, setting := range state.Settings {
		if setting.Key == "vm.swappiness" {
			swappiness = setting
		}
	}
	if swappiness.Current != "25" || swappiness.Desired != "25" || !swappiness.Managed {
		t.Errorf("setting after the write = %+v", swappiness)
	}
	if state.ManagedPath != "/etc/sysctl.d/90-flotestro.conf" {
		t.Errorf("panel file = %q", state.ManagedPath)
	}
}

// TestSettingsOutsideTheScopeDoNotReachTheHost guards the boundary:
// /proc/sys holds switches that disable kernel protections or stop the
// host.
func TestSettingsOutsideTheScopeDoNotReachTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, tc := range []struct {
		settings map[string]string
		why      string
	}{
		{map[string]string{"kernel.sysrq": "1"}, "the sysrq switch"},
		{map[string]string{"kernel.core_pattern": "|/tmp/x"}, "a program on core dump"},
		{map[string]string{"dev.raid.speed_limit_max": "1"}, "a branch outside the scope"},
		{map[string]string{"vm.swappiness": "10\nkernel.sysrq = 1"}, "a newline in the value"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
				map[string]any{"action": "sysctl.ensure", "reason": kernelReason,
					"payload": map[string]any{"kernel": map[string]any{
						"settings": tc.settings}}},
				nil, http.StatusBadRequest)
		})
	}

	// A key the host does not know would stay in the file forever and do
	// nothing.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "sysctl.ensure", "reason": kernelReason,
		"payload": map[string]any{"kernel": map[string]any{
			"settings": map[string]string{"vm.no_such_key": "1"}}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Error("the panel wrote a setting the kernel does not know")
	}
	if !strings.Contains(lastMessage(attempts), "does not know the setting") {
		t.Errorf("refusal without a reason: %q", lastMessage(attempts))
	}
}

// TestModuleBlacklistSaysWhatWillHappen checks that the panel does not
// pretend an entry in modprobe.d unloaded a running module.
func TestModuleBlacklistSaysWhatWillHappen(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// A module the host cannot boot without cannot be blacklisted.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "kernel.module.blacklist", "reason": kernelReason,
			"payload": map[string]any{"kernel": map[string]any{
				"module": "dm_mod", "blacklist": true}}},
		nil, http.StatusBadRequest)

	state := hostKernelSnapshot(t, h, host.ID)
	var loaded string
	for _, module := range state.Modules {
		if !module.Blacklisted && module.Name != "" && !strings.HasPrefix(module.Name, "dm") {
			loaded = module.Name
			break
		}
	}
	if loaded == "" {
		t.Skip("the host has no module suitable for the attempt")
	}

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "kernel.module.blacklist", "reason": kernelReason,
			"payload": map[string]any{"kernel": map[string]any{
				"module": loaded, "blacklist": false}},
		}, 2*time.Minute)
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "kernel.module.blacklist", "reason": kernelReason,
		"payload": map[string]any{"kernel": map[string]any{
			"module": loaded, "blacklist": true}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("module blacklist: state = %s, %s", job.State, lastMessage(attempts))
	}
	// A loaded module does not disappear once the blacklist is written, and
	// the operator is to read that, not discover it at the next reboot.
	if !strings.Contains(lastMessage(attempts), "after a reboot") {
		t.Errorf("blacklist without an explanation of the effect: %q", lastMessage(attempts))
	}

	after := hostKernelSnapshot(t, h, host.ID)
	found := false
	for _, name := range after.Blacklist {
		if name == loaded {
			found = true
		}
	}
	if !found {
		t.Errorf("the blacklist is not visible in the inventory: %v", after.Blacklist)
	}
}

func hostKernelSnapshot(t *testing.T, h *harness, hostID string) kernelSnapshot {
	t.Helper()
	var fragment inventoryFragment
	h.do(http.MethodGet, "/api/v1/hosts/"+hostID+"/inventory/kernel", nil, &fragment, http.StatusOK)
	var state kernelSnapshot
	if err := json.Unmarshal(fragment.Payload, &state); err != nil {
		t.Fatalf("kernel snapshot: %v", err)
	}
	return state
}
